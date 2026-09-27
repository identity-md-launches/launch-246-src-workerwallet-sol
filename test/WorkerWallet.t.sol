// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WorkerWallet} from "../src/WorkerWallet.sol";

// ----------------------------------------------------------------------------- cheatcodes

interface Vm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address msgSender) external;
    function deal(address account, uint256 newBalance) external;
    function chainId(uint256 newChainId) external;
    function expectEmit(bool checkTopic1, bool checkTopic2, bool checkTopic3, bool checkData) external;
    function expectRevert(bytes calldata revertData) external;
    function expectRevert() external;
}

// ------------------------------------------------------------------------------ interfaces

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external
        returns (bytes4);
}

// ----------------------------------------------------------------------------- mock ERC-721

/// @dev Minimal ERC-721 sufficient for the wallet tests: ownership, approvals, transferFrom,
///      and safeTransferFrom with the receiver check.
contract MockERC721 {
    mapping(uint256 => address) internal _owners;
    mapping(uint256 => address) internal _approved;
    mapping(address => mapping(address => bool)) internal _operators;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    function mint(address to, uint256 tokenId) external {
        require(_owners[tokenId] == address(0), "minted");
        _owners[tokenId] = to;
        emit Transfer(address(0), to, tokenId);
    }

    function ownerOf(uint256 tokenId) external view returns (address) {
        address o = _owners[tokenId];
        require(o != address(0), "no token");
        return o;
    }

    function approve(address to, uint256 tokenId) external {
        require(msg.sender == _owners[tokenId], "not owner");
        _approved[tokenId] = to;
    }

    function setApprovalForAll(address operator, bool ok) external {
        _operators[msg.sender][operator] = ok;
    }

    function _authorized(address spender, uint256 tokenId) internal view returns (bool) {
        address o = _owners[tokenId];
        return spender == o || _approved[tokenId] == spender || _operators[o][spender];
    }

    function transferFrom(address from, address to, uint256 tokenId) public {
        require(_owners[tokenId] == from, "wrong from");
        require(_authorized(msg.sender, tokenId), "not authorized");
        require(to != address(0), "zero to");
        delete _approved[tokenId];
        _owners[tokenId] = to;
        emit Transfer(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) external {
        safeTransferFrom(from, to, tokenId, "");
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public {
        transferFrom(from, to, tokenId);
        if (to.code.length > 0) {
            bytes4 ret = IERC721Receiver(to).onERC721Received(msg.sender, from, tokenId, data);
            require(ret == IERC721Receiver.onERC721Received.selector, "unsafe recipient");
        }
    }
}

// ------------------------------------------------------------------- mock EIP-712 application

/// @dev An application with its own EIP-712 domain that verifies signatures the way
///      OpenZeppelin's SignatureChecker does: ecrecover for EOAs, ERC-1271 for contracts.
contract MockApp {
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant ORDER_TYPEHASH = keccak256("Order(address maker,uint256 amount,uint256 nonce)");
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    bytes32 public immutable nameHash;

    mapping(bytes32 => bool) public filled;

    constructor(string memory name) {
        nameHash = keccak256(bytes(name));
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, nameHash, keccak256("1"), block.chainid, address(this)));
    }

    function orderStructHash(address maker, uint256 amount, uint256 nonce) public pure returns (bytes32) {
        return keccak256(abi.encode(ORDER_TYPEHASH, maker, amount, nonce));
    }

    function orderDigest(address maker, uint256 amount, uint256 nonce) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), orderStructHash(maker, amount, nonce)));
    }

    /// @dev Mirrors OpenZeppelin SignatureChecker.isValidSignatureNow.
    function isValidSignatureNow(address signer, bytes32 hash, bytes memory signature) public view returns (bool) {
        if (signer.code.length == 0) {
            if (signature.length != 65) return false;
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            if (uint256(s) > N / 2) return false;
            address recovered = ecrecover(hash, v, r, s);
            return recovered != address(0) && recovered == signer;
        }
        (bool ok, bytes memory ret) =
            signer.staticcall(abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature));
        return ok && ret.length >= 32 && abi.decode(ret, (bytes4)) == IERC1271.isValidSignature.selector;
    }

    /// @notice Fill an order signed by `maker`. Reverts if the signature is not accepted.
    function fill(address maker, uint256 amount, uint256 nonce, bytes memory signature) external {
        bytes32 digest = orderDigest(maker, amount, nonce);
        require(!filled[digest], "filled");
        require(isValidSignatureNow(maker, digest, signature), "bad signature");
        filled[digest] = true;
    }
}

// ------------------------------------------------------------------------- helper contracts

/// @dev Callee that reenters the wallet during `execute` and records what it got away with.
contract Reenterer {
    WorkerWallet public wallet;
    address public attacker;
    bool public reentered;
    bool public setWorkerOk;
    bool public allowDomainOk;
    bool public executeOk;
    bytes public setWorkerErr;

    function attack(WorkerWallet w, address a) external {
        wallet = w;
        attacker = a;
    }

    receive() external payable {
        if (reentered) return;
        reentered = true;
        bytes memory err;
        (setWorkerOk, err) = address(wallet).call(abi.encodeWithSelector(WorkerWallet.setWorker.selector, attacker));
        setWorkerErr = err;
        (allowDomainOk,) =
            address(wallet).call(abi.encodeWithSelector(WorkerWallet.allowDomain.selector, bytes32(uint256(1)), true));
        (executeOk,) = address(wallet)
            .call(abi.encodeWithSelector(WorkerWallet.execute.selector, attacker, address(wallet).balance, ""));
    }
}

contract Reverter {
    error Nope(uint256 code);

    fallback() external payable {
        revert Nope(7);
    }
}

contract Echo {
    fallback() external payable {
        bytes memory d = msg.data;
        assembly {
            return(add(d, 0x20), mload(d))
        }
    }
}

/// @dev Contract that rejects ERC-721 safe transfers, to prove the mock token enforces the receiver check.
contract BadReceiver {
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return 0xdeadbeef;
    }
}

// ------------------------------------------------------------------------------------ tests

contract WorkerWalletTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant INVALID = 0xffffffff;
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant WORKER_APPROVAL_TYPEHASH = keccak256("WorkerApproval(bytes32 hash)");

    // Events re-declared for expectEmit.
    event WorkerSet(address indexed previousWorker, address indexed newWorker);
    event DomainAllowed(bytes32 indexed domainSeparator, bool allowed);
    event Executed(address indexed to, uint256 value, bytes data, bytes result);
    event EtherReceived(address indexed from, uint256 value);
    event ERC721Received(address indexed token, address indexed operator, address indexed from, uint256 tokenId);

    uint256 internal constant WORKER_PK = 0xA11CE;
    uint256 internal constant WORKER2_PK = 0xB0B;
    uint256 internal constant STRANGER_PK = 0xC0FFEE;

    address internal owner = address(0x0000000000000000000000000000000000001111);
    address internal owner2 = address(0x0000000000000000000000000000000000002222);
    address internal stranger = address(0x0000000000000000000000000000000000003333);
    address internal worker;
    address internal worker2;

    WorkerWallet internal wallet;
    WorkerWallet internal wallet2; // shares the worker with `wallet`
    MockERC721 internal nft;
    MockApp internal app;
    MockApp internal otherApp;
    // Cached so that vm.prank / vm.expectRevert are not consumed by an argument-position call.
    bytes32 internal appDomain;
    bytes32 internal otherDomain;

    uint256 internal constant SEAT = 420;

    function setUp() public {
        worker = vm.addr(WORKER_PK);
        worker2 = vm.addr(WORKER2_PK);

        wallet = new WorkerWallet(owner);
        wallet2 = new WorkerWallet(owner2);
        nft = new MockERC721();
        app = new MockApp("MockApp");
        otherApp = new MockApp("OtherApp");
        appDomain = app.domainSeparator();
        otherDomain = otherApp.domainSeparator();

        nft.mint(address(this), SEAT);
        nft.safeTransferFrom(address(this), address(wallet), SEAT);

        vm.prank(owner);
        wallet.setWorker(worker);
        vm.prank(owner);
        wallet.allowDomain(appDomain, true);

        vm.prank(owner2);
        wallet2.setWorker(worker);
        vm.prank(owner2);
        wallet2.allowDomain(appDomain, true);
    }

    // ------------------------------------------------------------------------- helpers

    function _walletDomainSeparator(WorkerWallet w) internal view returns (bytes32) {
        return keccak256(
            abi.encode(EIP712_DOMAIN_TYPEHASH, keccak256("WorkerWallet"), keccak256("1"), block.chainid, address(w))
        );
    }

    function _approvalDigest(WorkerWallet w, bytes32 hash) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01", _walletDomainSeparator(w), keccak256(abi.encode(WORKER_APPROVAL_TYPEHASH, hash))
            )
        );
    }

    function _rawSign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Full ERC-1271 signature for `w` over app digest (domain, structHash), signed by `pk`.
    function _sign(WorkerWallet w, uint256 pk, bytes32 domain, bytes32 structHash)
        internal
        view
        returns (bytes32 hash, bytes memory sig)
    {
        hash = keccak256(abi.encodePacked("\x19\x01", domain, structHash));
        bytes memory workerSig = _rawSign(pk, _approvalDigest(w, hash));
        sig = abi.encode(domain, structHash, workerSig);
    }

    /// @dev Calls isValidSignature through staticcall so a revert is reported as a distinct failure.
    function _check(WorkerWallet w, bytes32 hash, bytes memory sig) internal view returns (bytes4) {
        (bool ok, bytes memory ret) =
            address(w).staticcall(abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, sig));
        require(ok, "isValidSignature reverted");
        require(ret.length == 32, "bad return length");
        return abi.decode(ret, (bytes4));
    }

    function _structHash(uint256 nonce) internal view returns (bytes32) {
        return app.orderStructHash(address(wallet), 1 ether, nonce);
    }

    // --------------------------------------------------------------------- constructor

    function test_constructor_setsOwnerAndNoWorker() public {
        WorkerWallet w = new WorkerWallet(owner);
        require(w.owner() == owner, "owner");
        require(w.worker() == address(0), "worker must start at zero");
    }

    function test_constructor_zeroOwnerReverts() public {
        vm.expectRevert(abi.encodeWithSelector(WorkerWallet.ZeroOwner.selector));
        new WorkerWallet(address(0));
    }

    function test_domainSeparator_matchesSpec() public view {
        require(wallet.domainSeparator() == _walletDomainSeparator(wallet), "domain separator");
        require(wallet.domainSeparator() != wallet2.domainSeparator(), "wallets must not share a domain");
        bytes32 h = keccak256("x");
        require(wallet.workerApprovalDigest(h) == _approvalDigest(wallet, h), "approval digest");
    }

    // -------------------------------------------------------------------- access control

    function test_setWorker_onlyOwner() public {
        vm.prank(worker);
        vm.expectRevert(abi.encodeWithSelector(WorkerWallet.NotOwner.selector));
        wallet.setWorker(worker);

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(WorkerWallet.NotOwner.selector));
        wallet.setWorker(stranger);

        // The other wallet's owner is a stranger here.
        vm.prank(owner2);
        vm.expectRevert(abi.encodeWithSelector(WorkerWallet.NotOwner.selector));
        wallet.setWorker(owner2);

        require(wallet.worker() == worker, "worker unchanged");
    }

    function test_setWorker_rotatesAndEmits() public {
        vm.expectEmit(true, true, true, true);
        emit WorkerSet(worker, worker2);
        vm.prank(owner);
        wallet.setWorker(worker2);
        require(wallet.worker() == worker2, "rotated");

        vm.expectEmit(true, true, true, true);
        emit WorkerSet(worker2, address(0));
        vm.prank(owner);
        wallet.setWorker(address(0));
        require(wallet.worker() == address(0), "revoked");
    }

    function test_allowDomain_onlyOwner() public {
        bytes32 d = otherApp.domainSeparator();
        vm.prank(worker);
        vm.expectRevert(abi.encodeWithSelector(WorkerWallet.NotOwner.selector));
        wallet.allowDomain(d, true);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(WorkerWallet.NotOwner.selector));
        wallet.allowDomain(d, true);
        require(!wallet.allowedDomains(d), "unchanged");

        // Worker cannot disallow either.
        vm.prank(worker);
        vm.expectRevert(abi.encodeWithSelector(WorkerWallet.NotOwner.selector));
        wallet.allowDomain(appDomain, false);
        require(wallet.allowedDomains(app.domainSeparator()), "still allowed");
    }

    function test_allowDomain_togglesAndEmits() public {
        bytes32 d = otherApp.domainSeparator();
        vm.expectEmit(true, true, true, true);
        emit DomainAllowed(d, true);
        vm.prank(owner);
        wallet.allowDomain(d, true);
        require(wallet.allowedDomains(d), "allowed");

        vm.expectEmit(true, true, true, true);
        emit DomainAllowed(d, false);
        vm.prank(owner);
        wallet.allowDomain(d, false);
        require(!wallet.allowedDomains(d), "disallowed");
    }

    function test_execute_onlyOwner() public {
        bytes memory data = abi.encodeWithSelector(MockERC721.transferFrom.selector, address(wallet), worker, SEAT);

        vm.prank(worker);
        vm.expectRevert(abi.encodeWithSelector(WorkerWallet.NotOwner.selector));
        wallet.execute(address(nft), 0, data);

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(WorkerWallet.NotOwner.selector));
        wallet.execute(address(nft), 0, data);

        vm.deal(address(wallet), 1 ether);
        vm.prank(worker);
        vm.expectRevert(abi.encodeWithSelector(WorkerWallet.NotOwner.selector));
        wallet.execute(worker, 1 ether, "");

        require(nft.ownerOf(SEAT) == address(wallet), "seat stays");
        require(address(wallet).balance == 1 ether, "eth stays");
    }

    function test_worker_cannotMoveSeatDirectly() public {
        vm.prank(worker);
        vm.expectRevert(bytes("not authorized"));
        nft.transferFrom(address(wallet), worker, SEAT);

        vm.prank(worker);
        vm.expectRevert(bytes("not authorized"));
        nft.safeTransferFrom(address(wallet), worker, SEAT);

        vm.prank(worker);
        vm.expectRevert(bytes("not owner"));
        nft.approve(worker, SEAT);

        require(nft.ownerOf(SEAT) == address(wallet), "seat stays");
    }

    function test_worker_hasNoFunctionOfItsOwn() public {
        // There is no worker-callable entry point: an unknown selector has no fallback to land on.
        vm.prank(worker);
        (bool ok,) = address(wallet).call(abi.encodeWithSignature("withdraw(address)", worker));
        require(!ok, "unknown selector must revert");
        vm.prank(worker);
        (ok,) = address(wallet).call{value: 0}(abi.encodeWithSignature("transfer(address,uint256)", worker, 1));
        require(!ok, "unknown selector must revert");
    }

    // ---------------------------------------------------------------- owner moves assets

    function test_owner_movesSeatOut() public {
        bytes memory data = abi.encodeWithSelector(MockERC721.transferFrom.selector, address(wallet), owner, SEAT);
        vm.expectEmit(true, true, true, true);
        emit Executed(address(nft), 0, data, "");
        vm.prank(owner);
        bytes memory result = wallet.execute(address(nft), 0, data);
        require(result.length == 0, "no return data");
        require(nft.ownerOf(SEAT) == owner, "seat moved to owner");
    }

    function test_owner_movesSeatOutViaSafeTransfer() public {
        bytes memory data = abi.encodeWithSignature(
            "safeTransferFrom(address,address,uint256)", address(wallet), address(wallet2), SEAT
        );
        vm.prank(owner);
        wallet.execute(address(nft), 0, data);
        require(nft.ownerOf(SEAT) == address(wallet2), "seat moved to another wallet");
    }

    function test_owner_movesEthOut() public {
        vm.deal(address(wallet), 3 ether);
        uint256 before = owner.balance;
        vm.expectEmit(true, true, true, true);
        emit Executed(owner, 2 ether, "", "");
        vm.prank(owner);
        wallet.execute(owner, 2 ether, "");
        require(owner.balance == before + 2 ether, "owner received");
        require(address(wallet).balance == 1 ether, "wallet remainder");
    }

    function test_execute_returnsCalleeData() public {
        Echo echo = new Echo();
        bytes memory data = hex"deadbeef01020304";
        vm.prank(owner);
        bytes memory result = wallet.execute(address(echo), 0, data);
        require(keccak256(result) == keccak256(data), "echoed");
    }

    function test_execute_bubblesFailure() public {
        Reverter r = new Reverter();
        bytes memory inner = abi.encodeWithSelector(Reverter.Nope.selector, uint256(7));
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(WorkerWallet.ExecutionFailed.selector, inner));
        wallet.execute(address(r), 0, "");
    }

    function test_execute_insufficientBalanceReverts() public {
        vm.prank(owner);
        vm.expectRevert();
        wallet.execute(owner, 1 ether, "");
    }

    function test_execute_selfCallCannotBypassOwnerCheck() public {
        // The wallet calling itself is not the owner, so config changes via execute(this, ...) fail.
        bytes memory data = abi.encodeWithSelector(WorkerWallet.setWorker.selector, stranger);
        bytes memory inner = abi.encodeWithSelector(WorkerWallet.NotOwner.selector);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(WorkerWallet.ExecutionFailed.selector, inner));
        wallet.execute(address(wallet), 0, data);
        require(wallet.worker() == worker, "unchanged");
    }

    function test_execute_reentrancyGainsNothing() public {
        Reenterer r = new Reenterer();
        r.attack(wallet, stranger);
        vm.deal(address(wallet), 2 ether);

        vm.prank(owner);
        wallet.execute(address(r), 1 ether, "");

        require(r.reentered(), "callee ran");
        require(!r.setWorkerOk(), "reentrant setWorker must fail");
        require(!r.allowDomainOk(), "reentrant allowDomain must fail");
        require(!r.executeOk(), "reentrant execute must fail");
        require(
            keccak256(r.setWorkerErr()) == keccak256(abi.encodeWithSelector(WorkerWallet.NotOwner.selector)), "NotOwner"
        );
        require(wallet.worker() == worker, "worker unchanged");
        require(!wallet.allowedDomains(bytes32(uint256(1))), "domains unchanged");
        require(address(wallet).balance == 1 ether, "only the owner's transfer left");
        require(address(r).balance == 1 ether, "callee got exactly what owner sent");
        require(stranger.balance == 0, "attacker got nothing");
    }

    // ----------------------------------------------------------------------- receiving

    function test_receivesEth() public {
        vm.deal(stranger, 1 ether);
        vm.expectEmit(true, true, true, true);
        emit EtherReceived(stranger, 0.5 ether);
        vm.prank(stranger);
        (bool ok,) = address(wallet).call{value: 0.5 ether}("");
        require(ok, "receive");
        require(address(wallet).balance == 0.5 ether, "balance");
    }

    function test_receivesSafeTransfer() public {
        uint256 id = 7;
        nft.mint(stranger, id);
        vm.expectEmit(true, true, true, true);
        emit ERC721Received(address(nft), stranger, stranger, id);
        vm.prank(stranger);
        nft.safeTransferFrom(stranger, address(wallet), id, hex"01");
        require(nft.ownerOf(id) == address(wallet), "received");
    }

    function test_onERC721Received_returnsSelector() public {
        bytes4 ret = wallet.onERC721Received(stranger, stranger, 1, "");
        require(ret == IERC721Receiver.onERC721Received.selector, "selector");
    }

    function test_mockToken_enforcesReceiverCheck() public {
        // Sanity: the mock actually rejects bad receivers, so the wallet test above means something.
        BadReceiver bad = new BadReceiver();
        nft.mint(stranger, 8);
        vm.prank(stranger);
        vm.expectRevert(bytes("unsafe recipient"));
        nft.safeTransferFrom(stranger, address(bad), 8);
    }

    // ------------------------------------------------------------------ ERC-1271 happy path

    function test_isValidSignature_validForAllowedDomain() public view {
        (bytes32 hash, bytes memory sig) = _sign(wallet, WORKER_PK, app.domainSeparator(), _structHash(1));
        require(sig.length == 224, "canonical encoding length");
        require(_check(wallet, hash, sig) == MAGIC, "valid");
        // Also through the plain external call path.
        require(wallet.isValidSignature(hash, sig) == MAGIC, "valid direct");
    }

    function test_isValidSignature_secondAllowedDomain() public {
        vm.prank(owner);
        wallet.allowDomain(otherDomain, true);
        (bytes32 hash, bytes memory sig) = _sign(wallet, WORKER_PK, otherApp.domainSeparator(), _structHash(1));
        require(_check(wallet, hash, sig) == MAGIC, "valid for other app");
    }

    function test_isValidSignature_sameSigAgainstSecondWalletSameWorker() public view {
        // wallet2 shares the worker and allows the same domain, yet a wallet-bound digest differs.
        (bytes32 hash, bytes memory sig) = _sign(wallet, WORKER_PK, app.domainSeparator(), _structHash(1));
        require(_check(wallet, hash, sig) == MAGIC, "valid on wallet 1");
        require(_check(wallet2, hash, sig) == INVALID, "must not validate on wallet 2");

        // And the mirror: a signature made for wallet2 does not validate on wallet 1.
        (bytes32 hash2, bytes memory sig2) = _sign(wallet2, WORKER_PK, app.domainSeparator(), _structHash(1));
        require(_check(wallet2, hash2, sig2) == MAGIC, "valid on wallet 2");
        require(_check(wallet, hash2, sig2) == INVALID, "must not validate on wallet 1");
    }

    // ------------------------------------------------------------ ERC-1271 replay defences

    function test_isValidSignature_disallowedDomain() public {
        // Domain never allowed.
        (bytes32 hash, bytes memory sig) = _sign(wallet, WORKER_PK, otherApp.domainSeparator(), _structHash(1));
        require(_check(wallet, hash, sig) == INVALID, "never allowed");

        // Domain allowed, then revoked: the very same signature stops validating.
        (hash, sig) = _sign(wallet, WORKER_PK, app.domainSeparator(), _structHash(2));
        require(_check(wallet, hash, sig) == MAGIC, "valid while allowed");
        vm.prank(owner);
        wallet.allowDomain(appDomain, false);
        require(_check(wallet, hash, sig) == INVALID, "invalid once disallowed");
        vm.prank(owner);
        wallet.allowDomain(appDomain, true);
        require(_check(wallet, hash, sig) == MAGIC, "valid again once re-allowed (nothing cached)");
    }

    function test_isValidSignature_domainSwapInEncodingDoesNotHelp() public view {
        // Worker signed for otherApp (not allowed). Relabelling the encoding with the allowed domain
        // breaks the hash reconstruction, so the wallet must reject.
        (bytes32 hash,) = _sign(wallet, WORKER_PK, otherApp.domainSeparator(), _structHash(1));
        bytes memory workerSig = _rawSign(WORKER_PK, _approvalDigest(wallet, hash));
        bytes memory relabelled = abi.encode(app.domainSeparator(), _structHash(1), workerSig);
        require(_check(wallet, hash, relabelled) == INVALID, "relabelled domain");

        // Or presenting a hash that does match the allowed domain but the worker never approved.
        bytes32 allowedHash = keccak256(abi.encodePacked("\x19\x01", app.domainSeparator(), _structHash(1)));
        require(_check(wallet, allowedHash, relabelled) == INVALID, "hash the worker never approved");
    }

    function test_isValidSignature_otherChainId() public {
        (bytes32 hash, bytes memory sig) = _sign(wallet, WORKER_PK, app.domainSeparator(), _structHash(1));
        require(_check(wallet, hash, sig) == MAGIC, "valid on this chain");

        uint256 original = block.chainid;
        vm.chainId(original + 1);
        // The app domain itself has moved too on the new chain, but even presenting the old
        // (still allowed) app domain and old hash must fail: the wallet digest is chain-bound.
        require(_check(wallet, hash, sig) == INVALID, "must not validate on another chain");

        vm.chainId(original);
        require(_check(wallet, hash, sig) == MAGIC, "valid again on the original chain");
    }

    function test_isValidSignature_otherChainIdEvenIfDomainAllowedThere() public {
        uint256 original = block.chainid;
        (bytes32 hash, bytes memory sig) = _sign(wallet, WORKER_PK, app.domainSeparator(), _structHash(1));

        vm.chainId(original + 1);
        // Make sure the old app domain separator is explicitly allowed on the fork as well.
        vm.prank(owner);
        wallet.allowDomain(appDomain, true);
        require(_check(wallet, hash, sig) == INVALID, "chain-bound digest rejects fork replay");
    }

    function test_isValidSignature_afterRotation() public {
        (bytes32 hash, bytes memory sig) = _sign(wallet, WORKER_PK, app.domainSeparator(), _structHash(1));
        require(_check(wallet, hash, sig) == MAGIC, "valid before rotation");

        vm.prank(owner);
        wallet.setWorker(worker2);
        require(_check(wallet, hash, sig) == INVALID, "old worker signature dies on rotation");

        (bytes32 hash2, bytes memory sig2) = _sign(wallet, WORKER2_PK, app.domainSeparator(), _structHash(1));
        require(hash2 == hash, "same app hash");
        require(_check(wallet, hash2, sig2) == MAGIC, "new worker signature valid");
        require(_check(wallet2, hash2, sig2) == INVALID, "new worker is not wallet2's worker");
    }

    function test_isValidSignature_afterRevocation() public {
        (bytes32 hash, bytes memory sig) = _sign(wallet, WORKER_PK, app.domainSeparator(), _structHash(1));
        require(_check(wallet, hash, sig) == MAGIC, "valid before revocation");

        vm.prank(owner);
        wallet.setWorker(address(0));
        require(wallet.worker() == address(0), "revoked");
        require(_check(wallet, hash, sig) == INVALID, "invalid after revocation");
    }

    function test_isValidSignature_noWorkerEverSet() public {
        WorkerWallet fresh = new WorkerWallet(owner);
        vm.prank(owner);
        fresh.allowDomain(appDomain, true);
        (bytes32 hash, bytes memory sig) = _sign(fresh, WORKER_PK, app.domainSeparator(), _structHash(1));
        require(_check(fresh, hash, sig) == INVALID, "no worker means nothing validates");

        // A signature that recovers to address(0) must not match a zero worker either.
        bytes memory zeroSig = abi.encode(app.domainSeparator(), _structHash(1), new bytes(65));
        require(_check(fresh, hash, zeroSig) == INVALID, "zero recovery vs zero worker");
    }

    function test_isValidSignature_wrongSigner() public view {
        (bytes32 hash, bytes memory sig) = _sign(wallet, STRANGER_PK, app.domainSeparator(), _structHash(1));
        require(_check(wallet, hash, sig) == INVALID, "stranger key");
        (hash, sig) = _sign(wallet, WORKER2_PK, app.domainSeparator(), _structHash(1));
        require(_check(wallet, hash, sig) == INVALID, "not-yet-rotated key");
    }

    function test_isValidSignature_workerSignedBareHashNotWalletDigest() public view {
        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", app.domainSeparator(), _structHash(1)));
        // Signing the application digest directly (as an EOA maker would) is not enough.
        bytes memory sig = abi.encode(app.domainSeparator(), _structHash(1), _rawSign(WORKER_PK, hash));
        require(_check(wallet, hash, sig) == INVALID, "bare hash signature");

        // Signing over the struct hash of WorkerApproval without the wallet domain is not enough.
        bytes32 structOnly = keccak256(abi.encode(WORKER_APPROVAL_TYPEHASH, hash));
        sig = abi.encode(app.domainSeparator(), _structHash(1), _rawSign(WORKER_PK, structOnly));
        require(_check(wallet, hash, sig) == INVALID, "struct-hash-only signature");

        // Signing with a wallet domain that has the wrong name/version is not enough.
        bytes32 wrongDomain = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH, keccak256("WorkerWallet"), keccak256("2"), block.chainid, address(wallet)
            )
        );
        bytes32 wrongDigest = keccak256(abi.encodePacked("\x19\x01", wrongDomain, structOnly));
        sig = abi.encode(app.domainSeparator(), _structHash(1), _rawSign(WORKER_PK, wrongDigest));
        require(_check(wallet, hash, sig) == INVALID, "wrong wallet domain version");
    }

    function test_isValidSignature_hashMismatch() public view {
        (bytes32 hash, bytes memory sig) = _sign(wallet, WORKER_PK, app.domainSeparator(), _structHash(1));
        require(_check(wallet, hash, sig) == MAGIC, "baseline");
        // Different hash, same encoding.
        require(_check(wallet, keccak256(abi.encodePacked(hash)), sig) == INVALID, "other hash");
        require(_check(wallet, bytes32(0), sig) == INVALID, "zero hash");
        // Same hash, struct hash inside the encoding altered.
        bytes memory workerSig = _rawSign(WORKER_PK, _approvalDigest(wallet, hash));
        require(
            _check(wallet, hash, abi.encode(app.domainSeparator(), _structHash(2), workerSig)) == INVALID,
            "struct hash altered"
        );
        // Domain and struct hash swapped inside the encoding.
        require(
            _check(wallet, hash, abi.encode(_structHash(1), app.domainSeparator(), workerSig)) == INVALID,
            "fields swapped"
        );
    }

    // ------------------------------------------------------- ERC-1271 malformed signatures

    function test_isValidSignature_malleableS() public view {
        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", app.domainSeparator(), _structHash(1)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(WORKER_PK, _approvalDigest(wallet, hash));
        require(uint256(s) <= N / 2, "vm.sign gives low s");
        // The other valid ECDSA representation of the same signature: (r, N - s, v ^ 1).
        bytes32 sHigh = bytes32(N - uint256(s));
        uint8 vFlipped = v == 27 ? 28 : 27;
        require(ecrecover(_approvalDigest(wallet, hash), vFlipped, r, sHigh) == worker, "malleable form recovers");

        bytes memory malleable = abi.encode(app.domainSeparator(), _structHash(1), abi.encodePacked(r, sHigh, vFlipped));
        require(_check(wallet, hash, malleable) == INVALID, "high s rejected");

        // Sanity: the low-s form is accepted.
        bytes memory good = abi.encode(app.domainSeparator(), _structHash(1), abi.encodePacked(r, s, v));
        require(_check(wallet, hash, good) == MAGIC, "low s accepted");

        // s exactly at N/2 + 1 is rejected; anything above the half order is malleable territory.
        bytes memory edge =
            abi.encode(app.domainSeparator(), _structHash(1), abi.encodePacked(r, bytes32(N / 2 + 1), v));
        require(_check(wallet, hash, edge) == INVALID, "s just above half order");
    }

    function test_isValidSignature_badV() public view {
        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", app.domainSeparator(), _structHash(1)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(WORKER_PK, _approvalDigest(wallet, hash));
        uint8[5] memory bad = [0, 1, 26, 29, 255];
        for (uint256 i = 0; i < bad.length; i++) {
            bytes memory sig = abi.encode(app.domainSeparator(), _structHash(1), abi.encodePacked(r, s, bad[i]));
            require(_check(wallet, hash, sig) == INVALID, "bad v");
        }
        // Wrong recovery id (still 27/28) recovers a different address.
        uint8 vWrong = v == 27 ? 28 : 27;
        bytes memory sigWrong = abi.encode(app.domainSeparator(), _structHash(1), abi.encodePacked(r, s, vWrong));
        require(_check(wallet, hash, sigWrong) == INVALID, "wrong recovery id");
    }

    function test_isValidSignature_wrongLengths() public view {
        (bytes32 hash, bytes memory sig) = _sign(wallet, WORKER_PK, app.domainSeparator(), _structHash(1));
        bytes memory workerSig = _rawSign(WORKER_PK, _approvalDigest(wallet, hash));

        require(_check(wallet, hash, "") == INVALID, "empty");
        require(_check(wallet, hash, hex"00") == INVALID, "one byte");
        require(_check(wallet, hash, workerSig) == INVALID, "bare 65-byte worker signature");
        require(
            _check(wallet, hash, abi.encodePacked(app.domainSeparator(), _structHash(1), workerSig)) == INVALID,
            "packed"
        );

        // Truncated by one byte and extended by one byte.
        bytes memory short = new bytes(223);
        bytes memory long = new bytes(225);
        for (uint256 i = 0; i < 223; i++) {
            short[i] = sig[i];
        }
        for (uint256 i = 0; i < 224; i++) {
            long[i] = sig[i];
        }
        require(_check(wallet, hash, short) == INVALID, "223 bytes");
        require(_check(wallet, hash, long) == INVALID, "225 bytes");

        // abi.encode with a 64-byte (compact) inner signature: 192 bytes.
        bytes memory compact = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            compact[i] = workerSig[i];
        }
        require(
            _check(wallet, hash, abi.encode(app.domainSeparator(), _structHash(1), compact)) == INVALID, "64-byte inner"
        );

        // abi.encode with a 66-byte inner signature: 256 bytes.
        require(
            _check(
                    wallet,
                    hash,
                    abi.encode(app.domainSeparator(), _structHash(1), abi.encodePacked(workerSig, uint8(0)))
                ) == INVALID,
            "66-byte inner"
        );

        // Extra trailing word after a canonical encoding.
        require(_check(wallet, hash, abi.encodePacked(sig, bytes32(0))) == INVALID, "trailing word");
    }

    function test_isValidSignature_garbageEncodings() public view {
        (bytes32 hash, bytes memory sig) = _sign(wallet, WORKER_PK, app.domainSeparator(), _structHash(1));

        // 224 bytes with the dynamic offset pointing somewhere else (abi.decode would still accept
        // some of these; the wallet must simply say no without reverting).
        bytes memory badOffset = _clone(sig);
        _setWord(badOffset, 2, bytes32(uint256(0x80)));
        require(_check(wallet, hash, badOffset) == INVALID, "offset 0x80");
        _setWord(badOffset, 2, bytes32(uint256(0x40)));
        require(_check(wallet, hash, badOffset) == INVALID, "offset 0x40");
        _setWord(badOffset, 2, bytes32(type(uint256).max));
        require(_check(wallet, hash, badOffset) == INVALID, "offset max");
        _setWord(badOffset, 2, bytes32(0));
        require(_check(wallet, hash, badOffset) == INVALID, "offset zero");

        // 224 bytes with the inner length wrong.
        bytes memory badLen = _clone(sig);
        _setWord(badLen, 3, bytes32(uint256(64)));
        require(_check(wallet, hash, badLen) == INVALID, "inner length 64");
        _setWord(badLen, 3, bytes32(uint256(96)));
        require(_check(wallet, hash, badLen) == INVALID, "inner length 96");
        _setWord(badLen, 3, bytes32(type(uint256).max));
        require(_check(wallet, hash, badLen) == INVALID, "inner length max");
        _setWord(badLen, 3, bytes32(0));
        require(_check(wallet, hash, badLen) == INVALID, "inner length zero");

        // All zero, all 0xff and pseudo-random 224-byte blobs.
        require(_check(wallet, hash, new bytes(224)) == INVALID, "all zero");
        bytes memory ff = new bytes(224);
        for (uint256 i = 0; i < 224; i++) {
            ff[i] = 0xff;
        }
        require(_check(wallet, hash, ff) == INVALID, "all ff");
        bytes memory rnd = new bytes(224);
        for (uint256 i = 0; i < 224; i++) {
            rnd[i] = bytes1(uint8(uint256(keccak256(abi.encode(i, hash)))));
        }
        require(_check(wallet, hash, rnd) == INVALID, "pseudo random");

        // A single flipped bit in r, s, domain and struct hash each break validation.
        for (uint256 word = 0; word < 6; word++) {
            if (word == 2 || word == 3) continue; // offset and length words tested above
            bytes memory flipped = _clone(sig);
            flipped[word * 32 + 31] ^= 0x01;
            require(_check(wallet, hash, flipped) == INVALID, "flipped bit");
        }
    }

    function testFuzz_isValidSignature_neverRevertsOnGarbage(bytes32 hash, bytes memory sig) public view {
        // Whatever comes in, the wallet answers instead of reverting, and random bytes never validate.
        require(_check(wallet, hash, sig) == INVALID, "random bytes must not validate");
    }

    function testFuzz_isValidSignature_neverRevertsOn224Bytes(bytes32 hash, bytes32[7] memory words) public view {
        bytes memory sig = abi.encodePacked(words);
        require(sig.length == 224, "len");
        require(_check(wallet, hash, sig) == INVALID, "random 224 bytes must not validate");
    }

    function testFuzz_isValidSignature_wrongHashNeverValidates(bytes32 otherHash) public view {
        (bytes32 hash, bytes memory sig) = _sign(wallet, WORKER_PK, app.domainSeparator(), _structHash(1));
        if (otherHash == hash) return;
        require(_check(wallet, otherHash, sig) == INVALID, "different hash");
    }

    function testFuzz_isValidSignature_structHashRoundTrip(bytes32 structHash) public view {
        (bytes32 hash, bytes memory sig) = _sign(wallet, WORKER_PK, app.domainSeparator(), structHash);
        require(_check(wallet, hash, sig) == MAGIC, "any struct hash under an allowed domain validates");
        require(_check(wallet2, hash, sig) == INVALID, "never on the sibling wallet");
    }

    // ------------------------------------------------------------- mock application flow

    function test_app_acceptsEoaSignatureAndRejectsWrongKey() public {
        address maker = vm.addr(STRANGER_PK);
        bytes32 digest = app.orderDigest(maker, 5, 1);
        require(app.isValidSignatureNow(maker, digest, _rawSign(STRANGER_PK, digest)), "eoa accepted");
        require(!app.isValidSignatureNow(maker, digest, _rawSign(WORKER_PK, digest)), "wrong key rejected");
        require(!app.isValidSignatureNow(maker, digest, ""), "empty rejected");
        app.fill(maker, 5, 1, _rawSign(STRANGER_PK, digest));
        require(app.filled(digest), "filled");
    }

    function test_app_acceptsWalletViaWorkerSignature() public {
        bytes32 structHash = app.orderStructHash(address(wallet), 1 ether, 1);
        bytes32 digest = app.orderDigest(address(wallet), 1 ether, 1);
        (bytes32 hash, bytes memory sig) = _sign(wallet, WORKER_PK, app.domainSeparator(), structHash);
        require(hash == digest, "app digest matches reconstruction");

        require(app.isValidSignatureNow(address(wallet), digest, sig), "checker accepts");
        app.fill(address(wallet), 1 ether, 1, sig);
        require(app.filled(digest), "order filled on behalf of the wallet");

        // Replaying the same order fails at the app; the wallet itself has no nonce, by design.
        vm.expectRevert(bytes("filled"));
        app.fill(address(wallet), 1 ether, 1, sig);
    }

    function test_app_rejectsWalletWhenDomainNotAllowed() public {
        bytes32 structHash = otherApp.orderStructHash(address(wallet), 1 ether, 1);
        (, bytes memory sig) = _sign(wallet, WORKER_PK, otherApp.domainSeparator(), structHash);
        require(
            !otherApp.isValidSignatureNow(address(wallet), otherApp.orderDigest(address(wallet), 1 ether, 1), sig),
            "rejected"
        );
        vm.expectRevert(bytes("bad signature"));
        otherApp.fill(address(wallet), 1 ether, 1, sig);

        // The owner allows it, and the same signature now goes through.
        vm.prank(owner);
        wallet.allowDomain(otherDomain, true);
        otherApp.fill(address(wallet), 1 ether, 1, sig);
        require(otherApp.filled(otherApp.orderDigest(address(wallet), 1 ether, 1)), "filled after allow");
    }

    function test_app_rejectsWalletAfterRotationAndRevocation() public {
        bytes32 structHash = app.orderStructHash(address(wallet), 1 ether, 1);
        (, bytes memory sig) = _sign(wallet, WORKER_PK, app.domainSeparator(), structHash);

        vm.prank(owner);
        wallet.setWorker(worker2);
        vm.expectRevert(bytes("bad signature"));
        app.fill(address(wallet), 1 ether, 1, sig);

        vm.prank(owner);
        wallet.setWorker(address(0));
        vm.expectRevert(bytes("bad signature"));
        app.fill(address(wallet), 1 ether, 1, sig);
    }

    function test_app_rejectsWorkerSignatureAgainstSiblingWallet() public {
        // Both wallets share the worker and allow the app. A worker signature for wallet 1
        // presented as wallet 2's signature over wallet 2's order must fail.
        bytes32 structHash2 = app.orderStructHash(address(wallet2), 1 ether, 1);
        (, bytes memory sig) = _sign(wallet, WORKER_PK, app.domainSeparator(), structHash2);
        vm.expectRevert(bytes("bad signature"));
        app.fill(address(wallet2), 1 ether, 1, sig);
        // And the correctly bound one succeeds.
        (, bytes memory sig2) = _sign(wallet2, WORKER_PK, app.domainSeparator(), structHash2);
        app.fill(address(wallet2), 1 ether, 1, sig2);
    }

    function test_app_rejectsGarbageFromWalletWithoutRevert() public {
        bytes32 digest = app.orderDigest(address(wallet), 1 ether, 1);
        require(!app.isValidSignatureNow(address(wallet), digest, ""), "empty");
        require(!app.isValidSignatureNow(address(wallet), digest, hex"deadbeef"), "short garbage");
        require(!app.isValidSignatureNow(address(wallet), digest, new bytes(224)), "zero 224");
        require(!app.isValidSignatureNow(address(wallet), digest, _rawSign(WORKER_PK, digest)), "eoa-style sig");
        vm.expectRevert(bytes("bad signature"));
        app.fill(address(wallet), 1 ether, 1, hex"deadbeef");
    }

    // ------------------------------------------------------------------ byte helpers

    function _clone(bytes memory b) internal pure returns (bytes memory c) {
        c = new bytes(b.length);
        for (uint256 i = 0; i < b.length; i++) {
            c[i] = b[i];
        }
    }

    function _setWord(bytes memory b, uint256 wordIndex, bytes32 value) internal pure {
        assembly {
            mstore(add(add(b, 0x20), mul(wordIndex, 0x20)), value)
        }
    }
}
