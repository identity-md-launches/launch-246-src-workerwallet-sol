// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title WorkerWallet
/// @notice An ERC-1271 contract wallet that holds an ERC-721 seat and lets a rotating
///         worker key sign EIP-712 messages for a set of allowed application domains.
///
/// Roles and invariants:
///  - `owner` is fixed at construction, nonzero, and is the only address that can move
///    anything out of this wallet (`execute`), rotate or revoke the worker (`setWorker`),
///    or change the allowed application domains (`allowDomain`).
///  - `worker` has no function of its own. The only thing a worker key can do is produce
///    off-chain signatures that `isValidSignature` will accept. It can never move assets.
///  - `isValidSignature` never reverts. It returns the ERC-1271 magic value only for a
///    signature by the *current* nonzero worker over this wallet's own EIP-712 digest of
///    `WorkerApproval(bytes32 hash)`, where `hash` is the EIP-712 digest of an allowed
///    application domain. Nothing is cached: rotating or revoking the worker invalidates
///    every earlier worker signature at once, and the wallet domain separator is
///    recomputed from `block.chainid` and `address(this)` on every call.
contract WorkerWallet {
    // ---------------------------------------------------------------- constants

    /// @dev ERC-1271 success value: bytes4(keccak256("isValidSignature(bytes32,bytes)")).
    bytes4 internal constant ERC1271_MAGIC = 0x1626ba7e;
    /// @dev ERC-1271 failure value.
    bytes4 internal constant ERC1271_INVALID = 0xffffffff;
    /// @dev ERC-721 receiver success value:
    ///      bytes4(keccak256("onERC721Received(address,address,uint256,bytes)")).
    bytes4 internal constant ERC721_RECEIVED = 0x150b7a02;

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant WORKER_APPROVAL_TYPEHASH = keccak256("WorkerApproval(bytes32 hash)");
    bytes32 internal constant NAME_HASH = keccak256("WorkerWallet");
    bytes32 internal constant VERSION_HASH = keccak256("1");

    /// @dev secp256k1 curve order / 2. Signatures with s above this are malleable and rejected.
    uint256 internal constant SECP256K1_N_DIV_2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// @dev Exact length of abi.encode(bytes32, bytes32, bytes) when the bytes are 65 long:
    ///      3 head words (a, b, offset) + length word + 65 bytes padded to 96 = 224.
    uint256 internal constant SIGNATURE_ENCODED_LENGTH = 224;

    // ------------------------------------------------------------------ storage

    /// @notice The only address that can move assets or change configuration.
    address public immutable owner;

    /// @notice The current worker key. Zero means no worker; every signature is then invalid.
    address public worker;

    /// @notice Application EIP-712 domain separators the worker may sign for.
    mapping(bytes32 => bool) public allowedDomains;

    // ------------------------------------------------------------------- events

    event WorkerSet(address indexed previousWorker, address indexed newWorker);
    event DomainAllowed(bytes32 indexed domainSeparator, bool allowed);
    event Executed(address indexed to, uint256 value, bytes data, bytes result);
    event EtherReceived(address indexed from, uint256 value);
    event ERC721Received(address indexed token, address indexed operator, address indexed from, uint256 tokenId);

    // ------------------------------------------------------------------- errors

    error NotOwner();
    error ZeroOwner();
    error ExecutionFailed(bytes result);

    // -------------------------------------------------------------- constructor

    constructor(address owner_) {
        if (owner_ == address(0)) revert ZeroOwner();
        owner = owner_;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    // ------------------------------------------------------------- owner actions

    /// @notice Rotate the worker key. Passing zero revokes it. Every signature made by the
    ///         previous worker stops validating immediately because nothing is cached.
    function setWorker(address newWorker) external onlyOwner {
        address previous = worker;
        worker = newWorker;
        emit WorkerSet(previous, newWorker);
    }

    /// @notice Allow or disallow an application EIP-712 domain separator for worker signatures.
    function allowDomain(bytes32 appDomainSeparator, bool allowed) external onlyOwner {
        allowedDomains[appDomainSeparator] = allowed;
        emit DomainAllowed(appDomainSeparator, allowed);
    }

    /// @notice Perform an arbitrary call from the wallet. This is the only path that moves the
    ///         NFT, ETH or anything else out of the wallet, and only the owner can reach it.
    /// @dev Reentrancy: every state-changing function is gated on `msg.sender == owner`, so a
    ///      callee reentering during `execute` gains nothing it could not already do as the
    ///      owner. The worker cannot reach this function under any call path.
    function execute(address to, uint256 value, bytes calldata data)
        external
        onlyOwner
        returns (bytes memory result)
    {
        bool ok;
        (ok, result) = to.call{value: value}(data);
        if (!ok) revert ExecutionFailed(result);
        emit Executed(to, value, data, result);
    }

    // ---------------------------------------------------------------- receiving

    receive() external payable {
        emit EtherReceived(msg.sender, msg.value);
    }

    /// @notice Accept ERC-721 safe transfers.
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata)
        external
        returns (bytes4)
    {
        emit ERC721Received(msg.sender, operator, from, tokenId);
        return ERC721_RECEIVED;
    }

    // ---------------------------------------------------------------- EIP-712

    /// @notice This wallet's own EIP-712 domain separator, recomputed on every call so that a
    ///         chain fork or a second wallet sharing the worker never shares a digest.
    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    /// @notice The digest the worker must sign to approve `hash`:
    ///         keccak256("\x19\x01" || domainSeparator() || keccak256(WorkerApproval typehash || hash)).
    function workerApprovalDigest(bytes32 hash) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked("\x19\x01", domainSeparator(), keccak256(abi.encode(WORKER_APPROVAL_TYPEHASH, hash)))
        );
    }

    // ---------------------------------------------------------------- ERC-1271

    /// @notice ERC-1271 signature check. Never reverts.
    /// @param hash      The EIP-712 digest the application is verifying:
    ///                  keccak256("\x19\x01" || appDomainSeparator || structHash).
    /// @param signature abi.encode(bytes32 appDomainSeparator, bytes32 structHash, bytes workerSig)
    ///                  where workerSig is a 65-byte (r, s, v) ECDSA signature with low s.
    /// @return 0x1626ba7e when every condition below holds, 0xffffffff otherwise:
    ///         - `signature` is exactly the canonical 224-byte encoding described above;
    ///         - `hash` equals the reconstructed application digest;
    ///         - `appDomainSeparator` is currently allowed;
    ///         - the current worker is nonzero;
    ///         - `workerSig` has v in {27, 28}, s in the lower half of the curve order, and
    ///           `ecrecover` over `workerApprovalDigest(hash)` yields the current worker.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        // Strict manual decoding of untrusted bytes: abi.decode would revert on malformed input.
        if (signature.length != SIGNATURE_ENCODED_LENGTH) return ERC1271_INVALID;

        bytes32 appDomainSeparator;
        bytes32 structHash;
        uint256 offset;
        uint256 sigLength;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            appDomainSeparator := calldataload(signature.offset)
            structHash := calldataload(add(signature.offset, 0x20))
            offset := calldataload(add(signature.offset, 0x40))
            sigLength := calldataload(add(signature.offset, 0x60))
            r := calldataload(add(signature.offset, 0x80))
            s := calldataload(add(signature.offset, 0xa0))
            v := byte(0, calldataload(add(signature.offset, 0xc0)))
        }
        // The dynamic `bytes` must sit right after the three head words and be 65 bytes long.
        if (offset != 0x60 || sigLength != 65) return ERC1271_INVALID;

        // The application digest must be exactly what the caller is verifying, so the domain
        // named in the signature is provably the one `hash` was built from.
        if (hash != keccak256(abi.encodePacked("\x19\x01", appDomainSeparator, structHash))) return ERC1271_INVALID;
        if (!allowedDomains[appDomainSeparator]) return ERC1271_INVALID;

        address currentWorker = worker;
        if (currentWorker == address(0)) return ERC1271_INVALID;

        if (v != 27 && v != 28) return ERC1271_INVALID;
        if (uint256(s) > SECP256K1_N_DIV_2) return ERC1271_INVALID;

        address signer = ecrecover(workerApprovalDigest(hash), v, r, s);
        if (signer == address(0) || signer != currentWorker) return ERC1271_INVALID;

        return ERC1271_MAGIC;
    }
}
