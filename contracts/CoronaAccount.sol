// SPDX-License-Identifier: GPL-3.0-only
pragma solidity =0.8.29;

import {Corona} from "./Corona.sol";
import {IERC4337, PackedUserOperation} from "./interfaces/IERC4337.sol";

/// @title Corona Account
/// @notice An ERC-4337 account whose user operations are authorised by a
/// committed Corona Ring-LWE threshold key, verified through the
/// `coronaThreshold` precompile.
///
/// @dev BINDING. Corona has no separate public key — the group key (A, b̃) lives
/// inside the serialized signature. The account commits
/// `(threshold, totalParties, keccak256(group-key region))` at construction; the
/// user-op signature carries the full serialized Corona signature, whose
/// embedded group key is re-hashed against the commitment before the signature
/// is verified over `userOpHash`. This pins the account to a SPECIFIC group key.
///
/// SIGNATURE PAYLOAD: the raw serialized Corona signature `bytes`.
contract CoronaAccount is IERC4337 {
    /// @notice The supported ERC-4337 entry point contract.
    address private immutable _ENTRY_POINT;
    /// @notice The minimum number of parties (t) this account verifies under.
    uint32 private immutable _THRESHOLD;
    /// @notice The total number of parties (n) this account verifies under.
    uint32 private immutable _TOTAL_PARTIES;
    /// @notice keccak256 of the committed Corona group-key region.
    bytes32 private immutable _GROUP_KEY_HASH;

    /// @notice Attempt to call a function reserved for the entry point.
    error UnsupportedEntryPoint();
    /// @notice `(threshold, totalParties)` violate `0 < t <= n`.
    error InvalidThreshold();

    /// @param entryPoint The ERC-4337 entry point contract.
    /// @param threshold The minimum number of parties required (t).
    /// @param totalParties The total number of parties (n).
    /// @param groupKey A reference serialized Corona signature from this key,
    /// used solely to extract and commit the stable group-key region's hash.
    constructor(address entryPoint, uint32 threshold, uint32 totalParties, bytes memory groupKey) {
        require(Corona.isValidThreshold(threshold, totalParties), InvalidThreshold());
        _ENTRY_POINT = entryPoint;
        _THRESHOLD = threshold;
        _TOTAL_PARTIES = totalParties;
        _GROUP_KEY_HASH = Corona.groupKeyHash(groupKey);
    }

    receive() external payable {}

    /// @notice Function must be called by the entry point.
    modifier onlyEntryPoint() {
        require(msg.sender == _ENTRY_POINT, UnsupportedEntryPoint());
        _;
    }

    /// @inheritdoc IERC4337
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        onlyEntryPoint
        returns (uint256 validationData)
    {
        if (missingAccountFunds != 0) {
            assembly ("memory-safe") {
                pop(call(gas(), caller(), missingAccountFunds, 0, 0, 0, 0))
            }
        }

        bytes calldata signature = userOp.signature;
        if (signature.length < Corona.GROUP_KEY_OFFSET + Corona.GROUP_KEY_LEN) return 1;
        if (Corona.groupKeyHash(signature) != _GROUP_KEY_HASH) return 1;
        return Corona.verify(userOpHash, _THRESHOLD, _TOTAL_PARTIES, signature) ? 0 : 1;
    }

    /// @notice Execute a transaction.
    /// @param target The call target.
    /// @param value The native token value to send.
    /// @param data The call data.
    function execute(address target, uint256 value, bytes calldata data) external onlyEntryPoint {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, data.offset, data.length)

            if iszero(call(gas(), target, value, ptr, data.length, 0, 0)) {
                returndatacopy(ptr, 0, returndatasize())
                revert(ptr, returndatasize())
            }
        }
    }
}
