// SPDX-License-Identifier: GPL-3.0-only
pragma solidity =0.8.29;

import {Corona} from "./Corona.sol";
import {ISafe} from "./interfaces/ISafe.sol";
import {IERC165, ISafeTransactionGuard} from "./interfaces/ISafeTransactionGuard.sol";

/// @title Safe Corona Co-Signer
/// @notice A Safe transaction guard that additionally requires every Safe
/// transaction to be co-signed by a committed Corona Ring-LWE threshold key.
/// Add it with `setGuard`; thereafter `execTransaction` reverts unless the
/// appended Corona co-signature verifies over the Safe-tx hash AND embeds the
/// committed group key.
///
/// @dev DECOMPLECTION: the guard enforces ONE policy — "a valid Corona
/// co-signature embedding this owner's group key must be present". The
/// cryptographic verify and the group-key extraction are delegated wholly to
/// {Corona}.
///
/// CO-SIGNATURE LAYOUT. The serialized Corona signature is a fixed length for a
/// given parameter set (the precompile carries the group key inside it), so it
/// is appended raw to the Safe `signatures` bytes. The guard slices exactly the
/// trailing `coSignatureLength` bytes (pinned at construction from the reference
/// group-key signature's length) and verifies them.
contract SafeCoronaCoSigner is ISafeTransactionGuard {
    /// @notice The minimum number of parties (t) this co-signer verifies under.
    uint32 private immutable _THRESHOLD;
    /// @notice The total number of parties (n) this co-signer verifies under.
    uint32 private immutable _TOTAL_PARTIES;
    /// @notice keccak256 of the committed Corona group-key region.
    bytes32 private immutable _GROUP_KEY_HASH;
    /// @notice The exact byte length of the appended serialized signature.
    uint256 private immutable _COSIG_LEN;

    /// @notice The transaction was not co-signed by the committed Corona key.
    error Unauthorized();
    /// @notice `(threshold, totalParties)` violate `0 < t <= n`.
    error InvalidThreshold();

    /// @param threshold The minimum number of parties required (t).
    /// @param totalParties The total number of parties (n).
    /// @param groupKey A reference serialized Corona signature from this key,
    /// used to commit the group-key hash AND pin the co-signature length.
    constructor(uint32 threshold, uint32 totalParties, bytes memory groupKey) {
        require(Corona.isValidThreshold(threshold, totalParties), InvalidThreshold());
        _THRESHOLD = threshold;
        _TOTAL_PARTIES = totalParties;
        _GROUP_KEY_HASH = Corona.groupKeyHash(groupKey); // reverts if too short
        _COSIG_LEN = groupKey.length;
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) external view virtual override returns (bool) {
        return interfaceId == type(ISafeTransactionGuard).interfaceId || interfaceId == type(IERC165).interfaceId;
    }

    /// @notice The expected length of the appended Corona co-signature.
    function coSignatureLength() external view returns (uint256) {
        return _COSIG_LEN;
    }

    /// @inheritdoc ISafeTransactionGuard
    function checkTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures,
        address
    ) external view {
        bytes32 safeTxHash;
        unchecked {
            uint256 nonce = ISafe(msg.sender).nonce() - 1;
            safeTxHash = ISafe(msg.sender).getTransactionHash(
                to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce
            );
        }

        require(signatures.length >= _COSIG_LEN, Unauthorized());
        bytes calldata coSignature = signatures[signatures.length - _COSIG_LEN:];

        require(Corona.groupKeyHash(coSignature) == _GROUP_KEY_HASH, Unauthorized());
        require(Corona.verify(safeTxHash, _THRESHOLD, _TOTAL_PARTIES, coSignature), Unauthorized());
    }

    /// @inheritdoc ISafeTransactionGuard
    function checkAfterExecution(bytes32, bool) external pure {}
}
