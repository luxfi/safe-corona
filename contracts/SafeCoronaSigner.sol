// SPDX-License-Identifier: GPL-3.0-only
pragma solidity =0.8.29;

import {Corona} from "./Corona.sol";
import {IERC1271, ILegacyERC1271} from "./interfaces/IERC1271.sol";

/// @title Safe Corona Signer
/// @notice Safe smart-account owner that verifies Corona Ring-LWE threshold
/// signatures through the `coronaThreshold` precompile, making a single Corona
/// group key a first-class Safe owner via EIP-1271.
///
/// @dev ONE key, ONE owner. The owner commits `(threshold, totalParties,
/// groupKeyHash)` at construction; all three are `immutable`, so the contract
/// holds NO mutable storage and `isValidSignature` is a pure `view`
/// (side-stepping the Safe's state-changing-EIP-1271-validator guard entirely).
///
/// BINDING — why a group-key hash, not a public key. Corona is not byte-equal to
/// a single-party scheme: the aggregated signature carries its own group key
/// (matrix A, rounded public key b̃) inside the serialized blob, and there is no
/// separate public-key argument. The per-message-varying part of the signature
/// (c ‖ z ‖ Δ) precedes the stable group-key region (A ‖ b̃). This owner commits
/// `keccak256(group-key region)` (see {Corona.groupKeyHash}) so that a signature
/// only authorises this owner if it embeds the EXACT group key the owner was
/// constructed with — closing the "any valid threshold signature from any group
/// is accepted" gap. The threshold metadata `(t, n)` is additionally pinned.
///
/// REPLAY. The Safe passes the EIP-712 Safe-transaction hash, bound to this
/// Safe / chain / nonce. The precompile additionally binds the
/// `"lux-evm-precompile-corona-v1"` context into the verified message.
///
/// SIGNATURE PAYLOAD: the raw serialized Corona signature `bytes` (the embedded
/// group key is part of it; no separate public key is supplied).
contract SafeCoronaSigner is IERC1271, ILegacyERC1271 {
    /// @notice The minimum number of parties (t) this owner verifies under.
    uint32 private immutable _THRESHOLD;
    /// @notice The total number of parties (n) this owner verifies under.
    uint32 private immutable _TOTAL_PARTIES;
    /// @notice keccak256 of the committed Corona group-key region.
    bytes32 private immutable _GROUP_KEY_HASH;

    /// @notice `(threshold, totalParties)` violate `0 < t <= n`.
    error InvalidThreshold();

    /// @param threshold The minimum number of parties required (t).
    /// @param totalParties The total number of parties (n).
    /// @param groupKey A reference serialized Corona signature from this key,
    /// used solely to extract and commit the stable group-key region's hash.
    constructor(uint32 threshold, uint32 totalParties, bytes memory groupKey) {
        require(Corona.isValidThreshold(threshold, totalParties), InvalidThreshold());
        _THRESHOLD = threshold;
        _TOTAL_PARTIES = totalParties;
        _GROUP_KEY_HASH = Corona.groupKeyHash(groupKey);
    }

    /// @notice The committed group-key hash (for off-chain reference / tooling).
    function groupKeyHash() external view returns (bytes32) {
        return _GROUP_KEY_HASH;
    }

    /// @notice Checks if the given signature is valid for the given message.
    /// @param message The message to be verified (the Safe tx hash).
    /// @param signature The raw serialized Corona threshold signature.
    /// @return ok Whether or not the signature is valid.
    function _isValidSignature(bytes32 message, bytes calldata signature) public view returns (bool ok) {
        // Bind the embedded group key to this owner's commitment.
        if (signature.length < Corona.GROUP_KEY_OFFSET + Corona.GROUP_KEY_LEN) return false;
        if (Corona.groupKeyHash(signature) != _GROUP_KEY_HASH) return false;
        return Corona.verify(message, _THRESHOLD, _TOTAL_PARTIES, signature);
    }

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 message, bytes calldata signature) public view returns (bytes4 magicValue) {
        if (_isValidSignature(message, signature)) {
            magicValue = IERC1271.isValidSignature.selector;
        }
    }

    /// @inheritdoc ILegacyERC1271
    function isValidSignature(bytes memory message, bytes calldata signature) public view returns (bytes4 magicValue) {
        if (_isValidSignature(keccak256(message), signature)) {
            magicValue = ILegacyERC1271.isValidSignature.selector;
        }
    }
}
