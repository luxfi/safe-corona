// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.29;

/// @title Corona Library
/// @notice Library for verifying Corona Ring-LWE threshold signatures through
/// the Lux on-chain `coronaThreshold` precompile at `0x012206`.
///
/// @dev DECOMPLECTION. This library does ONE thing: turn a Corona
/// `(threshold, totalParties, signature, hash)` into a boolean by framing the
/// calldata the on-chain precompile expects and staticcalling it under a strict
/// success-word check. It holds no state, enforces no policy, and never reverts
/// on a cryptographic "false". Ownership policy lives in the Safe; the
/// signature↔owner binding lives in {SafeCoronaSigner} / the account, which
/// commit `keccak256(threshold ‖ totalParties ‖ signature)`.
///
/// CRYPTOGRAPHIC IDENTITY. Corona (`github.com/luxfi/corona`) is a Ring-LWE
/// (lattice-based) two-round t-of-n threshold signature
/// (<https://eprint.iacr.org/2024/1113>) used in Quasar quantum consensus. It is
/// post-quantum (security reduces to Learning-With-Errors) and is NOT byte-equal
/// to any single-party scheme — the aggregated signature carries its own group
/// key (matrix A, rounded public key b̃) inside the serialized blob, so unlike
/// Pulsar / Magnetar there is no separate `pubkey` argument: the group key
/// travels with the signature and the verifier re-derives ring parameters.
///
/// SOUNDNESS OF `(threshold, totalParties)`. The precompile checks only the
/// STRUCTURAL constraint `0 < threshold <= totalParties`; these two integers are
/// advisory metadata. The real cryptographic soundness comes from the
/// aggregated signature verifying against the embedded group key, which is
/// DKG-derived from the actual t-of-n configuration. An attacker cannot forge a
/// signature that verifies without `threshold` honest shares; lying about
/// `(t, n)` does not create a forgery oracle (a real signature with mismatched
/// advisory `(t, n)` may still verify, but producing it required the real
/// threshold of shares). This matches the precompile's own soundness test
/// `TestCoronaThresholdVerify_BogusThresholdMetadataRejected`.
///
/// DOMAIN SEPARATION. The precompile binds the context string
/// `"lux-evm-precompile-corona-v1"` into the verified message (it verifies over
/// `fmt.Sprintf("lux-evm-precompile-corona-v1|%x", msgHash)`), so an off-chain
/// Corona signature produced by consensus for a per-block session id cannot be
/// replayed as an on-chain precompile call. The signing client MUST sign over
/// that domain-separated message — see {Corona.CONTEXT}.
///
/// WIRE FORMAT (must match `github.com/luxfi/precompile/corona`.Run
/// byte-for-byte — a RAW packed layout, NOT an ABI-encoded call: the precompile
/// reads `input[0:4]` directly as the threshold and does NOT strip a 4-byte
/// function selector. The `ICoronaThreshold.sol`/`verifyThreshold(...)` ABI
/// shim shipped alongside the precompile would misalign by 4 selector bytes and
/// must NOT be used to call the real precompile):
///
///     threshold:uint32(4) ‖ totalParties:uint32(4) ‖ msgHash:bytes32(32) ‖ signature
///
/// The serialized `signature` is the concatenation of 64-bit big-endian
/// polynomial coefficients in the order c ‖ z[N] ‖ Δ[M] ‖ A[M][N] ‖ b̃[M]
/// (the precompile's `deserializeSignature` layout); this library treats it as
/// an opaque blob and never parses it.
///
/// FAIL-CLOSED. {verify} treats anything other than the precompile's exact
/// success word `bytes32(1)` — revert, wrong-size return, zero word, missing
/// precompile — as `false`. Mirrors `luxfi/safe/contracts/pq/PQVerifier.sol`.
library Corona {
    /// @notice The canonical LP-4200 on-chain address of the Corona Ring-LWE
    /// threshold verify precompile.
    address internal constant PRECOMPILE = 0x0000000000000000000000000000000000012206;

    /// @notice The domain-separation context the precompile binds into the
    /// verified message. The signing client MUST sign over
    /// `"lux-evm-precompile-corona-v1|" + hex(msgHash)`. Exposed for off-chain
    /// reference; the precompile re-derives it and it is not part of the
    /// calldata.
    bytes internal constant CONTEXT = "lux-evm-precompile-corona-v1";

    /// @notice The fixed header length: threshold(4) + totalParties(4) +
    /// msgHash(32). The serialized signature follows.
    uint256 internal constant HEADER_LEN = 40;

    /// @notice The serialized-signature length for the default Corona ring
    /// parameters (sign.M=8, sign.N=7, sign.LogN=8 ⇒ ring degree 256, 8
    /// bytes/coefficient ⇒ 2048 bytes/polynomial). Components
    /// c ‖ z[7] ‖ Δ[8] ‖ A[8][7] ‖ b̃[8] = (1 + 7 + 8 + 56 + 8) = 80 polynomials
    /// × 256 coeffs × 8 bytes = 163840 bytes. The precompile is authoritative;
    /// these constants enable the group-key binding in {SafeCoronaSigner}.
    uint256 internal constant POLY_LEN = 2048; // 256 coeffs × 8 bytes
    uint256 internal constant DEFAULT_SIGNATURE_LEN = 163840; // 80 × POLY_LEN

    /// @notice Byte offset, within the serialized signature, where the stable
    /// group-key region begins. The first 16 polynomials (c ‖ z[7] ‖ Δ[8]) vary
    /// per message; the trailing 64 polynomials (A[8][7] ‖ b̃[8]) are the group
    /// key and are stable across signatures from the same key. An owner binds
    /// `keccak256(signature[GROUP_KEY_OFFSET:])` to pin a specific group key.
    uint256 internal constant GROUP_KEY_OFFSET = 32768; // 16 × POLY_LEN
    uint256 internal constant GROUP_KEY_LEN = 131072; // 64 × POLY_LEN

    /// @notice Whether `(threshold, totalParties)` satisfy the precompile's
    /// structural constraint `0 < threshold <= totalParties`.
    /// @param threshold The minimum number of parties required (t).
    /// @param totalParties The total number of parties (n).
    /// @return ok True iff the threshold is structurally valid.
    function isValidThreshold(uint32 threshold, uint32 totalParties) internal pure returns (bool ok) {
        return threshold > 0 && threshold <= totalParties;
    }

    /// @notice Extract `keccak256` of the stable group-key region of a Corona
    /// serialized signature (the trailing `GROUP_KEY_LEN` bytes beginning at
    /// `GROUP_KEY_OFFSET`). Owners commit this digest to bind themselves to a
    /// SPECIFIC group key while still accepting per-message signatures.
    /// @dev Reverts if the signature is too short to contain a full default
    /// group-key region — a signature that cannot carry the expected group key
    /// can never be the committed key, so a hard revert prevents binding to a
    /// malformed configuration.
    /// @param signature The serialized Corona threshold signature.
    /// @return digest keccak256 of `signature[GROUP_KEY_OFFSET : GROUP_KEY_OFFSET+GROUP_KEY_LEN]`.
    function groupKeyHash(bytes memory signature) internal pure returns (bytes32 digest) {
        require(signature.length >= GROUP_KEY_OFFSET + GROUP_KEY_LEN, "Corona: signature too short");
        assembly ("memory-safe") {
            // signature data starts at signature+0x20; group key region starts
            // at +GROUP_KEY_OFFSET and spans GROUP_KEY_LEN bytes.
            digest := keccak256(add(add(signature, 0x20), GROUP_KEY_OFFSET), GROUP_KEY_LEN)
        }
    }

    /// @notice Verify a Corona Ring-LWE threshold signature over the 32-byte
    /// `hash`, asserting the structural `(threshold, totalParties)` metadata.
    /// @dev Rejects up-front on a structurally invalid threshold (the precompile
    /// would reject `t > n` anyway, but the check keeps the framed call
    /// canonical). Then frames the exact raw wire bytes and staticcalls
    /// {PRECOMPILE} fail-closed. The `signature` blob is opaque to this library.
    /// @param hash The 32-byte message digest that was signed (the Safe tx hash).
    /// @param threshold The minimum number of parties (t) — advisory metadata.
    /// @param totalParties The total number of parties (n) — advisory metadata.
    /// @param signature The serialized Corona threshold signature (includes the
    /// embedded group key).
    /// @return ok True iff the precompile returned the exact success word.
    function verify(bytes32 hash, uint32 threshold, uint32 totalParties, bytes memory signature)
        internal
        view
        returns (bool ok)
    {
        if (!isValidThreshold(threshold, totalParties)) return false;

        // threshold:uint32(4) ‖ totalParties:uint32(4) ‖ hash(32) ‖ signature
        bytes memory input = abi.encodePacked(threshold, totalParties, hash, signature);
        return _callStrict(input);
    }

    /// @notice Staticcall {PRECOMPILE} with `input`, returning true iff the
    /// call succeeded AND returned exactly the 32-byte word `bytes32(1)`.
    /// @dev Fail-closed on staticcall failure, any `returndatasize != 32`, any
    /// returned word != 1, and a missing precompile (`returndatasize == 0`).
    /// @param input The framed precompile calldata.
    /// @return ok Whether the strict success word was returned.
    function _callStrict(bytes memory input) private view returns (bool ok) {
        assembly ("memory-safe") {
            let success := staticcall(gas(), PRECOMPILE, add(input, 0x20), mload(input), 0x00, 0x20)
            ok := and(success, and(eq(returndatasize(), 0x20), eq(mload(0x00), 1)))
        }
    }
}
