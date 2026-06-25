// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {Corona} from "contracts/Corona.sol";

/// @notice A stand-in for the on-chain `coronaThreshold` precompile (`0x012206`),
/// used in `forge test` where the Go precompile is not present.
///
/// @dev GROUND-TRUTH ABI CONFORMANCE. This mock does NOT re-implement the
/// Ring-LWE threshold verifier. It asserts the *calldata framing*: it returns
/// the precompile's exact success word `bytes32(1)` iff the incoming calldata is
/// byte-for-byte equal to a reference `input` blob whose keccak256 is stored in
/// slot 0. That blob is a real Known-Answer-Test vector produced by
/// `precompile/cmd/safekatdump` (a genuine 2-of-3 Corona threshold ceremony),
/// independently *proven to verify against the real Go precompile* by
/// `precompile/cmd/safekatverify`. If {Corona.verify}'s framed calldata matches
/// it, the real precompile would accept it too; any drift in the RAW wire layout
/// (e.g. mistakenly prepending a 4-byte ABI selector) changes the calldata and
/// this mock returns zero — failing the test.
contract MockCoronaPrecompile {
    fallback(bytes calldata input) external returns (bytes memory) {
        bytes32 expected;
        assembly {
            expected := sload(0)
        }
        bool ok = keccak256(input) == expected;
        return abi.encode(ok ? bytes32(uint256(1)) : bytes32(0));
    }
}

contract CoronaTest is Test {
    uint32 internal threshold;
    uint32 internal parties;
    bytes32 internal msgHash;
    bytes internal sig;
    bytes internal expectedInput;

    function setUp() public {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/tests/kat.json"));
        threshold = uint32(vm.parseJsonUint(json, ".threshold"));
        parties = uint32(vm.parseJsonUint(json, ".parties"));
        msgHash = bytes32(vm.parseJsonBytes(json, ".msgHash"));
        sig = vm.parseJsonBytes(json, ".sig");
        expectedInput = vm.parseJsonBytes(json, ".input");

        vm.etch(Corona.PRECOMPILE, type(MockCoronaPrecompile).runtimeCode);
        vm.store(Corona.PRECOMPILE, bytes32(uint256(0)), keccak256(expectedInput));
    }

    /// @notice The library frames calldata that byte-matches the KAT input the
    /// real precompile accepts, so {Corona.verify} returns true.
    function test_Verify_KAT() public view {
        assertTrue(Corona.verify(msgHash, threshold, parties, sig), "Corona KAT must verify");
    }

    /// @notice Independent proof the library frames the precompile calldata
    /// EXACTLY as the Go `Run()` parses it — a RAW packed layout with NO ABI
    /// selector:
    ///   threshold:uint32(4) || totalParties:uint32(4) || msgHash(32) || signature
    function test_CalldataFramingMatchesPrecompileABI() public view {
        bytes memory framed = abi.encodePacked(threshold, parties, msgHash, sig);
        assertEq(keccak256(framed), keccak256(expectedInput), "framing must equal precompile wire bytes");
        assertEq(framed.length, expectedInput.length, "framed length must equal precompile input length");
        // 4 (t) + 4 (n) + 32 (hash) + 163840 (default-param serialized sig).
        assertEq(framed.length, 4 + 4 + 32 + Corona.DEFAULT_SIGNATURE_LEN, "Corona default-param input size");
    }

    /// @notice The KAT signature has the expected default-parameter length, and
    /// the group-key region offsets are self-consistent.
    function test_SignatureLayout() public view {
        assertEq(sig.length, Corona.DEFAULT_SIGNATURE_LEN, "default Corona sig length");
        assertEq(Corona.GROUP_KEY_OFFSET + Corona.GROUP_KEY_LEN, Corona.DEFAULT_SIGNATURE_LEN, "regions tile the sig");
    }

    /// @notice The group-key region hash is deterministic and independent of the
    /// per-message-varying prefix (c ‖ z ‖ Δ): mutating a byte in the prefix
    /// does NOT change the group-key hash, but mutating the group-key region
    /// does. This is the property that lets an owner pin a stable group key.
    function test_GroupKeyHash_StableAcrossPrefix() public view {
        bytes32 gk = Corona.groupKeyHash(sig);

        // Mutate a byte inside the varying prefix (offset < GROUP_KEY_OFFSET).
        bytes memory mutatedPrefix = bytes.concat(sig);
        mutatedPrefix[0] ^= 0xFF;
        assertEq(Corona.groupKeyHash(mutatedPrefix), gk, "prefix mutation must not change group-key hash");

        // Mutate a byte inside the group-key region.
        bytes memory mutatedGk = bytes.concat(sig);
        mutatedGk[Corona.GROUP_KEY_OFFSET] ^= 0xFF;
        assertTrue(Corona.groupKeyHash(mutatedGk) != gk, "group-key mutation must change group-key hash");
    }

    /// @notice A tampered signature changes the calldata, so verification fails.
    function test_Verify_RejectsTamperedSignature() public view {
        bytes memory bad = bytes.concat(sig);
        bad[100] ^= 0xFF;
        assertFalse(Corona.verify(msgHash, threshold, parties, bad), "tampered sig must not verify");
    }

    /// @notice A wrong message changes the calldata, so verification fails.
    function test_Verify_RejectsWrongMessage() public view {
        bytes32 wrong = keccak256("not the signed message");
        assertFalse(Corona.verify(wrong, threshold, parties, sig), "wrong message must not verify");
    }

    /// @notice A structurally invalid threshold (t > n) is rejected before any
    /// precompile call.
    function test_Verify_RejectsBadThreshold() public view {
        assertFalse(Corona.verify(msgHash, 5, 3, sig), "t > n must not verify");
        assertFalse(Corona.verify(msgHash, 0, 3, sig), "t == 0 must not verify");
    }

    /// @notice Strict success-word check.
    function test_Verify_FailClosedOnNonOneWord() public {
        vm.store(Corona.PRECOMPILE, bytes32(uint256(0)), keccak256("never matches"));
        assertFalse(Corona.verify(msgHash, threshold, parties, sig), "non-success word must be false");
    }

    /// @notice The published precompile address is the canonical LP-4200 slot.
    function test_PrecompileAddress() public pure {
        assertEq(Corona.PRECOMPILE, address(0x0000000000000000000000000000000000012206));
    }

    /// @notice The published context matches the precompile's domain separator.
    function test_Context() public pure {
        assertEq(string(Corona.CONTEXT), "lux-evm-precompile-corona-v1");
    }

    /// @notice Threshold validity helper.
    function test_IsValidThreshold() public pure {
        assertTrue(Corona.isValidThreshold(2, 3));
        assertTrue(Corona.isValidThreshold(3, 3));
        assertFalse(Corona.isValidThreshold(0, 3));
        assertFalse(Corona.isValidThreshold(4, 3));
    }

    /// @notice groupKeyHash reverts on a signature too short to carry the group
    /// key (cannot bind to a malformed configuration).
    function test_GroupKeyHash_RevertsOnShort() public {
        bytes memory shortSig = new bytes(Corona.GROUP_KEY_OFFSET + Corona.GROUP_KEY_LEN - 1);
        vm.expectRevert(bytes("Corona: signature too short"));
        this.callGroupKeyHash(shortSig);
    }

    function callGroupKeyHash(bytes memory s) external pure returns (bytes32) {
        return Corona.groupKeyHash(s);
    }
}
