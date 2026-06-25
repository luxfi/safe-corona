// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {Corona} from "contracts/Corona.sol";
import {SafeCoronaSigner} from "contracts/SafeCoronaSigner.sol";
import {SafeCoronaCoSigner} from "contracts/SafeCoronaCoSigner.sol";
import {CoronaAccount} from "contracts/CoronaAccount.sol";
import {IERC1271} from "contracts/interfaces/IERC1271.sol";
import {PackedUserOperation} from "contracts/interfaces/IERC4337.sol";
import {MockCoronaPrecompile} from "./Corona.t.sol";

/// @notice A minimal Safe stand-in exposing exactly the surface the
/// {SafeCoronaCoSigner} guard reads (`nonce`, `getTransactionHash`).
contract MockSafe {
    uint256 public nonce = 1;
    bytes32 public immutable txHash;

    constructor(bytes32 txHash_) {
        txHash = txHash_;
    }

    function getTransactionHash(
        address,
        uint256,
        bytes calldata,
        uint8,
        uint256,
        uint256,
        uint256,
        address,
        address,
        uint256
    ) external view returns (bytes32) {
        return txHash;
    }
}

contract E2ETest is Test {
    uint32 internal threshold;
    uint32 internal parties;
    bytes32 internal msgHash;
    bytes internal sig;
    bytes internal expectedInput;

    address internal constant ENTRY_POINT = address(0xEE);

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

    // --- SafeCoronaSigner: EIP-1271 owner ------------------------------------

    function test_Signer_ReturnsMagicValueForValidSignature() external {
        SafeCoronaSigner signer = new SafeCoronaSigner(threshold, parties, sig);
        bytes4 magic = signer.isValidSignature(msgHash, sig);
        assertEq(magic, IERC1271.isValidSignature.selector, "valid Corona sig must yield ERC-1271 magic value");
        assertEq(signer.groupKeyHash(), Corona.groupKeyHash(sig), "committed group-key hash");
    }

    function test_Signer_LegacyERC1271FailsClosedForWrongHash() external {
        SafeCoronaSigner signer = new SafeCoronaSigner(threshold, parties, sig);
        bytes memory message = "legacy-erc1271-message";
        bytes4 magic = signer.isValidSignature(message, sig);
        assertEq(magic, bytes4(0), "legacy path must fail-closed for a non-matching message hash");
    }

    function test_Signer_RejectsWrongGroupKeyBinding() external {
        SafeCoronaSigner signer = new SafeCoronaSigner(threshold, parties, sig);
        // Mutate the group-key region: the embedded key no longer matches the
        // commitment, so verification fails without trusting the precompile.
        bytes memory otherKey = bytes.concat(sig);
        otherKey[Corona.GROUP_KEY_OFFSET] ^= 0xFF;
        bytes4 magic = signer.isValidSignature(msgHash, otherKey);
        assertEq(magic, bytes4(0), "wrong group key must not yield magic value");
    }

    function test_Signer_RejectsTamperedSignature() external {
        SafeCoronaSigner signer = new SafeCoronaSigner(threshold, parties, sig);
        // Mutate the varying prefix: group-key binding still matches, but the
        // (mocked) precompile rejects the changed calldata.
        bytes memory bad = bytes.concat(sig);
        bad[100] ^= 0xFF;
        bytes4 magic = signer.isValidSignature(msgHash, bad);
        assertEq(magic, bytes4(0), "tampered sig must not yield magic value");
    }

    function test_Signer_ConstructorRejectsBadThreshold() external {
        vm.expectRevert(SafeCoronaSigner.InvalidThreshold.selector);
        new SafeCoronaSigner(5, 3, sig);
    }

    // --- SafeCoronaCoSigner: transaction guard -------------------------------

    function test_CoSigner_AcceptsCoSignedTransaction() external {
        SafeCoronaCoSigner coSigner = new SafeCoronaCoSigner(threshold, parties, sig);
        MockSafe safe = new MockSafe(msgHash);

        bytes memory leading = abi.encodePacked(uint256(uint160(address(this))), uint256(0), uint8(1));
        bytes memory signatures = bytes.concat(leading, sig);

        vm.prank(address(safe));
        coSigner.checkTransaction(
            address(safe), 0, "", 0, 0, 0, 0, address(0), payable(address(0)), signatures, address(this)
        );
        assertEq(coSigner.coSignatureLength(), sig.length, "coSignatureLength must equal serialized sig length");
    }

    function test_CoSigner_RevertsWithoutCoSignature() external {
        SafeCoronaCoSigner coSigner = new SafeCoronaCoSigner(threshold, parties, sig);
        MockSafe safe = new MockSafe(msgHash);

        bytes memory bad = bytes.concat(sig);
        bad[100] ^= 0xFF; // tamper varying prefix; group-key still binds
        vm.prank(address(safe));
        vm.expectRevert(SafeCoronaCoSigner.Unauthorized.selector);
        coSigner.checkTransaction(
            address(safe), 0, "", 0, 0, 0, 0, address(0), payable(address(0)), bad, address(this)
        );
    }

    function test_CoSigner_RevertsOnShortSignatures() external {
        SafeCoronaCoSigner coSigner = new SafeCoronaCoSigner(threshold, parties, sig);
        MockSafe safe = new MockSafe(msgHash);
        vm.prank(address(safe));
        vm.expectRevert(SafeCoronaCoSigner.Unauthorized.selector);
        coSigner.checkTransaction(
            address(safe), 0, "", 0, 0, 0, 0, address(0), payable(address(0)), hex"deadbeef", address(this)
        );
    }

    // --- CoronaAccount: ERC-4337 ---------------------------------------------

    function test_Account_ValidatesUserOp() external {
        CoronaAccount account = new CoronaAccount(ENTRY_POINT, threshold, parties, sig);
        PackedUserOperation memory userOp = _emptyUserOp();
        userOp.signature = sig;

        vm.prank(ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, msgHash, 0);
        assertEq(validationData, 0, "valid Corona user op must validate (0)");
    }

    function test_Account_RejectsTamperedUserOp() external {
        CoronaAccount account = new CoronaAccount(ENTRY_POINT, threshold, parties, sig);
        PackedUserOperation memory userOp = _emptyUserOp();
        bytes memory bad = bytes.concat(sig);
        bad[100] ^= 0xFF;
        userOp.signature = bad;

        vm.prank(ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, msgHash, 0);
        assertEq(validationData, 1, "tampered Corona user op must fail validation (1)");
    }

    function test_Account_RejectsWrongGroupKeyBinding() external {
        CoronaAccount account = new CoronaAccount(ENTRY_POINT, threshold, parties, sig);
        PackedUserOperation memory userOp = _emptyUserOp();
        bytes memory otherKey = bytes.concat(sig);
        otherKey[Corona.GROUP_KEY_OFFSET + 64] ^= 0xFF;
        userOp.signature = otherKey;

        vm.prank(ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, msgHash, 0);
        assertEq(validationData, 1, "wrong group key user op must fail validation (1)");
    }

    function test_Account_OnlyEntryPoint() external {
        CoronaAccount account = new CoronaAccount(ENTRY_POINT, threshold, parties, sig);
        PackedUserOperation memory userOp = _emptyUserOp();
        userOp.signature = sig;
        vm.expectRevert(CoronaAccount.UnsupportedEntryPoint.selector);
        account.validateUserOp(userOp, msgHash, 0);
    }

    function _emptyUserOp() internal pure returns (PackedUserOperation memory userOp) {
        userOp = PackedUserOperation({
            sender: address(0),
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });
    }
}
