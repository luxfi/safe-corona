# safe-corona

## Overview

> [!WARNING]
> Code in this repository is not audited and may contain serious security holes. Use at your own risk.

`safe-corona` integrates **Corona** (Ring-LWE (RLWE) two-round t-of-n threshold signature) with the Safe smart account by
calling the on-chain `coronaThreshold` precompile at `0x012206`. It mirrors the
structure of `safe-frost` (verifier library + Safe signer/co-signer + ERC-4337
account + interfaces + Foundry tests), but the cryptographic verification is
delegated to a luxd-native precompile rather than implemented in Solidity.

## Package Information

- **Type**: solidity (Foundry) + rust workspace stub
- **Repository**: github.com/luxfi/safe-corona
- **Precompile**: `0x012206` (lux-evm-precompile-corona-v1)
- **Verify wire format**: `threshold:uint32(4) ‖ totalParties:uint32(4) ‖ msgHash:bytes32(32) ‖ signature`
- **Reference precompile**: github.com/luxfi/precompile/corona

## Directory Structure

```
.
contracts            Corona.sol verifier + SafeCoronaSigner/CoSigner + CoronaAccount
contracts/interfaces ISafe / ISafeTransactionGuard / IERC1271 / IERC4337 / IERC165
lib/forge-std        vendored forge-std for `forge test`
tests                Corona.t.sol (KAT + framing) + e2e.t.sol (signer/cosigner/account)
tests/kat.json       real known-answer-test vector (proven vs the Go precompile)
```

## Key Files

- `contracts/Corona.sol` — the decomplected verifier library (frame + strict staticcall).
- `tests/Corona.t.sol` — `test_CalldataFramingMatchesPrecompileABI` pins the wire format.
- `foundry.toml` — solc 0.8.29, via-IR, `fs_permissions` for `tests/kat.json`.

## Design notes (Hickey-simple, decomplected)

- **One concern per place.** Corona.sol does ONLY calldata-framing + strict
  staticcall. Key↔owner binding lives in the Safe wrappers; threshold/ownership
  policy lives in the Safe itself. The `verify` signature never changes when a
  new scheme is added — each scheme is its own orthogonal slot.
- **Fail-closed.** A valid result is ONLY: staticcall success AND
  `returndatasize == 32` AND the returned word `== 1`. Revert, wrong-size
  return, zero word, or a missing precompile are all `false`. Mirrors
  `luxfi/safe/contracts/pq/PQVerifier.sol::_callStrict`.
- **Raw wire, no selector.** The precompile parses a raw packed layout; the
  Solidity must NOT prepend an ABI function selector.

## Build & Test

```sh
forge build
forge test
```

## Regenerating the KAT fixture

```sh
cd ../precompile
SDKROOT=$(xcrun --show-sdk-path) CGO_ENABLED=1 go run ./cmd/safekatdump   > /tmp/safe_kats.json
SDKROOT=$(xcrun --show-sdk-path) CGO_ENABLED=1 go run ./cmd/safekatverify < /tmp/safe_kats.json   # asserts each KAT verifies on the real precompile
```

---

*Auto-generated for AI assistants. Mirrors the safe-frost template.*
