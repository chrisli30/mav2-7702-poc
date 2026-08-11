# When you delegate your EOA, can the delegate *sign* as you?

Sepolia-fork tests asking one question of three EIP-7702 delegation designs: **when you grant an
agent scoped authority to execute, does it also get the ability to sign ERC-1271 messages as your
account?**

It matters because the two authorities are separable and only one of them is usually discussed. A
key bounded to "0.0002 ETH to one address" that can still sign a Permit2 approval is not bounded —
and execution-side policy (hooks, caveat enforcers) never sees the signature path.

The three answers are different, and not in the direction the marketing suggests:

| | Execution scoping default | Can a scoped delegate sign as the account? |
|---|---|---|
| **Alchemy MA v2** (ERC-6900) | **fail-closed** — flags default false, account reverts | **No** — opt-in per validation, account-enforced |
| **MetaMask** (`EIP7702StatelessDeleGator`) | fail-open — caveats "strongly recommended" | **No** — impossible by construction |
| **Uniswap Calibur** | fail-open — hook must be CREATE2-mined | **Yes** — any registered key may sign |

Two suites live here (MA v2, MetaMask). The Calibur result is in
[chrisli30/calibur-7702-poc @ `verify/ava-protocol-standalone`](https://github.com/chrisli30/calibur-7702-poc/tree/verify/ava-protocol-standalone).
All three were run for the [Ava Protocol EIP-7702 evaluation](https://github.com/AvaProtocol/EigenLayer-AVS/discussions/658).

No funding, no broadcasting, no private keys. Everything runs against a pinned fork of the canonical
deployed contracts.

## Run

```bash
git clone --recurse-submodules <this-repo-url>
cd mav2-7702-poc
cp .env.example .env      # then set SEPOLIA_RPC_URL to an archive-capable endpoint
forge test -vv            # 12 tests, 2 suites
```

Requires Foundry with EIP-7702 cheatcode support (≥ 1.0). Verified on `forge 1.2.3-stable`.
The fork is pinned to Sepolia block **11,440,000**, so the endpoint must serve historical state.

## Contracts under test

Canonical deployments, each verified live on Sepolia via `accountId()` / `moduleId()`:

| Contract | Address | Identifier |
|---|---|---|
| SemiModularAccount7702 | `0x69007702764179f14F51cdce752f4f775d74E139` | `alchemy.sma-7702.1.0.0` |
| SingleSignerValidationModule | `0x00000000000099DE0BF6fA90dEB851E2A2df7d83` | `alchemy.single-signer-validation-module.1.0.0` |
| MetaMask EIP7702StatelessDeleGator | `0x63c0c19a282a1B52b07dD5a65b58948A07DAE32B` | `EIP7702StatelessDeleGator` |

`entryPoint()` on the account returns `0x0000000071727De22E5E9d8BAf0edAc6f37da032` — EntryPoint v0.7.

## MA v2 — `MAv2SignatureScope.t.sol`

| Test | Result |
|---|---|
| `test_delegationIsLive` | EOA delegates to `SemiModularAccount7702`; the account **is** the EOA address |
| `test_owner_canSignForAccount` | Baseline — the fallback signer (the EOA itself) signs, returning `0x1626ba7e` |
| `test_sessionKey_withoutSignatureFlag_CANNOT_sign` | **The result.** Reverts `SignatureValidationInvalid(module, entityId)` |
| `test_sessionKey_withSignatureFlag_CAN_sign` | **The control.** Same key, same encoding, flag set → signs |
| `test_signingAuthorityIsPerValidation_notPerKey` | The same signer under two entity ids: one signs, one is refused |
| `test_scopedSessionKey_cannotInstallAnotherValidation` | A scoped key cannot grant itself a second validation |
| `test_owner_canWidenScopeLater` | The owner *can* add the flag to an existing entity id afterward |

Two properties are worth stating plainly, because they are what a delegated-automation design
actually rests on:

**Signing authority is opt-in and enforced by the account.** ERC-6900 makes it a per-validation flag
and requires the account to honour it — *"If the validation function is attempted to be used for
signature validation and the flag `isSignatureValidation` is set to false, validation MUST revert."*
MA v2 implements that in `ModularAccountBase._exec1271Validation`. The last two rows matter for the
same reason: a grant is **upgradeable but never self-upgradeable**. Scope can be widened later, but
only by the account owner — holding the key gets you nothing toward widening what the key may do.

**The control test is load-bearing.** A negative test that reverts proves nothing on its own; it can
revert because the scope held, or because the signature was malformed. Every negative here asserts
the *exact* error, and the control flips one bit at install with an otherwise identical signature.


## MetaMask — `MetaMaskDelegateSignature.t.sol`

| Test | Result |
|---|---|
| `test_delegationIsLive` | EOA delegates to `EIP7702StatelessDeleGator` |
| `test_owner_canSignForAccount` | Baseline — the EOA signs for its own account |
| `test_delegate_CANNOT_signForAccount` | **The result.** Returns `SIG_VALIDATION_FAILED` (`0xffffffff`) |
| `testFuzz_onlyTheEOAKeyIsAccepted` | 256 runs — no key but the EOA's is ever accepted |
| `test_delegationManagerIsSeparateFromSignaturePath` | The execution counterparty is a different contract |

MetaMask reaches the same destination as MA v2 by a different road, and arrives more absolutely.
`EIP7702StatelessDeleGator` is stateless by design — it stores no signer data — so
`_isValidSignature` recovers the signature and compares it to `address(this)`, the EOA itself, and
nothing else:

```solidity
function _isValidSignature(bytes32 _hash, bytes calldata _signature) internal view override returns (bytes4) {
    if (ECDSA.recover(_hash, _signature) == address(this)) return ERC1271Lib.EIP1271_MAGIC_VALUE;
    return ERC1271Lib.SIG_VALIDATION_FAILED;
}
```

The signature path never reads delegation state. There is no configuration — no caveat, no flag, no
delegation — under which a delegate signs for the account. Where MA v2 makes signing an opt-in the
account enforces, MetaMask makes it **unreachable**.

Note the test sets up no delegation at all, and that is the point: delegations are off-chain objects
held by the delegate, and no code path on the signature side consults them. Holding one, with or
without caveats, cannot change the outcome.

## Encoding notes

Both encodings are easy to get wrong and neither is obvious from the ABI, so they are recorded here.

`ValidationConfig` is a packed `bytes25`:

```
[20-byte module][4-byte entityId][1-byte flags]
flags: 0x01 isUserOpValidation | 0x02 isSignatureValidation | 0x04 isGlobal
```

The `isValidSignature` signature is segmented:

```
[1-byte options][4-byte entityId][0xFF][1-byte sigType][65-byte ECDSA]
options: 0x01 global | 0x02 deferred action | 0x04 direct-call
0xFF    = RESERVED_VALIDATION_DATA_INDEX, marking the final segment
sigType = 0x00 for EOA
```

Omitting the `0xFF` segment marker fails with `ValidationSignatureSegmentMissing()` — which reverts
identically whether or not the flag is set, so a suite without a passing control test would read
that as a successful denial. The digest itself must be wrapped: `replaySafeHash(account, digest)` on
the module for an installed validation, or the account's own EIP-712 `ReplaySafeHash` envelope for
the fallback signer.

The suite declares minimal interfaces rather than importing `alchemyplatform/modular-account`, whose
build pins `evm_version = cancun`; EIP-7702 needs Prague.

## Not covered

The tests establish what the **contracts** enforce, on the paths exercised here.

What Alchemy's *managed* session-key API requests is settled separately, by reading aa-sdk rather
than by test: `PermissionBuilder` (`packages/smart-accounts/src/ma-v2/permissionBuilder.ts`) contains
exactly two occurrences of `isSignatureValidation`, both hardcoded `false`, and no branch mutates it.
`PermissionType.ROOT` sets `isGlobal = true` and nothing else — so even a root-scoped session key can
execute anything yet still cannot sign as the account. That is why the eight documented permission
types (`native-token-transfer`, `erc20-token-transfer`, `gas-limit`, `contract-access`,
`account-functions`, `functions-on-all-contracts`, `functions-on-contract`, `root`) are all
execution-scoped: execution and signing are separate axes, and the managed API only exposes the
first. The flag is reachable only via the low-level `installValidation` decorator, where the caller
supplies it explicitly.

Also untested here: the permission modules themselves (AllowlistModule, TimeRangeModule,
NativeTokenLimitModule) and per-operation gas cost. Note that a validation carrying hooks cannot
authorize deferred actions at all, which further constrains a hook-scoped session key.
