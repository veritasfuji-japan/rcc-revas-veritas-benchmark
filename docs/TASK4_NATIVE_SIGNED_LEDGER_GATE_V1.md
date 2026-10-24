# Durable local intent and signed receipt gate (contract increment)

Implements the first adapter/intent increment identified by the
[integration audit](TASK4_SIGNED_LEDGER_NATIVE_INTEGRATION_SOURCE_AUDIT_V1.md).
This module is **not yet called by NativePolicy.authorize or Custody**. It does
not change their existing modes, deployed operator service, keys or approvals.
An actual Native/Bind/closed-TLS integrated proof remains a separate next step.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

## Explicit trusted interface

`scripts/task4_native_signed_ledger_gate_v1.py` exposes NativeLedgerGate and no
CLI, enrollment initializer, credential/key loader, socket factory, Provider
connector or default transport. Trusted integration code supplies an exact
existing enrollment, pinned raw service public key, peer-authenticated transport,
admission callback and effect callback. Model/request JSON cannot select them.
The module is not a sandbox for arbitrary caller code: trusted callbacks and
transports can execute code. DENY/UNSCORED records label this synthetic contract;
those strings do not independently enforce a live egress or spending boundary.

Unlike the manual synthetic client's fixed-label hashes, this adapter computes
SHA-256 over the exact supplied SDK body (1-64,000 bytes). Slot names remain
A0-A3/B0-B3. Issuer can only reserve and accepts no grant. Custody can only
consume, binding the canonical digest of the complete supplied Native grant.
It checks bounded grant shape and run/manifest/arm/ordinal/request joins; it
does **not** replace actual issuer-signature/history/recipient/budget/expiry
validation. Those checks belong in the mandatory trusted admission callback.

`execute(operation=..., wire=..., admit=..., effect=..., grant=...)` calls admit
before claiming an attempt and again after the potentially slow exchange.
Admission must return None after successful validation or raise; returning
False/True is rejected. Revalidation must use the actual current clock, not a
cached entry-time check. A mutable grant changed by admission is rejected.

## Reopen-only enrollment and retained storage

The separately supplied expected enrollment has exactly:

| Field | Contract |
| --- | --- |
| schema | task4.native-signed-ledger-gate-enrollment.v1 |
| scope | SYNTHETIC_NATIVE_LEDGER_GATE_ONLY_NO_PROVIDER |
| binding | Existing six-field signed-ledger binding; Native manifest/run/role mapping requires separate trusted review |
| role | issuer or custody |
| service_public_sha256 | SHA-256 of the supplied raw 32-byte service public key; distinct from both role authority digests |
| journal | Exact absolute path, device, inode, effective uid and mode 0700 |

The existing journal contains a canonical enrollment.json, owned by the role,
mode 0600, regular and single-link. It must equal the complete expected
enrollment. Source shares descriptor-pinned no-follow directory traversal with
receipt-key custody, including trusted ancestors and root-sticky test ancestors.
Normal construction never creates storage, rewrites enrollment, repairs modes,
discovers a replacement identity or generates keys. The future provisioning
step must durably retain this enrollment and its expected identity independently
of model inputs; tests create disposable records explicitly.

The registered journal identity and enrollment are rechecked on every execution
and before the callback, including a check that the claimed slot is still the
same inode. A same-byte directory replacement does not match enrollment.
The owning role and administrator can still delete/replace trusted material or
call other code; no hostile-owner, independent administration, host reboot,
privileged rollback or mount-namespace guarantee is made.

## Attempt ordering

1. Perform input/role/grant-join checks and trusted admission.
2. Exclusively mkdir `<run_id>-<reserve|consume>-<slot>` and fsync its parent.
   Write exclusive intent.json, fsync file and slot before any transport call.
   Every existing directory, including empty or partially written, is burned.
   The name does not vary with request/grant hashes, so changed input cannot
   recover the same slot. No exception path deletes it.
3. Obtain one fresh signed view, then at most one mutation at its exact revision.
   Existing LedgerClient checks signatures, nonces, command/binding/ledger,
   exact committed revision and resulting attempt. No refresh/retry/fallback.
4. Exclusively retain verified-receipts.json (both command/receipt pairs and
   resulting snapshot), fsync file/directory, recheck enrollment/slot, and run
   trusted admission again. Only then invoke the effect once in that attempt.
5. If effect returns, exclusively/fsynced write effect-returned.json and return
   its result to trusted code. The result itself is never journaled. A callback
   exception or final-record failure can follow a callback that already ran;
   STOP or a missing final record never proves zero effects or permits replay.

All exposed exceptions are sanitized to NATIVE_SIGNED_LEDGER_GATE_STOP. Abrupt
process exit/interrupt is not converted to success and leaves the retained slot.
Journal records contain protocol metadata/hashes/receipts, not the SDK body,
private grant bytes, key or callback result. Records are bounded to 24,000 bytes.
No reusable permission object or automatic resume API is returned by the gate.

Local intent and external mutation are deliberately not an atomic transaction.
If the remote write commits but its reply is lost, the local slot remains burned
and no callback runs. If no remote request occurred, a prior durable intent still
stops a retry. This conservative availability tradeoff avoids pretending that a
rollbackable local SQLite transaction can undo a remote commit.

## Verification and limits

35 unittest cases exercise actual filesystem/fsync boundaries and signed
SQLite ReferenceService receipts, both roles and exact non-label request/grant
digests. They include bad signatures/nonces/bindings/states, read receipt
substitution, revision conflict, response discard after commit, admission/expiry
recheck, mismatched/mutated grants, missing/unsafe/replaced enrollment, write and
fsync faults, callback/final-record failures, two-thread/two-process claim races,
and a fresh interpreter in a changed working directory.

Two subprocess tests exit abruptly after reservation commit (73) and after
verified consumption receipt retention but before effect (74). Fresh gate
instances refuse those retained slots without transport/effect. These are
process-exit tests on one local filesystem, not power-loss or remote deployment
proof. Fault injection at write/fsync boundaries is distinguished from actual
hardware I/O failure. Test role labels share the test runner's effective uid;
they are not separate-UID/TLS identity or credential/egress evidence.

The test admission/effect hooks are controlled fixtures. Existing Native checks,
actual Native SDK/Bind/archive/scorer trajectories, mTLS and the real GitHub
backend are not executed by these tests. The source-neutral helper is groundwork,
not proof of Native integration or a reason to re-enroll the operator run.

Run in a disposable Linux test workspace with cryptography installed:

```sh
python -m unittest discover -s tests -p test_task4_native_signed_ledger_gate_v1.py -v
```

The existing standard PR pytest discovery also collects these unittest cases.
No new workflow, live credential, enrollment command, API request or spending
approval is added. Integration must require this gate through trusted active
enrollment rather than allow callers to omit it, preserve all existing Native
checks and legacy proof profiles, and join real callback/receipt/state evidence
on the same closed local Native path before claiming the next gate is complete.
