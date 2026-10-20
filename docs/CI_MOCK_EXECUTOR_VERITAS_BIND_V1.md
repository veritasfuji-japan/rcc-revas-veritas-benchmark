# Actual VERITAS Bind inside the isolated mock Executor

Baseline: merged #491, `8843b6a34291ba8f16928bb9c831e4922616324c`.
Environment: the same owner-selected, trusted GitHub Actions VM. This closes
one local integration gap: the actual Bind call and authenticated mock effect
are observed in the same Executor process/run, with the same backend/ledger.

## Same-run order and source identity

1. Retain #491's separate UIDs, loopback-only agent namespace, host UID firewall,
   protected files, SO_PEERCRED and exact HMAC fixture checks.
2. Commit the Executor's single-use CONSUMED_UNKNOWN row before the effect path.
3. Read authenticated backend state across the actual veth/TCP connection.
4. Invoke the real `execute_bind_adjudication` from VERITAS
   `a1d66aef02262cf8a913295270c3aafd159c6adb` through a mock-only ReferenceBindAdapter.
5. Reach the only authenticated effect POST from adapter.apply on Bind admission;
   verify actual backend poststate, then require Bind COMMITTED.
6. Join full Bind receipt hashes, exact request/backend receipt, final backend
   state and Executor ledger. Replay before/after Executor restart still fails.

The root supervisor verifies the exact checkout commit, clean tracked package
and Bind core git blob `0f64201e2599495ce4e3991348aa320995716ffc`. It copies the
VERITAS package and new adapter into root-owned read-only temporary storage.
The Executor inserts only that trusted temporary root into its import path.
The same setup-python 3.11.16 interpreter runs supervisor and unprivileged roles;
Package initialization dependencies are pinned to PyYAML 6.0.3, cryptography
50.0.0, pydantic 2.11.10 and numpy 1.26.4; these imports are checked before the
kernel test. No runtime dependency download
occurs inside the agent, Executor or backend namespaces/processes.

The backend adds an authenticated read-only `/status` endpoint with a distinct
HMAC domain. Its state reports counter, revision and spent count. Bind snapshots
and postcondition checks use this backend-owned state rather than fabricated
local state. The existing effect endpoint/authentication remains unchanged.

## Actual denied and admitted Bind cases

Before the one positive effect, the Executor evaluates three source-owned
negative fixtures using actual Bind: withdrawn authority, wrong target and
wrong expected prestate fingerprint. Each must return BLOCKED, never invoke
apply, and leave backend state at counter=revision=spent=0. The positive fixture
must return COMMITTED, invoke apply once and produce backend state 1/1/1.

These negative fixtures are internal test cases, not agent-selectable bypass
parameters. They run inside the already-consumed positive test attempt. They
are not three independently approved business actions. Expected timestamps and
source authority are explicit synthetic fixtures, not a fresh human grant or
production revocation policy. No authority condition is weakened to repair
Utility; this does not run a model or score Native tasks.

Full Bind receipts plus their hashes are stored in `bind-evidence.json`. They
contain fixture identifiers/fingerprints, not backend credentials, HMAC verifier
keys or the signed bearer grant packet. The report hashes this entire evidence
object and the adapter source. The root supervisor independently compares the
backend's spent record to the Executor's persisted consumed receipt and the
Bind path's returned backend receipt. The synthetic backend receipt is the
digest of the fixed operation body; it is correlation evidence, not third-party
Provider attestation. The backend uses its credential to authenticate the write
and its own SQLite transaction to persist the effect.

## Mandatory CI gate and remaining scope

Every PR runs the existing kernel workflow with `--with-veritas-bind`; missing
source/dependencies or incomplete evidence fails, never skips. Its 28 assertions
are the original 23 plus three actual Bind refusals, one actual Bind commit and
one same-run receipt join. The existing 11 scope-validation tests remain. A local
precheck can use the exact public VERITAS source with an in-memory fake backend;
only the dedicated kernel run establishes the veth/UID/firewall integration.

The original no-Bind CLI mode remains reproducible and reports
`real_veritas_bind_integrated=false`; the every-PR gate requires true and all
four real receipts. No production flag is promoted by that local integration.

This uses an actual Bind engine with a synthetic exact-operation adapter, not
the original Native Task4 policy adapter, a real enterprise issuer, remote
administrator, real bank service or paid Provider. `native_task4_pipeline_integrated`
and `production_policy_proven` stay false. #487's selected Native run is a
separate regression and is not claimed integrated into this mock flow. Historical
direct HTTPS helpers remain callable in source and are not invoked here.
Same-VM root, kernel, Executor and trusted source remain trusted. Distributed
CAS, lost-ACK reconciliation, independent identity/administration and external
adversarial reproduction remain open. No real credentials/paid settings or
historical source pins are changed.

`REAL_PROVIDER_NO_GO` / `UTILITY_UNSCORED` /
`PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN` remain unchanged.

## Current issuer extension

The current workflow additionally requires the
[separate Ed25519 issuer proof](CI_MOCK_EXECUTOR_SEPARATED_ISSUER_V1.md).
The Bind receipts remain unchanged in scope; backend signature validation does
not independently attest that a compromised Executor invoked Bind.
