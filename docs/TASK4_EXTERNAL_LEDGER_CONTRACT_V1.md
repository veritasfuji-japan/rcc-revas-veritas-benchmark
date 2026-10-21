# External retained-ledger contract and fail-closed client

This increment defines the boundary between an ephemeral caller and a retained authority service. It provides a local SQLite reference service, a receipt-verifying client with no default transport, and failure/concurrency/process-restart tests. It **does not deploy external storage or connect this client to Native issuance/Custody dispatch**. Existing #517 Native proofs still use same-host `/run` enrollment. An external-ledger deployment remains a prerequisite, not an accomplished result.

## Contract

Trusted administration enrolls a binding containing the schema, authority ledger ID, globally unique authorization run ID, exact manifest digest, and distinct issuer/Custody public-key digests. The ledger ID names the retained service namespace; different runners must receive the **same independently approved binding and pinned service public key**. A caller cannot replace either with a new namespace to restart a run. This reference does not enforce that external administration requirement.

The client protocol exposes only `view`, `reserve` and `consume`. Enrollment is an explicit service administration operation. There is no client-side enroll, reset, retire or repair command. A duplicate run ID is rejected, even with the identical binding or changed manifest/keys. A different legitimate research run needs a new approved run ID. Administrators must retain the run registry/tombstones beyond disposable jobs; deletion/rollback of that registry defeats this property and is outside this proof.

Each fixed operation A0–A3/B0–B3 follows `absent -> RESERVED -> CONSUMED_UNKNOWN`. Reserving binds the exact SDK request digest. Consuming binds the same request and the signed grant's digest. There is no transition back to an unused state. `CONSUMED_UNKNOWN` is conservative bookkeeping, not evidence that a Provider was contacted, succeeded, or returned a response. This ledger does not validate Native histories, grant signatures, scope, budget, recipient, expiry or observations: the existing policy and Custody checks remain necessary. No public Provider capability is added.

Mutations use a transaction and an expected run revision. One mutation wins a conflicting compare-and-swap; all losers stop. The reference serializes SQLite transactions on one local service filesystem. This is **not distributed CAS, multi-region consistency, or independent anti-rollback evidence**. Mutation acknowledgement is signed only after commit. Receipts bind the schema, ledger/binding identity, fresh random nonce, full command digest, action and exact resulting revision/state. Each callback gate obtains a fresh view and performs a fresh mutation; a read receipt or previously successful mutation receipt cannot authorize a callback. Clients never automatically retry mutations.

`LedgerClient.gate('reserve', ..., issuance_callback)` runs the supplied callback only after a verified reservation acknowledgement. `gate('consume', ..., dispatch_callback, grant_digest)` runs the callback only after verified consumption. These are contract-level callbacks used by synthetic tests; **no existing Native service invokes them yet**. They cannot prevent other code from calling an API directly. Integrating them requires trusted enrollment, an authenticated transport, and placing the mutation inside the actual policy/dispatch boundary after all existing checks and before signing/sending. Adding a remote counter after issuance or after sending would not meet the contract.

## Unavailable and ambiguous outcomes

The production transport is deliberately absent. Without an explicitly supplied transport the client refuses operation, with no local SQLite/file/cache fallback. A missing, corrupt, malformed, oversized, incorrectly signed, mismatched, replayed or unverifiable response prevents the callback. Missing/corrupt reference storage is never initialized implicitly. Opening existing storage requires its registered service key; bootstrap uses exclusive creation.

A lost acknowledgement can occur **after commit**. The client stops; it does not infer absence, repair storage, reissue a grant, or resend. A fresh client sees the retained reservation/consumption and cannot repeat it. A callback exception likewise leaves the operation consumed. This trades availability for duplicate prevention. A later observation/reconciliation protocol would need its own authenticated evidence and must never convert ambiguity into automatic resend. Such recovery is not implemented here.

The injected transport must authenticate issuer and Custody separately and supply the service with their verified identities. The JSON command cannot choose its role. The local test transport supplies a trusted peer identity directly; it does not prove mutual TLS, IAM, network isolation or peer authentication. Service signatures provide acknowledgement integrity; they do not provide confidentiality, server availability, independent administration, or protection against a compromised trusted signer. The in-memory client revision floor detects regressions observed by that client; it is not a durable monotonic witness for a new runner.

## Verification and limits

The subsequent [backend selection](TASK4_EXTERNAL_LEDGER_BACKEND_SELECTION_V1.md)
conditionally selects a GitHub expected-head state branch for research storage.
It does not provision that branch, supply this client's signed transport, or
establish cross-runner retention; deployment remains blocked on explicit gates.

The existing Actions workflow runs the contract tests and a sanitized rehearsal on every PR. Tests cover a new service process reopening the same database after a prior reservation, clients with separate empty working directories, duplicate/changed enrollment, role crossing, binding/signature/nonce/command mismatches, stale revisions, simultaneous reserve/consume races, storage failures and lost acknowledgements before/after commit. The subprocess uses a synthetic signing key passed privately on stdin. No key, raw history or database is uploaded. Separate working directories and a fresh process in one CI host are explicitly **not separate GitHub runners**.

Run locally with the pinned cryptographic/test dependencies:

```sh
python -m pytest -q -o addopts= tests/test_task4_external_ledger_contract_v1.py
python -m scripts.task4_external_ledger_contract_v1 --output results/task4-external-ledger-contract
```

Before actual Runner integration, select/provision a retained backend outside job workspaces, define one approved namespace and run lifecycle, implement peer-authenticated bounded transport with a pinned service key, and verify crash durability, backup/restore and concurrent clients across real runners. Specify administrator/key access, run retention and recovery, including how rollback is detected or trusted. Then connect the gate to real Native issuance and Custody before send, and verify real fault boundaries. Backend/credential/egress provisioning, live private recipient lifecycle, current pricing and fresh owner consent remain separate gates. No Secrets, Environments, Rulesets, paid services or real credentials are changed.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`
