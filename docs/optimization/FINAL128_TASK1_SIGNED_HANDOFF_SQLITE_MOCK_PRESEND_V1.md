# Task1 First A/B — Ed25519 handoff to SQLite mock-send intake V1 (offline only)

**Status: LOCAL MOCK-ONLY EVIDENCE, PAID TASK1 NO-GO. NOT WIRED TO #423.**

This contribution joins two previously isolated pieces without upgrading either to live execution authority:

- **#437:** strictly scoped, test-owned Ed25519-signed fake `MockJobContext` and handoff, including separate numeric-looking issuer and sender job IDs. Those IDs are *self-declared fixtures*, **not independent GitHub/OIDC job authentication**.
- **#442:** exact first synthetic A/B packet bytes and the `InMemoryFakeProviderPort` which merely records a local Python method call, not an HTTP request.
- **#445:** source audit and inert issuer/sender job blueprint. No GitHub Actions job split was installed; the actual protected #423 sender continues to share `contents:write` authority with tag creation.

This PR introduces **`scripts/final128_task1_signed_handoff_sqlite_mock_presend_v1.py`**, a new local SQLite-backed fake-sender intake which refuses to interpret the research-tag readback as a send grant. It uses #437's existing exact Ed25519 signature and scope validator; it checks #441's frozen research evidence **must** say `PAID_TASK1_NO_GO`, and only proceeds using a separate fresh **synthetic** test signer and first-packet fixture.

## What runs and what is isolated

- A local test creates a private 0700 directory and SQLite database file 0600, with `synchronous=FULL`, `BEGIN IMMEDIATE` and per-arm attempt rows.
- A valid source-owned test handoff can reserve **A** once by committing `UNKNOWN_A` to SQLite **before** calling the local mock port. After a strictly checked local mock ACK, the durable phase becomes `A_ACK`.
- Only after `A_ACK` may **B** reserve once with `UNKNOWN_B`; a validated local ACK advances to `PAIR_ACK`.
- A second gate object opening **the same SQLite path** refuses A replay; two **separate OS processes** racing on the same file admit only one mock A request. Separate in-memory #437 replay ledgers can be replaced without bypassing the shared local SQLite reservation.
- A fake timeout, invalid local ACK, deliberate stop after reservation or stop after the local fake call leaves `UNKNOWN_A` or `UNKNOWN_B` durably recorded. A future gate object on that file refuses both further A and B; no auto-retry, no unobserved promotion to COMMITTED or official scoring.
- Fake-signer mismatch, claimed Run ID or job ID drift, wrong first-packet hash, model/case/tag substitution, false paid consent, wrong attempt count, ref drift or newly asserted live provenance are denied **before** any mock port call.

Tests reside in `tests/test_final128_task1_signed_handoff_sqlite_mock_presend_v1.py`. They use generated ephemeral test-only Ed25519 keys, never any GitHub/Provider secret. Network connect methods are forbidden in the pytest parent. Spawned child processes exercise only this local database and in-memory method call. Existing CI can run the tests without adding a workflow or changing any paid configuration.

## Why this is useful, but NOT an execution authority proof

**One local SQLite database** can serialize mock consumers and preserve a no-retry marker between objects/processes; it is *not* a remote independently controlled global Provider-send lease. A distinct SQLite file accepts the same signed A fixture in the negative control. A client who can delete or rewrite the test database can defeat its uniqueness. The in-process test signer/public key are not trusted production IAM identities; these tests do not prove a recipient/issuer is enrolled by GitHub or an organization.

The mock sink is **not independent** of Python code. A caller can bypass the intake and call `InMemoryFakeProviderPort.deliver` directly. The synthetic packet is **not real AgentDojo Native HTTP payload data**, the SQLite phases are **not authentic Provider transaction statuses**, and the LocalReceipt is not a Provider bill, server receipt or verifiable execution result.

The code does **not** invoke VERITAS Bind or the real #423 sender; the earlier separate #410–#412 experiments show real Linux cross-UID, pinned VERITAS Bind, backend SQLite and mock-network mTLS but do **not** themselves establish this first-pair Provider send boundary. No existing privilege/egress path has been closed by this PR.

| Concrete claim | Result |
| --- | --- |
| Signed mock context and exact first packet verification | Locally tested, never real GitHub Run ID attestation |
| SQLite record committed before fake-port call | Locally tested for single shared DB |
| Concurrent independent OS processes on same DB | Local mock admission only |
| Reopen/retry after fake timeout/partial acknowledgment | Denied on the same database |
| Global durable single-use across Actions Runners | **NOT PROVEN** |
| Real Provider network/non-bypassable egress | **NOT IMPLEMENTED** |
| Real issuer/sender job permissions and key isolation | **NOT IMPLEMENTED** |
| Real financial spending cap, consent or Native utility | **NO PROOF / NO-GO** |

## Required actual integration, separately authorized

1. Implement distinct real GitHub job principals and least-privilege permissions, with issuer unable to read Provider secrets and sender unable to modify the production ref. Job-scoped access must be checked against actual installed GitHub policy.
2. Bind the issuer's signature and intended recipient to independently verified GitHub Job/Run/commit context and an enrolled external signing principal; in a real trust architecture, the untrusted workflow cannot mint its own accepted permit.
3. Place provider secret/key custody, pre-send Bind validation and **atomically consumed remote durable per-arm ledger** behind a separate trusted sink, such that all alternative credentials/network routes are denied. A local SQLite file in an agent-controlled Runner is insufficient.
4. Complete real request/response provenance and encrypted evidence custody; confirm limits and fresh explicit consent for exact SHA/model/case/two sends **after** reviewing the real boundary.
5. Keep the separate current production tag untouched; it is not a Provider request-by-request lease. Research ref existence is only historical evidence.

## Hard NO-GO and zero effects

**Issue #427 remains OPEN / NO-GO.** This PR does not add/edit `.github/workflows` files, modify #423, create/delete tags, modify secrets/Rulesets/Environments, invoke `workflow_dispatch`, retry a failed paid Run, or send any actual Provider request. Tests may run as part of the repository's existing ordinary PR CI; no new manual runs are requested.

**Acceptance boundary: a passing CI proves only local simulated signed handoff + durable fake-send admission. It does not prove real API spend protection, non-bypassable IAM or production readiness.**
