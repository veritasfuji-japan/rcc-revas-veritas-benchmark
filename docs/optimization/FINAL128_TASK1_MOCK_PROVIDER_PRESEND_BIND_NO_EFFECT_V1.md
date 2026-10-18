# Final128 Task1 — mock Provider pre-send Bind boundary, NO EFFECT V1

**STATUS: OFFLINE IN-PROCESS MODEL ONLY. PAID TASK1 NO-GO. NOT WIRED INTO LIVE PROVIDER WORKFLOW.**

This PR adds an executable **local mock send-boundary rehearsal** of the separation recorded in PR #440 and PR #441. The exact research tag `refs/tags/final128-task1-research-first-two-once-v1` was observed against `4e864ebad860be2ce71a6c233e98a581094b45aa`, under active research Ruleset #25305970 with an explicitly empty bypass list. **Those facts are historical source-controlled observations, not a Run ID, issuer, cost approval or Provider credential.**

The new source-controlled fixture validates the frozen [read-only evidence JSON](../../evidence/final128_task1_research_tag_live_readback_2026-10-18_v1.json) using [PR #441's offline snapshot checker](../../scripts/final128_task1_live_ref_run_authority_gap_offline_v1.py) **immediately before simulated mock transmission**. A valid snapshot itself always reports `PAID_TASK1_NO_GO`; it can never authorize actual model calls.

## Precisely what differs from existing security work

- #407–#412 already prove limited synthetic backend effects, a real VERITAS Bind path in a Linux sandbox, local SQLite persistence, kernel peer identity and mocked mTLS/network restrictions. This PR **does not recreate or extend that real Bind integration**.
- #423 already has a *separately protected* manual real-HTTPS Native first A/B sender and injected fake-connection tests. This PR does **not** modify it or supply its secrets.
- #441 established **read-only historical snapshot consistency without any mock send**. This PR places that checker at a **new, independent, local fake-Provider call boundary** and tests exact synthetic permit, packet, ordering, receipt and ambiguous outcome behavior. It is deliberately **not wired** into any existing GitHub Workflow or #423's real send path.
- This version tests only one same-process mock instance. It is **not production-grade OS/egress bypass prevention**, and a Python actor with arbitrary code execution can still call the underlying local fake port directly. No real Provider endpoint or real credential is reachable through this module.

## Offline source-owned fixture / pre-send decision

| Stage | Exact rule | Effect |
| --- | --- | --- |
| Frozen research ref snapshot | #441 checker must match exact tag, SHA, Ruleset, CI blob, Issue #427 hold and all NOT-PROVEN flags | Refuse before fake transport on mismatch |
| Sender identity and Run ID | A fixed `OFFLINE_FIXTURE_RUN_NOT_GITHUB`, fake issuer and fake sender only | Real GitHub identity/OIDC not authenticated |
| Synthetic signer | Fresh in-process random HMAC test key; exact signed scope, type and MAC check | Reject tamper / foreign fake signer; **not trusted IAM** |
| Request | Exact **synthetic** bytes `{"offline_test_only":true,"synthetic_native_first_packet":"A_B_EQUAL"}` and exact SHA256 for A/B | No real Native/SDK request; a source-owned unit-test packet |
| Expiry | Bounded integer `fake_tick` 0–2 | Fake tick, **not a trustworthy wall clock** |
| Call sequence | A first, then B at most once each, with a single mutex on one mock gateway | In-process serialization only |
| Transition | Mark `UNKNOWN_AFTER_A` / `UNKNOWN_AFTER_B` before calling the local fake port | No retry after timeout, malformed mock receipt or unknown outcome |
| Fake receipt | Exact local marker, ordinal and SHA validated before `A_ACK` / `PAIR_ACK` | No Provider-origin receipt, HTTP response, bill or Native score |

**Positive test**: a source-owned synthetic permit allows two local fake method invocations, Arm A then Arm B. The fake port creates two in-memory markers and **zero actual Provider calls**. This demonstrates only that the local mock code obeys its rules, not that an enterprise execution authority has been enrolled.

**Negative tests**: missing permit, wrong arm order, replay, changed/fake Run ID, fake actor/issuer/sender, wrong digest, changed packet, fake approval, production tag substitution, missing `bypass_actors`, altered Ruleset, expired fake tick, forged signature, wrong fake port class, invalid ACK, fake timeout and concurrent same-gate attempts are refused. A mock timeout may occur **after** its single local fake request is counted; neither A nor B may be retried or assumed completed.

**Counterexample**: two independently created in-memory mock sinks can each accept A. Therefore, this PR does **not** establish a durable global once-only claim, inter-run exclusion, crash persistence, or Provider-side idempotency. Production execution needs a separately authoritative sink/ledger with real IAM/network controls and independently verifiable reconciliation.

## Code, tests and operator safety

- `scripts/final128_task1_mock_provider_presend_bind_no_effect_v1.py` — stdlib-only synthetic issuer, signed local test fixture, snapshot-integrated gate and fake local sink. **No socket, HTTP, OpenAI SDK, GitHub API, environment-secret lookup, CLI or subprocess.**
- `tests/test_final128_task1_mock_provider_presend_bind_no_effect_v1.py` — offline parameterized negative tests with real outbound sockets blocked, common secret environment variables removed, no real Action dispatch or tag write.
- Local test command: `python -m pytest -q tests/test_final128_task1_mock_provider_presend_bind_no_effect_v1.py`.

The test issuer's HMAC key is **not an enrolled external identity**. It is minted by the test process; same-process code or a modified source could mint another. There is no actual independent principal, provider-secret release, user payment authority, threshold signature or durable replay lock. Neither the signed fixture nor the archived research tag grants live permission.

## Remaining true execution boundary gaps

1. Authenticate a GitHub Run/job, protected source, issuer and intended sender from an independent trust root; do not rely on self-asserted CI variables or offline fixture MAC.
2. Enforce a real, durable cross-run use-once Provider-send ledger and recover partial or unknown outcomes without retries; tag creation itself is not a send-time lease.
3. Place an actual (not mock) deny-by-default transport or provider egress barrier *outside* untrusted agent code, isolating Provider keys and every alternate credential/network route.
4. Bind real pinned AgentDojo/VERITAS first request bytes, model, Tool stages and scopes to verified authority; test genuine Independent A/B responses and source-owned Native scorer separately.
5. Review OpenAI account/project billing limits as risks, independently verify controls, and request **fresh explicit paid consent** for the exact case/model/commit/Run. USD 1 is an earlier target, not a guaranteed hard ceiling.

No tag `POST /git/refs`, PATCH/DELETE, Ruleset/Environment/secret change, workflow_dispatch, paid Provider request, bank effect or scorer is authorized or performed. The separate production singleton remains untouched. [Issue #427](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/427) stays **OPEN / NO-GO**.

**Conclusion: `LOCAL_MOCK_PRESEND_BARRIER_OBSERVED_NO_LIVE_PROVIDER_AUTHORITY`. An offline test pass is not proof of live Bind enforcement or production non-bypassability.**
