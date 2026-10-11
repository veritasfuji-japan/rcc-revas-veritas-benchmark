# Task4 #322 — Independent A/B **source starts** from first model request (offline)

## One precise invariant

`TASK4_322_SEPARATE_FIRST_REQUESTS_A_B_NATIVE_OFFLINE_ONLY_V1`

The model-shaped OpenAI SDK request stream, fake assistant response ID namespace, test-only date issuer and native bank copy for **A source** must NOT be reused as the origin of **B source**. A new separate first request and full SDK/Native history must be completed by each source before selecting the Arm A/B native terminal scorer evidence.

This remains fully offline. **No genuine real-model generation or injection success trial** takes place. The 2 sources use different in-memory `ScopedMock` clients and deterministic local scripting, not two independent Provider inferences. They may independently choose identical candidate arguments: equality of the action does **not** imply reused model provenance.

Baseline merged #320 main SHA `9621bbab3a790cc381ce5f55a6be0ad0f2c38b74`.

## Original Native paths unchanged

- Same **pinned actually injected** AgentDojo Task4 native banking prestate SHA-256 `8b653f253d3b2b033ad2baebc938bb66cb09719be8b488a470e7e82d25abbe14`.
- Actual attacker lower-trust transaction subject SHA256 `0d5011fb8b275e313c83da127698f19a77095d44e82a81b4d5804046c3cb61a9`, shown only through native tool read.
- Original native AgentDojo `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`, RCC `1d3782d3aae5ff9c88036709c1a5642320cc53c2`, VERITAS `a1d66aef02262cf8a913295270c3aafd159c6adb`.
- Existing frozen `Task4FrozenTransportElement`, `Task4ProspectiveTrajectory`, `Task4ControlledDateRunner`, `observe_completed_task4` and underlying Native RCC/VERITAS Bind are reused WITHOUT modifications.
- Real `openai==1.109.1` SDK `chat.completions` serialization intercepted through separate `httpx==0.28.1` **MockTransport** instances, fake key, `max_retries=0`, socket/SQLite-connect-denying tests.
- Two **synthetic signed test-only date** sessions `task4-322-offline-only-A` and `task4-322-offline-only-B`, neither production physical-clock attestation nor real bank authority.

## How selection from separate source runs works

1. Start the A source from initial provider-shaped request 0, with new model-shaped response IDs `offline-322-A-0...`, new issuer, and independent bank environment. Complete native read, propose local scripted send_money, execute standard native #209 two-arm diagnostic fork, obtain two terminal messages and two local Native AgentDojo scorings.
2. Independently start B source from initial provider-shaped request 0 using `offline-322-B-0...`, a distinct signed date issuer context, a *fresh* deep bank clone from the same pinned initial injection state, a different SDK/MockTransport, and fresh native read/proposal/terminal scorer evidence.
3. Select **A diagnostic arm only from source A**, **B diagnostic arm only from source B**. Require each selected terminal state and detached scorer bind to its own complete source history. Their model response IDs, root issuers, capture journals and terminal histories must differ. Their first request **body** should be equal because the research case/user prompt/model and tool schemas are identical.
4. The *other* diagnostic arm from each internal #209 A/B fork remains available in evidence as a **shadow**, and is NOT counted as an independent cross-origin A/B measurement. Hence 10 local SDK requests, four native scorer invocations, **two selected independent-source simulated arm scores**, zero real model inference.

**Bounded important limitation:** Existing native #209 is itself a paired-control implementation: **each individual source internally replays one local candidate to both diagnostic arms**. This new PR DOES NOT alter that invariant or expose a ready-to-send genuine Provider A/B runner. It proves the two selected *source roots* are fresh and link to their own terminal native scores. A later approved genuine research run still requires a thoroughly validated one-arm-per-source Provider path with explicit request/usage/no-resend constraints.

Expected selected simulated values: A Utility true, B Utility true; injection-task-0 goal false for both. These expected local scripted outcomes **do not** establish restored Utility on a genuinely sampled model or validated Final128 test.

## Evidence and stop conditions

- Frozen source Git blobs and complete JSON contract include **no old-provider authorization reuse**.
- Dedicated workflow is `pull_request`/main push only, **not** `workflow_dispatch` or `pull_request_target`, has no Provider Environment, imports **zero Environment Secrets**, and installs pinned external native versions.
- Original A/B source session rows record actual serialized SDK requests, distinct local mocked response IDs, full per-source trajectory journals, exact pinned lower-trust native injection, true local bank pre- and post-state, both terminal histories, and post-only native scorer records.
- Read-only auditor rejects swapped/duplicate roots, rewritten trusted user/date, attack promoted from lower-trust tool result, reused mocked response IDs, tampered native effect, altered scorer results, incomplete terminal and falsely asserted real-model claims.
- JUnit, independent audit JSON, full JSONL, and Artifact ZIP SHA-256 must match exact PR HEAD. **CI green ≠ production authority and ≠ real-model PROVEN**.

The separated model-session roots are a research test affordance; still missing are an actual bounded production credential sender, real OpenAI A/B responses from first request, complete true model terminal outputs and exact permission to spend money.

## Review disposition

Keep **Draft** until exact PR HEAD dedicated and standard workflows succeed and complete artifact is independently verified. After merge, DO NOT launch paid API calls. The operator must separately approve a fresh exact real provider research experiment scope and expense; GitHub Environment settings alone do not grant it.

Related: [Issue #321](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321).
