# Task4 #455 — Actual Native → OpenAI SDK research sender staging, HARD NO-GO

## What is actually integrated

This PR closes a specific source integration gap beyond #454: the **real pinned AgentDojo Native Task4 first model request**, issued under the same frozen local RCC/VERITAS setup used by #323, is serialized by the **real OpenAI Python SDK** and presented to a new narrow research wire transport that **cannot delegate to any network connection**. The first request for each independently prepared A and B arm is deliberately refused, before a Provider call, model reply, native protected effect, terminal continuation, or scorer.

Changes are isolated to four new files. No existing workflow, native policy, benchmark scorer, production key, Environment, Ruleset, tag, frozen proof or paid user grant changes.

- `scripts/task4_455_research_native_sender_hard_nogo_v1.py`: reusable Native→SDK staging point. `stage_paired_native_ab()` rebuilds two distinct native first-turn sources (A RCC, B RCC+VERITAS planned, **neither reaches the decision/dispatch step**). Frozen genuine SDK construction uses exactly `gpt-4.1-mini-2025-04-14`, the real on-wire request including tool schemas, `max_completion_tokens=256`, `temperature=0`, `max_retries=0`, `httpx.Client(transport=RejectingResearchWire(...), trust_env=False)`. The sole transport has no destination, network client, proxy or forwarding fallback. Its only method `handle_request` checks the pinned original request, suite, local test metadata, size/BPE and strictly refuses. A second attempt is rejected.
- `tests/test_task4_455_research_native_sender_hard_nogo_v1.py`: forbidden keys, forbidden send CLI, no retry, invalid wire consumption, static GitHub workflow non-privilege and full native pinned first-wire tests using blocked real sockets.
- `.github/workflows/task4-455-research-native-sdk-sender-deny.yml`: pull-request-only standard `ubuntu-24.04`, read-only GitHub token, `persist-credentials:false`, historical consumed tag check read-only, exact frozen AgentDojo/RCC/VERITAS checkout, pinned SDK `openai==1.109.1` and local BPE `tiktoken==0.12.0`. Zero production secrets and **no** `workflow_dispatch`, `push`, `environment:`, `id-token:write` or privileged GitHub ref write.
- This document is the review boundary.

## Explicit limitations

- **It does not yet send a genuine model request** or obtain any Provider response, tool continuation or official scorer input. Running this default-deny transport is not a completed genuine research Sender or a live readiness grant. The first SDK request must fail; the code intentionally cannot produce a fake assistant answer or execute a banking effect after denial. This is a narrow source-level bridge to be reviewed before a *separately authorized* genuine provider delivery implementation.
- The date `2031-07-08` is the frozen offline fixture, **not a real issuer date**. A new actual research run requires real pre-issued request/date/amount/recipient ownership before first inference; changing it after a blocked proposal is prohibited.
- The 10,000-byte and local BPE checks are deterministic local gates but are **not Provider-reported billable prompt token counts**, and do not guarantee dollar charges. The current OpenAI API account Project `VERITAS-Task4-Research` was owner-confirmed at $1/month enforced limit; project model listing does not demonstrate API access or an exact experiment spend ceiling.
- The sender uses a test-only sentinel API key with `httpx` local rejecting transport; actual Provider environment keys are rejected, not opened. There is no deployment Identity, external egress/IAM enforcement, durable cross-Runner one-use consumption, paid billing cap proof, externally signed receipt, or production Bank effect.
- **Issue #321 Task4 and Issue #427 Task1 remain OPEN / NO-GO.** No historical approvals reissued or inherited. Zero actual Provider calls, new authentic Utility scores, provider-backed injection outcomes or frozen Final128 changes. Existing V13 A=93/128 B=64/128 B injection 0/128 remains historical.

## Next necessary work before live trial

1. Review actual #455 Native first-wire preflight logs; verify the exact request bytes SHA and no model dispatch. Confirm the intended research case/owned pre-date requirements from independent sources, rather than promote the synthetic `2031` fixture.
2. Separately implement and review **real** protected research-only send transport / post-model native tool-result loop, honest terminal Scorer eligibility and evidence persistence; DO NOT simply remove #455's denial or expose its isolated fake transport to a Project API key. All secrets must remain inaccessible to untrusted PR/fork code. A test-only source denial is not independent production enforcement.
3. Validate exact model availability and usage limits for the isolated Project and scoped `Restricted` API key, an enforceable per-experiment call/UNKNOWN policy in addition to the screenshot-attested monthly $1 project hard limit, and test interruption/replay denial without paid calls.
4. Request **fresh explicit owner approval** of the **exact reviewed Run SHA**, target model, single case, independent A/B attempt limit, expiry, maximum USD and residual billing risks **only after** these preparations are independently verified. No paid inference is approved by this PR.

### Rule of One
Never fabricate final assistant text or native score from archived third-turn incomplete actual Provider proposals. The next useful Utility result needs complete same-origin genuine A/B model histories, one native selected arm per origin, unmodified VERITAS Bind and detached official native scoring.

Keep Draft pending latest-HEAD overall CI and dedicated #455 Native staging proof. CI success demonstrates a *refused source-level SDK interface*, not authentication or live authorization.
