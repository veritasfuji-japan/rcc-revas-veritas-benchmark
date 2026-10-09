# TASK15_CANONICAL_ENROLLMENT_GAP_PREFLIGHT_V1

**Status:** Implemented / NOT PROVEN until exact-HEAD dedicated CI and Artifact review.

## Central invariant

The pinned AgentDojo suite must resolve all **eight** Task15 members of
the frozen **128-case** banking/direct enrollment, while refusing any
attempt to treat the already-proven **local offline synthetic**
`banking:user_task_15:refund-design-v1` trajectory as one of those
canonical, score-eligible executions.

A roster is not an executed case. A valid model-output schema is not an
authenticated model completion. In particular, changing only the case ID
does **not** authenticate the original direct attack payload, provider
response, independently generated A-arm candidates, or benchmark result.

## Sources and exact scope

- Freeze: `contracts/AGENTDOJO_INJECTION_ENROLLMENT_FREEZE_v0.1.json`
- Native scorer freeze:
  `contracts/AGENTDOJO_NATIVE_SCORER_FREEZE_v0.1.json`
- AgentDojo pinned commit `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`
- Banking v1.2.2, native `get_user_task_by_id("user_task_15")`,
  `get_injection_task_by_id("injection_task_N")` for N=0,1,2,3,4,5,6,8
- Exact direct attack template `TODO: {goal}`
- Source projection: PR #256 exact A/B final output and 6 native tool
  calls; paired source native model history: PR #255, original B-only
  candidate generation.
- No modification to any earlier RCC, Bind, execution or scorer source.

The preflight emits each of the eight exact case IDs and a machine-readable
list of unclosed requirements, including actual direct injection payload
and source provenance, independent A-arm candidate generation, authenticated
provider responses and genuinely case-bound post-execution native scoring.

## Refusal tests

Reject changed enrollment membership, duplicate IDs, denominator reduction,
different attack template, wrong AgentDojo pin, wrong suite, open gate,
changed scorer method, runtime gold leakage, a falsely eligible local
projection, a substituted original instruction, modified scorer input, a
forged paired source, or a local-case relabel into an enrolled case ID.

## Nonclaims

- **Zero** actual OpenAI provider calls or benchmark scorer invocations.
- **Zero** new native tool dispatches, permits, side effects or retries.
- **No** canonical Task15 case has been executed by this preflight.
- **No** Task15 utility/security score, Final128 Utility recovery, or
  real external-bank effect is asserted.
- This does **not** open the frozen gate or reuse the V10 single-use
  authorization.

## Evidence gate

Replay full #256 predecessor proof chain (2,337 prior tests), run 15
new checks (1 native roster positive + 14 refusals), verify exact source
blobs and validate evidence Artifact by exact run, job, HEAD and digest.

Do not merge on CI green alone.
