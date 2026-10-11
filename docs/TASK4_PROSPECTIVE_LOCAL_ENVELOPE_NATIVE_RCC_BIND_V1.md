# PR #305 — ONE issuer / ONE synthetic completion / native RCC & VERITAS Bind

**Rule of One:** Show that one **new prospective**, harness-owned date issued
*before* a model-compatible wire is built is the **same** context used to
capture the single local fake tool proposal, and to pass that exact candidate
and full original native state through RCC and the pinned actual VERITAS Bind.

No real model call, billing, scoring or bank effect is authorized.

## Why a separate full-state adapter is required

PR #303's \`ProspectiveWireBoundary\` and #304's
\`OfflineCompletionBridge\` are intentionally locked to a small synthetic
\`fixture_prestate()\`. PR #302's native Task4 runner instead works with the
**full AgentDojo environment**. They cannot be directly composed by
exchanging their separate session HMACs: doing so would mean generating
different authorization contexts, or replacing trusted state without
authorization.

For #305 the bridge is therefore additive and deliberately narrow:

- Unchanged #208 \`Task4ControlledDateRunner.prepare()\` issues **one**
  signed, 5-minute harness-controlled date before calling our single
  trusted local generator. The generator sees only date, original request
  and detached **full** native prestate, not signer/key/issuer.
- Full native state is rebuilt from pinned AgentDojo injected Task4 fixture
  \`banking:user_task_4:injection_task_0:direct\`, SHA pinned, **never
  inferred from the lower-trust incoming subject**.
- A model-compatible but **unsent** wire is frozen inside the generator.
  Real injection text is present only as the tool-result role, not a
  privileged developer instruction or a new user request.
- One explicitly fake completion is assembled locally, #304's strict
  duplicate-key/non-finite JSON parser and synthetic response schema rules
  are reused with the issuer's **actual context digest** in local
  correlation. The full-state adapter does **not** pretend to call #304's
  fixture-bound \`OfflineCompletionBridge.receive_once\`; no fresh
  authorization is minted to force compatibility.
- The generator returns one native RCC \`CandidateAction\`.
  The unchanged \`runner.prepare()\` uses native Pydantic normalization,
  immutable paired capture and that **same** date session/prestate.
- \`runner.replay_arm()\` drives the existing native RCC review on both
  identical candidates; Arm B executes the **actual pinned VERITAS Bind**
  with final sink validations, receipt and in-memory AgentDojo mutation.
  Arm A remains the RCC-only comparison baseline; it does not claim
  a VERITAS Bind ALLOW.

## Positive observation and constraints

Expected: A and B each COMMITTED into **separate disposable Python
environment copies** under trusted test fixtures. B's receipt must show
COMMITTED from actual native Bind. Same full prestate hash, candidate hash,
date-context pairing identity and resultant poststate must match; the
original trusted environment never mutates. The original non-integrated
Task4 resolver must still fail closed for the unsupported date authority.

These are not live bank operations. Signed repository benchmark fixtures
and an artificial 2031 UTC harness clock are **not** production auth or
physical-clock attestation.

## Fail-closed cases

Malformed or forged local response, cross-session correlation, changed
model/tool/role, multiple calls, duplicate keys, non-finite numbers,
misbound recipient/amount/date, and replay must refuse.

For a syntactically valid but unauthorized candidate the **B** arm must
reject before native Apply, with unchanged pre/post state; the **A**
baseline is *not* run for malicious variants. RCC refusal must block before
Bind; lack of benchmark authority, expiry and Bind refusal must not
dispatch a simulated mutation.

No Provider credentials, network calls, scoring, Final128, real bank
writes, or persistent TrustLog writes are allowed in CI.

## Proof limit / merger conditions

Only the end-to-end **local fake completion → synthetic native simulator**
path is tested. This does not prove actual model utility, Provider reply
authentication, general injection resistance or production live IAM
bypass resistance. Prior genuine third-run replies remain BLOCKED;
the consumed tag must not be reused or rewritten.

**DRAFT — do not merge** until the exact PR head passes the dedicated
offline CI and existing PR checks, with independently inspected JUnit,
report, artifact and SHA evidence.
