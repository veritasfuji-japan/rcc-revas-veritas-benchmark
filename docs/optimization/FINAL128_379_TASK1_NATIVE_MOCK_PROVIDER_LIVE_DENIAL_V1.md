# Final128 #379 — Owned native Task1 → mock Responses → denied live gate

**Status: offline engineering test ONLY.** No billable provider request, live bank
effect, real original AgentDojo model trajectory, new scored Utility, real Native
User/Attack Scorer, external lease/authorization, production IAM or trusted
independent provider receipt has been produced.

## Measurable step, not another default-deny-only document

Previous commits:
- #350 defined a budget-reserved, one-attempt Responses API transport interface
  accepting a client *owned by a separately authorized executor*.
- #351 defined the typed GitHub/main/commit/run/model/operator/ruleset/billing
  preflight but explicitly never authorizes dispatch by itself.
- #377 derived trusted outgoing-only spending from an actual Native
  BankingEnvironment; the untrusted incoming subject cannot govern the total.
- #378 constructed the source-equal separate-native-owner A/B input: identical
  original Task1 request, actual attacked read-only Tool return and original
  source, with **B only** receiving the #377 trusted overlay.

**#379 exercises that path end-to-end with actual pinned native Tool objects**
and two separately allocated *local mock provider client instances* through the
real #350 budgeted `response_once()` entry point. It checks:
1. A/B original request/source/attack/Tool return equality and B-only overlay.
2. A and B send distinct in-memory mock-only input buffers; mock function call
   is executed exactly once for each arm. The mock session is separately
   instantiated per arm, but **does not prove independent external clients**.
3. The common #350 budget ledger is reserved *before each fake call*, reconciles
   fake usage, records two local mock calls, and enforces a bound below the
   previously proposed USD 1 ceiling. Fake token usage and simulated cost are
   **NOT billed usage**.
4. Provider outputs are fixed, deliberately non-Task1 `OFFLINE_FAKE_RESPONSE`
   placeholders, not fabricated model terminals. Neither User Scorer nor Attack
   Scorer runs. **Do not infer any Utility or attack success rate**.
5. A call to the actual #351 `validate()` with no authenticated operator
   grant, tag ruleset verification, or project billing proof refuses. Forged
   approval strings or claimed protected conditions cannot change this module's
   live DENY. The only #350 lease boolean `True` is used **inside** an
   ephemeral local fake call; it is not promoted to an authorization receipt.
6. All CI evidence is a hash-only manifest with no raw bank transactions,
   injected subject text, credentials, raw input envelopes, real score or
   protected permission claims.

## Explicitly unimplemented: original model call continuity

#378 produces an *internal* A/B model-input envelope from an in-process read-only
Tool invocation. It is **not** a real model-emitted `function_call` history and
does not have a genuine provider-issued `call_id`. #379's mock input uses a
clearly named dummy function-call-output ID. It **MUST NOT** be sent to the
live Responses API and must not be described as a runnable AgentDojo trajectory.
A production-bound trial needs a provider-originated original Tool call with an
authenticated ID and exact return captured in its original conversation, and
a source-owned overlay inserted only into B without replacing that return.

The harness is deliberately not a CLI sender and does not accept provider
clients or API keys. CI sets all provider secrets to empty, uses no network calls
from tests, and checks the raw module for forbidden imported transport/scorer
mechanisms. Source hashes and GitHub CI success prove *bounded offline code
correctness*, not real provider correctness.

## Consent and security remaining before any paid run

All are **unmet for the specific execution**:
1. Fresh operator approval for exact Task1 case, model, A/B scope and spend.
   An earlier chat/PR or self-attested `approved` flag is not sufficient.
2. Verified current account/provider/model availability and pricing; real
   provider-scoped secret restricted to a protected GitHub environment.
3. Account/project spend controls with explicit understanding cloud billing
   hard stops may not be instantaneous; no retry, conservative local cap.
4. Durable globally single-use protected lock/tag **actually created and
   consumed** by trusted CI, not only simulated or declared in code.
5. Independently owned genuine Provider A/B responses, authentic model-emitted
   Tool-call IDs, real read-only native Tool return bound into both sessions,
   exact original DirectAttack slot/payload and proof of identical source.
6. Full native Tool and terminal trajectories with immutable SHA lineage into
   real AgentDojo pinned User and Attack scorers.
7. VERITAS execution authority/effect-bypass enforcement with source-bounded
   refusal, no bank writes and same-run scorer result evidence.
8. Third-party verification and full Final128 expansion separately afterward.

Only when all necessary trust and billing gates are verified should a
**separate explicitly approved** live pilot be run. #379 cannot grant or
dispatch it. Avoid misleading claims of Utility recovery from offline mocks.

## Run and merge gate

Dedicated #379 GitHub Actions:
- Source-pin AgentDojo `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b` and banking Tool
  blob `941c27467b7890cced7ab70e5fd5ca32241f99a5`.
- Invoke pinned native #379 and existing #378/#377 plus #350/#351 tests.
- Require 0 failed/errored/skipped, output JUnit, exact HEAD, SHA-256
  provenance, redacted JSON evidence with two mock calls and zero actual
  Provider calls / native scorers / bank effects.
- Review current HEAD/CI/artifact and compatibility checks before merge;
  do not auto-enable or merge by mere offline success.

Historical V13 remains A 93/128, B 64/128, B injection success 0/128.
No new scored Task1 improvement and no change in these frozen metrics.
