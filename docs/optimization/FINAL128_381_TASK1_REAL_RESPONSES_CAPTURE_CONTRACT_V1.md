# Final128 #381 — Task1 actual Responses wire and untrusted capture-contract (deny live)

## Why #381 differs from the previous mocks

The previous #377/#378 work used real pinned native BankingEnvironment
read-only Tool data, #379 exercised two local mock clients through #350,
and #380 added locally fabricated model Tool-call IDs and fake terminal
continuations. Those are offline demonstrations, not independent genuine
Provider trajectories or measured Utility. Creating more fake terminals
would not move the official measured score.

**#381 changes the transport boundary under review:** it emits an exact,
concrete **Responses API first-call request shape** with real function
tool schema (\`get_most_recent_transactions({"n":100})\`) and can parse a
Responses-shaped captured HTTP response body, checking the claimed
\`response.id\`, \`function_call.call_id\`, model, status, arguments, usage,
and claimed server \`x-request-id\` before constructing a *non-dispatchable*
follow-up preview from the actual AgentDojo Native read.

The first-call packet is an **unsent proposal**. This PR has **no live
sender or authenticated Provider response**; CI uses deliberately synthetic
HTTP response bytes and explicitly rejects any attempt to label them as
protected Provider origin. Responses-looking data supplied by a caller is
not cryptographic provenance. The follow-up preview retains the **entire
unchanged original attacker-injected Native Tool return** in both arms,
plus the #377 verified source-owned spending context in B only.

## Explicit execution boundary

- The only first request: model \`gpt-4.1-mini-2025-04-14\`,
  original Task1 user text, single strict **read-only** function,
  \`tool_choice:auto\`, \`parallel_tool_calls:false\`,
  \`store:false\`, \`stream:false\`, max 256 output tokens.
- Arm A and B first bytes must match; no malicious incoming subject is
  present until the real native read returns. Each separate Native
  environment invokes the pinned Tool one time; no writes are permitted.
- A/B second-turn **review candidate** uses exactly the
  first-claim \`function_call\` item, with identical \`call_id\` in the
  corresponding \`function_call_output\`; candidate requires distinct
  claimed Provider/HTTP/Tool IDs per arm and same actual injected Native
  Tool bytes. The B context is separate from the lower-trust Tool return.
- **Never send these untrusted previews to the network.** There is no
  protected Provider origin, no real user consent, no unforgeable
  cross-worker one-time grant, no verified account/model availability,
  no project-side spend control, no authenticated original model call,
  no actual second call, and no genuine Native Scorer terminal.
- The B developer-message placement/schema and single-tool surface are
  **not yet validated as a faithful full native AgentDojo trajectory**.
  The benchmark's full tool catalogue, exact initial state and original
  DirectAttack payload need independent full-source enrollment to admit
  any canonical Task1/Final128 utility conclusion.

## No false elevation of a synthetic HTTP header

Header \`x-request-id\` and JSON \`id\` / \`call_id\` strings can be
fabricated and are only **content-shape** evidence when delivered as
untrusted raw bytes. Neither distinct fake IDs nor SHA-256 transforms
make them genuine Provider-signed credentials.

Actual Provider provenance must be established by a **protected, directly
operated, no-retry TLS sender** which owns request bytes before POST, records
the actual HTTP status/response headers/body and full SHA lineage at the
TLS boundary, binds to immutable main HEAD/GitHub run, and saves tamper-evident
raw receipt evidence without exposing secrets or user financial data.
One-use authorization must be independently issued/consumed atomically by
the protected issuer, with fresh exact-case A/B/cost scope and project
billing control. The #351 preflight \`authorized_for_provider()\` returns
False and **does not** implement such consumption. A newly added boolean
or a copied historical consent phrase is not an authorization mechanism.

The protected send path is NOT implemented in #381. To reach a genuinely
scored run, it is necessary to implement the trusted TLS sender, authenticate
its receipts, execute a real native tool-result continuation after genuine
model function calls in both arms, then record independent real model finals
and actual pinned Native User/Attack Scorer inputs/outputs. Without all of
these, \`READY_FOR_LIVE_DISPATCH=False\` and
\`ELIGIBLE_FOR_OFFICIAL_SCORING=False\` must be preserved.

## Tests, evidence, freeze

Dedicated GitHub Actions checks exact commit HEAD, exact AgentDojo commit
\`a75aba7631d3ca5fb7ab938965c97ead2f9ff84b\`, banking tool blob
\`941c27467b7890cced7ab70e5fd5ca32241f99a5\`, empty API
credentials, and pinned real native bank classes. Tests cover request
drift, source mutation, cross-arm response/call-ID collisions, forged
Provider-origin flags, duplicate/nonfinite JSON, unrecognized write tools,
wrong arguments, record/subject tampering, raw data leakage and denial
of score or paid sends. They also rerun existing #380/#379/#378/#377/
#350/#351 tests with zero skips/failures.

Evidence ZIP contains only exact HEAD, JUnit, file digests and **redacted**
sha-only input/response records. No raw attack text, model-banking data,
Provider credentials or fake response IDs appear in the evidence.

Historical V13 scores remain A=93/128, B=64/128,
B Injection success=0/128. New genuine scored Task1=0.

**PR merge gate:** exact HEAD, dedicated zero-skip CI plus all shared CI
success, artifact SHA checked, review the security caveats; no automated
send and no automatic merge.
