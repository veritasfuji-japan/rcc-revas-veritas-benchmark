# Task4 #364 — Prospective live A/B research preflight (default DENY)

## Purpose
Prepare a **new** prospective independently generated A/B research run from
the **first** model request, with the trusted test date context issued
**before** candidate generation. It must not re-label historical third-turn
real `send_money` proposals as newly authorized.

## What already exists
#294/#300 captured genuine real-model A/B first through third responses.
#318 established that historical third responses end at tool-call proposals:
there is no genuine final assistant response or completed Native Scorer score.
#323/#363 proved independent **scripted** origins and exact SDK/Native/scorer
lineage; this does not establish independent genuine LLM terminal Utility.
#326 gives strict local wire-byte/BPE gates but not authoritative billed tokens.
#308 rehearsed SQLite one-use collision behavior but not protected distributed
permission consumption.

## Proposed research-only scope (not permission)
One canonical Task4 DirectAttack case, two separately sourced arms, exact
`gpt-4.1-mini-2025-04-14`, at most 5 attempted requests per arm and 10
total, max 256 completion tokens per attempt, local raw JSON <=10000 bytes
and local BPE <=10000. A planning-only USD 0.50 target is **not** a
provider-side hard spending cap and is **not approved**. Actual model
billing, availability and cost must be rechecked. Abort if any hard bound
cannot be established or a source/continuation becomes ambiguous.
No automatic retry, including timeouts and unknown outcomes.

All banking execution must remain isolated, disposable in-memory simulation;
no real bank network, real credentials or production authority. The actual
Native Bind and detached Native Scorer must be used only with original
same-arm, same-session model responses and the prospectively issued context.

## Release gates
The nine gates in the JSON contract are **NOT_ATTESTED** or **NOT_GRANTED**.
A future reviewed sender must prove secret isolation from untrusted PR/fork
content, one-use consumption before POST, no retry on ambiguity, independent
receipt/usage binding, current provider availability/pricing and independently
attributable terminal Native scoring. Fresh explicit owner approval must
specify case, model, max calls, tokens, expiry, maximum spend and stop rules.

## Current outcome
This PR adds only JSON, a read-only validator, adversarial unit tests, and
a pull_request-only GitHub workflow with no Environment, Provider secret,
workflow_dispatch, network sender or authority issuer. Every gate stays
unmet. **REAL_PROVIDER_DISPATCH=DENY** and **authorized spend=0**.

A green CI proves that the planning contract remains fail-closed. It does
not prove the proposed experiment can safely or economically run.
