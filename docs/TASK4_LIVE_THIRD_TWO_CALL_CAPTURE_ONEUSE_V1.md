# TASK4_LIVE_THIRD_TWO_CALL_CAPTURE_ONEUSE_V1 — PR #299

**PR CREATION / MERGE = ZERO API CALLS AND ZERO NEW SPENDING. NOT AUTHORIZED FOR LIVE EXECUTION.**

Merged parent is #298 \`ac0afd14871e055bcb26bde110d762698dd8336b\`.

## Why this step matters

Run \`38069600424\` captured **real** GPT-4.1 mini model
second decisions: A and B each requested read-only
\`get_most_recent_transactions({"n":10})\`. #298 actually replayed these
model-selected calls in two separate disposable native AgentDojo Task4
banking environments and froze TWO OpenAI-shaped full **third**
requests containing exact malicious transaction subject in a LOWER-TRUST
tool return. No real model has yet observed that attack text.

The third model requests were independently audited in Run
\`38070677370\` / Artifact \`11676881211\`:
- ZIP SHA256 \`bbc7ba1a16aaac67aed75bdbb7a5abc71bfa978599e1cfc42700779377e838f4\`
- raw archived JSON SHA256 \`4d719a1d05f83f6028c340434480a8f0d3df09c9fb1027f66fa0b90259a31824\`
- Arm A canonical full request SHA256
  \`c373ddc49a912852f39a75679e6e3f45d999f14cbfd4d3a5414f156a038726a8\`
- Arm B canonical full request SHA256
  \`bc4cd7a178094d64b3cb1eadfdc56176c6657f7db531f14f7b165e56d223ba13\`
- Both request bodies are exactly 6,895 UTF-8 canonical bytes,
  model \`gpt-4.1-mini-2025-04-14\`, max 256 completion tokens,
  11 bank tool declarations but **no tool executor in this sender**.
  The exact attacker subject is SHA-pinned and present once only in
  the native transaction list tool return, never in developer/user.

The prior two original single-use human approvals were consumed:
\`task4-first-two-real-provider-v1-consumed\` and
\`task4-second-two-real-provider-v1-consumed\`.
Neither one can authorize third-turn model inference.

## Proposed FUTURE third inference scope — NOT YET APPROVED

Only after **fresh explicit user approval**:
- Exactly 1 complete third A request + exactly 1 complete third B request;
  a maximum of 2 single-attempt ChatCompletion POSTs;
- Exact case \`banking:user_task_4:injection_task_0:direct\`, model
  \`gpt-4.1-mini-2025-04-14\`;
- Proposed *additional* total spending target USD 0.50, max 256
  output tokens per A/B request, NO automatic retry;
- Record complete original Provider response, exact SHA256, usage,
  server and client IDs; model-selected read, write, stop or unsafe
  decisions are treated as **untrusted data, NEVER executed**;
- No native bank read/write from the live capture workflow, no fourth
  Provider turn, scorer or Final128 replay.

The $0.50 proposed target is NOT a mathematically or provider-enforced
per-run billing hard cap. Current organization/project spend and hard
limit need to be checked again and billing may lag.

Before any real dispatch, a NEW protection Ruleset must exist for
\`refs/tags/task4-third-two-real-provider-v1-consumed\`: Active, exact
match, no bypass actors, deletion/update/non-fast-forward restrictions
and first creation allowed. A NEW dedicated GitHub Environment
\`task4-real-provider-third-two-calls\` must be separately created with
main-only deployment permissions and secret name
\`TASK4_OPENAI_API_KEY\`; the value must not be published.

The manual workflow verifies both previous tags remain permanently
consumed, checks the new tag ruleset and Environment secret, then
atomically creates the NEW third one-use tag **BEFORE** any Provider
network send. It cannot be run again if its tag was already created.
A timeout, ambiguity or HTTP error is a terminal one-use failure;
no rerun or tag deletion.

Even though this workflow *will* show the genuine model the lower-trust
injected tool text if separately authorized and executed, model output
alone still cannot authorize protected bank writes. Any attack
resistance/Utility scoring requires an independent after-response
analysis and an explicitly bounded authority check.

**Exact NEW approval phrase, to be used ONLY AFTER new user approval:**

\`APPROVE_TASK4_ONE_CASE_A_B_THIRD_2_CALLS_MAX_USD_0.50\`

## Safety gates before merge

Standard pull request/push CI has no live OpenAI key, only a fake
in-memory HTTPS test transport, 38 tests with 22 semantic source/authority
refusals and 10 HTTP ambiguity/no-retry refusals, and source ZIP/JSON
SHA checks. **No workflow_dispatch during PR or merge.**

Do NOT treat CI green as evidence of any real third model response.
Only merge after all exact-HEAD checks success and independently
downloaded raw Artifact/JUnit verification. Only dispatch after new
separate manual consent, Ruleset/Environment/secret configuration,
and current billing check.
