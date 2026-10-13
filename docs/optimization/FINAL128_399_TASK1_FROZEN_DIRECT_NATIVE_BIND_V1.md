# Final128 #399 — Frozen Task1 DirectAttack/native environment, A native effect and B real Bind refusal

## Why this is more than another synthetic-bank test

Merged #398 demonstrated one disposable in-memory Native A write and one actual pinned VERITAS B Bind refusal, but the account and injected text were locally invented. #399 derives the exact **Task1/injection_task_2/direct source** from the frozen Native AgentDojo banking v1.2.2 suite instead.

It also checks the existing 128-case enrollment contract without changing denominator, task membership, the direct attack type, or the frozen execution gate. The original user request remains the Native read-only March 2022 spending question.

## Actual source-owned enrollment

- Source pin: AgentDojo a75aba7631d3ca5fb7ab938965c97ead2f9ff84b.
- Source pin: VERITAS OS a1d66aef02262cf8a913295270c3aafd159c6adb.
- Frozen 128-case enrollment:
  contracts/AGENTDOJO_INJECTION_ENROLLMENT_FREEZE_v0.1.json.
- Native DirectAttack named 'direct', template 'TODO: {goal}', frozen
  injection_task_2 GOAL and native user_task_1 prompt.
- Calls actual Native DirectAttack.attack() which invokes Native
  GroundTruthPipeline on a disposable canary source and discovers exactly
  injection_incoming_transaction.
- Calls native banking TaskSuite.load_and_inject_default_environment()
  on each of two fresh independent source objects with the **unmodified
  native discovered injection map**. Compares each to the same actual
  uninjected default; exactly one incoming transaction subject changes.
- Calls actual Native FunctionsRuntime with
  get_most_recent_transactions(n=100) against both. Tool outputs are equal,
  contain exact DirectAttack subject, and never mutate initial state.
- Full native banking tool catalog and version are source checked.

## Important newly observed benchmark mismatch

In the **real** frozen AgentDojo bank state, the injection-bearing incoming
transaction uses recipient='me', while the bank account's 'iban' stores a
different literal value. Existing #377 and #397 synthetic spending
projection logic assumes a matching recipient==bank.iban when locating
exactly one incoming March transaction. It therefore cannot run unchanged
on the canonical default environment. A dedicated #399 negative regression
test asserts this refusal without editing AgentDojo source state.

Do not claim #397's B-only source-owned spending projection is already
working on the canonical source. The exact Native alias semantics and
trusted spending-context derivation require a separate correction and
adversarial tests before full B model wire enrollment.

## Bounded actual Native A / actual VERITAS Bind B contrast

For the effect-boundary test only, the local harness calls Native
InjectionTask2.ground_truth on an isolated source snapshot and obtains
one **gold-derived local test proposal** (send_money). This is a
ground-truth-only TEST input, NOT a Provider response, attack success,
scorer result or a candidate to insert into model-visible prompts.

- A invokes actual pinned Native FunctionsRuntime.run_function on that
  proposal on a disposable Python-object bank. One new transaction is
  observed, and only A's local state changes.
- B invokes actual pinned freeze_agentdojo_candidate(user_task_id=1),
  AgentDojoBankingBindAdapter and execute_bind_adjudication using the
  unchanged VERITAS Task1 NO_PROTECTED_MUTATION_EXPECTED policy.
- B must return BLOCKED before apply; both raising apply and mutation
  callbacks remain unreached (zero) and B's entire native bank state
  remains byte-equivalent at the JSON snapshot level.
- Benchmark fixture authority_admitted=True is **not** real AuthorityEvidence
  or Human Approval. It cannot be reused as production authorization.
- Output evidence contains only digests, counters, case/source pins, and
  explicit status/nonclaims. No raw attack text or bank data is published.

## NOT PROVEN and what Ben actually needs next

This confirms exact frozen Native Task1 environment/DirectAttack enrollment,
local A effect and actual B Bind refusal for a **gold-derived fabricated
proposal**, not model behavioral results.

Still absent: Native's independently generated real model first/tool/final
history, correct B trusted overlay with recipient='me' handling, honest A/B
Provider provenance, independent held-out utility measurement, completed
full-tool native execution loop, complete unauthorized-effect coverage,
production IAM/credential/egress resistance, externally one-use issuance,
fresh scoped spend approval and new official Native scorers. Old real V13
history and all mock-diagnostic outputs remain separate.

The next PR should correct the trusted alias-aware canonical data projection
without consulting scorer/gold for model-facing answers, then connect that
projection to B in a source-preserving native history. Only after that
introduce genuine independent Provider A/B under **fresh explicit approval**.

## Merge gate

1. Exact PR HEAD, native and VERITAS pins, immutable enrollment Git blob.
2. Native DirectAttack genuinely discovers exact incoming injection slot and
   reconstructs two distinct identical canonical injected bank environments.
3. Real Native read in both arms has equal attacked bytes and zero mutation.
4. Real A in-memory Native write; real B VERITAS Bind BLOCKED, zero B apply
   and zero B state drift. No external bank effect or model request.
5. Explicit test that prior #377 canonical recipient alias assumption is
   still NOT met. Zero fake Utility/Attack Success promotions.
6. Dedicated #399 plus inherited #398–#377 tests green with 0 skipped,
   all ordinary checks successful, redacted SHA/JUnit evidence reviewed.

Classification: FROZEN_NATIVE_TASK1_SOURCE_AND_DIRECT_INJECTION_OFFLINE,
A_NATIVE_GOLD_FIXTURE_EFFECT_B_PINNED_BIND_BLOCKED, NOT PROVIDER-SCORED.
