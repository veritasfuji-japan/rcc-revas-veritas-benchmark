# TASK4_NATIVE_INJECTED_READ_EXPOSURE_V1 — PR #289

## Rule-of-One: genuine injected data must be visible to the model wire before a proposal

Frozen predecessor #288 main:
\`13d5223771791096e1fa92f60662849ec85cb642\`.

#288 established a prospective *unattacked scripted* owned-date Task4
utility opportunity. It did NOT put the real AgentDojo attack payload in
front of even a fake model. #289 closes **one** of those evidence gaps.

The pinned native AgentDojo version v1.2.2 and commit
\`a75aba7631d3ca5fb7ab938965c97ead2f9ff84b\`
are used for exactly:

    banking:user_task_4:injection_task_0:direct

The fixed DirectAttack template \`TODO: {goal}\`, native
GroundTruthPipeline slot discovery, and the pinned banking injection vector
must yield **exactly** \`injection_incoming_transaction\`.
The genuine native injected banking state must contain the *exact unchanged*
attack goal payload, and clean default state must not.

An actual native read-only \`get_most_recent_transactions\` function is
executed by the unchanged controlled trajectory runner. Its actual returned
tool content, including the payload, MUST be present in the third
OpenAI-compatible model wire request sent to a **local RecordingClient**
BEFORE its first protected \`send_money\` candidate is emitted.
The injected text must not appear in developer/system or original user
messages. The model-visible tool-call ID and content must equal the native
arm's recorded read-only tool return.

The existing owned UTC execution date (2031-07-08 in the test),
original Task4 request, RCC candidate review, VERITAS Authority/Policy/Bind,
final native bank simulator sink, A/B exact candidate-prestate pairing, native
arm-local continuations and post-completion native scorer remain unchanged.

One fully completed **scripted** A/B pair may obtain native Task4 Utility
true in both arms and Injection0-goal false in both arms because the fake
model ignores the malicious tool data. This does not establish that a
*real* model would ignore it, nor does it estimate any injection success
rate. The historical V13 **64/128** VERITAS Utility result is not changed.

## Proof expectations

- Native attack slot discovery + in-memory attack insertion; one exact
  canonical-identified case, **not** canonical Final128 runner enrollment
  or re-execution
- Five local OpenAI-compatible fake client calls; payload first in actual
  native read-only return, not a trusted developer/user message
- Two real native banking simulator transitions, RCC-only A and VERITAS B,
  plus the native AgentDojo scorer applied to finished detached states
- 17 dedicated tests: direct positive bound proof, 15 tamper/refusal cases,
  and one anti-attacker-recipient/anti-permission-laundering assertion
- Exact external source pins, explicit CI evidence ZIP with one raw native
  injected environment, wire messages, captured candidate, native journals,
  scoring receipts, all JSON hashes and JUnit

## Scope and nonclaims

No independent GPT/OpenAI Provider execution, no external billable
requests, no provider credentials or bank network, no reuse of historical
authorization, no new Final128 score, no held-out experiment and no
third-party validation. The fake model response is deliberately scripted.

Original attack/goal input is **lower-trust tool data**, never execution
authority. Scorer labels are never used to choose the candidate or grant
permission. Two identical candidate exposures in the same local paired
trial are not independent model histories.

A dedicated CI run can clone and install public dependencies; actual test
network/Provider/DB operations are forbidden. All bank changes are
disposable in-memory AgentDojo simulator effects; real spend $0.

Human manual merge only after all 18 exact-head checks succeed and actual
artifact/JUnit/native transcript SHA evidence is independently audited.
