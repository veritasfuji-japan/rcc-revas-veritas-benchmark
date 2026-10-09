# TASK15_INDEPENDENT_AB_THREE_STEP_OFFLINE_NATIVE_HISTORY_V1

**Status: IMPLEMENTED / NOT PROVEN pending exact-HEAD CI and independently inspected artifact.**

## Rule-of-One

Two independent **logical** Task15 A/B synthetic model source sessions must each perform **three** native-format candidate queries, and after each local governed native operation, the same session's **own actual native return** must be the source context of the subsequent query. Distinct injected clients and independently owned runner objects are compulsory. Six global call IDs are unique. Cross-arm reuse, forged previous native results, failed transport or replay must refuse the combined proof.

## Exact interpretation of physical versus logical arms

The prior controlled comparison runner executes its own *physical* local A/B pair from the **same candidate**, with subsequent model queries sourced from its B subarm. This PR does **not** modify that frozen control design. Instead it instantiates **two separate** bounded local comparison runners, one under logical arm A and one under logical arm B. The synthetic model candidates for logical A are generated independently from the logical B candidate source using a different offline client and a distinct governed-local sandbox. Each of those two isolated sessions binds new candidates to its own native local effect and feeds back its own B-subarm native return.

The execution involves two logical model source histories, each with three distinct source queries and two inter-query native return links. Total: **six model-source queries, four next-query native-return links, and twelve local protected native operations** (two local physical comparison subarms per independent logical session). All twelve operations take place exclusively in isolated local in-memory banking state under frozen synthetic fixtures. **Zero real bank/external effects.**

## Guardrails and limitations

- Exact noncanonical fixture: `banking:user_task_15:refund-design-v1` only.
- Retains the original frozen same-candidate attribution harness, #259 injection slot proof and #260 first-candidate proof unchanged.
- Uses the pinned native AgentDojo OpenAI codec, Task15 source history implementation and unchanged local RCC/Bind/native runner.
- Every candidate is bound to the completed native step of its own source session; subsequent source query is checked against that session's own immutable call IDs and native returns.
- Failed logical arm B does not erase logical arm A's already committed local effects or manufacture a paired output. No retry, rollback or NO_EFFECT claim.
- API keys empty; actual provider calls 0, actual native AgentDojo scorer calls 0, new live effects 0.
- **No provider response authenticity, independent real-model computation, full canonical Final128 enrollment, real-provider Utility, Injection Success, production deployment or global deduplication proof.** No prior V10/V13 approval may be reused for a live call.

## Evidence gates

Exact merged main base after #260:
`7d6487b71b799994eb5931c8b9853345322b0c86`.

The new dedicated CI replays #260 predecessor audit (2,397 prior tests, including the #259 chain) and requires: exactly 15 new tests, one positive evidence record, 14 distinct refusal records, six globally unique offline source tool-call IDs, matching equal initial state hashes, four prior-native feedback links, distinct offline clients/runners, exactly 12 **local** sink dispatches and zero provider/scorer/real external-effect claims.

Manual merge only after exact-HEAD success, job/run identity, artifact download, ZIP digest verification and direct inspection of new positive/refusal/JUnit data. **CI green alone is not PROVEN.**

## Later work

Bridge these genuine independent offline source histories into each of the eight **native canonical Task15 DirectAttack environments**, then extend the proof across all 128 canonical cases and provider-authenticated scoring when explicitly authorized. Treat this as a separate scope and proof round.
