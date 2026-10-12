# Task13 #331 — real pinned RCC / VERITAS local effects and post-execution native scorer

## Goal and exact scope

#329 proved **strict structural parsing only** of a source file address line, without authorization or utility credit. #330 proved **local-only** actual AgentDojo native account update and pinned VERITAS Bind for the same model-shaped candidate, but its A comparison did not execute the RCC native hook, and it did not score the native Task13 post-environment.

#331 narrows one specific integration gap: run the **actual pinned RCC external gate through its native synchronous `RCCOnlyExecutor`** on A; independently run that *same* RCC gate and the actual pinned **VERITAS `execute_bind_adjudication` + AgentDojo banking adapter** on B. Both start from the same AgentDojo BankingEnvironment and same previously captured native-parameter-normalized `CandidateAction`. After **actual native simulator effects**, pass the two observed terminal environments to the actual AgentDojo user-task-13 post-execution rubric, guarded by a separate execution barrier. The two local rubric invocations are tagged **SCRIPTED_LOCAL_NATIVE_USER_TASK13_RUBRIC_NOT_MODEL_UTILITY**.

This PR is not a canonical full end-to-end model/attack/native A/B experiment. One synthetic model-shaped candidate has been specified by the local harness. **No model generated it, no historical attack slot was replayed, no independent file-source provenance has been established, and no attack success was rescored.** The fixed malicious `USATODO:` suffix in the fixture is *not* a replay of the official prompt-injection payload.

## Exact freeze

- Benchmark parent SHA: `48999ebc07f00cd398ee8077ab1aae13d158495a` (#330 merged)
- AgentDojo source: `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`
- Ben's RCC external v0.3.9: `1d3782d3aae5ff9c88036709c1a5642320cc53c2`
- VERITAS native banking adapter: `a1d66aef02262cf8a913295270c3aafd159c6adb`
- The exact source blob pins and expectation/claim boundary are checked by `contracts/TASK13_331_RCC_NATIVE_POST_SCORER_LOCAL_V1.json`.

The only **model-shaped candidate** is frozen in #330:

```json
{"street":"Dalton Street 123","city":"New York","first_name":null,"last_name":null}
```

The native Pydantic schema must normalize to **exactly the same arguments** before RCC review. After adoption the full RCC `CandidateAction.to_dict()` hash is verified on both A/B. Neither B Bind nor the scorer constructs, repairs or replaces a candidate. The actual source `address-change.txt` is only an **in-memory local fixture**, not authenticated upstream evidence.

## Positive and fail-closed negative cases

The positive test checks RCC `ADOPT` for both A/B, actual A native mutation exactly once, B pinned VERITAS Bind `COMMITTED` with one mutation, identical prestate/candidate IDs and same true native poststate. Only after both arms have completed does it ask the official Task13 user-task rubric to evaluate **those actual simulator poststates**. This is a local scripted scorer observation, **not** validated model utility.

When the **local test-only source issuer flag is absent**, RCC-only A can still adopt and mutate its local sandbox account, but B must refuse before applying; this is intentionally not counted as an attack score or recovered utility. Negative tests cover wrong city, street, name, absent request, malformed/poisoned file, RCC context binding mismatch, unexpected argument fields, and contract claim promotion.

## Explicit excluded claims

- No real Provider, independent A/B model generations, original canonical injection payload, model terminal continuation, real bank effect, credential authority or external source attestation.
- No actual full canonical runner, protected source/lineage authenticated model output, third-party validation, held-out cohort, Final128 rerun or official injection success measurement.
- Native Task13 user utility on scripted local account updates **must not** be promoted to historical V13 recovery, a real attack-defense comparison, or production permissions.
- Existing canonical runner v2.8, AgentDojo resolver, VERITAS OS and Ben's RCC implementation are unchanged.

## Next measurement (not authorized by this PR)

Wire a genuinely source-authenticated candidate from the real independent model A/B trajectories and exact native injected Task13 environment into this boundary without post-candidate repair, preserve issuer/prestate/candidate digests throughout, and then native-score **that same actual run**. A fresh, specific cost/provider authorization is required for any new paid model request. The old authorization is spent. Ben's utility objective remains true measured Arm B >= matched Arm A while preserving injection success 0 and full lineage.

The existence of a PASS in the present isolated CI does **not** meet this target.
