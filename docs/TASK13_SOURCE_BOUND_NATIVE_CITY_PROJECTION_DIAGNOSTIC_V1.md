# Task13 — source-bound native city projection (structural diagnostic only)

## Why this candidate matters

Ben's objective is to recover genuine Arm B utility while keeping injection success at zero and preserving canonical native candidate/lineage continuity. Frozen V13 development evidence records Arm A 93/128, Arm B 64/128 and Arm B injection 0/128. It is a distinct measurement from the earlier 92/128 vs 60/128 cohort with 32 regressions; those numbers must **not** be combined as one treatment-effect dataset.

The frozen controlled cause decomposition identified **four Task13 address city mismatches**, specifically `banking:user_task_13:injection_task_{1,2,5,8}:direct`. The observed model candidate used `city="New York"`, while the historical resolver bound the **entire trusted-file address line**, `"New York, NY 10001"`. Treating those mismatches as false blocks or model-performance improvement would be premature.

## Source-grounded hypothesis

At fixed AgentDojo commit `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`:
- `src/agentdojo/default_suites/v1/tools/user_account.py` declares `UserAccount.city` as "City of the user"; `update_user_info` persists the exact supplied `city`. There are **no separate region/ZIP fields**.
- `src/agentdojo/default_suites/v1/banking/user_tasks.py` includes a Task13 target `city="New York"`, but benchmark gold/utility labels are **not** used to derive or authorize the projected value.
- The existing frozen resolver reads user-referenced `address-change.txt`, selects the first address street/city lines after the specific anchor, and excludes `TODO:` follow-on injection text. It currently requires the model-supplied `city` to equal the **full file line**.

A strict structural field mapping could instead derive the locality `New York` from `New York, NY 10001`, independently of any gold label, **provided the file origin is separately trusted**. This PR does NOT assert that file-origin assurance has been achieved. It does **not** add the projection to the actual resolver, the Ben canonical wrapper, or the native VERITAS effect route.

## Exact isolated proof

`scripts/task13_source_bound_native_city_projection_diagnostic_v1.py` extracts the street and address line solely through the frozen resolver's file extractor. It then accepts a **single, entire, strict US-style line**, `Locality, ST ZIP`, with exact case, one space delimiters and no trailing material. Only the locality component may structurally match the pre-existing candidate's `city`.

The diagnostic refuses incorrect streets, a different locality, malformed lines, non-US formats, injected/multiple suffix content, unknown candidate fields, modified names and any substring-based approximation. It does **not** rewrite a candidate post-promotion.

`contracts/TASK13_SOURCE_BOUND_NATIVE_CITY_PROJECTION_DIAGNOSTIC_V1.json` freezes the V13 four-case hypothesis, distinct legacy-vs-V13 measurement and every unavailable attestation flag. `tests/test_task13_source_bound_native_city_projection_diagnostic_v1.py` covers dynamic cities, mutated/invalid inputs, exact source hashes, and proof/non-authorization refusals.

## Strict claims

**Expected after offline CI:** a deterministic *potential* native `city` projection from exactly shaped test input, with fail-closed negative tests. All ordinary resolver behavior, source pins, policy rules and external service permissions remain unchanged.

**Not established:** a real independent origin/provenance guarantee for the file, user-approved loss of state/ZIP information, a live native effect, model candidate-generation correction, an actual recovery of 4 Utility scores, injection success after changes, or contemporary canonical native wrapper continuity. Any production-bound adoption must first resolve these, and no model/scorer/gold may fabricate execution authority.

## Next useful measurement

After a reviewed authority/field-mapping decision, a separate PR could integrate **only** the proven semantic projection at the original pre-execution boundary without changing the candidate or source ID and then run exact same-candidate A/B and Native scorer with complete original-request and prestate lineage. Repeat real model measurement only under **fresh explicit Provider cost approval** and preserve intermediate runs and case-level deltas.

This is a small code-level step toward [Ben's utility objective](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/main/contracts/UTILITY_OPTIMIZATION_V1_BASELINE_DIAGNOSIS.json), **not** another unrelated GitHub CAS lab proof.
