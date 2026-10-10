# TASK15_REAL_PROVIDER_FIRST_CALL_PREFLIGHT_DEFAULT_DENY_V1

**DRAFT / NOT PROVEN before latest exact-HEAD CI and independent artifact inspection.**

## Rule-of-One

Seal **one non-executable future real-model response capture request**, exactly pinned to the original frozen AgentDojo Task15 first attack case A-arm native read source. The plan records source SHA-256 (model request, user message, tool schema, native read call ID and prior full provenance), proposed spend and output limits, an exact model snapshot and real-provider authorization status.

**The plan MUST NOT issue real provider authority**. No OpenAI API client or transport exists in this module; no API keys, operator consent, actual call, live charge, external model response, tool invocation or bank writes are used by CI. An audit must not infer fresh approval from an earlier $5 budget ceiling or from the newly proposed $0.25 maximum.

## Exact proposed first call

| Parameter | Frozen proposal | Authorization status |
|---|---|---|
| Provider | OpenAI | NOT CONNECTED |
| Exact model snapshot | `gpt-4.1-mini-2025-04-14` | Proposed only |
| Case | `banking:user_task_15:injection_task_0:direct` | One pinned prior source |
| Arm | A | Fixed |
| Maximum model requests | 1 | No rights issued |
| Maximum output tokens | 256 | Proposed only |
| Per-call cost ceiling | US$0.25 | Proposed only; **not spending permission** |
| Native bank/write/effect dispatch | Forbidden | No execution adapter |
| Actual API credential, trusted operator signature | Absent | Fail closed |

Model availability, exact pricing, API semantics and cost calculation must be revalidated separately **before** any later billable run. A cost ceiling alone is not a provider-side hard cap; any future one-shot runner needs pre-dispatch enforcement and post-call cost reconciliation.

The original frozen historical $5 ceiling is also **not authorization** to incur any charge.

## Evidence requirements

- Exact #274 predecessor merged-main: `7fdfed5cf4d8b1302fc376d36d97b67089dcfa12`; all preceding Task15 source/case evidence replayed at frozen pins.
- Original case A read/tool/user source hashes and actual `source_read_call_id` copied unchanged into the sealed planning manifest.
- SQLite `PREPARED_NO_EXECUTION` row contains the canonical plan SHA-256, immutable expected JSON, actual call count 0, spend 0, bank effects 0 and one preparation audit event. Reopening and checking the raw DB must not mutate it.
- 15 dedicated JUnit tests, 14 fail-closed refusals including model/case/arm/provider and budget/token drift, fake approval, fake credential or transport, altered predecessor, duplicate issuance, direct SQLite mutation, forged live dispatch, retry and bank-write attempts.
- Independently download Artifact, verify Git SHA/ZIP SHA/JUnit/refusal JSONL and inspect the actual archived SQLite database with `PRAGMA integrity_check`, exact row and hash equality.

## Next separately authorized round

After the #275 proof is independently reviewed and merged, the first live run may be built as a **separate explicit authorization and execution task**. Before any live invocation, define the exact allowed request payload, model availability, total cost guard, no retries, source/call pin, safe credential isolation, real response provenance, durable records including transport timeout/UNKNOWN and a zero-bank-effect transport. Request fresh explicit human consent with its precise scope and charge ceiling. Nothing in this PR permits the call.

**NOT PROVEN:** any signed operator consent, live provider connection, provider-signed response, authentic external effect receipt, actual Token usage, Final128 utility, injection success, production effect-sink control or system-wide bypass prevention. This proof remains strictly offline and non-executable.
