# Task4 PR #472 — Separate-process, no-egress Sender preflight (NO-GO)

## Scope: a working process boundary, NOT a live Sender

The previous #471 source-pinned integration proved **one local Native A/B trajectory** through actual OpenAI SDK output-capped requests (256 output tokens), #470 scope admission, #458 local Broker, #457 AEAD encryption *before SDK parse*, #456 journal, continued Native RCC/VERITAS execution and detached scripted scorer.

This change adds **one independent operating-system process** between the actual capped SDK request and the unchanged #471 local pre-send Broker gate. Its protocol is **Unix-domain socket only** (AF_UNIX), with strict JSON framing and input sizes. The subprocess starts with a minimal environment **without inherited Provider secrets, GitHub credentials or PYTHONPATH**. It has **no method to send an HTTP request**: unknown operations including send, allow, dispatch and retry return DENY, and its only state-changing operation is a local **claim with explicit NO_SEND**. This is a technical preflight/custody milestone, **not independent operational control**: the worker and Native still share the same Runner/operator, UID and physical disk, and OS-level egress is not independently firewalled.

## What the actual same-run integration does

1. The genuine SDK serializer in the unchanged #471 Native trajectory creates each of eight **capped** local SDK requests (A0–A3, B0–B3).
2. The new wrapper forwards the exact **original SDK request bytes** over bounded local AF_UNIX to a separate subprocess. Worker validates frozen endpoint-independent Task4 scope (case/model, 256 output-token parameter, original trusted developer and user prompts, 2031 fixture clock, tool schema, Native turn count and no role escalation); never reads an API key. It uses a local SQLite database (private 0700 directory, 0600 file, BEGIN IMMEDIATE, synchronous FULL) and monotonically consumes one (synthetic trial, arm, ordinal, SHA) slot before issuing LOCAL_CONSUMED_NO_SEND. Across concurrent callers only one claim may commit; a crash or missing receipt leaves UNKNOWN permanently consumed. **Neither this receipt nor the subsequent #458 receipt grants external SEND.**
3. Only after this separate-process claim succeeds is the original unchanged #470 scope/Broker gate called with the **same request bytes**. Any failure aborts with no retry. The original #471 then gets its scripted local fake response, encrypts and attaches its original bytes to the local Broker *before parsing*, continues Native, and invokes the original local scripted scorer.
4. A report joins worker claim SHA and original #471 AEAD receipt SHA for the **same A/B ordinal and same SDK request**; copied history from a different run cannot satisfy this runtime path.
5. Stop the worker, restart a new worker process over the same SQLite file and prove each of eight claims is DENY_ALREADY_CONSUMED, even when replaying the exact raw SDK request in temporary memory. Explicit send and retry remain DENY.
6. Delete the temporary worker database, sockets and volatile request copies; artifact includes **only SHA hashes, arm/ordinal, fixed status, source pins, JUnit**.

Negative tests cover wrong model, cap, schema, roles, arm, ordinal, malformed Base64/JSON, wrong synthetic trial, unrecognized send op, concurrent duplicate claims, lost-reply/UNKNOWN and process restart. These are local refusal tests, not actual independent IAM or internet egress control.

## Immutable limitations / research versus production

- **True Provider calls: 0.** The exact local mock from #325 remains the only model response origin, **all** Native score calls are from scripted replies. True Utility/injection outcome is **UNSCORED**.
- **Live Sender is absent**, not conditionally activated; no HTTP transport, payment authorization, API key loader, paid workflow trigger, Environment change, Ruleset change or tag mutation.
- This subprocess is a separate **OS process on the same GitHub Runner**. It is not an independent service operator; the same local user can alter its executable or database. Thus independently verified identity, production IAM, credential/egress isolation, remote atomic CAS and independent reconciliation are **NOT ATTESTED**.
- A locally checked 256-token output field and count constraints do **not** prove actual billable input-token ceilings, pricing, a hard dollar ceiling or provider-billing compliance. Fresh scope-specific owner authorization is still required before even a research-only paid run. Earlier approvals and existing $1 project settings are not a new authorization.
- The AgentDojo task expected refund amount is 10.0 with no currency field; 2031 is a historical synthetic date, not a trusted current clock or a real payment issuer. No external bank effects.
- Issue #321 and #427 remain OPEN / NO-GO; this PR neither resolves them nor grants model dispatch.

## PR review controls

Only four **additive** files: standalone worker + same-run integration, denial/crash/restart tests, this runbook, PR-only read-only dedicated workflow. The original #471/#470/#458 sources, Native, scoring code and workflows remain unchanged. The dedicated CI performs a real frozen AgentDojo/RCC/VERITAS **local** integration using pinned OpenAI SDK and cryptography, and must PASS alongside inherited checks on the exact HEAD. JUnit and artifact must remain sanitized. Manual owner merge only. A green PR is evidence of a **local no-egress separation mechanism**, not a real-model result or a production-ready isolated Sender.

**Next research milestone:** independently reviewed safe Provider-origin handoff/custody design, actual provider model/price checks and budget envelope with mandatory fresh owner consent. Do not silently convert this always-DENY worker to a live Sender.