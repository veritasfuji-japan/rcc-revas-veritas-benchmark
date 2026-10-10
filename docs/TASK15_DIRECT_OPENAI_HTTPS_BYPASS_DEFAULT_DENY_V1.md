# TASK15_DIRECT_OPENAI_HTTPS_BYPASS_DEFAULT_DENY_V1

**DRAFT / NOT PROVEN. No live OpenAI request is authorized.**

## Central Rule-of-One

The #276 independent audit (merged main `677a65721fb44d11618a0f906b71eb1931166b44`) identified a concrete bypass: anyone holding an API key could directly call `DirectOpenAIHTTPSOnce.send(request)` without `DurableOneShotModelCapture` first checking a human signature and consuming a SQLite grant.

**This PR closes those specific existing callable paths by disabling them**, not by claiming that all arbitrary Python code is unable to send HTTP. The previous direct class constructor always raises `DIRECT_HTTPS_HELPER_WITH_KEY_DEFAULT_DENIED`; even an object created through `object.__new__()` has a `send()` method that always raises `DIRECT_HTTPS_DISPATCH_NOT_AN_AUTHORIZED_EFFECT_SINK`. Similarly, `DurableOneShotModelCapture.capture(...,live=True)` always rejects before calling `_claim()`, so a signed *test* fixture cannot accidentally enable a real API request.

The old `capture(...,live=False)` path, using a separate **mock transport**, is retained for independently reproducible proof of one-use consumption, timeout UNKNOWN, and no bank tool dispatch. No code in this PR replaces the disabled class with another network-capable sender.

## Exact proof requirements

- Pin previous merged-main SHA `677a65721fb44d11618a0f906b71eb1931166b44` and original #276 historical implementation Git blob `a3ff123d5df3fc47e5014b212666050f525cba02`.
- Preserve all previous archived #276 results and re-run the full bounded original chain against the **new** explicitly pinned source. Updated source blobs in the checked-out regression contract do **not** change the historical archived result tied to the old main SHA.
- JUnit: **15 new cases** (1 positive unchanged mock behavior / original entrypoint denial + 14 unique negative attempts with different injected keys, altered model request, forged object bypass, live path, tampered manifest or operator key).
- Archived two real SQLite files: one `MOCK_RECORDED` and one `PREPARED` after an attempted forged live send. Independent auditor must verify the source, grant digest, full journal and one-time claim count directly from raw SQLite via `PRAGMA integrity_check`, rather than trusting JSON status alone.
- Confirm **no HTTPS object is created and no socket is used** in the test path. Test-only signature/clock is not a real operator trust root. Zero provider calls, zero billable usage, zero bank effects.
- The old #276 workflow also runs on changed source and must remain green, so that past offline invariants are not silently broken.

## Important limitations

This is a **local code-path remediation**: it closes the named direct helper and `live=True` entrypoints. It is **not** a system-wide guarantee: any arbitrary user code holding an API credential and outbound network could call the OpenAI endpoint through another library or direct TCP/TLS. The old `DirectOpenAIHTTPSOnce` source is still recoverable through Git history and may be checked out elsewhere. A production-ready control plane must **withhold provider credentials from all untrusted callers** and enforce outbound network isolation so only a separately scoped, credential-owning effect sink can connect.

Do not claim the new module has made a real OpenAI call or proves external provider request acceptance/authenticity. It deliberately makes live execution unavailable.

## Next step

Design and independently test a **separate credential-isolated effect sink**, with OS/IAM network rules, externally enrolled human trust root, fresh consent for exactly one model response capture, budget headroom checks, no retries, request/response receipts, and no banking effect dispatch. Only after this architecture and proof are reviewed should the user be asked for fresh explicit **billable** consent. Neither the historical US$5 ceiling nor the proposed US$0.25 ceiling authorizes a request.

**DO NOT MERGE** until latest-head CI, original #276 regression and independent ZIP/JUnit/refusal/SQLite review pass.
