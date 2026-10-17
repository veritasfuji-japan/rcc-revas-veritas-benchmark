# Final128 #425 — Redacted pre-tag diagnostic after failed Run #39010798949

## Observed, not guessed

Manual paid-capable Run [39010798949](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39010798949) completed FAILURE during `Validate Environment API and AES256 secret formats BEFORE singleton consumption` on 2026-10-17. The exact approval phrase and billing-review phrase passed the earlier step. Both secret names were present in Actions' masked environment display, **but neither secret value nor its correctness is independently visible**. GitHub skipped the immutable production singleton creation and the Native OpenAI A/B posts. The production consumed ref was still HTTP 404 when checked. The single uploaded artifact was presend-only, not a model reply.

The current CLI emits only `TASK1_423_REFUSED_Denied`; that does not determine if the failure was credential syntax, runtime context, or protected approval/billing context. Do not blindly overwrite secrets or retry an already attempted run.

## Scoped fix

Only the `--mode secrets-preflight` exception handler now prints an **exact allowlisted constant category** prefixed with `TASK1_425_SAFE_PREFLIGHT_REFUSAL_`. It never includes the actual exception message, arbitrary input, secret values, prefixes, character counts, hashes, or traceback. Unknown `Denied` or exceptions print `UNCLASSIFIED`. No new `print` is introduced in the protected workflow and no new file or output artifact is produced by the secret check.

| Safe fixed category | Interpretation |
|---|---|
| `RUNTIME_CONTEXT` | Main/ref/actor/run attempt or runtime context did not match |
| `APPROVAL_OR_ENVIRONMENT` | Manual consent or protected Environment reference mismatch |
| `BILLING_REVIEW` | Exact fresh operator billing-review phrase mismatch |
| `API_KEY_FORMAT` | Dedicated Task1 API-key missing or violates local format policy |
| `AES256_KEY_FORMAT` | Dedicated capture-key Base64/32-byte format invalid |
| `TAG_CONSUMPTION_REQUIRED` | Only the true send phase requires consumed tag and SHA |
| `UNCLASSIFIED` | Unmapped failure, no details disclosed |

A successful secrets-preflight is **silent**; it does NOT authorize paid dispatch, create a tag, send a Provider request or score utility. Preflight does not verify an API key is accepted by OpenAI; no project-limit guarantee is made. The existing paid-capable manual workflow trigger, source SHA pins, GitHub Environment, single-use consumed tag, zero-retry behavior, AES-GCM response capture and `send` phase are **unchanged**.


## New independent **NO-PAID, NO-TAG** diagnostic workflow

The new `.github/workflows/final128-425-task1-safe-local-secrets-diagnostic-no-provider-v1.yml` is a **separate manually dispatched workflow**, titled **Task1 425 SAFE NO PAID Environment Secret Format Diagnostic**. It is not the existing Task1 paid-capable workflow. Its only job has `contents: read`, `persist-credentials: false`, main-only/actor-only/first-attempt checks and the same GitHub Environment gate. It runs `scripts/final128_425_task1_local_secret_format_diagnostic_v1.py` with Python's standard library, *without importing or invoking* the Provider API, AgentDojo executor, GitHub tag issuer or #423 sender.

The job emits one static status and returns success/failure:

- `TASK1_425_SAFE_NO_PAID_DIAGNOSTIC_LOCAL_SECRET_FORMATS_VALID_NOT_PROVIDER_AUTHENTICATED`: the protected runtime and both local secret shapes passed, but the OpenAI API key has **not** been validated with OpenAI.
- `TASK1_425_SAFE_NO_PAID_DIAGNOSTIC_API_KEY_FORMAT`: the local Task1 API key is missing or fails the existing #423 whitespace/length shape policy.
- `TASK1_425_SAFE_NO_PAID_DIAGNOSTIC_AES256_KEY_FORMAT`: the capture key is absent or not canonical Base64 for 32 bytes.
- `TASK1_425_SAFE_NO_PAID_DIAGNOSTIC_RUNTIME_CONTEXT`: the job has unexpected run/ref/actor/attempt context.
- `TASK1_425_SAFE_NO_PAID_DIAGNOSTIC_UNCLASSIFIED`: an unknown failure, printed without exception content.

No raw key, prefix, length, content hash, traceback or echo of Environment inputs is intentionally logged. No paid request, tag mutation, test corpus execution or encrypted Provider artifact occurs. These guarantees apply to the source as reviewed; they are **not** full account/network/IAM bypass-resistance attestations. Any access granted by GitHub to a separately changed malicious workflow remains out of scope.

### To investigate the old Run safely

**Do not rerun Run #39010798949**, and do not launch the previously staged **Task1 Native First Two Chat A/B PROTECTED MANUAL V1** solely for diagnostics. After merging this PR and checking main, the operator may manually launch the **separate NO PAID diagnostic** workflow, approve its Environment and wait the configured delay. Only its fixed status is needed for further debugging. This is a new diagnostic run, not a replay of the failed paid-capable Run. Paid Task1 A/B still requires **fresh explicit human authorization** and separate cost-risk acceptance.

## Validation before any another real run

- Dedicated offline, pinned Native AgentDojo + VERITAS CI runs the existing full #403–#424 test suite with sockets blocked and no secrets. New parametrized CLI tests inject **dummy** invalid API/AES/context/approval/billing values; stderr must exactly match a known fixed category, no dummy value, traceback or raw exception. Unexpected failures stay `UNCLASSIFIED`. Valid preflight stays silent and writes no files.
- No operational secrets should be shared with a reviewer, in GitHub issue/PR text, in a screenshot, or with an LLM.
- A new GitHub `workflow_dispatch` on main would be **a new irreversible attempt**, not a retry of Run #39010798949. Its possible Provider calls need a **fresh explicit approval** after the expected failure category is reviewed. **Do not dispatch this PR/merge as a paid test**.
- Original run remains failure with zero native Provider responses, no authenticated A/B Utility scoring, and **new genuine utility recoveries = 0**.

## Boundaries

This diagnostic is safe *only because it prints constants in a closed allowlist*. It should not become arbitrary `str(exception)` printing or a user-supplied debug flag. Avoid categorizing actual secret length or content in more detail; do not add raw traceback logging. Log messages on other CLI modes remain non-sensitive class names.
