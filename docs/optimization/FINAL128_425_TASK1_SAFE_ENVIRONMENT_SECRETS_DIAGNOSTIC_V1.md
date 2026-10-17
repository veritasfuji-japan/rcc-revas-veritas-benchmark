# Task1 #425 — Safe refusal categories and read-only Environment diagnostics

## Why

Real manual workflow Run [#39010798949](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39010798949) stopped at step 9 `Validate Environment API and AES256 secret formats BEFORE singleton consumption`, with only `TASK1_423_REFUSED_Denied`. Earlier approval phrases and Environment variable names matched; both Environment secrets were present but masked. The outcome proves neither secret is valid or invalid individually. GitHub singleton tag **did not exist/was not consumed**; steps 10 (tag) and 11 (two paid Provider requests) were SKIPPED; no newly measured Utility.

Two problems exist: no useful NON-SECRET failure category in the original job, and **re-running the real manually gated paid workflow merely to diagnose the cause would risk consuming the singleton tag and causing paid calls**.

## Implemented changes

1. The existing #423 `--mode secrets-preflight` now logs **one fixed allowlisted failure category** on rejection, e.g. `TASK1_425_PRETAG_DENIAL_CATEGORY=API_KEY_FORMAT`, `AES_KEY_BASE64_OR_LENGTH`, `GITHUB_RUNTIME_CONTEXT`, `APPROVAL_OR_ENVIRONMENT`, or `BILLING_REVIEW`. Arbitrary exceptions collapse to `OTHER_PRETAG_FAILURE`. No exception messages, key values, length, masked strings, key fragments, previews, hashes, or Python exception cause/traceback enter the public job log.
2. Extract the exact token syntax + strict canonical Base64/32-byte AES predicate into `scripts/final128_425_task1_environment_secret_diagnostic_v1.py`. The **same predicate** now validates the real #423 sender; all existing consent, environment, pretag/aftertag checks and no retry remain intact.
3. Add a **separate manually dispatched, secret-shape-only workflow**:
   `.github/workflows/final128-425-task1-readonly-environment-secret-shape-diagnostic-v1.yml`.
   It runs only on main by the expected GitHub actor, inside the same protected Environment `task1-real-model-pilot`; `contents:read`, no GH_TOKEN passed, checkout credentials not persisted, no provider SDK, no Python dependencies, no network/API calls from diagnostic code, **no tag GET/POST/create/write**, no outcome artifact, and no API spending or Native scoring. It outputs ONE of these categories:
   - `SHAPES_OK_NOT_A_PROVIDER_AUTHENTICATION` (form only; not real OpenAI authentication)
   - `API_KEY_FORMAT`
   - `AES_KEY_BASE64_OR_LENGTH`
   - `GITHUB_RUNTIME_CONTEXT`
   - `ENVIRONMENT_SCOPE`
4. Add refusal tests covering secrets containing sensitive sentinel text, blank/short/whitespace API keys, malformed/short/long/noncanonical AES Base64, wrong actor/ref/attempt/Environment, unknown exception attempts to insert secret text, exact CLI stderr and static check that read-only workflow cannot dispatch Tag/Provider or emit artifacts.

## Safe operator procedure AFTER review and merge

Do **NOT** re-run, rerun failed jobs, retry, or dispatch old paid `Task1 Native First Two Chat A/B PROTECTED MANUAL V1` only for diagnosis. Instead open GitHub Actions and select:

`Task1 425 Read-Only Environment Secret Shape Diagnostic (NO PROVIDER)`

Branch `main`; invoke **only that separate diagnostic**. It still uses GitHub Environment approval/wait timer, but that job is read-only and will not create the singleton tag nor call the Provider regardless of secret format. Read its single `TASK1_425_SECRET_FORMAT_DIAGNOSTIC=` line, and share only the code/status/Run URL, **not secret values**. Diagnose and correct the specific Environment setting, then obtain **new and specific user approval** before any future paid live workflow attempt; old approval must never be presumed reusable.

## Claims explicitly NOT made

The read-only diagnostic checks syntactic secret format, not actual Provider key validity, API access entitlement, billing enforcement, AES key security/custody, or independently provable human execution authority. The project Limit Enforced $1 may reject requests after reaching a threshold, but is not a mathematically strict upper bound on eventual invoice. Existing script still only sends one first Native Chat completion per arm when separately authorized; no Native Tool execution or official scorer.

**Run #39010798949 is permanently a failed, unscored attempt**, and its tag remains unconsumed. No paid Provider requests were made by this PR or its offline CI. Historical V13 A Utility 93/128, B Utility 64/128, B injection success 0/128 remain historical and unmodified. New genuine Utility recoveries: **0**.

## Strict CI

Dedicated existing pinned Native + VERITAS #423 PR-only CI compiles and reruns the extended sender tests with network sockets blocked, provider credentials unavailable, no GitHub tag writes and JUnit `failure=error=skip=0`. Artifact digest and exact PR head must be audited. `CI SUCCESS` does **not** grant permission to launch paid Task1 job.
