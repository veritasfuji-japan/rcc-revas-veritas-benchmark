# RCC/REVAS External v0.3.9 — VERITAS Native Compatibility Gate

Status: **CURRENT-PIN WRAPPER COMPATIBILITY / CANONICAL SOURCE-PIN DRIFT EXPLICIT / NO EXTERNAL BENCHMARK RUN**

## Exact pins

Ben canonical package:

`effacermonexistence/rcc-revas-veritas-benchmark@1d3782d3aae5ff9c88036709c1a5642320cc53c2`

Ben v0.3.9 canonical native-source manifest pins VERITAS:

`veritasfuji-japan/veritas_os@b39961b003179aea70e320a57cb000f56a81951e`

Current VERITAS pin under compatibility review:

`veritasfuji-japan/veritas_os@825e5c5c539c98e12b0c9702f3cb4a12d67539d3`

## Why the first PR #22 compatibility run failed

The first run, GitHub Actions Run `36662939950`, reached Ben's fresh full native
sandbox tests and failed before semantic compatibility was exercised.

The exact failure was:

`NATIVE_SOURCE_PIN_MISMATCH: veritas_os/policy/bind_core/core.py`

This is expected fail-closed behavior from Ben's canonical
`SOURCES_NATIVE.json`. The canonical package pins the historical VERITAS source
commit `b39961b...` and exact critical-file hashes. The current VERITAS pin is
different.

Therefore the failed run must **not** be described as proof that the wrappers are
incompatible with current VERITAS. It proves that the canonical source pin is
working and refuses silent source substitution.

The upstream source manifest is not modified to make the test pass.

## Revised compatibility question

The current gate asks:

> With Ben's source-pin mismatch explicitly preserved, do the canonical wrapper
> APIs and semantic guards remain compatible with the current VERITAS pin on
> tests that do not require pretending the current source is the historical
> canonical source?

## NativeDecisionIntentFactory

The gate runs Ben's own `integration_tests/test_decide_pipeline.py` against the
current VERITAS pin, excluding only the three
`test_fresh_native_http_policy_cda_bind_trustlog` profiles.

Those three profiles are excluded because they intentionally enforce the
historical `SOURCES_NATIVE.json` source hashes before the HTTP/native chain is
allowed to begin.

The remaining upstream tests still cover:

- exact selected-candidate promotion;
- CDA semantic integrity;
- top-level response/CDA mismatch rejection;
- request and receipt identity binding;
- candidate binding;
- source-function pin enforcement;
- no reuse of stale prior success.

## NativeAuthorityResolver / NativeBindExecutor

The gate runs targeted upstream native-boundary regressions against the current
VERITAS pin for:

- real native Bind commit/block behavior;
- failed attempted effect remaining failure/unknown rather than successful refusal;
- persistent operation reservation;
- real Ed25519 AuthorityEvidence + revocation into native Bind;
- mutation of native intent by an authority callback being rejected.

## What PASS means

PASS means the canonical wrappers remain compatible with the current pinned
VERITAS primitives across this bounded upstream engineering test set, while the
historical full-sandbox source pin remains intentionally distinct and
unmodified.

PASS does **not** mean the canonical historical full sandbox was rerun against
the current pin. Doing that would require a newly frozen source manifest rather
than silently replacing Ben's canonical one.

## Next gate

After bounded current-pin compatibility is green:

1. freeze the exact benchmark-specific `CandidateAction → DecisionCandidate` mapping;
2. freeze original request/context lineage;
3. freeze actor/policy/authority/revocation/approval sources;
4. freeze state snapshot and sole effect owner;
5. freeze persisted decision/Bind receipt verification;
6. freeze benchmark/model/enrollment/scorer/metrics/success-failure conditions;
7. only then execute a fresh external clean A/B.

## Claim boundary

This gate does not establish:

- a benchmark-specific adapter freeze;
- AgentDojo or another external benchmark execution;
- clean A/B results;
- independent third-party validation;
- production readiness;
- certification.
