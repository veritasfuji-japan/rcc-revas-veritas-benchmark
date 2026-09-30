# RCC/REVAS External v0.3.9 — VERITAS Native Compatibility Gate

Status: **CANONICAL WRAPPER COMPATIBILITY GATE / NO EXTERNAL BENCHMARK RUN**

## Exact pins

Ben canonical package:

`effacermonexistence/rcc-revas-veritas-benchmark@1d3782d3aae5ff9c88036709c1a5642320cc53c2`

VERITAS native:

`veritasfuji-japan/veritas_os@825e5c5c539c98e12b0c9702f3cb4a12d67539d3`

## Purpose

PR #21 established that Ben's three named connection surfaces are wrapper
interfaces around lower-level VERITAS native primitives.

This gate now executes Ben's own source-pinned integration tests against the
exact current VERITAS pin to answer a narrower question:

> Do the canonical v0.3.9 wrappers actually remain compatible with the pinned
> current VERITAS implementation before benchmark-specific mapping is frozen?

## Tested surfaces

### NativeDecisionIntentFactory

Runs the complete upstream `integration_tests/test_decide_pipeline.py` suite,
including:

- exact selected-candidate promotion;
- top-level response versus CDA semantic mismatch rejection;
- receipt / request identity tamper rejection;
- source-pin enforcement;
- fresh native HTTP → policy → CDA → promotion → Authority → Bind → persistence
  sandbox profiles for valid / tampered / revoked paths.

These are upstream-owned engineering fixtures, not benchmark outcomes.

### NativeAuthorityResolver / NativeBindExecutor

Runs the targeted upstream native-boundary regressions that do not require
unrelated benchmark ecosystems:

- real native Bind commit/block behavior;
- failed effect remains failure/unknown, not a successful refusal;
- persistent operation reservation;
- real Ed25519 AuthorityEvidence + revocation resolution into native Bind;
- mutation of the native intent inside authority callback is rejected.

## Why this precedes adapter implementation

A custom benchmark-specific adapter should not be written around assumed
compatibility. The upstream canonical wrappers and exact current VERITAS pin are
first tested together directly.

If this gate passes, the remaining work is benchmark-specific configuration and
mapping:

- typed CandidateAction projection;
- original request/context source;
- actor/policy/authority/approval source;
- native state snapshot and exact effect owner;
- persisted receipt verification;
- benchmark/model/scorer/metric freeze.

## Claim boundary

PASS here means only wrapper/native compatibility under the upstream engineering
regressions.

It does not mean:

- a benchmark-specific adapter is frozen;
- AgentDojo or another external benchmark has run;
- a clean A/B result exists;
- independent external validation has occurred;
- production readiness or certification has been established.
