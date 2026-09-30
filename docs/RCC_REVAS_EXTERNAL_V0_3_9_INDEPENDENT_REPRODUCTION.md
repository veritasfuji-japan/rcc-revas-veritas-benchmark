# RCC/REVAS External v0.3.9 — Independent Reproduction Gate

Status: **REPRODUCTION HARNESS ONLY / NO REAL EXTERNAL EVALUATION**

## Canonical handoff pin

Repository:

`effacermonexistence/rcc-revas-veritas-benchmark`

Exact canonical commit:

`1d3782d3aae5ff9c88036709c1a5642320cc53c2`

Package:

`external-eval/v0.3.9`

Primary entrypoint:

`docs/PARTNER_START_HERE.md`

VERITAS mapping contract:

`contracts/VERITAS_MAPPING_v0.3.4.json`

## Purpose

This gate independently reproduces the unmodified partner starter from Ben's
exact canonical commit before any VERITAS-native adaptation is introduced.

It intentionally does **not** connect the current VERITAS native implementation.

The sequence is:

```text
exact upstream checkout
→ verify exact commit
→ verify every SOURCE_MANIFEST entry
→ install v0.3.9 package
→ init-pilot
→ mapping-check
→ freeze
→ run unmodified engineering starter
→ verify retained evidence
→ preserve reproduction manifest + artifact
```

## Boundary

A successful run establishes only that the canonical v0.3.9 package can be
independently installed and its unmodified engineering starter can be reproduced
from the pinned source.

It does not establish:

- native VERITAS integration;
- RCC/REVAS + VERITAS treatment validity;
- AgentDojo or any other external benchmark result;
- model performance;
- independent third-party validation;
- production readiness;
- certification.

## After this gate

Only after the reproduction artifact is preserved should the next versioned work
map the current VERITAS native implementation to the three named connection
surfaces:

- `NativeDecisionIntentFactory`
- `NativeAuthorityResolver`
- `NativeBindExecutor`

Any interface mismatch must be resolved and frozen **before** a clean external
A/B run, never after observing benchmark results.
