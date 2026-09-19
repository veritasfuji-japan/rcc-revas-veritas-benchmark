# RCC / REVAS × VERITAS — Paired Clean Evaluation Pre-Freeze Preparation

Date: 2026-09-19

## Purpose

This note separates what can be fixed from repository evidence now from what still requires Ben's confirmation before Paired Clean Evaluation Contract v1.0 can be frozen.

No benchmark run is authorized by this document.

## Verified now

### VERITAS candidate source

Repository:
`veritasfuji-japan/veritas_os`

Current main at preparation time:
`d2405d5460a8812aeb7fd127f8475c960d022161`

This is a **candidate**, not the final frozen evaluation SHA.

### Benchmark baseline source

Repository:
`veritasfuji-japan/rcc-revas-veritas-benchmark`

Current main:
`13d97aff4600a38494c85e1731827686f2cac93b`

### Existing dataset

Path:
`fixtures/Governance_labelled_Evaluation_Set_v0.1.1.json`

Case count:
`36`

SHA-256:
`1e6ea7f9366876b4cbf041cc0841ab72bd58d6f561ff78553deb6645e5bf2a88`

This dataset already has preregistered synthetic governance labels. The final paired contract must freeze the exact dataset bytes and labels before execution.

### Historical PR #10

PR #10 remains open and mergeable, but it pins VERITAS:
`3d9b8f85138fb0c5cde48915f10410861d015abc`

Decision:
**Do not merge PR #10 as the new current paired-evaluation surface.**

It remains historical work only.

## Proposed treatment boundary for joint review

Arm A:
`RCC / REVAS only`

Arm B:
`RCC / REVAS -> current VERITAS full governance treatment`

VERITAS entry boundary:
`POST /v1/decide`

Proposed first-run stop point:
`native Bind eligibility / gate-review boundary before external dispatch`

External effects:
`not permitted in the first clean paired run`

This stop point is still **proposed**, not frozen. It should be jointly confirmed before implementation.

## Still requires Ben confirmation

Do not infer these from historical benchmark artifacts:

1. canonical current RCC / REVAS repository;
2. canonical current RCC / REVAS commit;
3. canonical current RCC / REVAS entrypoint;
4. any semantic changes since the historical public artifacts used in the v0.2 field contract.

## Still requires joint freeze

After Ben confirms the upstream source surface:

1. final VERITAS evaluation SHA;
2. exact downstream stop point;
3. runtime/environment manifest;
4. exact cost-accounting method;
5. any exclusions / unsupported-case rules;
6. final dataset and labels;
7. final contract bytes + SHA-256;
8. new paired runner implementation SHA.

## Implementation rule

Do **not** build or run the new paired benchmark before the freeze gate closes.

The next implementation surface should be a new versioned paired runner built from the frozen contract. It should not reuse PR #10 as current evidence merely because PR #10 is still mergeable.

## Evidence rule

The paired evaluation must preserve three separate evidence layers:

1. historical/internal compatibility evidence;
2. preregistered paired incremental-value measurement;
3. later external/independent validation.

These must not be collapsed into one claim.

## Core invariant

```
Decision Adoption != Execution Authority
```

The benchmark may measure governance outcomes and Bind eligibility. It must not convert upstream adoption, benchmark labels, or synthetic ground truth into execution permission.

## Current conclusion

The VERITAS-side and benchmark-side pre-freeze inputs are now concrete enough to prepare the joint freeze.

The only source pin that must not be guessed is Ben's canonical current RCC / REVAS commit and entrypoint.
