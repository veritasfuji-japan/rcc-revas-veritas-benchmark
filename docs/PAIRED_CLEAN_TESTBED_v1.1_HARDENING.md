# Paired Clean v1.1 Synthetic Testbed — Harness Hardening

Date: 2026-09-23  
Status: **HARDENING CANDIDATE / NO TESTBED RUN EXECUTED BY THIS CHANGE**

## Context

The historical adverse result from Run `35813291352` remains unchanged.

Ben's 2026-09-23 direction reclassifies the current 36-case corpus as a synthetic engineering testbed for iterative RCC/REVAS → VERITAS integration work. Results produced after iterative optimization are not independent external-validation evidence.

## Hardening changes

This change makes four harness-level corrections before any new versioned testbed execution.

### 1. Frozen-validator integration regression

The v1.1 regression suite now constructs the remediated paired handoff, builds the real frozen VERITAS validation context and invokes the frozen CanonicalDecisionHandoff validator.

The positive approval-required control must reach:

`READY_FOR_GUARDED_PROMOTION`

This closes the gap between helper-only rebinding tests and the actual validation boundary that rejected the historical paired run.

### 2. Separate artifact namespace

v1.1 default output moves from:

`results/paired-clean-v1`

to:

`results/paired-clean-v1_1`

The historical v1 artifact namespace is not reused.

### 3. Contract claim boundary separated from runtime facts

The frozen Contract bytes remain unchanged.

v1.1 evidence now records:

- `contract_claim_boundary_snapshot` — the immutable preregistered Contract claim boundary;
- `runtime_facts` — what actually happened in the versioned synthetic testbed run.

This prevents a completed run from being represented by a copied Contract field saying `paired_run_executed=false`.

A complete treatment-delta measurement is true only when there are:

- zero infrastructure errors;
- zero pairing violations;
- zero unsupported cases.

### 4. Dedicated synthetic-testbed workflow

A new workflow is added:

`Paired Clean Synthetic Engineering Testbed v1.1`

It is manual-dispatch only and requires:

- an exact runner commit;
- the exact frozen Contract hash;
- explicit synthetic-testbed confirmation;
- explicit preservation of historical Run `35813291352`.

The historical `Paired Clean Scored Run v1` workflow remains untouched.

## Still intentionally unresolved

The five approval-not-required expected-ALLOW cases remain an explicit integration-compatibility target:

- GOV-A04
- GOV-A07
- GOV-A10
- GOV-A11
- GOV-A12

This hardening change does not silently add support for them.

That compatibility work should be separately versioned and measured on the synthetic testbed.

## Claim boundary

This hardening change does not prove:

- improved Arm B performance;
- Arm B >= Arm A;
- complete treatment-delta measurement;
- independent external validation;
- production readiness;
- certification;
- customer deployment.

No 36-case testbed execution is performed by this PR.
