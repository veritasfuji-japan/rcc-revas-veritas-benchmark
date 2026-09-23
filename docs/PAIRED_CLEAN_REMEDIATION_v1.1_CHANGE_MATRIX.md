# Paired Clean Remediation v1.1 — Changed / Unchanged Matrix

Date: 2026-09-23  
Status: **PRE-ACK REMEDIATION CANDIDATE / NO SCORED EXECUTION AUTHORIZED**

## Purpose

Define the smallest separately versioned remediation for the identity-rebinding defect preserved by frozen scored Run `35813291352`.

The original runner `paired_clean_runner_v1.py` and its adverse result remain unchanged.

## Changed in v1.1

| Area | v1.0.1 behavior | v1.1 remediation |
| --- | --- | --- |
| Runtime request lineage | Only `source_decision.request_id` was replaced by the real `/v1/decide` request ID | Rebind `source_decision`, `trustlog_lineage`, and `replay_lineage` request IDs atomically |
| Canonical replay lineage | Template values could remain stale after actual CDA insertion | If canonical replay-lineage v1 is present, rebind original CDA id/hash/timestamp |
| Approval candidate reference | Approval evidence could retain synthetic candidate ID | Rebind `human_approval_evidence.candidate_ref` to the exact RCC candidate ID when approval evidence exists |
| Regression coverage | No dedicated test for these rebinding seams | Add deterministic request-lineage and approval-candidate-reference regression tests |
| Scored-run gate | Contract hash + manual run confirmation | v1.1 additionally requires explicit counterparty-remediation ACK confirmation |

## Explicitly unchanged

- Contract v1.0 bytes and SHA-256:
  `532958fc9371fb34e550fb2a108868c64e87a980833dd46e8a92c7a133d9ae1f`
- 36-case dataset bytes and SHA-256:
  `1e6ea7f9366876b4cbf041cc0841ab72bd58d6f561ff78553deb6645e5bf2a88`
- RCC/REVAS publication commit:
  `805cd5ff17e431cf50a3dafa7f78a60a704613b9`
- RCC/REVAS source archive SHA-256:
  `4c736357ab93a8f4b5027b94c20340b973c760de1a0027df30bb53d3d10f47d8`
- VERITAS treatment commit:
  `b39961b003179aea70e320a57cb000f56a81951e`
- frozen labels;
- semantic expectations;
- scoring implementation;
- denominator;
- known preserved divergences `GOV-H06`, `GOV-H07`, `GOV-D08`;
- no-selective-rerun rule;
- no-automatic-retry rule;
- no credential handoff;
- no transport invocation;
- no network dispatch;
- no external effect;
- no Bind authorization creation;
- no execution-authority creation.

## Important bounded limitation

This remediation addresses the two forensic rebinding defects only.

It does **not** silently add support for the frozen native Bind profile's approval-not-required path. Any such capability change would be a separate treatment-scope decision and must not be folded into this v1.1 remediation without explicit review.

## Pre-ACK rule

Before Ben's explicit ACK:

- unit / regression tests may run;
- pin-only preflight may run;
- the candidate runner may be reviewed and merged;
- an exact candidate pin may be communicated.

A new scored 36-case remediation execution must not run.

## Original evidence remains controlling history

Run `35813291352` remains the latest completed scored evidence until a separately authorized remediation evaluation is actually executed. v1.1 does not rewrite, replace, or retroactively correct that run.
