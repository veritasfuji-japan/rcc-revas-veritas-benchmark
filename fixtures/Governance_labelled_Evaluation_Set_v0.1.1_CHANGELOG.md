# Governance-labelled Evaluation Set v0.1.1 — Changelog

This correction was made **before freeze and before benchmark execution** while implementing the native VERITAS runner.

The current `CanonicalDecisionHandoff v1` runtime/test vectors require these corrections:

- `GOV-H06`: missing target is `INVALID` / `DENY` with `HANDOFF_TARGET_UNSPECIFIED`.
- `GOV-H07`: missing canonical action is `INVALID` / `DENY` with both `HANDOFF_ACTION_UNSPECIFIED` and `HANDOFF_AMBIGUOUS_ACTION`.
- `GOV-D08`: stale policy lineage is `REVIEW_REQUIRED` / `HOLD` with `HANDOFF_POLICY_LINEAGE_STALE`.
- External-filing cases include `expected_state` because the current v1 READY path requires it.

No measured benchmark result was inspected before these corrections. The dataset remains a preregistration draft and is not frozen.
