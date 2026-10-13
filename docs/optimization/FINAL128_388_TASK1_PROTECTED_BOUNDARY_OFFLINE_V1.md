# Final128 #388 — Task1 protected execution boundary, REVIEW ONLY (NO PROVIDER)

## Purpose and explicit exclusions

This stage turns Task1's proposed protected launch requirements into an exact,
negative-testable contract **without installing a live sender**. It does not
change any frozen V13 histories or the 15 historical manual Provider YAML blobs.
It does not dispatch workflows, modify GitHub tags, use Environment secrets,
issue authenticated authorization, access external Provider APIs, call Native
scorers or remeasure Utility.

The operator manually reported removal of the Repository-level OPENAI_API_KEY
and revocation of the older key. Screenshots in the review conversation showed
the Task1 Environment secret exists, Required reviewers set to the single
operator, 10-minute wait, disallowed admin bypass, and main-only deployment.
**These observations are not runtime evidence**. Reviewers can self-approve;
Prevent self-review is off. No independent reviewer attestation is present.

## Contract and negative coverage

- Exact review-only specification in contracts/FINAL128_388_TASK1_PROTECTED_BOUNDARY_REVIEW_ONLY_V1.json.
- Fixed repo, actor, main ref, environment, model, two initial A/B attempts
  maximum, USD 1.00 **proposed** ceiling, no re-runs/retries, and fixed globally
  single-use tag from #382/#383 (not a per-run or per-SHA tag).
- A simulation can consume its single fake lease once, but even simulated
  success returns permission_to_call_provider = false.
- Unknown-before, unknown-after, explicit rejection and replay all STOP;
  caller-asserted approvals, purported 201 replies and provider receipts
  have no authority. They never unlock the real transport.
- Source scan locates job bodies with the Task1 Environment and literal
  Provider secret binding, and distinguishes Task4 declarations. It does
  **not** query GitHub workflow enabled/disabled state or prove that an
  Environment is enforced for a real paid task.
- Existing #350 local budget guard and #351 static preflight regressions are
  retested. Local USD estimates are **not** an enforced account hard cap.

The JSON field externally_unverified enumerates gates that are required for a
future sender, not attested booleans to be promoted to AUTHORIZED. The auditor
always returns execution_authorized: false, independent of fixture claims.
The new CI workflow is PR-only with read-only token permissions, explicit empty
Provider variables, no protected Environment, and no live dispatch trigger.
All new evidence is unscored, source-scoped and SHA-bound.

## Still required before a separately approved, bounded Task1 live experiment

1. Audit a separately implemented protected caller binding the actual
   secret-consuming job to task1-real-model-pilot, including runtime
   Environment approval and stronger independent authorization.
2. Prove globally durable, immutable one-use **real issuer** with trusted
   permission scope, replay/UNKNOWN/no-retry behavior, old-ref bypass audit
   and prohibition on delete/update; a local fake tag is not sufficient.
3. Verify exact model/project access and an **effective** hard spending stop,
   independent of local estimates. Confirm no other credential/egress route.
4. Bind authentic Provider TLS response provenance to the native banking read
   and full terminal to original Native User/Attack Scorer evidence chain.
5. Obtain fresh, specific operator approval for exact Task1 case, A/B,
   model, call count, exposure and maximum spend. Earlier approvals/CI green
   do not constitute that approval.

**Real Task1 paid Provider calls = 0 for #388. Native scorer calls = 0.
Historical Final128 A=93/128, B=64/128, B injection=0/128 are unchanged.**
Do not merge merely because the offline suite is green. Review the artifacts,
source-vs-live caveat and general CI before manually merging.
