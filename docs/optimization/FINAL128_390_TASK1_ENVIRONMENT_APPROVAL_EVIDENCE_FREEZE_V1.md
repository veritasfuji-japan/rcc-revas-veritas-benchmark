# Final128 #390 — observed Task1 GitHub Environment approval gate evidence freeze

## Scope and immutable target

This PR freezes the observed **zero-Provider** Environment gate from PR #389,
GitHub Actions run **38386775595**, HEAD
c9accc3a15d97b53d0d3e140b2410f659aa0391f.

Observed behavior:
- 2026-10-13 10:56:31–10:56:33 UTC: preflight-no-environment
  (Job 115260406333) SUCCESS.
- At 10:56:34 UTC, the prior live pending_deployments read reported
  task1-real-model-pilot, a 10-minute timer and the operator reviewer. The
  run and marker were WAITING. The operator supplied a UI screenshot around
  20:08 JST (about 11 minutes after dispatch) showing **still waiting for
  review**. This previous pending response was **not independently signed
  or persisted in a canonical raw Evidence Bundle**; after approval the GET
  endpoint now returns an empty array. No third party can rerun the earlier state.
- Current GitHub GET actions/runs/38386775595/approvals returns two records:
  veritasfuji-japan APPROVED; github-actions[bot] APPROVED with comment
  "10 minute wait timer". The endpoint does **not** provide the time of
  the user approval. Environment metadata created_at is NOT approval time.
- At 11:11:15–11:11:19 UTC: protected-marker-no-provider
  (Job 115260436932) SUCCESS.
- Run status completed/success; first attempt on main.
- All dates stored as UTC; 19:56/20:11 are JST conversions.

## Evidence and reproducibility levels

The file evidence/final128_task1_environment_approval_run_38386775595_v1.json
contains a **selected, normalized subset** of GitHub REST observations,
source URLs, the non-replayable historical wait-context and explicit limits.
It is not a raw byte-for-byte archive of GitHub signed logs, and the GitHub
REST endpoints do not cryptographically attest these records to an
independent observer.

The script scripts/final128_390_environment_approval_readback_v1.py:
- Validates the frozen snapshot with strict exact field and JSON-type checks.
- Optionally obtains **only 3 allowlisted unauthenticated HTTPS GETs**
  to GitHub public repository endpoints: run, jobs, approvals.
- Rejects redirects, unexpected response sizes, broken timelines,
  unknown job or review identities, changed run SHA, failed steps and
  inconsistent environment/bypass records.
- Produces separate offline and live readback verdicts; never grants
  execution authority. The --readback flag is a GitHub public GET, **not** an
  OpenAI API call. GitHub GET availability/rate limits are CI dependencies.

CI is PR-only with contents: read, checkout pinned at exact PR HEAD,
no Provider credentials, no Environment, and no manual dispatch.
It requires both offline negative tests and live re-readback, JUnit
failures/errors/skips=0, hashes the evidence/report and uploads
SHA-only and status-only artifacts.

## Precise proof boundary

The meaningful claim is **ENVIRONMENT_APPROVAL_GATE_OBSERVED** for this
specific zero-Provider marker. The before-vs-after gate was *observed* in
the live workflow. Completed job and approval records are currently
re-readable. The original preapproval waiting state is historical and
not durably independently attested.

It does NOT prove an independent second reviewer:
Prevent self-review was unchecked, with the sole reviewer also the run
initiator. GitHub Environment approvals do not themselves prove full
IAM/credential/egress bypass protection, protection of the as-yet
uninstalled live Task1 sender, globally immutable atomic single-use
grant, enforced Provider project billing cap, Native AgentDojo scorer
or actual Utility recovery.

**Task1 real Provider execution remains DENY, no new paid calls, no
new Native scores. Frozen Final128 A=93/128, B=64/128, B injection
success 0/128 remain historical and unchanged.**

## Reviewer instructions

1. Review the exact 5-file PR diff and confirm no existing frozen code
   was edited.
2. Check the dedicated PR-only CI plus shared CI and existing #387
   historical workflow freeze scanner against exact HEAD.
3. Compare the run, jobs and approvals using the three GitHub URLs
   in the fixture, and retain the provenance caveat.
4. Do not merge solely because source fixtures or CI are green.
   No new workflow_dispatch, no secret usage, no real Provider calls
   or implicit authorization should be added by #390.
