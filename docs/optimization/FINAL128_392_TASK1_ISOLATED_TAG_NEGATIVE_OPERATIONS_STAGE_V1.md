# Final128 #392 — REAL GitHub isolated tag negative operations, STAGED ONLY

## Purpose

Extend the completed #391 GitHub Environment protected test-only tag creation
evidence with a *separately authorized* future negative-operation experiment:
ONE duplicate POST, ONE forced update PATCH, ONE DELETE, with a strict fixed
SHA readback before and after each attempted mutation.

This PR **only creates source, CI, tests, and docs**. No tag mutation will run
from PR CI or simply by merging. The manually triggered protected writer
must receive **new, explicit human permission**, separate from the approval
to prepare this PR. These attempted operations are *real GitHub writes* and
could damage the test-only tag if the protections do not work.

## Exact protected object

- Fixed test-only ref:
  refs/tags/final128-task1-real-ab-once-v1-391-test-only-global-consumed
- Expected Git commit:
  d9ba430e62d37c7b776bcfc93e3d46bc51f6ae3e
- Distinct existing update target:
  c9accc3a15d97b53d0d3e140b2410f659aa0391f
- Task1 Ruleset: 24921425 / Task1 Single-Use Protection
- Environment: task1-real-model-pilot
- **Production singleton NOT used**:
  refs/tags/final128-task1-first-two-real-responses-v1-consumed

## Observed prerequisites

#391 protected test-only creation ran successfully on 2026-10-13,
run 38396754454:
- protected job 115293852526 succeeded following GitHub Environment approval
  and 10-minute wait;
- job logs report GitHub POST 201 and ref GET 200, followed by a live
  independent GitHub REST readback of the test tag at the exact SHA;
- no Provider credential/calls, no Native scorer or official Utility changes.

#392's PR-only read-only audit fetches the current fixed test ref and GitHub
Ruleset ID 24921425 and verifies scope, active enforcement and configured
update/deletion/non-fast-forward prohibitions. Privileged bypass metadata
missing from public GET is recorded UNKNOWN, never asserted safe. These
configuration reads **do not prove actual rejection**.

## Manual writer safeguards and proof levels

New workflow:
.github/workflows/final128-392-isolated-protected-tag-negative-operations-probe.yml

- workflow_dispatch only, main branch only, exact operator/triggering actor,
  run_attempt=1; preflight without Environment uses exact typed consent:
  I AUTHORIZE TEST TAG DUPLICATE UPDATE DELETE DENIAL NO PROVIDER
- Real negative writer is gated by Environment and uses job-scoped GitHub
  contents: write; no checkout, third-party action or Provider secret.
- Entire inline Python writer is exact Git blob pinned by read-only
  source audit and PR CI. No dynamic repository code is run in writer.
- A fixed test-only URL allowlist permits only GitHub POST refs (with exact
  payload), PATCH/DELETE and GET for the same test tag.
- The initial GET must match the expected ref/type/SHA. A duplicate POST
  must be rejected specifically for already-existing ref; no generic 422
  or auth-denied 403 is treated as duplicate protection.
- Forced PATCH targets a different *known existing* commit SHA, so a real
  update would be observable. A specific repository ruleset violation
  with protected-ref update reason is required.
- DELETE is attempted only after duplicate and update denials, and
  specific repository ruleset violation with protected-ref deletion
  reason is required.
- Readback must show the original exact ref/type/SHA after each attempt.
  Any unexpected success, unknown result, mismatched ref or generic
  response stops immediately; no retries and no restoration attempts.
- The tag remains in place on expected denials. If the protection fails,
  it may be moved or deleted: the run fails and manual incident review is
  needed; **do not attempt automated repair**.
- A manual rerun can trigger the same attempts again if freshly dispatched;
  the run_attempt guard only prevents GitHub rerunning *the same run*.
  This is not a proven globally single-use protected issuer.

## Audit and evidence

PR-only CI:
.github/workflows/final128-392-isolated-tag-negative-source-readonly-audit.yml

- full workflow Git blob pin, exact HEAD, no tokens/Provider, PR-only;
- offline negative test matrix including synthetic API response classifiers,
  invalid tag/Ruleset and modifications to source;
- 2 fixed public GitHub GETs (ruleset + test tag), not a write test;
- JUnit checks, SHA256 evidence/manifest, unscored artifact only.

Once separately authorized and run, **different future PR** must persist
the actual run ID, Job IDs, explicit denial statuses, exact timeline,
readback SHA, approval information, provider-zero boundary and incomplete
proof claims. Do not promote PR CI alone to PROVEN.

## Limitations

Actual update/delete denial for this tag is **NOT PROVEN BEFORE MANUAL RUN**.
Even after three explicit denials, only this GitHub Actions token / ruleset
surface was tested. GitHub job-scoped contents:write is NOT create-only
authority; the Environment currently allows self-review and does not prove
IAM/credential/network bypass impossibility or global atomic once issuance.

No real Task1 Provider calls permitted or performed. Real Provider Task1
remains **DENY**. Historical frozen Final128 utility/scorer results unchanged.
