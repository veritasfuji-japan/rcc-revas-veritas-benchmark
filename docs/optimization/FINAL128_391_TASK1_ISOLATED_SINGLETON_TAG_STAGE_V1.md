# Final128 #391 — isolated REAL GitHub singleton probe, STAGED / NO DISPATCH

## What this PR does

#391 stages one **separately approved**, manually triggered, actual GitHub
ref creation probe, plus a **PR-only read-only** source/ruleset audit.
This tests the GitHub infrastructure boundary with a fixed test-only ref,
not the Task1 paid Provider or production lease.

The synthetic tag is:
refs/tags/final128-task1-real-ab-once-v1-391-test-only-global-consumed

The protected production Task1 singleton remains:
refs/tags/final128-task1-first-two-real-responses-v1-consumed

These tags are different. **DO NOT consume the production singleton** in
this experiment. The test-only tag is intended to remain permanently as
evidence; there is no cleanup/delete stage.

## Actual current ruleset observed before this PR

Task1 Single-Use Protection, ruleset ID 24921425:
- target tag; active
- refs/tags/final128-task1-real-ab-once-v1-* and
  refs/tags/final128-task1-first-two-real-responses-v1-consumed
- deletion, update, non_fast_forward prohibited
- bypass_actors empty; current_user_can_bypass never

The test tag matches the first pattern. These are currently observed GitHub
ruleset fields, **not empirical proof of denial**. Creation permission and
actual enforcement remain to be tested on a later explicitly authorized run.

## How the manual workflow is guarded

.github/workflows/final128-391-task1-isolated-github-tag-once-probe.yml:

- workflow_dispatch only; a required exact typed acknowledgment
  I AUTHORIZE ONE TEST-ONLY GITHUB TAG CREATE NO PROVIDER
- Preflight job (read-only, no Environment, no secrets) rejects any
  non-main, wrong repo/actor/triggering actor, rerun, event or phrase.
- Protected writer job depends on successful preflight and names
  Environment task1-real-model-pilot, previously observed in #389/#390
  to enforce reviewer approval and 10-minute wait on a non-Provider marker.
- The writer has GitHub contents: write **only in that job** (GitHub
  grants broad write capability, not a fine-grained create-only token).
- The job does not check out any repository source and uses no third-party
  Actions; the only intended remote mutation is ONE fixed GitHub REST
  POST to create the synthetic ref, followed by an immutable GET readback.
- Unknown transport outcome, 422/403/error, duplicate or mismatch stop.
  **Never retry** on an unknown result. A later independent re-run
  requires separate fresh approval; the job itself denies run_attempt >1.
- No Provider keys read, no calls to OpenAI, no Native tool execution,
  no bank effects, no scorer, no DELETE/PATCH mutation attempted.
- A successful 201 + GET is evidence of one test-only tag creation, not
  evidence that updates/deletes are impossible or that a trusted issuer
  exists for production Task1.

The manually triggered workflow **must not be dispatched as part of the
PR, by CI, or automatically after merge**. A separate user authorization
to actually create the test-only GitHub tag is required.

## Offline and public-read-only PR gate

- scripts/final128_391_isolated_tag_once_source_audit_v1.py pins
  exact whole workflow Git blob SHA; every byte drift fails tests.
- Public optional GET only to fixed ruleset ID 24921425 and the fixed
  synthetic tag ref; no credentials, GitHub POST or Provider.
- tests/test_final128_391_isolated_tag_once_source_audit_v1.py
  mutates workflow permissions, event, actor, attempts, tag and methods
  and rejects unapproved drift. It tests ruleset mismatches with synthetic
  objects and parses the Python sender source without executing it.
- PR-only CI has read-only permissions, blank Provider token env and
  uses pinned GitHub Actions; JUnit and SHA-only evidence in artifact.
- Existing 15 frozen historical workflows remain unchanged.

## Approval tiers and evidence classification

Stage A (#391 PR): REVIEWED SOURCE / RULESET READBACK ONLY.
Stage B (AFTER MERGE, NEW CONSENT): zero-Provider manual GitHub POST for the
test tag, readback; require real Environment review and timer.
Stage C (NEW CONSENT/PR): negative update/delete trials and replay refusal,
using a separately audited narrowly bounded workflow. The current #391
does NOT attempt deletion/update and cannot claim they are denied.

The real GitHub token still provides contents:write during the Stage B job.
No exclusive create-only IAM scope, strong independent reviewer or
third-party immutable evidence is proved. A repository admin or other
credential path may have broader powers and is NOT audited here. The
Environment still permits self-review.

**Task1 LIVE Provider remains DENY. Final128 historical A Utility 93/128,
B Utility 64/128 and B attack success 0/128 are unchanged.**

## Public GET visibility limitation discovered during #391 CI

The unauthenticated public GitHub Ruleset GET may omit privileged bypass
fields such as bypass_actors. A missing field is **UNKNOWN**, not proof
that no bypass is possible. The CI requires the expected target, active
enforcement, matched test tag scope and update/delete/non-fast-forward
rule types, but marks bypass verification UNKNOWN if those fields are
missing. Separately authenticated admin review and later negative tests
are prerequisites for any stronger production claim. CI green does not
clear the runtime write probe for autonomous execution.
