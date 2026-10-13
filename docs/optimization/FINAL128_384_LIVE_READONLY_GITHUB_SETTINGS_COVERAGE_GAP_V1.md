# Final128 #384 — LIVE read-only GitHub Settings / tag ruleset coverage audit

## Important **observed** mismatch (2026-10-13)

The GitHub connector read these **current repository REST responses**, rather
than assuming controls from the #383 offline fake store:

- GET \`/repos/veritasfuji-japan/rcc-revas-veritas-benchmark/rulesets/24921425\`
  showed \`Task1 Single-Use Protection\`, \`target:"tag"\`,
  \`enforcement:"active"\`, \`bypass_actors:[]\`,
  \`current_user_can_bypass:"never"\`, three rules:
  \`deletion\`, \`update\` and \`non_fast_forward\`.
- Its include pattern is
  \`refs/tags/final128-task1-real-ab-once-v1-*\`.
- #383 froze a **DIFFERENT global singleton** ref:
  \`refs/tags/final128-task1-first-two-real-responses-v1-consumed\`.
  That exact singleton does **NOT match** the observed Task1 ruleset pattern.
- The exact tag GET
  \`/git/ref/tags/final128-task1-first-two-real-responses-v1-consumed\`
  returned 404 at observation. Absence does **not** grant execution rights:
  creating it without the correct protections would leave a bypass gap.
- Older per-commit/per-run \`final128-task1-real-ab-once-v1-*\` tags
  exist, illustrating why a single **fixed** protocol-wide ref and
  confirmed immutable protections are different requirements.

**Therefore #383's proposed fixed ref is NOT verified protected by the
observed currently active Task1 ruleset.** This is a concrete blocker,
not merely an untested possibility. #383's 249 passing offline tests
prove only the fake in-memory single-use behavior.

## What this PR can verify without writing to GitHub

The new script makes only unauthenticated HTTPS **GET** requests to the
public GitHub REST ruleset list, each exact ruleset detail, and the
single exact proposed tag-ref path. It has no arbitrary API URL input,
no token, no external mutation and no Provider calls. It emits a
redacted read-only report with rule IDs/names, target/enforcement,
glob inclusion/exclusion, deletion/update/nonfastforward,
explicit bypass fields and fixed-tag presence.

The evaluator requires a complete detail collection and an observed
matching active tag rule with all required rules and zero bypass actors
*before even reporting that defensive rule coverage appears to match*.
Failures, 403s, incomplete pagination, bad JSON, stale/unknown tag state
and inaccessible endpoints stay \`UNKNOWN\`, never \`PASS\` or execution
permission. All outcomes end in \`live_dispatch_permitted:false\`.

A public API rule-detail observation is NOT a third-party authenticated
immutability audit. GitHub administrators and credentials with bypass/
ruleset-edit power can still change actual protection. This PR does not
try to assume current-user bypass semantics imply *all* privileged
actors are constrained.

## Currently unreachable configuration controls

The connector does **not** permit these endpoint families; they cannot
be honestly labeled checked or compliant:
- GitHub \`task1-real-model-pilot\` Environment restrictions/reviewers;
- Actions default GITHUB_TOKEN permission and workflow editing policies;
- branch protection admin endpoint (connector returned 403);
- dedicated Provider secret actual scope/availability (never read secrets);
- current Provider model access/prices, **actual** project billing hard stop;
- production IAM/egress and credential-bypass resistance;
- fresh human consent and a real atomic issuer/ref consumption receipt.

The live read-only CI is a *diagnostic*, not a protected attestation.
The PR workflow has \`permissions:contents:read\` and only
\`pull_request\` / \`push\`; no \`workflow_dispatch\`, no API key or writable
GitHub token. The test job never creates a tag. The publicly accessible
ruleset API may be rate limited; unavailable results are reported
\`UNKNOWN\`, not green.

## Actual fix required outside #384

A repo administrator must create or update a GitHub tag Ruleset which
**explicitly targets**
\`refs/tags/final128-task1-first-two-real-responses-v1-consumed\`,
enforces deletion/update/non-fast-forward protections and audits all
bypass and ruleset modification permissions. A successful rule GET is
still not sufficient to mint a real single-use issuer: independently
verify effective tag immutability and rule editing permissions.

Then verify and configure the dedicated protected Environment,
restricted credentials/egress, protected workflow source, actual
project-spending stop and immutable evidence; require a separate
specific user approval **before** any paid A/B first Provider calls.
A new ruleset alone does not clear other blockers.

## Merge gate / scored-result nonclaims

#384 implementation should be judged only as a *read-only detector*:
all exact-HEAD CI green, no skips, artifact SHA, actual GET statuses and
remaining UNKNOWN controls described explicitly. No API spend, no
new actual native Tool run/Scorer, no new Task1 Utility.

Historical frozen V13 (not remeasured here) remains
Arm A Utility 93/128, Arm B Utility 64/128, Arm B attack success 0/128.

**NO real Provider dispatch is authorized by #384 or its merge.**
