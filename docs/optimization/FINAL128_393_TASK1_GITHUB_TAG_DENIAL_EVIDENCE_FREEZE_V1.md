# Final128 #393 — Fixed evidence for #392 isolated protected GitHub test-tag denials

## Identity and outcome

A **completed real GitHub Actions run** — [Run #38404886383](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/38404886383) — executed the #392 protected negative probe. This PR is a **read-only evidence freeze** of observations, not a new protected test or production authorization.

| Field | Frozen value |
|---|---|
| Repository | `veritasfuji-japan/rcc-revas-veritas-benchmark` |
| Run | `38404886383` |
| Run HEAD | `0129a324f4c5ccd6512d5bf3d354d0b348bd8b2f` |
| Source workflow Git blob | `aaaf8c22d32080e694905a048c640d13b23de2ea` |
| Preflight Job | `115321810022` SUCCESS |
| Environment-gated Job | `115321885432` SUCCESS |
| Environment | `task1-real-model-pilot` |
| Approval records | `veritasfuji-japan` human and `github-actions[bot]` 10-minute timer |
| Test tag | `refs/tags/final128-task1-real-ab-once-v1-391-test-only-global-consumed` |
| Tag target (unchanged) | `d9ba430e62d37c7b776bcfc93e3d46bc51f6ae3e` |
| Ruleset | `24921425`: active tag deletion, non-fast-forward, update prohibition |
| Evidence JSON | `evidence/final128_task1_392_tag_negative_denials_run_38404886383_v1.json` |

## Real GitHub request observations (protected Job #115321885432)

The GitHub job log contains these runtime markers, in order:

| UTC time | Outcome |
|---|---|
| 2026-10-13 13:42:26.2499631 | Initial exact tag SHA readback succeeded |
| 2026-10-13 13:42:27.6721260 | Duplicate ref POST → **422** |
| 2026-10-13 13:42:28.8567719 | Forced ref PATCH → **422** |
| 2026-10-13 13:42:29.7405661 | Ref DELETE → **422** |
| 2026-10-13 13:42:29.7406061 | `392_REAL_GITHUB_TEST_TAG_DUPLICATE_UPDATE_DELETE_DENIED_UNCHANGED` |

The exact published #392 workflow fails if duplicate POST is not specifically an already-existing ref response, if PATCH/DELETE do not carry their respective repository-rule-violation meanings, **or if any post-attempt GET no longer matches the same original ref/SHA**. The completed-success status therefore supports the interpretation that all three semantic refusal gates and all four exact GET readbacks passed **for this one protected GitHub test tag and token**.

**Proof limitation:** The selected run log prints HTTP codes and success markers, not raw HTTP error bodies. The rule-violation string match is inferred from the reviewed #392 workflow source plus success; original full HTTP bodies were not archived. Do not misrepresent the selected markers as third-party-signed raw logs.

## Immutable-style references vs independent attestation

This PR pins the exact fixture content via Git blob ID, pins the workflow source blob, and validates completed run/job/approval REST fields and current ref/ruleset scope by **five unauthenticated GitHub GET requests** (if GitHub allows those public fields). It writes SHA-256 manifest and JUnit results as CI artifacts.

The evidence JSON is a checked-in source-controlled snapshot: a Git blob hash and CI SHA-256 are integrity checks **within this repository's trust domain**, not third-party signatures or an independently operated attestation service. Run log snippets are selected transcriptions, not re-downloadable, independently verified signed archives. If public GitHub API omits privileged bypass fields, the audit must say **UNKNOWN_MISSING_FIELDS**, never infer empty bypasses.

The current `pending_deployments` API is empty after approval; the historical waiting response and the exact approval action timestamp are not replayable from this endpoint. A historical 10-minute timer approval record and job start timeline are observed; this does **not** establish independent review because the same operator could self-approve.

## Exact claim boundary

**OBSERVED:**
- Test-only ref existed, original SHA verified on each phase, remained unchanged.
- One duplicate POST, one forced PATCH, one DELETE each returned HTTP 422 and passed phase-specific semantic denial checks.
- GitHub Environment gate approved deployment (operator and timer bot) before protected job completion.
- Tag ruleset was active with configured update/deletion/non-fast-forward protections.
- The reviewed workflow includes no OpenAI Provider key reference or model call.

**NOT PROVEN:**
- Independently operated approver, signed off-repository attestation, enterprise trust separation.
- Create-only GitHub IAM privilege: #392 writer used broader `contents: write`.
- Globally atomic once-only issuance / lock under concurrent executors.
- Production `final128-task1-first-two-real-responses-v1-consumed` credential/lease issuance or any bypass-resistance across all IAM, credentials and network routes.
- Provider hard spend cap, actual real-model A/B native scorer, fresh Final128 Utility.
- A valid permission to run paid Task1: **paid Task1 remains DENY**.

## Safety / replay constraints

- #393 CI: PR-triggered only, `contents: read`, no stored tokens, no Environment, no GitHub ref modification methods, no workflow_dispatch and no Provider.
- #392 manual workflow remains **not invoked** by this PR. Never dispatch it again to reconfirm the snapshot; tags and mutation attempts are historical evidence, not repeatable requirements.
- If current ref or GitHub REST state drifts from the frozen subset, the optional live audit fails closed. A missing GET is not equivalent to a successful denial.
- The same run cannot demonstrate every possible bypass. Further provider-facing pilots require **newly scoped explicit authorization** and additional independent controls.

Potential next work after freeze: independent external witness and actual bypass-path proof, not paid Provider execution.

## Evidence links

- [Protected denial Run #38404886383](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/38404886383)
- [Previous test-tag creation Run #38396754454](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/38396754454)
- [GitHub Ruleset #24921425](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/settings/rules/24921425)

## Classification

`REAL_ISOLATED_GITHUB_TAG_DENIALS_OBSERVED_LIMITED_NOT_PRODUCTION_ONCE_OR_BYPASS_PROOF`.
