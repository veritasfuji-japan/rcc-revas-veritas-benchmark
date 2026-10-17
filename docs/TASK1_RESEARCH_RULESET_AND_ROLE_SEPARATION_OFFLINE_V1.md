# Task1 research-only Ruleset and issuer/sender privilege split — OFFLINE REVIEW V1

**Status: SYNTHETIC CONTRACT REVIEW ONLY. NOT INSTALLED. NO DISPATCH AUTHORITY.**

PR #436 demonstrated a *simulated* one-winner Git reference creation across competing mock workers. The fixed research claim \`refs/tags/final128-task1-research-first-two-once-v1\` remains **absent** in GitHub as last read; it is not covered by the currently active production Task1 tag Ruleset #24921425.

This PR only reviews **caller-supplied synthetic snapshots** of proposed GitHub policy, job permissions and run metadata. It does not install/modify Rulesets or Environments, create a tag, execute GitHub Actions, send any Provider requests, read credentials, or authenticate the supplied data. There is **no approval or issuance path**, including on a passing test.

## 1. Proposed dedicated research tag Ruleset — NOT created

A reviewer could later configure a *new*, repository-scoped Ruleset targeting only:

\`refs/tags/final128-task1-research-first-two-once-v1\`

Review requirements for a hypothetical privileged GitHub REST Ruleset snapshot:

| Field | Required synthetic review value |
| --- | --- |
| \`target\` | \`tag\` |
| \`source\` / \`source_type\` | \`veritasfuji-japan/rcc-revas-veritas-benchmark\` / \`Repository\` |
| \`enforcement\` | \`active\` |
| \`conditions.ref_name.include\` | Exact research ref only (single element) |
| \`conditions.ref_name.exclude\` | Empty array |
| \`bypass_actors\` | **Present and explicitly \`[]\`**, not missing/redacted |
| \`current_user_can_bypass\` | \`never\` from a suitably privileged reviewer |
| Rules | \`deletion\`, \`update\`, \`non_fast_forward\` only |
| Creation | No \`creation\` rule; otherwise the first claim could be refused |

\`MOCK_RULESET_ID = 76543210\` is a **synthetic test fixture ID**, not an allocated/enrolled real Ruleset. Any eventual real ID needs an explicit separate enrollment and independent authoritative inspection. The tests do not query GitHub. Missing \`bypass_actors\` remains **UNKNOWN/DENY**, never \`[]\`.

**Do not edit existing Ruleset #24921425 or branch Ruleset #25299895.** The proposed exact-match scope must not overlap the production once-tag. A separate tag name without its own active protection can be deleted or repointed, enabling replay.

The Ruleset may be changed by a repository administrator; a privileged GET and tag POST are not one atomic authority operation. Its \`updated_at\` and any signed prior snapshot are **not** an issuance-time fence. Other overlapping Rulesets may constrain tag creation; an isolated snapshot does not prove complete policy evaluation. A \`contents:write\` issuer can potentially write other refs unless independently constrained by GitHub protection and granted permissions. The checker **does not** assert lifetime uniqueness or admin-resistance.

## 2. Proposed issuer/sender isolation — mock contract, not deployed

| Proposed role | GitHub job \`permissions\` | Environment | Secrets |
| --- | --- | --- | --- |
| **Research claim issuer** | \`contents: write\` only | None | None |
| **Research first-pair sender** | \`contents: read\` only | \`task1-research-native-first-two\` (proposed, not created) | Dedicated research Provider key plus AES-256-GCM capture key |

The future proposed sender's two environment-only secret names are \`TASK1_RESEARCH_OPENAI_API_KEY\` and \`TASK1_RESEARCH_CAPTURE_AES256_KEY\`. They are **names**, not credentials created or inspected by this PR. Existing production \`task1-real-model-pilot\` Environment and all its secrets remain unchanged.

A \`contents:write\` GitHub Actions token is **not** limited to the single proposed tag just because a script references it. Do not put administration credentials, PATs with broad scopes, or Provider keys in the issuer job. The future sender must not receive a write-capable \`GITHUB_TOKEN\`, or be able to invoke an unguarded tag writer through another reusable workflow. Prevent both roles from importing a changed workflow via PR-trigger or untrusted branch inputs. Environment settings, allowed branches, protection rules and approval policy require independent manual review and cannot be inferred from a code snippet.

**Critical handoff gap:** merely checking that a research ref exists, or even checking it points at a commit, cannot identify which GitHub Run owns the claim. It does not authenticate run ID, owner approval, intended model/first packet SHA256, budget, environment release, or prevent a different run from using a previously issued ref. Any issuer-to-sender handoff needs a trusted channel binding exactly one verified run and commit, and needs to fail closed for forged/old/replayed evidence, even with concurrent jobs. That real mechanism is neither proposed as complete nor deployed here.

## 3. Explicit run and response binding (synthetic shape only)

The mock review checks an exact input packet digest for A and B (the **first Native A/B requests are identical**), original case, model, named research ref, main SHA, run ID, no retries, and at most two initial POSTs. The mock flags \`owner_approved=False\`, \`provider_project_hard_cap_verified=False\`, \`ref_created=False\` are required because this is **pre-authorization design review**.

The caller can fabricate every mock field. A passing result is labeled \`ALL_SYNTHETIC_SHAPES_MATCH_NO_REAL_AUTHORITY\` and **every** Review field for real provenance, production authority, paid dispatch, actual Ruleset enrollment and tag writes remains false.

## 4. What the tests actually demonstrate

- Accepted shape for an *untrusted synthetic* research-only Ruleset and strict issuer/sender declarations.
- Reject redacted, unknown or nonempty \`bypass_actors\`; wrong ref namespace, broad \`~ALL\`, extra include/exclude or wrong Ruleset source/enforcement/rules.
- Reject \`creation\` protection, missing update/deletion/non-fast-forward protections or multiple active fixture entries.
- Reject issuer access to any Provider secret, issuer Environment, sender \`contents:write\`, administration/actions write, missing capture key, production Environment, and extra roles.
- Reject forged consent, hard-cap claims, already-issued ref claims, incorrect SHA/run/model, changed arm hashes, third model call or retry.
- Verify the implementation exposes no GitHub REST client, real issuance, Provider transport, executable workflow, credential access or authorization branch.

Run locally with no credentials:

\`pytest -q tests/test_final128_task1_research_ruleset_role_review_offline_v1.py\`

## 5. Stop conditions and distinct future decisions

1. **Before creating any REAL research Ruleset:** separate operator authorization for exact research ref, rule types, placement/scope and no-bypass intent. Review via adequately privileged GitHub API; never assume an Actions token's omitted bypass field is empty. Existing production protection must remain unchanged.
2. **Before writing a REAL research tag:** separate explicit approval for a non-Provider sandbox test, reviewed exact SHA, enrollment, immutable protections, issuer least privilege and failure reconciliation. Real GitHub race and admin-override risk remains unproven by synthetic tests.
3. **Before sending any PAID OpenAI request:** separate reviewed live sender+issuer handoff; independently verified source/version, environment/key custody, one-shot ledger, real model availability and API billing constraints; new explicit human authorization referencing *then-current main SHA*, Task1 case, model, <=2 first POSTs, no retry, expected loss if A/partial fails, and budget risk. No previous approval transfers.
4. **Before claiming VERITAS attack resistance:** genuine post-read attacked tool response, B-only VERITAS overlay, additional independently generated model turns, zero external effect, same-run scoring and independent assessment. Two identical first-turn requests prove none of this.

**Issue #427 remains OPEN / PAID NO-GO.** Do NOT use the existing protected #423 manual paid workflow, restart historical failed paid Runs, change its \`bypass_actors == []\` fail-closed requirement, create either real tag, alter existing Rulesets, enable paid jobs, or place high-privilege tokens in general Actions. No CI green or PR merge grants spend or execution authority.
