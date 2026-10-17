# Task1: owner-privileged GitHub Ruleset read-only checkpoint V1

**Decision: AUDIT-ONLY. PAID DISPATCH IS NO-GO.** This procedure checks a **real** Ruleset via a privileged GitHub credential on the owner's trusted computer; it does not sign, issue, authorize or consume anything.

## Verified situation (October 17, 2026)

- A human-authorized GitHub app connection can read repository Ruleset [#24921425](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/rules/24921425) as active with an explicitly empty `bypass_actors: []` and three rules: deletion, update and non-fast-forward. Its conditions include the Task1 singleton tag with no exclusions.
- GitHub Actions read-token [Run #39021182542](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39021182542) **omitted** `bypass_actors` entirely even though GET returned HTTP 200. GitHub's documented response redaction for insufficient ruleset permissions explains the discrepancy.
- First integrated NO-EFFECT [Run #39024259712](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39024259712) succeeded on 13 **synthetic** cases and 6 offline unit tests. This is not production evidence.
- GitHub API reports `main.protected: false`. Repository Ruleset listing at the time contained four active **tag** Rulesets, not a main-branch Ruleset. Protecting `main` requires a separate intentional owner action and impact review, not an automatic change in this PR.

## What the owner-local tool verifies

`scripts/final128_task1_owner_privileged_ruleset_readonly_capture_v1.py` is deliberately incompatible with `GITHUB_ACTIONS` and `CI`. It has **no workflow**, no GitHub write-capable code and no Provider SDK.

After explicit operator action, from a trusted computer outside GitHub Actions:

1. Review the script and confirm the current exact 40-character `main` SHA in the GitHub UI. Do not use a prior SHA if a PR has since merged.
2. If you **already possess** a safely managed GitHub credential that may inspect all Ruleset fields, supply it to the *local process only* as `VERITAS_RULESET_OWNER_TOKEN`. Do **not** add such a token as a repository/Environment secret, commit it, send it in ChatGPT/LinkedIn/GitHub comments, or obtain unnecessarily broad privileges merely for this rehearsal.
3. Run `python3 scripts/final128_task1_owner_privileged_ruleset_readonly_capture_v1.py --expected-main-sha FULL_40_CHARACTER_SHA` locally. No external Python dependencies are needed.
4. The tool makes only four fixed-endpoint GETs to `api.github.com`: exact singleton tag (must return 404), branch `main` (must equal expected SHA), repository Rulesets list (must include exactly one active target Ruleset ID), and target Ruleset detail. It refuses a missing/null/nonempty `bypass_actors`, wrong protection types, different name patterns, nonempty exclusions, wrong source/identity or unparseable Ruleset update timestamp.
5. Success emits categorical `OBSERVATION_VALID_READ_ONLY_NOT_ISSUANCE_AUTHORITY` and SHA256 over a **minimal sanitized, local and unsigned** observation, plus `PAID_DISPATCH_NO_GO`. The digest does NOT authenticate the inspector, GitHub response source, privileges, time, or continuous Ruleset protection. It is **not** a signed privileged attestation, nonce-based replay barrier or proof that a GitHub administrative setting will not change.

**Important:** Unlike the connected GitHub app used for a direct authorized inspection, a locally acquired token may not have write access to the Ruleset and may return a redacted field. This is a normal **refusal**. Do not change GitHub permissions or disable security checks just to achieve a green result.

### What not to do

- Never run this script in GitHub Actions, Codespaces CI, shared shells or untrusted machines. In particular, **do not** place a Ruleset-admin GitHub token in the paid workflow.
- Never reclassify `bypass_actors: MISSING` as `[]`. An authenticated GET HTTP 200 is insufficient.
- Do not create/delete the one-use tag, modify the Ruleset or manually trigger the paid Provider workflow to test whether the read succeeds.
- Do not treat SHA256 or this read as authority at tag issuance. Even repeated reads do **not** close the administrator-change window between Ruleset GET and ref POST.

## Acceptance and release decision

This PR is successful if static/offline tests of **real-shaped responses** are green and no write or Provider path was added. Separately, a human owner may collect real privileged evidence locally, *if an appropriately secured credential already exists*. The result can become part of a human audit, but no run may consume the production tag or call a paid Provider based on it.

The **unresolved production dependency** is a trustworthy enrolled observer/key/issuer separation **and** enforceable change control over the Ruleset at issuance. A solo-admin repo without an independently enforced change barrier cannot claim cryptographic atomicity from a local hash. Also review main branch protection as a separate operator decision with its own safe migration plan.

[Issue #427](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/427) remains OPEN/NO-GO. New paid execution would require a separate architecture security review and **new, explicit approval for the then-current main SHA**; older approvals and Runs #39010798949 / #39018816423 must not be reused.
