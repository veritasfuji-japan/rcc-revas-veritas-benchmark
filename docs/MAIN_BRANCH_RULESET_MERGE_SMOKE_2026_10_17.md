# Main Branch Ruleset Merge Smoke — 2026-10-17

**Status:** operational check pending human-controlled PR merge. **No paid Provider or tag issuance authority.**

## Purpose

Verify that a normal **documentation-only pull request** can be merged into the protected `main` branch by the repository's single maintainer after branch Ruleset #25299895 was activated.

This file is the entire intentional diff. It changes **no executable code, workflow, dependency, policy engine, GitHub Ruleset, secret, credential, tag, or paid-model integration**.

## Pre-merge checks

- [ ] PR targets `main` and has exactly this documentation-only diff.
- [ ] Check runs have completed without unexpected failures.
- [ ] PR GitHub UI reports mergeable under the active branch Ruleset.
- [ ] Ruleset #25299895 remains **active**, targeting only `refs/heads/main`, with PR requirement, zero required approving reviews, deletion/force-push restrictions and no bypass actors.
- [ ] Task1 singleton tag `refs/tags/final128-task1-first-two-real-responses-v1-consumed` remains **absent**. Task1 tag Ruleset #24921425 remains active.
- [ ] User explicitly confirms merge of this documentation-only PR. **Do not automatically merge it.**

## Post-merge interpretation

If the GitHub PR merge succeeds with the branch Ruleset active, it demonstrates that the **normal single-maintainer PR merge path is operational** for this repository configuration. It does **not** prove branch protection cannot be changed by a repository administrator or guarantee future CI results.

Document the resulting new `main` SHA and confirm branch protection is still active. If merging fails, stop and diagnose the exact GitHub error; do not add bypass actors or disable Rulesets to make a test pass.

## Unchanged execution boundary

Issue [#427](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/427) remains **NO-GO** for paid Task1 Native A/B until a separate, verified privileged-read and ruleset-change control at singleton issuance, plus new explicit exact-main-SHA spending authorization.

Do **not** dispatch any paid workflow, retry old paid Runs, create/consume the production singleton tag, change the tag Ruleset, or use this smoke PR as Provider authorization.
