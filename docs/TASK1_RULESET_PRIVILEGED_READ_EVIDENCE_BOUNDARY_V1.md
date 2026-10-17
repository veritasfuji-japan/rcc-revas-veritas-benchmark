# Task1 Ruleset Privileged Read Evidence Boundary V1

Status: **DIAGNOSTIC / NO-GO FOR PAID DISPATCH**. This note does not authorize API sending, tag creation, Ruleset changes, or retries.

## Why

The first paid-capable Run [#39018816423](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39018816423) did **not** send either Provider request. Its singleton Ruleset predicate returned `423_NO_EXACT_ACTIVE_NO_BYPASS_PRODUCTION_TAG_RULESET`. The subsequent GET-only Run [#39020549124](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39020549124) observed:

- exact consumed tag absent (404);
- Ruleset list HTTP 200, 4 items, expected active tag Ruleset listed;
- Ruleset detail HTTP 200 and the exact tag included;
- `bypass_actors == []` was **not** established by the Actions token, so the original predicate correctly failed closed.

GitHub's Ruleset API may omit `bypass_actors` from a response for callers without write access to the Ruleset (not the same as `contents: write`). **An omitted field is unknown, never evidence of no bypass actors.** This must not be "fixed" by treating missing/null as empty.

## Safe evidence collection by a privileged human

1. From GitHub repository **Settings → Rules → Rulesets**, open the exact repository-tag Ruleset ID `24921425`. Verify it is active, the intended singleton `refs/tags/final128-task1-first-two-real-responses-v1-consumed` is included, and the Ruleset includes deletion, update, and non-fast-forward protections. Verify no bypass actors are configured.
2. Record a bounded signed/traceable inspection note: Ruleset numeric ID, repository, GitHub observation timestamp in UTC, logged-in inspector role or account identifier, expected tag, observed protection rule types, and bypass conclusion `EMPTY` or `NOT_VERIFIABLE`. Do **not** include tokens, headers, credentials, session cookies, private user names, or raw GitHub API responses in CI logs, issue bodies or public artifacts.
3. If the inspector can obtain an authorized Ruleset detail response, use a **locally generated integrity digest of a normalized, narrowly scoped evidence statement** and preserve the original in their private secure store. A digest by itself does not authenticate the observer, establish the source was GitHub, or make the evidence fresh. Do not copy privileged API credentials into GitHub Actions.
4. Compare the inspection to the GitHub Actions GET-only diagnostic categories (MISSING, NULL, EMPTY, NONEMPTY, OTHER_TYPE). For the Actions token, MISSING/NULL/OTHER_TYPE must continue to be treated as UNKNOWN; NONEMPTY means unsafe for the old policy. Only EMPTY directly satisfies that exact field check for that token.
5. A later paid-capable issuer requires a **separately reviewed, race-aware, fail-closed trust design** for fresh privileged evidence at the issuance boundary, including who can alter the Ruleset between inspection and tag issuance, what verifier trusts the evidence, and how changes invalidate it. This document and read-only classifier cannot satisfy that requirement.

## Immutable boundaries

- **NO-GO** for any new paid Provider POST until there is separately authorized new code and a fresh human spending approval bound to the exact new main SHA.
- Never rerun Runs #39010798949 or #39018816423; no retry if a future singleton tag is consumed.
- No GitHub ref POST/PATCH/DELETE, no Ruleset relaxation, no extra bypass actors, and no paid Provider call to test this theory.
- GET-only workflow is manual and must be run as a **new first attempt on main**, only after its reviewing PR is merged. Its result is diagnostic, not authority.
- OpenAI credentials/AES capture key are not required for any step in this note.

Linked issue: [#427](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/427).
