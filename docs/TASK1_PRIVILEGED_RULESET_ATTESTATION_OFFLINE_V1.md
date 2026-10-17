# Task1 privileged Ruleset attestation — offline design V1

**STATUS: DESIGN / OFFLINE CANDIDATE ONLY. NO-GO for paid Provider traffic, tag issuance, or any new singleton consumption.**

## Grounded failure

- Run #39018816423 failed before tag creation and before both Provider POSTs: `423_NO_EXACT_ACTIVE_NO_BYPASS_PRODUCTION_TAG_RULESET`.
- Read-only Run #39021182542, main `1bdf8bc9cc28d33671d5b96ebfd2c81cc75c9f6f`, observed the exact tag HTTP 404; the Ruleset list and detail HTTP 200; the intended tag and active Ruleset ID #24921425; and `EXPECTED_DETAIL_BYPASS_FIELD_STATE_MISSING`.
- Separately authenticated GitHub Ruleset reads showed `bypass_actors: []`, but this is not automatically available to the Actions `GITHUB_TOKEN`. An omitted field MUST remain UNKNOWN/NO-GO.
- The present paid workflow is intentionally unchanged and still fails closed.

## Proposed separation of trust

1. **Ruleset owner / privileged observer**: an enrolled principal whose GitHub authorization permits reading the full Ruleset detail (including `bypass_actors`). Its credentials **never** enter the benchmark repo, GitHub Actions job, or Provider runner. A privileged read must establish repository identity, exact Ruleset ID, enabled enforcement, included singleton tag, required deletion/update/non-fast-forward protections, absence of creation prohibition, no exclusions, and an explicitly present empty `bypass_actors`.
2. **Independent attestor**: binds this observation to a specific run ID, 40-character main SHA, exact singleton ref, and fresh random challenge nonce; records the Ruleset's `updated_at`, `observed_at`, and expiration; signs canonical UTF-8 JSON with an enrolled Ed25519 key stored **outside the Actions runner**. Merely including a public key in the same envelope is NEVER sufficient for trust. A signature only establishes that an enrolled key signed its claims; not that GitHub actually returned them.
3. **Verifier / issuer**: receives the trusted public key from a separately pinned, reviewed, non-user-input enrollment; verifies signature and bindings; independently checks run attempt, main SHA, tag absence and freshness, and obtains a privileged *current* Ruleset state/revision at issuance. Missing, stale, replayed, changed, or unsigned evidence => DENY. Without a production-safe attestor, trusted key enrollment, and a fresh privileged current-state verification method, **remain NO-GO**.
4. **Immutable singleton**: only after all independent authorities pass, an issuer may attempt the one allowed Git ref create and verify the created SHA via readback. It must never retry an uncertain POST or issue a second tag. Provider dispatch requires a separate, explicitly reviewed authorization tied to the new commit and target/cost.
5. **Race / TOCTOU limitation**: GitHub Ruleset reads and ref creation are separate REST operations, not atomic. A snapshot, a short TTL, a signed digest, and even a fresh `updated_at` comparison do **not** remove the interval in which an administrator could modify a Ruleset. A deployable design must address concurrent administrative changes with an independently enforced change freeze/monitor plus stop-on-change, or an equivalent server-side atomic policy; this remains **OPEN**, not proven by this PR.

## Offline validation only

The module `scripts/final128_task1_privileged_ruleset_attestation_offline_v1.py` verifies an **inert hypothetical signed attestation** with a test-supplied public key, expected run/sha/challenge/current Ruleset update revision, and a caller-observed no-tag assertion. Its best result is the literal `EVIDENCE_VALID_OFFLINE_NOT_DISPATCH_AUTHORITY`. It **does not**:
- request GitHub API endpoints, administer Rulesets, issue/consume any refs, or use Provider credentials;
- implement a privileged observation service or a real signature issuance system;
- retrieve or install trusted public keys, run an Actions paid workflow, or grant execution authority;
- establish freshness independently of its caller inputs, prevent signer forgery/theft, or eliminate the Ruleset read/write race.

**Never invoke this library as a replacement for the production `bypass_actors == []` check.** Existing paid workflow, secret handling, Ruleset #24921425 and singleton ref stay unchanged.

## Evidence and decision matrix

| Situation | Result / disposition |
| --- | --- |
| Actions GET omits bypass actors | UNKNOWN; fail closed |
| Signed privileged snapshot with explicit empty bypass list and matching caller-pinned context | `EVIDENCE_VALID_OFFLINE_NOT_DISPATCH_AUTHORITY` only |
| No trusted enrolled key, invalid signature, stale snapshot, mismatched run/SHA/challenge/update timestamp | DENY |
| Nonempty or missing privileged bypass field | DENY |
| Singleton already exists or its status is indeterminate | DENY |
| Ruleset changes after signed observation | DENY if observed; otherwise **race unresolved**, do not issue |
| Privileged attestor service absent / authorizations not enrolled / no safe race control | NO-GO for live issuer |
| User agrees to offline design / PR merges / CI green | Does not authorize paid dispatch |

## Before any eventual live integration

- Obtain a scoped, reviewed mechanism for a privileged observer (no admin credentials in general Actions); ensure independent attestation identity and key rotation/revocation.
- Pre-register cryptographic trust anchor outside candidate evidence, exact issuer/main/repo/ref, challenge nonce, one-time challenge use, freshness clock and immutable audit.
- Reconcile privileged latest state with signed `updated_at` at the issuance boundary, and **close the TOCTOU/admin-policy-change gap** with an enforceable mechanism. Fail closed for uncertain API responses or incomplete key rotation.
- Obtain independent security review, offline adversarial tests, controlled non-Provider/no-tag rehearsal, and **new, explicit paid-API approval for the then-current main SHA**.
- No retries of Runs #39010798949 or #39018816423. Never weaken Ruleset protection or treat an omitted `bypass_actors` field as empty.

Related: Issue #427, merged PRs #428 and #429, and `docs/TASK1_RULESET_PRIVILEGED_READ_EVIDENCE_BOUNDARY_V1.md`.
