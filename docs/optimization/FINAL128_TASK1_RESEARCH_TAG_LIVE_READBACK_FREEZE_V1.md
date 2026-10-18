# Final128 Task1 — research-only Git tag live readback evidence freeze V1

**Observation date: 2026-10-18. STATUS: RESEARCH REF READBACK OBSERVED. NOT LIVE EXECUTION AUTHORITY. PAID TASK1 REMAINS NO-GO.**

This record freezes selected **read-only GitHub REST GET observations** made after a human-operated iPhone research-tag issuance. It is not a replay of the original write, a raw/signed HTTP transcript, a real Provider result, or an attestation independent of this repository. It does **not** change the protected research ref or any workflow, secret, Environment, Ruleset, or Provider authorization.

The companion structured snapshot is [`evidence/final128_task1_research_tag_live_readback_2026-10-18_v1.json`](../../evidence/final128_task1_research_tag_live_readback_2026-10-18_v1.json). Git file hashes protect repository contents within GitHub's control domain; they are **not** third-party attestations.

## Exact frozen identifiers

| Item | Read-only observation / fixed value |
| --- | --- |
| Repository | `veritasfuji-japan/rcc-revas-veritas-benchmark` |
| Research-only ref | `refs/tags/final128-task1-research-first-two-once-v1` |
| Ref target object type | `commit` |
| Ref target SHA | `4e864ebad860be2ce71a6c233e98a581094b45aa` |
| Main SHA at observation | `4e864ebad860be2ce71a6c233e98a581094b45aa` |
| Research Ruleset ID | `25305970` — `Task1 Research Single-Use Protection V1` |
| Research Ruleset state | `active`, target `tag`, exact included ref only |
| Research Ruleset protections | `deletion`, `non_fast_forward`, `update` |
| Research Ruleset exceptions | `bypass_actors: []` explicitly returned by the inspected Ruleset detail |
| Frozen `.github/workflows/ci.yml` blob | `35eeb3670190cc96b341ea834cd03df11f8ed46e` |
| PR that restricted CI tag push | [#439](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/439) — merged |
| Actions by research tag branch, checked at observation | `total_count: 0` |
| Separate production singleton ref | `refs/tags/final128-task1-first-two-real-responses-v1-consumed` |
| Production singleton matching refs at observation | `0` — no consumption is implied or performed by the research tag |
| Task1 paid-execution hold | [Issue #427](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/427) OPEN / **NO-GO** |

The exact research ref GET returned the specified ref with object type `commit` and the 40-hex SHA above. This is stronger than interpreting a nonempty prefix-search result, but proves **only current Git reference state at inspection time**. The configured tag Ruleset forbids reference update/deletion in the observed configuration; an owner/admin able to change repository policy remains a different threat boundary.

## Reproducible GET-only audit locations

All links below are for **read-only** inspection. Inspect exact objects/fields, not only HTTP success; no write operation is requested.

1. [Exact research Git ref](https://api.github.com/repos/veritasfuji-japan/rcc-revas-veritas-benchmark/git/ref/tags/final128-task1-research-first-two-once-v1) — expect exact `ref`, `object.type=commit` and `object.sha=4e864ebad860be2ce71a6c233e98a581094b45aa`.
2. [Research tag Ruleset detail](https://api.github.com/repos/veritasfuji-japan/rcc-revas-veritas-benchmark/rulesets/25305970) — inspect state, exact include, `deletion`/`update`/`non_fast_forward`, and explicit `bypass_actors: []`. A missing field is UNKNOWN, **not** an empty list.
3. [Current main branch](https://api.github.com/repos/veritasfuji-japan/rcc-revas-veritas-benchmark/branches/main) — observed HEAD was the frozen SHA; it may advance after this evidence PR.
4. [GitHub Actions scoped to the research tag](https://api.github.com/repos/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs?branch=final128-task1-research-first-two-once-v1&per_page=25) — returned `total_count=0` at observation. This query is neither exhaustive GitHub App telemetry nor proof of no paid/third-party effects.
5. [Production singleton prefix search](https://api.github.com/repos/veritasfuji-japan/rcc-revas-veritas-benchmark/git/matching-refs/tags/final128-task1-first-two-real-responses-v1-consumed) — returned `[]` at observation, for a **different, production-only** ref.
6. [Frozen CI source](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/4e864ebad860be2ce71a6c233e98a581094b45aa/.github/workflows/ci.yml) — `push.branches: [main]` and `pull_request`, rather than unfiltered tag push.

The earlier no-paid [Run #39015342320](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39015342320) was reported `SUCCESS` for **local secret-format preflight only**. It did not authenticate the credential against OpenAI, send model requests, prove a hard spend ceiling, or score official Native Utility.

## Operator POST and evidence provenance boundary

The operator used an iPhone Shortcut to attempt creation of the fixed research ref. An initial Shortcut invocation displayed a response-parsing error and subsequent GitHub GET checks showed the research ref absent. Later, the operator reported success and independent GitHub exact-ref GET and matching-ref GET showed the correctly targeted ref. This record does **not** contain the original successful `POST /git/refs` response, a verified HTTP 201, a signed request transcript, or proof of exactly how many POST attempts occurred. **Do not claim that the actual create request executed exactly once.**

The audit performed for this freeze used read-only GitHub APIs. **Do not replay** the Shortcut, try a duplicate POST, PATCH or DELETE, run a new tag negative-probe on this ref, or consume a different production ref to enhance the evidence. The user confirmed the issuance Shortcut had a stop action restored at the beginning.

## Observed versus NOT PROVEN

**OBSERVED (bounded):**

- One correctly named Git ref currently exists and points to the specified frozen commit.
- One exact active research-only tag Ruleset is configured with update, non-fast-forward and deletion protections and an explicit empty bypass list.
- The frozen `ci.yml` is main-branch push and PR triggered after PR #439.
- The tag-branch Actions query returned zero runs at observation time.
- The production consumed tag was absent on the observed GET; Issue #427 remained open.

**NOT PROVEN / NOT AUTHORIZED:**

- At-most-once real POST issuance across the initial parsing-error ambiguity; global durable lease/Run-bound single-use consumption.
- Binding of the research ref to an authenticated GitHub run/job, independent issuer, controlled recipient, Native first A/B request SHA256, Provider key release, trusted signature or budget approval.
- Admin-proof immutability, independent attestation, all GitHub App hooks/event effects, complete network/credential/IAM bypass resistance, or absolute zero external side effects.
- Any actual OpenAI-first-pair A/B responses for this research claim, Provider billing receipt, injection blocking, Native tool execution, terminal trajectories, official scorer result, recovered Task1 Utility or Final128 Utility.
- A hard Provider spend limit or approval for **any** paid workflow. Historical permissions/phrases are **not reusable**.

The existing paid-capable `Task1 Native First Two Chat A/B PROTECTED MANUAL V1` workflow consumes the **separate production singleton ref** and requires protected Environment secrets and separate human/billing authorization. The research tag does not satisfy those preconditions. Its intended first A/B packets are initially identical and do not by themselves measure attack/VERITAS post-read outcomes.

## Safety and change scope of this evidence PR

- **Add documentation and selected normalized JSON observation only**; no runnable code or workflow changes, Ruleset edits, secret access, environment changes, new tags, GitHub write probes, paid Provider requests, bank effects or scoring.
- Do not invoke `workflow_dispatch` or rerun old Run #39010798949. Issue #427 stays OPEN/NO-GO until a later, explicitly authorized and independently reviewed decision.
- Later checks may observe drift. If `main` moves after this freeze, do not silently reinterpret the frozen SHA; if the tag/ref or Ruleset changes, record that discrepancy without repairing or reissuing it.
- Source-controlled evidence is useful for review and traceability **within the repository trust domain**, but no independent signed archival receipt is claimed.

**Conclusion: `TASK1_RESEARCH_TAG_LIVE_READBACK_OBSERVED_NO_PROVIDER_AUTHORITY`. Paid Task1 execution: `NO-GO`.**
