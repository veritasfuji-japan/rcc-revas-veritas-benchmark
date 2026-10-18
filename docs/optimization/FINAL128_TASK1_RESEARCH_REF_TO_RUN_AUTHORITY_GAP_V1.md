# Task1 — live research ref to authenticated Run authority gap V1 (OFFLINE ONLY)

**STATUS: SOURCE-SNAPSHOT CONTRACT CONSISTENT / PAID TASK1 NO-GO. NO ISSUER ENROLLMENT, NO REAL AUTHORITY, NO PROVIDER.**

This PR addresses **evidence interpretation**, not execution. The separately authorized iPhone GitHub research ref now exists, while the previous mock and signed-handoff designs in [`docs/TASK1_RESEARCH_SIGNED_RUN_HANDOFF_OFFLINE_V1.md`](../TASK1_RESEARCH_SIGNED_RUN_HANDOFF_OFFLINE_V1.md) and [`docs/TASK1_RESEARCH_RULESET_AND_ROLE_SEPARATION_OFFLINE_V1.md`](../TASK1_RESEARCH_RULESET_AND_ROLE_SEPARATION_OFFLINE_V1.md) were synthetic. Nothing about a live tag upgrades synthetic Run signatures, mock issuers, in-memory replay ledgers or GitHub self-reported metadata into authenticated paid authority.

## Frozen observation that this offline review consumes

- **Repository:** `veritasfuji-japan/rcc-revas-veritas-benchmark`.
- **Existing research ref:** `refs/tags/final128-task1-research-first-two-once-v1`.
- **Frozen ref target (NOT today's moving main):** `4e864ebad860be2ce71a6c233e98a581094b45aa`.
- **Installed research Ruleset #25305970:** active, exact included ref, deletion/update/non-fast-forward prohibited, explicit empty bypass list in the reviewed GET.
- **Frozen `ci.yml` blob:** `35eeb3670190cc96b341ea834cd03df11f8ed46e` — main-only push and PR. The research tag was issued only after [PR #439](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/439) merged.
- **Snapshot source:** [PR #440's evidence file](../../evidence/final128_task1_research_tag_live_readback_2026-10-18_v1.json), merged into main on 2026-10-18.
- **Separate production consumed ref:** `refs/tags/final128-task1-first-two-real-responses-v1-consumed`. It was **absent in the recorded GET**, but this research tag is not its replacement or permission to create it.
- **Administrative hold:** [Issue #427](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/427), OPEN / paid NO-GO when this work was prepared.

The snapshot is selected source-controlled output of earlier **read-only GET** inspections, **not a fresh, authenticated, independently signed live observation**. The human-operated create attempt first surfaced a Shortcut response-parsing error; later, GitHub's exact-ref GET showed the intended tag. A successful original `POST /git/refs` HTTP 201 transcript or independently verified number of POST attempts is not archived. Never rewrite those limits as proof of one-time issuance.

## Gap matrix: observed property versus missing execution proof

| Boundary | Current evidence | Necessary additional independently checked proof | Current decision |
| --- | --- | --- | --- |
| Exact ref, commit and Ruleset | GitHub exact-ref GET and active no-bypass Rule #25305970 observed; frozen in #440 | Repeat privileged read at a future decision point; separately review admin/rule mutation threat and source provenance | **OBSERVED REF ONLY** |
| Tag ownership by a GitHub Run/job | A ref points to a Git commit, not a Run ID or job ID | Independently verify protected workflow/event/ref, immutable Run ID, run attempt, issuer and intended sender job, not solely variables or PR artifacts | **NOT PROVEN** |
| Issuer identity and recipient binding | #437 signed handoff uses ephemeral test keys and self-supplied context | Trusted enrolled issuer verification; recipient identity challenge/attestation tied to exact request and execution context | **NOT PROVEN** |
| Issuer–sender credential separation | #436 only checks hypothetical permissions/Environment; #423 production workflow is different | Enforce issuer without Provider secrets, sender without ref-write/admin rights; independently review reusable workflows, Environment, IAM and network | **NOT PROVEN** |
| Durable Provider use-once right | GitHub ref was created earlier; it is not a Provider-send consumption ledger | External durable atomic claim/consume tied to authenticated Run/arm/request, and denial across runners after crash/unknown outcome | **NOT PROVEN** |
| Native exact first A/B request binding | Historical offline mock binds caller-supplied hashes, not this tag to an authenticated model send | Verified pinned AgentDojo/VERITAS inputs, distinct owned A/B origins, exact raw request digests and immutable signed handoff | **NOT PROVEN** |
| Partial/unknown outcome and no retry | iPhone parser error demonstrates an observation ambiguity; prior mocks model no retry | Durable pre-send intent and partial-A-only terminal denial, Provider receipt correlation, reconciliation without repeating uncertain calls | **NOT PROVEN** |
| Cost and authorization | No fresh paid consent from this PR; local secret-format diagnostic is not live OpenAI authentication | New explicit operator permission bound to model/case/commit/Run/two first calls; independently reviewed billing and remaining spend risk | **NO-GO** |
| Provider and scoring | Research tag and a zero-run Actions query; neither is a Provider result | Actual encrypted Provider reply evidence, source-owned tool continuation, real native terminal/scorer independently verified | **NOT PROVEN** |

**Boundary rule:** `Authorization at tag issuance != permission at Provider execution`. A static GitHub tag may support reproducible source identity; it is not a lease that can be redeemed by a new Run. Since the research tag already exists, do not try to issue it again, delete/retarget it, or perform a second claimed consumption against it.

## Offline no-promotion guard in this PR

- Module: [`scripts/final128_task1_live_ref_run_authority_gap_offline_v1.py`](../../scripts/final128_task1_live_ref_run_authority_gap_offline_v1.py).
- Tests: [`tests/test_final128_task1_live_ref_run_authority_gap_offline_v1.py`](../../tests/test_final128_task1_live_ref_run_authority_gap_offline_v1.py).
- Test command on a local checkout: `python -m pytest -q tests/test_final128_task1_live_ref_run_authority_gap_offline_v1.py`.

The module performs **no network, GitHub API, secret lookup, subprocess, tag write, workflow dispatch, signature issuance, or Provider call**. It reads a caller-supplied mapping and validates that the source-controlled evidence still matches the exact frozen 2026-10-18 observation. A matching result means **snapshot consistency only**; it explicitly reports live reauthentication, Run identity, producer/sender separation, global Provider single-use, signed digest binding, cost hard stops and paid dispatch authority as **false**. Tests refuse altered commit/ref, redacted/bypassed ruleset, production-name substitution, invalid boolean coercion, attempted promotion of previously unproven claims, fake bill approval, and arbitrary forged Run/job/OIDC claim objects.

This is an **offline adversarial example and documentation**, **not a new wired pre-dispatch guard**. The production workflow does not call this module. CI green would establish these test cases passed, not that any live IAM/egress/single-use boundary was enforced. Tests also prevent outward socket connections and clear common secret environment variables.

## What must happen before a future paid Run is even considered

1. Independently verify current protected GitHub Run/job identity and source/ref/event binding; separately enroll the signer/verifier and recipient, rather than trusting a reconstructed artifact.
2. Design and prove a **new**, durable Provider execution-time use-once control with issuer/sender isolation, provider-secret custody and fail-closed unknown-result behavior. Do not repurpose or reissue the already-created research tag.
3. Obtain provider-origin/cost-control evidence and fresh, separate, specific financial risk approval; an estimated USD 1 target is not a guaranteed ceiling and prior approvals cannot be reused.
4. Reassess the dedicated production workflow, separate protected production once tag, and Issue #427. Until then, do not manually dispatch `Task1 Native First Two Chat A/B PROTECTED MANUAL V1`, rerun Run #39010798949, or trigger any paid model request.

**Result: `OFFLINE_SNAPSHOT_CONSISTENT_REF_NOT_RUN_AUTHORITY`. Production singleton: untouched. Paid Task1: `NO-GO`.**
