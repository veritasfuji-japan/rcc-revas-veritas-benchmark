# Task1 B-pilot research-tag CAS: in-memory REST simulation V1

**STATUS: OFFLINE DESIGN ONLY. NOT A GITHUB-TAG ISSUER; NOT PROVIDER AUTHORIZATION.**

## Goal

Test a **hypothetical** single-winner remote Git reference creation shared by two independent research workers, without creating ANY real GitHub tag or Ruleset, sending model requests, changing credentials, or modifying the existing paid workflow.

The previously merged [PR #435](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/435) implements only local mock \`O_EXCL\` journaling. A local path cannot coordinate separate GitHub-hosted Actions runners. The proposed replacement for *global* coordination would have to rely on one external compare-and-create authority and later enforceable protection against tag deletion/retargeting.

This PR **does not implement that real mechanism**. It simulates only the state transitions of an in-memory fake server guarded by a Python lock. Do not equate a green test with GitHub REST guarantees or production authorization.

## Exact named targets

| Purpose | Reference | Action in this PR |
| --- | --- | --- |
| Proposed fixed research-only claim | \`refs/tags/final128-task1-research-first-two-once-v1\` | **Never created**. String constant only. |
| Existing production singleton | \`refs/tags/final128-task1-first-two-real-responses-v1-consumed\` | **Never touched**. Explicitly rejected by mock. |
| Production tag Ruleset | #24921425 | **Unchanged**; its current include patterns do **not** cover the proposed research ref. |
| Main branch Ruleset | #25299895 | **Unchanged**; protects \`main\`, not the research tag. |

A research tag without a separately reviewed, active, correctly scoped tag Ruleset can be deleted or retargeted by permitted actors. The fake test deliberately simulates an administrator deleting the claim, after which a second contender "wins". Thus, even a future successful GitHub POST would **not** by itself prove lifetime one-shot protection.

## Components (new files only)

- \`scripts/final128_task1_research_tag_cas_mock_v1.py\`
- \`tests/test_final128_task1_research_tag_cas_mock_v1.py\`
- This document

The mock module has no CLI, HTTP/GitHub client, SDK, credential loader, network imports, system command, environment-reading step, Actions trigger, real tag writer, or model sender. Its \`MockDecision\` defaults to **all authorization fields false**, even on \`SIMULATED_CAS_OBSERVED_NOT_LIVE_AUTHORITY\`.

## Simulated algorithm and bounded decisions

1. Require a strictly fixed **research-only** ref and syntactically valid Run ID, 40-character main SHA and equal initial Native A/B SHA256 request digests. These are caller assertions, not authenticated GitHub facts.
2. Fake \`GET\` to inspect absence. An existing ref refuses without \`POST\`; 403/500 or any unknown outcome stops.
3. Fake \`POST\` **at most once** to the shared in-memory server. Atomic creation is simulated by a lock. Under competing requests only one can return mock 201; the other returns mock 422/409 conflict or discovers the ref already exists.
4. **NO retry** after timeout, HTTP 5xx, 429/403, 409/422, a malformed 201 body, or conflicting reference SHA. A timeout can occur BEFORE or AFTER the fake commit, and a 500 can occur AFTER the commit; do not infer outcome from the exception or an eventual readback.
5. On an apparent 201 with exact ref and SHA, fake GET readback must match. If readback is stale, fails, or lacks the reference/SHA, stop. A successful simulated readback is an observation about **fake state only**, never live-dispatch authority.

### Negative tests

- Concurrent runners sharing one fake remote: one winner, one loser.
- Independent fake remote namespaces: both can "win" — demonstrates why independently ephemeral runners cannot provide the lease.
- Preflight 403/500, stale preflight 404, fake 422 with *no* claim, 409, 429, 403, 500 before/after commit, and timeout before/after commit; all stop without retry.
- 201 missing/wrong ref body, fake 201 without an actual stored tag, invalid/missing/wrong-SHA readback.
- Simulated administrator deletes the fake ref, enabling a second winner: **admin-change threat remains unclosed**.
- Changed main SHA, request SHA drift, malformed Run ID, production tag as proposed ref: refusal before any simulated access.
- Every outcome has \`origin_authenticated=False\`, \`live_provider_dispatch_authorized=False\`, \`real_tag_issued=False\`, and \`official_native_scoring_eligible=False\`.

## Still-open conditions before any paid B research pilot

1. **Real GitHub behavior and permissions:** review fixed exact research ref, actual create-ref HTTP behavior, immutable/readback semantics, separate tag Ruleset and enforced exclusions/bypass list from a sufficiently privileged reader. This PR deliberately makes NO real GitHub ref mutations. A real disposable tag test would need a **new explicit authorization**, not the production tag.
2. **Lifetime uniqueness and administrator changes:** any tag authority protected only by repo-owner-modifiable GitHub configuration is weaker than an independently enforced lock. Explicitly document admin override/deletion risk, separation of issuer/write permission from provider-secret sender, and how a read/write race is handled.
3. **Run binding and evidence:** lightweight Git refs bind only a commit SHA to a ref name, **not** a run ID, model, cost authorization, exact request digests, or independent signing identity. These must be externally verified/pinned. A mock plan is never an enrollment, signature, or attestation.
4. **Secret release and billing:** standalone reviewed research-only sender with no automatic replay, at most ONE initial Native Chat POST each Arm A/B, encrypted body **before** strict parse, safe unknown-result handling, key/decryption custody, dedicated API project and independently verified billing constraints. USD 1 is a soft proposed tolerance, not a code-enforced hard account cap.
5. **Exact operator consent:** after code/security review, independently confirm current main SHA, frozen model, case, two-call scope, irreversible single-use loss on partial failure and potential spend above operator target. No old consent or synthetic CI green can substitute.
6. **Scientific limitation:** native A/B first inputs are **identical**; attacked tool response and B-only VERITAS overlay are on subsequent turns. Two first requests measure transport/capture readiness, not injection success, VERITAS block rate, Native Utility, terminal outcomes or held-out 128-case scores.

## Hard stop

**Issue #427 remains OPEN / paid dispatch NO-GO.** Do not run or modify \`.github/workflows/final128-423-task1-protected-first-two-native-chat-live-v1.yml\`, weaken \`bypass_actors == []\`, create/consume/reset the production singleton, manually create a research ref during this PR, modify either active Ruleset, or add broad-scoped admin credentials to Actions.

This is an **offline test PR only**, with no merge or spending action authorized by CI success alone.
