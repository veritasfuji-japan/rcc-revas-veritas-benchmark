# Final128 Task1 — issuer/sender capability split job-graph audit V1

**CURRENT STATE: SOURCE-VERIFIED SINGLE JOB; TWO-ROLE DESIGN IS INERT; PAID TASK1 NO-GO.**

## Why this additional PR is needed

PR #436 already tested **caller-supplied synthetic** issuer/sender permission shapes, and PR #437 tested **ephemeral signed synthetic handoffs**. Those are useful, but neither inspects the **actual** #423 protected paid-capable Workflow that remains on main. PR #444 has now repaired Capture-First ordering; it **did not** change the ability of a job to both create a Git tag and send real Provider requests.

This PR therefore closes a narrow **auditability gap**, not the actual security gap. It pins the current paid Workflow Git blob `c2182fef2574d1be3019cf6455947b64751ef474` (observed on main `e57226797908488eb0711f46384905f221ecf528`), inspects its job/step privileges, and separately specifies an inert, hypothetical two-job graph.

## Finding: real #423 has a single shared job

File: `.github/workflows/final128-423-task1-protected-first-two-native-chat-live-v1.yml`

| Evidence in the checked-in source | Observed behavior / security meaning |
| --- | --- |
| Workflow root: `permissions: contents: write` | The sole job has a write-capable GitHub Actions token scope |
| Sole job `protected-first-pair-only` | No independently isolated issuer vs sender jobs |
| Tag consumption step uses `GH_TOKEN: ${{ github.token }}` and `POST /git/refs` | Git ref creation uses that job's GitHub token |
| The same job's send step runs `--mode send` | Tag issuance and Provider HTTP transport live in one job |
| Steps within that job reference `TASK1_OPENAI_API_KEY` and `TASK1_CAPTURE_AES256_KEY` | Secret use is configured within the same job; they are not injected into every step automatically |
| Job environment `task1-real-model-pilot` | Environment declaration **does not** itself verify reviewers, IAM or billing settings |

This is **source-level evidence of a missing issuer/sender security separation**, not evidence of improper or repeated Provider calls. `persist-credentials: false` on checkout is helpful but does **not** remove the write-scoped `github.token` available to the job when invoked. A text check or workflow-level `concurrency` group is not an independent execution-time Bind or a durable cross-run Provider lease.

A later change to this protected live Workflow's bytes deliberately fails this frozen source audit until re-reviewed. The audit does not attempt to prove a changed Workflow automatically safe.

## Future two-job graph — design only

The non-executable file `docs/optimization/TASK1_423_ISSUER_SENDER_JOB_SPLIT_INERT_BLUEPRINT_V1.yml` is **not an executable workflow**. It has **no GitHub trigger, actual `jobs` root, `steps`, `run`, `uses`, ref writer, network call or deployed Environment**. No change is made under `.github/workflows`.

| Proposed isolated role | Declared token capability | Secrets and environment | What remains unverified |
| --- | --- | --- | --- |
| **issuer** | `contents: write`, nothing else | No Provider/AES secrets; no protected sender Environment | Independently authenticated Run/job; exact protected singleton Rule and scope; admin bypass; securely signed handoff |
| **sender** | `contents: read`, nothing else | **Symbolic names only** for dedicated Provider/AES secrets in the *future* sender job | Independently authenticated recipient; least privilege, actual Environment settings, secret release, send-time Bind and durable per-Arm use-once |

The sender depends on the issuer by **graph shape only**; `needs: [issuer]` would not itself constitute a trusted handoff. The issuer might lack the sender's Provider credential while still having a broad `contents:write` token able to modify other refs unless separate protections are enforced. The sender must not be able to reuse a previously issued singleton tag to send again, even if it has only `contents:read`. Likewise, an in-memory Ed25519 mock signed by a key supplied from a candidate job cannot independently authenticate issuer/sender identities. Real GitHub OIDC/job claims, signed issuer enrollment and secure handoff remain **unimplemented**.

The exact first **A/B initial** Native requests and their equal first-packet hashes must be bound to an independently authenticated run, commit, model, case, recipient, expiration/nonce and an explicit *new* consent decision. A protected tag pointing to a commit is not proof of those bindings. The research tag `refs/tags/final128-task1-research-first-two-once-v1` has already been issued: **do not reissue, retarget, delete, reuse or consume it for real-model permission**. The different production consumed ref remains separate and cannot be issued by this design.

## What the new offline test proves

- Source-controlled exact #423 workflow **contains tag create and Provider send in the same write-enabled job**, based on static YAML and Git blob identity.
- A separate **inert** blueprint expresses the intended split, requires exact-role privileges, a declared directed issuer → sender dependency and false values for all real enrollment/consent/egress/once proofs.
- Altering either role to cross the privilege boundary, inserting real secrets in issuer, broadening tokens, forging real approval/attestation/once claims, swapping tag names or adding `on`, `steps`, `run` or workflow root keys **fails closed**.
- Test code monkeypatches outbound socket operations, removes named secret environment values and neither calls the GitHub API nor sends a Provider request.
- Matching the proposal **returns NO-GO** and explicitly leaves `actual_job_separation_enforced=false`. Neither mocked permissions nor a passing CI check proves IAM, egress coverage, credential isolation or a durable provider ledger.

Code: `scripts/final128_task1_issuer_sender_job_graph_audit_offline_v1.py`; tests: `tests/test_final128_task1_issuer_sender_job_graph_audit_offline_v1.py`. Offline test command:

```bash
python -m pytest -q tests/test_final128_task1_issuer_sender_job_graph_audit_offline_v1.py
```

## What a future *separately authorized* implementation would still need

1. Review a new actual workflow with **distinct** issuer/sender jobs and least-privilege job-level GitHub token permissions; verify reusable workflows/checkout/workspaces, branch protection, Environment reviewers and role-confusion paths externally.
2. Bind identity and source provenance to the intended issuer and sender using independently validated job/Run/ref/commit claims. Resolve the recipient-job-ID bootstrap problem; no unverified artifact or a `github.run_id` string is sufficient.
3. Use an independently enforced **per-arm durable Provider-send lease**; create a persistent pre-send attempt record before egress, exclude parallel/cross-Runner access, preserve UNKNOWN/no-retry, and reconcile partial-A-only outcomes.
4. Restrict **all** Provider-credential and network egress paths outside the agent process, not only calls through a Python helper. Third-party bypass tests are still required.
5. Verify protected run controls and project spend risk, receive fresh explicit authorization for current main SHA, exact model, case, A/B count and financial risk **before** any Tag POST or paid dispatch.

## Deliberate no-effect and consent boundary

This PR **only adds** a design YAML under `docs/`, a stdlib/PyYAML static inspector, offline tests and documentation. It does not create, execute, alter or dispatch any Actions Workflow; does not change the #423 sender, GitHub refs, Rulesets, PAT, secrets, Environments, billing, repo settings or any tagged evidence; and performs no real Provider call, bank effect or Native scoring.

[Issue #427](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/427) remains **OPEN / PAID TASK1 NO-GO**. The issue is an administrative decision, not an enforceable IAM lock. A merge of this PR is **not** authority to run the paid #423 workflow.

**Audit conclusion: SOURCE-VERIFIED SAME-JOB EXPOSURE; INERT TWO-ROLE DESIGN RECORDED. NO LIVE ROLE SEPARATION OR AUTHORIZATION PROVEN.**
