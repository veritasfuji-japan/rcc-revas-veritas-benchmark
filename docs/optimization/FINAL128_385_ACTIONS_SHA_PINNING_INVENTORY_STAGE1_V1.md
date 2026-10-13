# Final128 #385 — complete workflow Actions reference inventory; stage 1 core CI pinning

## Why this change

The repository-level GitHub Actions settings have read-only default
GITHUB_TOKEN, but they currently permit all third-party Actions and do **not**
require full-length commit-SHA pins. Before enabling a global SHA requirement,
every active workflow that uses a mutable version-tag Action must be migrated.
A one-click global SHA enforcement today could break existing CI and manual
workflows. The Action reference's commit pin improves integrity; it does not
guarantee that a pinned Action is safe or that it cannot be bypassed.

## Stage 1 (this draft)

Only the following two existing CI workflows are changed:
- `.github/workflows/ci.yml`: checkout v4 and setup-python v5 changed to
  their **already successfully exercised** 40-hex commit IDs.
- `.github/workflows/native-veritas-benchmark.yml`: two checkout v4,
  setup-python v5, and upload-artifact v4 uses changed to existing
  tested 40-hex commit IDs. The native benchmark's existing triggers, fixed
  VERITAS commit, logic and evidentiary boundary remain unchanged.

Exact pins in stage 1:
- `actions/checkout@11d5960a326750d5838078e36cf38b85af677262`
- `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065`
- `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02`

The repository-wide scanner `scripts/final128_385_actions_sha_pinning_inventory_v1.py`
checks every `.github/workflows/*.yml` / `*.yaml` in the **current actual
checked-out HEAD** and each file in a **pinned exact PR base Git commit**.
It categorizes local and SHA-pinned Actions, mutable tags, Docker digests
versus Docker tags, invalid or expression-derived uses, and explicitly
requested workflow/job GITHUB_TOKEN write scopes. It reports inventory
counts, file hashes, every known unpinned reference with filename and line,
and difference in unsafe references from the exact base SHA.

The regression gate only permits the phase-one change if core Actions refs
are pinned to reviewed 40-hex SHAs and **no new unpinned reference identity**
appears in the full tree relative to the PR base. It does **not** falsely
require all hundreds of existing workflows to be compliant in this stage.

## What this audit does NOT prove

- It is a static *literal YAML line* analyzer, not a complete YAML workflow
  evaluator. Anchors, template expressions and dynamically generated YAML may
  need an additional workflow-aware parser/audit.
- Ref pinning is only one supply-chain boundary. Job-level explicit
  `permissions`, privileged PR events, reusable workflows, artifact trust,
  container digests, self-hosted runners, repository settings and secret
  injection must receive independent review.
- The reported write scopes are an **inventory**, not proof of effective
  token permissions. No GitHub Actions permissions are changed in this PR.
- Current default read-only permissions can still be overridden in workflow
  YAML. The scanner therefore records explicit write requests for subsequent
  least-privilege analysis.
- The existing `workflow_dispatch` workflows and secret references may
  support paid operations, but #385 adds NO dispatch trigger or Provider
  calls. No Provider secret is read. Historical authorizations do not apply.
- Stage 1 is **not sufficient to enable GitHub's global Require actions
  to be pinned to a full-length commit SHA checkbox**. Only do so once
  the whole repository inventory has zero external mutable references and
  independent required validation has passed.

## Security and operational gates

- Exact pull-request HEAD, exact base SHA, no repo writes, no Provider keys
  and no external Provider/Native Scorer calls.
- Dedicated CI runs local classifier tests and then scans the actual complete
  checkout. The complete inventory is stored as an artifact with every
  workflow SHA and only safe action names/refs, no raw secret values.
- Shared CI for the amended core workflows must be successful. The old
  native v0.1 workflow has a limited pull_request branch filter; its
  historical compatibility should be checked carefully and not assumed from
  one unrelated PR workflow result. The existing main CI is the
  authoritative stage-one triggered check.
- In follow-up PRs, migrate the **critical secret-bearing and manual-run
  workflows next** after reviewing each workflow's expected Action version,
  before globally flipping SHA pinning. No one PR should churn 300+ workflows.
- GitHub protected Environment review, real globally single-use tag
  issuance, true project billing cap, egress controls and fresh explicit
  approval remain separately necessary before genuine Task1 A/B calls.

Historical V13 scores remain unchanged; no new scored Task1 or paid provider
run is part of #385.
