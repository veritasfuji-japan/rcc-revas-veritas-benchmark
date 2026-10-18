# Task1 #452 — Actual Manual Workflow Role Split, HARD NO-GO V1

**Decision: NO-GO. Issue #427 OPEN. No paid Provider request, no production tag issue, no new grant, no Utility claim.**

## What changes in a real executable workflow

Unlike #445's inert blueprint or #446–#450's local mock services, this change actually edits the checked-in **manual paid-capable** #423 GitHub Actions Workflow at:

`.github/workflows/final128-423-task1-protected-first-two-native-chat-live-v1.yml`

The previous exact workflow bytes, Git blob SHA-1 `c2182fef2574d1be3019cf6455947b64751ef474`, are preserved verbatim in a `.snapshot.txt` under `docs/optimization/` (not an executable workflow). The #445 frozen historical auditor and dedicated test now reference that archived snapshot, preserving the original same-job finding rather than rewriting history.

The *actual current* manual workflow is split into **three jobs** with explicit least-privilege GitHub token scopes:

| Job | GitHub contents | Environment / API secret | Role / current effect |
| --- | --- | --- | --- |
| `preflight` | read | `task1-real-model-pilot`, API/AES test access at the original secrets-preflight step | **Hard-disabled** by `if: ${{ false && ... }}` at job evaluation; no tag, send or secret reads execute |
| `issuer` | write | **No** protected Environment and **no** Provider/API/AES secret reference | `needs: [preflight]`; only original production tag check/create/readback source, skipped because preflight cannot run |
| `sender` | read | `task1-real-model-pilot`, API/AES secrets at the original send step | `needs: [issuer]`; **hard-disabled** by `if: ${{ false }}`; rehydrates exact pinned first A/B Native packets independently in its own job |

The workflow defaults to `permissions: contents: read`; only the issuer job overrides to write. The sender references `needs.issuer.outputs.consumed_sha`, rather than a step output from its own job, and does not have a GitHub write token. All existing original case/model/source pins, frozen packet preparation, manual-only `workflow_dispatch`, `concurrency.cancel-in-progress: false`, AES-256-GCM capture code and two-call sender source remain preserved. This changes the source of the **real** workflow, but neither a live Provider transport nor a production tag is executed in PR CI.

## Why it must remain disabled

This is a structural privilege reduction, not a finished independent authority deployment. The three-job structure is **not a real external Executor**. Both parties are still controlled by the repository/workflow trust domain. Even the three-job graph does **not** authenticate an independent issuer/Executor, establish attested sender identity, grant trusted approval, or bind one signed handoff to exact model/request bytes. GitHub Actions `needs.*.outputs` is **not a cryptographic attestation** or a consumption ledger. The Python `one_post` sender from #423 is still callable in an environment with credentials, and the preexisting tag still protects issuance rather than independently gating every Provider POST.

The Linux cross-UID #450 mock and evidence join #451 are useful but are **not** wired to the real Provider sender; shared same-host SQLite would not become a globally durable across-Runner lease even if copied. An independently controlled remote Executor with custody of API credentials, real authenticated issuer claims, an atomic persistent cross-Runner spend ledger, post-consume no-retry behavior, and enforced IAM/egress coverage across alternative direct-send paths remain **unimplemented**.

The current source has no externally audited project billing hard stop, independent deployment control, genuine current Provider A/B utility result, or fresh human cost authorization. The previous research tag and any consumed historical API approval are not reusable. Thus **a manual workflow_dispatch cannot issue the production singleton or execute paid Provider transport after this PR is merged**, even if the manual approval text matches. Anyone changing or removing either hard-disable must submit a separately reviewed PR under an independently enforced protected branch/Environment policy; repository admins or other privileged users remain in the threat model.

## Evidence and review

- Historical exact original SHA recorded as a preserved *inert* snapshot; no historical audit claims rewritten to say the old workflow never had the same-job risk.
- Existing source-pinned #423 sender tests retain the manual workflow, original secret validation-before-tag ordering, actual consent strings and exact Native source pins.
- New `tests/test_final128_task1_452_actual_workflow_role_split_hard_nogo_v1.py` parses the current YAML with duplicate-key rejection and verifies exact three-job DAG, per-job token scopes, no Provider secrets in issuer, no tag writer in sender, both disabling expressions, manual trigger only and unchanged no-retry source. It rejects attempts to silently enable jobs, add issuer secrets, change role privileges, reorder needs, remove sender Environment or add push triggers.
- No existing scripts for real model transport are modified; no new workflow is added, dispatched, or scheduled; no new secrets, Rulesets, GitHub tags, cloud systems or billing settings are created or edited.
- Retain *Draft* until latest exact-HEAD dedicated and normal CI is green; specifically check that old #445 audit still passes against archived original, that all current #423 manual-only checks pass, that the new split checker is not skipped, and that all workflow jobs' code paths really remain NO-GO.

## Ben / Utility consequence

This PR is **not a new Task4 or Task1 Utility recovery**, and does not score or send a real native model request. Historic Final128 V13 remains A=93/128, B=64/128, B injection success=0/128. It reduces a production-bound source-level privilege gap while deliberately not claiming it solves global ledger, IAM, billing or native terminal scoring. After actual independent Executor/deployment identity and external budget controls are available, future work must connect those enforced controls to the real sender, obtain new explicit paid approval, run one **fresh** authentic Task4 A/B from the first turn through terminal Native scorer, and only then credit new Utility recovery.
