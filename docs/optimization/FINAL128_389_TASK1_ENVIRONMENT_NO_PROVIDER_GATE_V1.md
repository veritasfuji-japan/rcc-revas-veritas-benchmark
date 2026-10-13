# Final128 #389 — Real GitHub Environment approval probe, ZERO Provider

## Purpose

This PR creates **one separately manually dispatched**, low-privilege
GitHub Actions probe to observe whether the real GitHub Environment
"task1-real-model-pilot" holds a *non-Provider marker job* behind GitHub's
review / waiting / deployment branch protection rules.

**Do not dispatch this probe merely by opening or merging the PR.** PR
CI is a separate, offline, source-audit-only workflow. Human authorization
to execute even this harmless probe is a distinct action after reviewing
its exact merged SHA. No approval to use real paid APIs is granted.

The operator previously displayed UI settings:
- Required reviewer: veritasfuji-japan
- Prevent self-review: unchecked (no independent approval)
- Wait timer: 10 minutes
- Allow administrator bypass: unchecked
- Selected deployment branches: main only
- Environment-specific Provider Secret exists
- Repository-wide OPENAI_API_KEY reportedly removed and UI-confirmed

These are **user-supplied screenshots**, not attested runtime state. They
do NOT prove protected job was actually held, no bypass was possible,
secret scope is enforced at all paths, or any external issuer is durable.

## Files and protected job

- .github/workflows/final128-389-task1-environment-approval-zero-provider-probe.yml
  **workflow_dispatch only**. Two jobs. No checkout, no third-party
  Actions, no secrets context, no network access, no ref mutation, no
  Provider script, no Native tool or scorer.
  - preflight-no-environment: rejects non-main, wrong actor/repo/event,
    reruns and wrong acknowledgment *before entering Environment*. Its
    acknowledgment is NOT paid-run permission.
  - protected-marker-no-provider: needs successful preflight, binds
    environment: task1-real-model-pilot, prints a harmless marker and
    run ID/SHA to GitHub job summary only after the job is allowed to begin.
  - All jobs have only contents: read. "concurrency" serializes runs but
    is NOT a global single-use issuer.
- scripts/final128_389_task1_environment_probe_source_audit_v1.py:
  strict YAML source validator; no API calls or mutation.
- tests/test_final128_389_task1_environment_probe_source_audit_v1.py:
  mutation-based negative tests for automatic triggers, broader token,
  mismatched branch/actor/environment, rerun, fake approval and network
  or Provider insertion.
- .github/workflows/final128-389-task1-environment-offline-audit-v1.yml:
  PR-only, blank Provider variables, no protected Environment, source
  mutation tests, SHA/JUnit evidence only.

## Subsequent real Environment observation (NOT part of this PR)

Requires **fresh explicit user authorization for a zero-Provider dry run**,
separate from approval to create this PR. After merging, inspect the exact
manual workflow on main. Only if explicitly authorized, dispatch it on main:

1. Record preflight job success and protected-marker **waiting** / review
   request in GitHub's workflow timeline. Do not infer approval from an
   untrusted JSON flag.
2. Verify observed waiting and required-review state. Do not infer
   configured wait timer fired solely from nominal YAML, or from
   elapsed wall time if GitHub queues/runner scheduling are involved.
3. Without approving, capture the waiting/blocked state. If separately
   authorized, approve with the configured reviewer account, capture
   GitHub's decision/timestamps and later successful protected marker.
4. For a negative run, select a non-main ref **only if a separately
   authorized safe test is planned**. The preflight itself explicitly
   refuses non-main; this does not prove an Environment rule denied it,
   since that job never reaches the Environment.
5. Rerunning a previous dispatch should be refused at preflight; this is
   job-local behavior, not globally durable single-use authorization.

**Do not conflate** observed GitHub Environment wait/review, independent
human review (self-review is allowed here), protection of the actual
Task1 Provider job (none is installed), immutable global one-use grant,
account-enforced spend cap, credential isolation or verified production
bypass resistance. Those are still required for live Task1.

## Gate classification

- #388: offline review-only authority contract, merged.
- #389: ready to observe a real **zero-Provider** Environment gate,
  only **after** a separate explicit manual dispatch authorization.
- Task1 LIVE: DENY. No paid Provider calls, scorer runs, new A/B Utility
  values, GitHub single-use tag writes, or production PROVEN claims.
- Frozen historical 128: A 93/128, B 64/128, B injection 0/128,
  unchanged.
