# Final128 #387 — Historical manual Provider jobs: default-DENY source quarantine

## What is being stopped

The 15 source files listed in `scripts/final128_387_legacy_manual_provider_quarantine_audit_v1.py`
include the four Task2/12/13/15 development validation workflows,
two historical clean A/B final runners, and nine Final128 legacy
manual-dispatch workflows (V4/V5/V7/V7-v2/V8/V10/V11/V12/V13).
The old workflows were manually dispatchable and directly referenced
`secrets.OPENAI_API_KEY` without a protected job Environment.

**#387 makes the single executable job in each such file fail at
GitHub's job admission stage**, before checkout, secret injection,
network transport, Native bank work, or Provider billing.
The exact job expression is `${{ false }}` (static,
not operator-controlled). For historical jobs with an original
confirmation expression, that line is preserved as an adjacent comment.
The original scripts, historical argument shapes, and evidence remain
in the repository. No historical artifacts or test score are altered.

This is a deliberate retirement of unprotected legacy live entries.
A GitHub manual dispatch of these files on the updated main source
may still show a workflow run, but the paid-capable job is skipped.

## Whole-workflow survey, independent detection

The new script scans **every** actual workflow file in
`.github/workflows` (expected at least 330), identifies
manual-dispatch workflows that reference known Provider secrets
`OPENAI_API_KEY`, `TASK4_OPENAI_API_KEY` or `ANTHROPIC_API_KEY`,
and rejects any such file if it has any job without a literal
`${{ false }}` at job level. It independently checks the
15 edited workflows against the exact immutable PR-base Git blob:
**only the job-level stop and historical-comment addition are allowed**.
Unexpected changes to triggers, model code, billing flags, runner
commits, README, Secret expressions, workflow permissions or
external dependencies are rejected.

The PR-only read-only CI installs no Provider client and supplies no
credentials. No old manual workflow is dispatched by #387 CI.

## Important bypass limitations — do not claim PROD PROVEN

**Stopping jobs on the current branch is not a global execution
authority proof.** The old workflows exist in earlier Git objects.
GitHub may allow a user with sufficient privileges to dispatch old
branches/refs or modify workflows. Repository-level secrets can be
accessible to other workflow files or privileged authors, independent
of which job is skipped. Separately installed API credentials may
also exist outside this repository, and some historical jobs use a
database secret without a Provider key.

To close **credential-side** bypass rather than merely 15 source paths:
1. **Immediately revoke/rotate** legacy shared Provider credentials
   at the provider, and remove any repo-wide Provider secret from
   Actions secrets after independent inventory. Avoid disclosing its
   value and confirm whether other approved workflows still depend on it.
2. Store a fresh, limited-capability Task1 API key **only in the
   dedicated protected** `task1-real-model-pilot` Environment;
   never provide that credential to old repo-wide workflows.
3. Verify project/account hard spending stop, locked trusted workflow
   source, exact main, protected issuer/tag creation and consumption,
   unforgeable fresh approval, network/IAM/credential controls and
   independent test of all bypasses before any paid run.
4. Review DB-only manually dispatched workflows and other non-OpenAI
   provider/secret aliases; this scanner only audits a specific
   Provider Secret name set. Keep the #385/#386 repository-wide SHA
   hardening separate and do not enable global pinning prematurely.

No GitHub admin settings or secrets were changed by this PR.
No actual provider calls, Native scorer, billing charges or Utility
measurements were made.

## Merge gate

Check exact HEAD and exact base, no skipped/failed tests, all common
CI success, dedicated artifact SHA and complete scan. Do not
recommend paid Task1 execution or claim credential bypass resistance.
Human/security review is needed before merging a high-impact
retirement; legacy manual workflow operators must know they are disabled.

Historical V13 reported A Utility 93/128, B Utility 64/128,
B injection success 0/128. **These are NOT updated here.**
