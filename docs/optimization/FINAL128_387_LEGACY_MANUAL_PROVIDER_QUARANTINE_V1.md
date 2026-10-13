# Final128 #387 — Readiness audit for disabling historical manual Provider workflows

## Why the draft direction changed

An initial draft inserted a literal static FALSE job condition in 15
historical manually dispatchable workflows. Multiple frozen historical
integrity audits failed because even one source-line change invalidates
the pinned workflow blob. **Every old workflow was restored byte-for-byte
from main before this PR can be merged.**

The durable solution for these frozen historical entries is to **disable
the GitHub Actions workflow ID administratively** rather than change
the tracked source. This PR builds the read-only inventory and evidence
for that follow-on operation. The PR does NOT itself disable any live
workflow, alter a GitHub setting, grant authority or make a paid call.

## Scope and evidence

The new auditor scans every current repository workflow for a
workflow_dispatch event plus references to one of the known Provider
Secret names: secrets.OPENAI_API_KEY, secrets.TASK4_OPENAI_API_KEY or
secrets.ANTHROPIC_API_KEY. It records filenames, job IDs, source
SHA256, whether all jobs are literally static-FALSE, and which
workflows still need GitHub Actions administrative disabling.

The known historical set comprises 15 Task2/12/13/15 development,
Clean A/B and Final128 V4 through V13 manual Provider workflows.
The auditor checks that ALL 15 frozen historical files exactly equal
their PR-base Git blobs; changing any one fails. Other matching files
are included in the inventory automatically.

PR-only CI is read-only, has no Provider API secret, triggers no
historical manual workflow, and produces SHA-only evidence. An exit
code 0 from the inventory proves successful IDENTIFICATION; it does
not claim the legacy Provider routes have actually been disabled.

## Required GitHub administrative action (NOT done by #387)

For each identified workflow, an authorized repository admin can
use Actions -> choose workflow -> '...' -> Disable workflow.
The equivalent REST call, when separately approved and available,
is PUT /repos/{owner}/{repo}/actions/workflows/{workflow_id}/disable.

Then independently read each workflow's GitHub Actions live status
and verify disabled_manually (or GitHub's equivalent disabled state).
The connected GitHub API available to this PR cannot inspect that
administrative workflow state. Until verified, the inventory's
workflow-state-verification flag MUST remain false.

## Remaining credential bypass

Disabling a workflow does not revoke a repo-level Provider Secret,
prevent an admin from re-enabling the workflow, or prove old-ref and
alternate workflow routes blocked. A separate admin should inventory
actual consumers, then revoke/rotate old Provider credentials and
place newly scoped credentials ONLY in the protected Task1 Environment
after independent project cost, approval and one-use issuer checks.

DB-only effect workflows, unfamiliar secret aliases, privileged
workflow mutation, GitHub account compromise and network-level bypass
remain outside the claimed scope. No official Task1 Utility/Attack
Scorer run is performed.

## Merge gate

Only four new files should change (auditor, tests, dedicated read-only
CI, document). All 15 original manual Provider workflow blobs must be
exactly unchanged. All shared CI and the dedicated audit must be green,
artifact SHA checked, and unverified disablement explicitly reported.

Historical V13 A Utility 93/128, B Utility 64/128 and B attack success
0/128 remain historical, not new measurements.
