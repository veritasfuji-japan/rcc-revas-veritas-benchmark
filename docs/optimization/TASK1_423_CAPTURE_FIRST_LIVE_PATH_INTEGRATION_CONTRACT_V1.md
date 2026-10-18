# Task1 #423 Capture-First live-path integration contract — offline only

**Status (2026-10-18): OPEN GAP / DRAFT REVIEW / PAID TASK1 NO-GO.**

This document does **not** approve, fix, or exercise the paid sender. It records
a **testable implementation gap**, keeping the existing real-sender path and
protected workflow unmodified.

## Audit finding

- PR #423 added a paid-capable protected manual Chat Completions sender.
- Its `one_post` currently reads the response and rejects oversized, non-200,
  or missing/invalid server request ID **before returning the received body**.
- Its `execute` currently invokes `shape.capture_one` (strict response schema,
  provenance and usage checks) **before** encrypting the HTTP body.
- The encrypted file is subsequently written via `write_bytes`, not an
  exclusive, fsync-verified ciphertext commit.
- PR #434 already proves an isolated mock-only encrypt-and-commit-before-parse
  mechanism. That module is **not attached to the #423 live path**.
- PR #442's fake pre-send Bind is also **not attached to #423**; no issuer/sender
  authority split, independently authenticated execution subject or durable
  cross-run per-Arm consumption is established here.

These are **code-path observations**, not allegations of any unauthorized real
Provider transmission.

## What this PR changes

Only **two new no-effect files**:

1. `tests/test_task1_423_capture_first_integration_contract_v1.py`
2. `docs/optimization/TASK1_423_CAPTURE_FIRST_LIVE_PATH_INTEGRATION_CONTRACT_V1.md`

The test module imports the already existing #434 offline mock helper, uses
a public synthetic AES fixture, blocks socket connections, clears named
Provider/GitHub tokens from the test environment and never imports or invokes
the #423 sender. It inspects #423's source **as text and AST only**.

### Meaning of test results

- **PASS**: synthetic invalid JSON is sealed, preserved, decryptable, and
  duplicate capture cannot overwrite; paid workflow has not gained automatic
  PR/push dispatch in the inspected text.
- **XFAIL (strict)**: three required #423 live-path properties are **not yet
  implemented**: transport must return bounded unvalidated HTTP evidence;
  encryption must precede schema/usage parsing; and ciphertext must be
  committed exclusively with storage synchronization.
- **XPASS (strict)** after a future code fix is intentionally a test failure
  until a reviewer removes the corresponding `xfail` marker, reruns the
  positive contract and verifies the implementation. Do not relabel the old
  XFAIL as PROVEN.

Suggested local read-only execution:

```bash
python -m pytest -q -o addopts= tests/test_task1_423_capture_first_integration_contract_v1.py
```

No test requires a GitHub token, OpenAI key or paid response, and none should
be supplied. The existing production manual workflow is not invoked.

## Separate subsequent #423 implementation review (NOT performed here)

A separately reviewed change to the live sender would need to ensure that:

1. After receiving bounded HTTP bytes and header/status information, it does
   **not** reject a non-200, unknown request ID or invalid JSON prematurely.
2. It AES-256-GCM seals received raw body and minimal required HTTP metadata,
   binding to exact Arm, locally owned request digest and execution context.
3. It commits ciphertext with restrictive permissions, exclusive final
   filename, file fsync and directory fsync before semantic parsing.
4. It then performs status, origin-ID, response-shape and usage checks. Any
   failure stops both retries and later Arm dispatch; the ciphertext is kept.
5. Oversized response captures explicitly indicate **partial bytes**, never
   misrepresenting a truncated body as complete.
6. No response after a timeout or partial TLS failure remains UNKNOWN; do
   not invent a received body, provider acknowledgment or billing certainty.
7. A Runner-local fsync alone **does not** guarantee remote Artifact retention.
   Secure long-term evidence custody, upload success and decryptability require
   separate proof.

All changes must be reviewed and tested with fake connections **without**
real Provider access. A passing mock test is still not proof of independent
production send authorization, credential confinement or single-use durability.

## Hard exclusions

- Do not edit or dispatch the existing protected live workflow.
- Do not edit the #423 paid sender in **this** PR.
- Do not create/readjust/consume production tags, Rulesets, API keys, secrets,
  GitHub environments, billing controls, or prior failed runs.
- Do not issue real OpenAI requests, invoke tools, scorer or external effects.
- Do not treat a PR merge, CI success or local fake receipt as approval.

**Issue #427 must remain OPEN; paid Task1 execution remains NO-GO.**
The `NO-GO` Issue is an administrative decision record, not an IAM/network
enforcement gate. A later production execution-boundary review remains required.
