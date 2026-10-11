# PR #309 — Protected live authorization: **gap audit**, not a live-grant implementation

## Exact question being answered

After #303–#308 have passed, **what can actually be proven before the first
prospective real model call?**

Existing success is meaningful *within bounded offline tests*: issuer-owned
mock date/wire, synthetic response parsing, native RCC and VERITAS Bind
in-memory exercise, exact real OpenAI SDK JSON through a local MockTransport,
file-level one-use rehearsal, and SQLite single-host collision control.

**None of those tests authorizes or proves production-level, cross-run
single-use spending or execution.** This PR deliberately refuses to turn a
green CI result into a live approval.

## Rule of One

Pin #303–#308 and report all nine **external live prerequisites as
NOT_ATTESTED**, never ready. Any attempt to modify a frozen parent, import
real API credentials, supply a previous consent phrase, or provide arbitrary
user-supplied "approved" assertions must fail or leave the report in
\`BLOCKED_NOT_READY_FOR_REAL_PROVIDER_DISPATCH\`.

The audit and workflow have no real Provider transport, use no Provider
credentials, create no protected authorization, and invoke neither a native
banking effect nor a scorer. The real third-run permission remains consumed.

## Evidence matrix and concrete closure artifacts

| Priority | Required evidence (not provided here) | What independent proof must demonstrate |
|---|---|---|
| P0 | HUMAN_APPROVAL_SCOPED | New explicit human approval tied to one exact model, case, frozen request hash, maximum calls and monetary ceiling |
| P0 | PROTECTED_GLOBAL_SINGLE_USE | Atomic consume-before-send in an independently controlled store accessible across runners, crash-safe UNKNOWN state and no replay |
| P0 | CREDENTIAL_AND_EGRESS_ISOLATION | A dedicated provider key scoped to the approved sender, protected workflow/environment, and restricted egress; PR code and untrusted agent cannot reach it |
| P0 | ACCOUNT_SPEND_ENFORCEMENT | Fresh real model pricing and actual platform/project spend protections; historical estimate $0.0044096 is **not** a billing cap |
| P0 | PRODUCTION_ISSUER_CLOCK | Authenticated issuer-owned fresh date and exact real native prestate/request pairing, no synthetic 2031 clock |
| P0 | REMOTE_UNKNOWN_NO_RETRY | A different audited sender forbids automatic and human replay even on timeout or ambiguous Provider result |
| P0 | PROVIDER_ORIGIN_RECEIPT | Real external request/response IDs, response digest, model and usage correlated and independently reviewable |
| P0 | LIVE_NATIVE_BIND_EFFECT_COVERAGE | Native RCC/Bind gates an actual permitted action; bypass via credentials, IAM or network refused and terminal reconciliation observed |
| P0 | INDEPENDENT_UTILITY_AND_ATTACK_EVAL | Authorized real-model held-out utility and injection scoring, scorer input provenance, no invented Final128 result |

**NOT_ATTESTED does not mean demonstrably absent**. These external
infrastructure and approval settings are not available in the offline
GitHub files and were not inspected by this workflow. Actual verification
requires owner access and durable independently checkable evidence.

## Architecture decision still required

A protected workflow/environment alone does not guarantee distributed
single-use consumption, especially after cancel, timeout or rerun.
A proposed deployment must establish a permission root of trust outside
an attacker-controlled job (for example an independently administered
compare-and-set ledger), separate per-run execution credentials, hard
permission denial on unknown effect, and independent audit storage.
Its configuration and security tests must be evaluated, not assumed
from GitHub Actions names or branch protection alone.

The dedicated CI reads exactly pinned Git blobs and validates the
unchanged #306 \`MockTransport\`, #307 \`DENY\`, and #308 SQLite atom
and the source workflow's read-only/no-manual-dispatch shape.
External assertions cannot be injected to flip the result into ALLOW.
A green job produces JSON + JUnit evidence of *gap identification*,
not a production proof.

## No new paid inference or bank effects

Real Provider posts: **0**. New authorizations: **0**. Native bank
effects: **0**. Final128 scores: **0**.

**Exit criterion:** Do not implement another mock grant PR solely to
count additional tests as progress. The next genuine milestone is to
choose the protected grant/storage/egress and billing controls, obtain
their own independent evidence, then request a *new*, narrowly scoped,
explicit authorization before any prospective real Provider POST.

PR #309 remains **DRAFT** until exact-HEAD dedicated CI, full existing
CI checks, JUnit, JSON report, and artifact SHA have been reviewed.
Merging it cannot issue any permission or enable a live sender.
