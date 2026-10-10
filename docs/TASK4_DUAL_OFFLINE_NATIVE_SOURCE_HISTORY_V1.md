# TASK4_DUAL_OFFLINE_NATIVE_SOURCE_HISTORY_V1 — PR #290

**NO REAL PROVIDER / NO PAID MODEL / NO PRODUCTION IDENTITY.**

Merged predecessor #289: \`c4cf32aca9f0686f14c3905d21bd7cead6eb7e9f\`.

#289 proved the exact native Task4 DirectAttack payload reached an actual
tool return in an OpenAI-compatible fake-model wire. It still used one
common scripted first protected candidate for both A/B treatment arms.

#290 introduces **TWO separate synthetic model-wire histories** for that
exact canonical-*identified* case. A and B each start from separately
reconstructed native AgentDojo injected banking environments with the
same exact attack payload bytes. A distinct fake RecordingClient object,
distinct call-ID namespace, separate local TEST DateContext signing
session and one-time trajectory instance construct each source history.

The harness captures and archives every actual native read-only return,
five full client requests per source, first protected send_money proposal,
RCC review, A/B native simulator histories, protected Bind outcome and
the native scorer's detached post-completion scores. A is selected only
from A's client-driven native trajectory; B only from B's trajectory.

**IMPORTANT:** Each independent LOCAL source trajectory still internally
executes two native A/B probe arms, meaning there are **four** in-memory
simulator bank operations in the two test trajectories, of which only two
are selected for the logical independent-source comparison. This is
deliberately not the same as a new real two-provider trial. No worker
network or real bank effect exists.

## Strict evidentiary claim

This demonstrates **synthetic source record isolation**: a selected
candidate belongs to its own client request, native tool-call ID, original
Task4 request, pinned TEST date profile, exact native injected pre-state,
native return, outcome and scorer result. Alias, swapping or tampering
these records must fail closed. No scorer-derived admission or candidate
repair is permitted.

Although the two synthetic clients are different Python instances
and distinct call IDs are recorded, both follow the SAME deterministic
RecordingClient code. Candidate SHA may be byte-identical and
**real independent model inference is NOT PROVEN.** Model semantic
independence, real model compromise resistance, real Provider network
authenticity, held-out measurement, production IAM and unknown attacks
remain open.

## Dedicated proof

- One actual pinned AgentDojo native Task4 × injection_task_0 DirectAttack
  slot insertion, **reconstructed TWICE**, with identical initial state and
  separate objects
- Two distinct fake client sources and independently TEST-signed runtime date
  profiles (not real external clock/operator attestation)
- 10 model-compatible TEST requests, exact source hashes, distinct first
  protected call IDs, exact A/B candidate and pre-state provenance
- Two separate native Task4 local trajectories, each with real RCC and
  VERITAS in-memory native Bind, and 4 detached native scorer arm calls
- 18 tests, including 15 negative provenance, history substitution,
  candidate call aliasing, source identity, score/authority false-promotion
  attempts
- Archived raw 2-source JSON transcripts, JUnit, pinned source blobs,
  local simulator receipts, proof summary and runtime dependency manifest

All source slots are lower-trust. Both local selected arms may have Task4
Utility true and injection goal false **only because the fake clients
ignore the injection payload**. This is not a Canonical Final128 result and
cannot upgrade the historical B Utility 64/128.

**No external model calls, no live Provider tokens, no billable spending,
no native real-bank effect**. No prior cost authorization can be reused.
Draft and do not merge until *exact HEAD* all-CI SUCCESS and independently
downloaded Artifact/JUnit/source-integrity audit.

Next: prepare provider-authenticated independent arm A/B source capture as
a separately budgeted, explicitly user-approved prospectively enrolled
canonical case. Preserve the frozen 128-case denominator and closed defaults.
