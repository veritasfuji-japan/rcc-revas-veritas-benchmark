# Task4 #365 — One-use A/B session rehearsal (OFFLINE ONLY)

## Concrete advance
Adds an executable SQLite transaction-backed **local-only** state machine
for separately initialized A/B source sessions, each with its own source
identity and first request. Each attempt is consumed **before** validating
the proposed request; ambiguous or malformed attempts remain consumed and
stop that arm. Restarted workers cannot re-use consumed ordinals. Only
a labeled local fake response may unlock the next ordinal. This does
**not** replay the original model response or authorize Provider traffic.

## Explicit boundaries
The model/case are frozen to Task4 and gpt-4.1-mini-2025-04-14.
The research proposal permits at most five attempts per arm, ten total,
256 output tokens per attempt and local byte/BPE thresholds; these are
not real billed-token or monetary guarantees. A locally fabricated
response is never promoted to Provider evidence or genuine Utility.
No Provider SDK, API secret, workflow_dispatch, network sender, real
bank account, production authority or actual spending is introduced.

SQLite in the GitHub runner is **not** an independently administered
durable cross-job permit. The fake response observer is not an actual
Provider-origin receipt. Local byte/BPE fields are caller-supplied
in this rehearsal, not independently measured wire data; never use
this module as a live predispatch gate. Concurrent worker safety is
rehearsed locally only, not attested under an adversarial file owner.

## Next gap
Bind the frozen #325/#326 actual SDK wire observations and same-arm
#363 native/scorer history to a separately controlled future research
sender, with fresh owner approval, real account price/usage checks,
protected one-use permit, no-retry ambiguity handling and isolated
credential/egress boundary. The historical Provider consent is spent.

This PR is default DENY; no live model request may be inferred from
its CI result. Merge only after exact HEAD CI and artifact verification.
