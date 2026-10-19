# Task4 #479 — adversarial bypass matrix, with an explicit boundary gap (NO-GO)

## Critical result this PR is designed to preserve

**The legacy #458 local UNIX Broker's `consume` operation can be invoked directly by a same-OS-identity local process without a #478 inline CAS receipt.** This is a **local bypass of the Python-level #478 hook**, not a real Provider or bank-effect bypass. The legacy Broker has no live Provider transport, and returns `live_post: false`. The test **must fail if the gap is concealed** by a misleading `bypass_resistance_proven: true` claim.

This matters because the #478 hook is a parent-process `patch.object` seam, not an independent IAM or credential/network-enforced chokepoint. A malicious process able to call the legacy local Broker directly does not have to traverse the #478 Python function. SQLite is writable by the same local identity; it is not an independently controlled authorization ledger.

## Adversarial matrix

- Duplicate consumed slot: refused by #477 local CAS.
- Mutated SDK wire for consumed slot: refused.
- Forged `provider_post_allowed: true`: refused.
- Missing SQLite file: refused, no auto-create fallback.
- SQLite exclusive lock: refused, no fallback.
- Legacy Broker `send_live` opcode: refused.
- **Direct legacy Broker `consume` without #478 CAS: succeeds locally** (synthetic NO_SEND only). This is the documented residual gap.
- Optional pinned Native SDK integration: rerun eight #478 inline CAS controls with hash-only receipts; **does not eliminate the separate legacy Broker bypass**.

## Evidence and safety

No live Provider calls, no bank effects, no independent IAM, no protected remote CAS, no cross-runner proof, no paid approval, no secrets/rulesets/environment changes. Genuine Native Utility remains UNSCORED; Task4 #321 and Task1 #427 remain OPEN / NO-GO. This is not production bypass resistance or a real-world attack on a bank.

Four additive files based on merged #478 `915648b4fa84252a1283ea1e4dcc223cc28237d8`. Dedicated PR-only workflow, `contents: read`, pinned public dependencies and no paid workflow. Draft until all CI and human review pass.

## Recommended remediation (not claimed by this PR)

Enforce independent broker-side verification of a scoped signed receipt and atomic consume, reject all unauthenticated local opcodes, isolate the broker identity/credentials and network egress, and test across independently controlled runners. Do not confuse a local proof-of-concept patch with a production control plane.
