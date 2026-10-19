# Task4 #478 — original Native SDK inline local CAS (OFFLINE / NO-GO)

## Precisely proven scope

For each of the eight scripted A/B requests in the original local Native SDK request path, the #473 original-wire scope and budget guard runs first; a #475 ephemeral child process signs a #474 **synthetic NO_SEND** claim, verified by its public key in the parent. Then #477's local SQLite CAS stores a scoped `UNKNOWN_PERMANENTLY_NO_SEND` attempt **before** the #472 isolated deny-only worker claim and before #471 local AEAD Native continuation.

This is the main difference from #477, where the ledger consumed evidence only **after** the Native run. The #478 hook is inline at the #473 pre-worker `check_sdk_wire` seam. Eight hashes must match the #473 evidence, and all eight stored slots must refuse a later replay.

The separate signer process and SQLite store still run on the **same GitHub Actions runner and operating-system identity**. No real Provider transport is in this call graph. SQLite is not independently protected; parent-process code could bypass the hook, and this cannot establish production non-bypassability.

## Negative boundaries

- No independent IAM, egress enforcement, external durable CAS, cross-runner replay resistance or real approval.
- No live Sender, Provider POST, real bank effect, genuine model response or genuine Native Utility score.
- No Secrets, Environments, Rulesets, tags or paid workflow changes.
- Store failure is fail-closed in the local model; no production distributed failure semantics are established.
- Real Provider POSTs **0**; Utility **UNSCORED**; Task4 #321 and Task1 #427 remain OPEN / NO-GO.

Four additive files, base merged #477 `c04c3d4f66720afb0763f2a8e23f1dee62d80186`. Dedicated workflow PR-only, `contents: read`, no injected credentials, frozen public pins. Draft until all CI succeeds and owner manually reviews.

Next proof needed: genuinely independent issuer + storage and network/credential enforcement across separately operated runners, an audited unbypassable execution boundary, explicit narrowly scoped fresh owner authorization before any paid Provider POST.
