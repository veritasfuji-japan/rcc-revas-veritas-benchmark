# Task4 #477 — single-host simulated shared-store CAS failure matrix (OFFLINE / NO-GO)

## What this proves, precisely

A local SQLite database **on the same GitHub Actions runner** is accessed from four independently spawned OS processes. Each transaction uses `BEGIN IMMEDIATE`, a unique `(trial, arm, ordinal)` primary key, `synchronous=FULL`, and a durable **UNKNOWN_PERMANENTLY_NO_SEND** state. The state is a **research-only attempt receipt, never SEND authority**.

The offline tests check:

- Four processes race for one identical synthetic scope: **exactly one local commit, three duplicate refusals**.
- Existing slot cannot be reclaimed with a changed original SDK-wire hash or changed synthetic claim hash.
- Reopen after restart refuses a replay.
- An issuer process terminates with `os._exit(17)` **after COMMIT before reply**, then retries still refuse.
- Missing store and SQLite lock both fail closed, without reopening as a fresh ledger or falling back to SEND.
- Changed policy, unauthorized trial, arm, model claim shape and attempts to mark a Provider POST permitted fail closed.
- When frozen Native dependencies are installed, the **eight hash-only original Native SDK request/signature receipts from #476** are imported into a *separate post-hoc local* evidence ledger and replay attempts are denied. This is a hash/evidence continuity demonstration, **not an inline execution-side authorization gate**.

## Claims expressly NOT established

**No cross-runner or remote durability has been proven.** The database is a single local file on one Runner, with no external CAS service, independently controlled IAM/credential, tamper-resistant ownership, durable remote revocation, remote quorum, distinct-machine execution, or independent egress enforcement.

The #476 Native integration is reused **only to obtain offline receipts**. #477's CAS model is applied *after* that local Native run. It does **not** intercept the pre-dispatch gate in production. Store availability/lock tests prove refusal behavior locally but do not prove how a cloud database behaves under partition, failover, split brain, or crash-recovery replication.

This PR is explicitly NO-GO: **0 live Provider posts**, **0 bank effects**, **0 external real-model calls**, **no paid approval**, and genuine Native Utility remains **UNSCORED**. Task4 #321 and Task1 #427 remain OPEN/NO-GO.

## Changes and execution rules

Four additive files. Base is manually merged PR #476 `081b623092e27e28a8c7f683b5e84dc86691d9e1`. Dedicated GitHub Actions runs on PR only, `contents: read`, no Secrets reference, no `workflow_dispatch`, frozen public source pins and pinned offline dependencies. No Environment, Ruleset, tag or GitHub Secret is created or updated. Owners review and manually merge only after dedicated and inherited CI are green.

## Next necessary milestone

To make a cross-runner guarantee credible: choose a truly shared independently managed atomic datastore; separately operated issuer/worker identity; non-bypassable original SDK pre-dispatch consumption; denial across multiple isolated machines/runners, network partitions and crash recovery; clear irreversible UNKNOWN handling; independently audited evidence. Any paid Provider exercise would need **fresh explicit owner scope and authorization**, which this PR does not contain.
