# Final128 #408 — durable simulated one-use effect and real crash recovery

## Parent, threat model and exact source

Parent: #407 MERGED \`1f5477360c541125bc0145987c8228d64631934c\`.
Frozen AgentDojo \`a75aba7631d3ca5fb7ab938965c97ead2f9ff84b\`
banking v1.2.2, VERITAS \`a1d66aef02262cf8a913295270c3aafd159c6adb\`,
unchanged Task1 DirectAttack and original frozen 128-case enrollment.

#407 successfully executed a source-owned **synthetic counter increment**
through genuine pinned \`execute_bind_adjudication\` and distinct Linux
agent/gateway/backend users. Its one-use backend state was held in RAM.
A restart would reset consumed state and permit a *second* synthetic effect.

#408 replaces only the **local fake backend** with a backend-UID-owned
SQLite file. The **real #407 Bind gateway is reused without
loosening Task1 Native NO_MUTATION**, and #407–#377 tests remain enabled.

## Backend-owned SQLite commit

The backend process runs as \`veritas407backend\`, with its database file
in a \`0700\` backend-owned directory, and file mode \`0600\`. Agent UID,
gateway UID and a stranger UID remain distinct. The backend's Unix socket
still authenticates the kernel-observed gateway UID via \`SO_PEERCRED\`;
only that UID can call \`apply\` or \`status\`.

The SQLite transaction \`BEGIN IMMEDIATE\` with \`synchronous=FULL\`
atomically performs three operations:

1. Check the single-use simulated grant is still unconsumed and the
   source-owned target, action and integer units exactly match.
2. Mark consumed and increment the fake counter by **exactly 7**.
3. Insert one effect-row with grant hash, target hash, prestate hash,
   action units and a receipt hash. A unique grant-hash constraint
   prevents a second effect row in this database.

The effect-row plus consumed state must **match** the backend's
current counter and hash; inconsistent state fails closed. The backend's
redacted \`status\` discloses only the digest of its last effect receipt.
The gateway's real VERITAS Bind COMMITTED receipt may only be claimed
when the call **actually returned and postconditions were checked**.

### Three independent forced-process scenarios

| Phase | Injected OS process termination | Durable state after restart | Recovery |
|---|---|---|---|
| Normal / clean restart | No forced crash | Consumed, counter 7, 1 effect | Repeat rejected |
| Before commit | \`os._exit(77)\` after BEGIN, before COMMIT | Unconsumed, counter 0 | Fresh Bind call commits once; repeat rejected |
| After commit, before acknowledgment | \`os._exit(78)\` after COMMIT, before reply | Consumed, counter 7, 1 effect | Result is **ACK UNKNOWN** until target-owned reconciliation; repeat rejected |

For every scenario, the **actual** backend and gateway processes are
stopped and restarted with their prior Linux UIDs, reading the same
owner-only SQLite file. There is a **second restart**, preserving receipt
and exact state hashes, followed by an attempt from the correct gateway
UID to reuse the same source-owned grant. The backend itself refuses it,
even if a gateway was recreated with fresh in-memory state.

The crash-after-commit case intentionally makes the gateway's original
Bind invocation **fail before receiving an effect acknowledgment**.
Do not record a COMMITTED Bind receipt for that call. After restart,
reconcile the unknown outcome from the independently owned backend
effect/state journal, and do not reissue the effect.

The real Native Task1 mutation remains forbidden: inherited #407
executes \`send_money\` through the real pinned Bind and receives BLOCKED.
All of the inherited #406 Linux DAC tests still run.

## Scope restrictions

This is **one local synthetic SQLite effect** on a trusted CI machine:
not a real bank transaction, network effect, production credential,
actual independent human grant, cross-host IAM boundary or
production-grade exactly-once delivery.

SQLite's atomic local COMMIT and FULL synchronous setting are verified,
but no power-loss filesystem durability, OS corruption, multisite
replication, secure enclave, distributed lease, revoked permission,
network cut/partition, unauthorized root, file backup restore or
real external service denial is demonstrated. One private DB file and
one source-owned fake grant are scoped to this test.

The parent GitHub runner is a **trusted privileged supervisor**, and
uses sudo to instantiate/unlink the test principals and sockets, not
an adversary. Only the backend is intended to mutate the authoritative
simulated counter. There are no real Provider/LLM model calls, bank
effects or official AgentDojo scoring. Original 128-case Utility figures
are not remeasured by this PR.

A green CI indicates that this **bounded offline durable backend**
passed. It does NOT promote real production bypass-resistance or
crash-safe effect governance to PROVEN.

## Merge gate

- Same exact pinned Native and VERITAS sources and unmodified roster.
- Four distinct nonroot Linux UIDs and inherited #406 local DAC proofs.
- Database and parent directory enforced by backend UID (0600/0700);
  gateway-only kernel peercred at effect sink, agent direct bypass refused.
- Real pinned VERITAS Bind COMMITTED on normal and recovered precommit
  cases; one and only one durable target-owned synthetic effect.
- Forced \`os._exit\` before SQL commit rolls back; restart can safely
  commit once. Forced exit after SQL commit loses ACK but **preserves
  consumed/effect state**; reply remains UNKNOWN until independently
  reconciled; no second effect.
- Two successive restarts retain identical digest and effect receipt.
  Backend rejects replay even by authorized gateway UID.
- Redacted logs/SHA hashes only, zero real Provider, bank, official
  scoring, and no unsupported external IAM/durability/PROVEN claims.
- Dedicated #408 and inherited #407–#377 tests all PASS without skips;
  exact HEAD and all other repository CI SUCCESS.

## Next step

Validate multi-target/parallel concurrency and persistence under a
properly authenticated backend and real credential confinement;
model lease/expiry/state drift and reconciliation uncertainty explicitly.
Only after scope-bound **fresh operator approval** may paid independent
Provider A/B and official Native scoring be performed.
