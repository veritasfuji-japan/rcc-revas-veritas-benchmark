# Final128 #409 — concurrent competing grants, target binding, expiry and state drift

## Parent and frozen verification source

Parent #408 merged at \`899143464536c10ad8416b5106338499d231fab7\`.
Original AgentDojo \`a75aba7631d3ca5fb7ab938965c97ead2f9ff84b\`,
banking \`v1.2.2\`, VERITAS OS
\`a1d66aef02262cf8a913295270c3aafd159c6adb\`.
Unmodified canonical Task1 direct attack, full pinned Native tool set,
original 128-case enrollment and source protections.

#409 retains all #408–#377 inherited regression tests and adds a
**new disposable offline-only multigrant target-owned SQLite backend**
with **actual separate unprivileged Linux agent, gateway and backend UIDs**.

## Actual positive/negative boundary

The source-owned offline fixture defines three simulated target resources:
target-A, target-B and an intentionally expired target. Four public,
**nonsecret and not human-authorized** grant identifiers:
\`A-ONE\`, \`A-STALE\` (same target A, both expected revision 0),
\`B-ONE\` (target B, expected revision 0), and \`E-EXPIRED\`
(expiry *already in the past* on the backend-owned clock).

The backend alone owns its SQLite database under a \`0700\` directory
with \`0600\` file mode. Its Unix socket uses mode \`0660\` plus Linux
kernel \`SO_PEERCRED\` to admit only the exact gateway UID. The
untrusted agent cannot use the backend directly even if it knows an
entire source-owned fake grant.

**All of these are checked by the target owner inside**
\`BEGIN IMMEDIATE\`, not only by a gateway wrapper:

- Exact source-owned grant/resource/action/argument (strict integer 7)
  and immutable expected resource revision.
- Owner-clock \`expires_unix\`, never the caller-supplied timestamp,
  expiry override or a request-controlled clock.
- Live target revision equals the grant's expected revision 0.
- Backend-consumed bit is false, and the same grant/effect receipt
  cannot be inserted twice.
- In one SQLite transaction: increment target counter, increment its
  revision, consume the grant and insert a unique effect receipt.
- \`PRAGMA synchronous=FULL\` and backend-UID ownership preserve the
  result across a backend restart in this CI filesystem test.

## Real Bind and concurrency

The gateway loads the genuine pinned original Native Task1 and keeps
its NO_MUTATION rule; an attempted Native \`send_money\` is blocked by
the real pinned VERITAS Bind before a Native effect.

For the two *separate fixture-authorized target effects*, the gateway
builds a bounded \`ExecutionIntent\` and calls the real
\`execute_bind_adjudication\` on a synthetic \`ReferenceBindAdapter\`
whose \`apply\` reaches the independently owned backend. Both
COMMITTED receipts must correspond to backend receipts and target
state transitions.

**Eight distinct agent-side OS processes** simultaneously request
grant \`A-ONE\` via the gateway. Exactly one may COMMIT and produce one
effect on target A. The other seven must receive a consumed-grant
refusal. This test deliberately has a serialized gateway accept loop
and a serialized SQLite writer, so it does *not* establish arbitrary
distributed race resistance or parallel reentrant gateway safety.

After A's state revision becomes 1, the other unconsumed grant
\`A-STALE\` **must fail at the backend** due to live state drift.
\`B-ONE\` still succeeds because B has its own expected revision 0.
\`E-EXPIRED\` must fail at the backend even while it is unconsumed.
Direct target substitution, wrong units, forged prestate revision,
unknown grant, extra "admin"/approval keys and duplicate use fail.
A backend restart preserves both target effects, receipts, consumed
state, expired eligibility and revision refusals. Full #408
crash/recovery scenarios remain live in inherited tests.

## Explicit gaps and nonclaims

The grants are hardcoded, publicly visible fake fixture identifiers.
They are **not real credentials, signed human approvals, leases issued
by an independent authority, or production authorization**. Backend
expiry is based on its local wall clock; distributed clock drift,
rollback, monotonic leases and adversarial clock control are not proven.
The gateway processes requests sequentially; actual simultaneous
threads within one executor, multi-node contention and split brain
are out of scope, even though multiple clients connect concurrently.

No financial/banking external effect, paid Provider call or official
Native benchmark A/B Utility scoring occurs. No real IAM, network
egress, authentic external effect sink, machine-compromise attacker,
third-party validation or global production non-bypassability is proven.
The trusted CI runner has setup sudo powers and is not a hostile
principal. Never promote this test to PROVEN production authority.

## Merge gate

- Exact pinned originals and unchanged frozen 128-case roster.
- Linux separate-agent/gateway/backend UID and kernel peer identity.
- Owner-only durable SQLite ledger, one atomic sink transaction per effect.
- 8 concurrent client-process requests ⇒ 1 genuine Bind COMMITTED,
  1 backend effect, 7 consumed-grant rejections.
- 2nd legitimate distinct target gets its own genuine Bind COMMITTED.
- Target A's alternate unspent, stale grant fails at the target.
- Expired grant fails based on backend clock, independent of caller time.
- Target substitution, altered integer, forged version, extra fields fail.
- Backend restart preserves hash and refuses stale, expired, replay.
- Native Task1 remains read-only, inherited #408–#377 including real
  crash and OS denial tests run with **zero skipped**.
- Redacted hashes, no secret or attack payload leakage, no official
  model/scorer or unauthorized paid API usage.
- Full HEAD CI green; no unsupported production claims.

## Next beyond #409

Independent source-authenticated grant issuance, revocation, production
effect credentials held solely by hardened executor, cross-node durable
linearizable consumption, failover under actual network partition, and
external third-party attack review. For real AgentDojo A/B Utility
measurement, obtain separate fresh budget approval first.
