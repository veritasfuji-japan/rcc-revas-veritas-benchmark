# CI Synthetic Owner policy and effect atomicity in one mock backend transaction

**Research-only; isolated Linux UIDs/netns; no real provider, owner or trusted clock.**

## Precisely demonstrated boundary

The existing opt-in mock Custody chain has an additional, opt-in
`--owner-backend-atomic` mode. The backend process (UID 61103), rather than
the untrusted agent or Custody alone, checks a signed synthetic Owner statement,
separate Owner/issuer public keys, the exact request/prestate, and *its own*
durable Owner policy row under `BEGIN IMMEDIATE` in the **same SQLite
connection and write transaction** as inserting the mock spent operation
and incrementing the counter. Failed validation rolls the transaction back;
no effect is committed. No user-provided bypass/skip flag is accepted by the
backend HTTP request.

A separate CI root process can mutate the mock backend's policy row with
its own `BEGIN IMMEDIATE` transaction (synthetic authority only).

### Tests

- Normal valid synthetic approval traverses Agent → Executor → Custody →
  pinned real VERITAS Bind → protected mock backend and produces one mock
  effect with matching durable receipts.
- **revoked-first**: Custody's final preflight passes and sends HTTP.
  The backend pauses before its effect transaction. The trusted test
  supervisor commits a backend Owner-policy revocation (epoch increment),
  then releases the HTTP handler. The backend reads the revoked row
  **inside its effect transaction**, refuses the effect and leaves the
  backend spent table empty.
- **expired-first**: same schedule, except the backend's synthetic tick moves
  beyond the signed validity interval. Again zero mock effects.
- Rejected attempts preserve Custody `CONSUMED_UNKNOWN`; replay is refused.
- An independent SQLite unit test proves a competing policy writer gets
  SQLITE_BUSY while a backend effect transaction holds the write lock.

## Trust assumptions and limitations

1. The Owner's key is still synthesized by root for CI. Root also seeds and
   modifies the backend policy row. This is **not independently established
   human consent, real authority provenance, or production Owner Approval**.
2. `clock_tick` is a synthetic logical tick. No trusted real time, revocation
   propagation SLA, distributed epoch consistency or anti-rollback authority
   proof is established.
3. This is **atomic only inside one mock backend SQLite database**: policy
   read and effect INSERT/UPDATE are guarded by the same SQLite write lock.
   It is not an atomic transaction spanning Custody and backend, multiple
   nodes, a real SaaS provider or an irreversible external side effect.
4. When effect is refused after local durable Custody consumption, the state
   remains `CONSUMED_UNKNOWN`; no automatic retries or false COMMITTED receipt.
5. The test deliberately handles revocation/expiry **committed before the
   backend starts the effect transaction**. If a revocation transaction is
   committed *after* the effect transaction, no retroactive prevention is
   possible. Serialization determines order; it is not clairvoyance.
6. The atomic Owner mode is opt-in only for isolated normal-path research
   runs; combined crash, restart and concurrent owner cases have not been
   demonstrated in this mode. Older separate non-owner/Owner tests remain
   scoped as before.
7. HMAC transport trust remains shared by Custody and backend. Compromised
   root/Custody or external reality cannot be ruled out here.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`
