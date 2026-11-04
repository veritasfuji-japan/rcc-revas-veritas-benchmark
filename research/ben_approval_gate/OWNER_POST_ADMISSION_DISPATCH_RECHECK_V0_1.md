# Ben synthetic Owner post-admission recheck at the final mock dispatch

**Research-only / isolated Linux CI mock / pinned VERITAS Bind / no provider calls.**

## What changes after #586

In opt-in `--with-synthetic-owner` mode, the trusted isolated mock
Custody now performs a second fresh nonce-bound backend prestate read and
re-runs signed Owner Approval and synthetic revocation/validity checks
**inside the pinned Bind adapter's `apply` callback immediately before
the mock HTTP effect POST**. This is distinct from the initial
pre-consumption check and enforces a second decision at a later boundary.

## New deterministic negative experiments

The CI supervisor injects exactly one of `--owner-dispatch-drift=revoked`
or `expired` into a separate isolated run. After the initial owner
check and durable `CONSUMED_UNKNOWN` insert, the pinned Bind reaches
the adapter `apply` callback and pauses before the final check. The
supervisor modifies the root-owned synthetic Owner current-validity file,
then releases the adapter. The second check must deny.

The test asserts:

- a real pinned Bind invocation reached its adapter `apply` boundary;
- the Owner state changed after initial authorization and durable consume;
- the Custody returned denial rather than a false success receipt;
- backend mock effect count remained **zero**;
- local Custody ledger remained **`CONSUMED_UNKNOWN`**, not released for
  retry and not presented as evidence of an external effect;
- same-run replay remained rejected; no real provider API calls occurred.
- separate normal-mode CI remains green and still confirms one legitimate
  synthetic mock effect and reconciled receipt.

## Security boundaries that this DOES NOT prove

1. **Not atomic with the HTTP effect.** There is a window after the second
   check and before the mock backend commits the effect. A still later
   revocation cannot be proven to stop the operation. The backend currently
   does not independently verify the Owner proof or the revocation epoch.
2. **No independently trustworthy current time.** The expiry clock is a
   root-controlled synthetic tick, not wall-clock, distributed time, or
   hardware attestation. Revocation is also a root-controlled CI fixture.
3. **No external execution.** The pinned Bind adapter applies only to an
   isolated mock endpoint with one synthetic counter. No real owner, money,
   provider credentials or production RCC dispatch adapter.
4. **No distributed atomicity.** The existing Custody durability and mock
   backend guarantees do not establish atomic interservice or multinode
   single-use consumption. This new test concerns two post-admission
   negative races only, not general crash/concurrency coverage.
5. **Fail-safe unknown, not zero-cost rollback.** A consumed permit remains
   `CONSUMED_UNKNOWN` after late denial. No automatic retry is allowed.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
ATOMIC_REVOCATION_AND_EFFECT_NOT_PROVEN`

The next research stage is a mock backend policy epoch enforced atomically
with its effect transaction, followed by synchronized concurrency and
failure-window tests.
