# Custody process crashes and lost-response reconciliation

Extends #494 in the same disposable trusted Linux CI environment. The normal
42-observation run remains mandatory. Three additional independent runs each
use a fresh issuer key, credential, backend DB and Custody DB. They repeat all
applicable UID/netns/firewall/forgery checks, then inject one precise fault:

| Fault | Actual injection | Backend effects | Durable Custody row | Terminal Bind receipt |
| --- | --- | --- | --- | --- |
| before-post | os._exit(73) after consumption commit, before Bind or POST | 0 | CONSUMED_UNKNOWN, no receipt | Absent |
| backend-response-lost | Backend commits effect, closes TCP without HTTP reply; Custody exits 74 on the resulting OSError | 1 | CONSUMED_UNKNOWN, no receipt | Absent |
| before-client-reply | os._exit(75) after completed Bind and local result commit, before caller reply | 1 | MOCK_OBSERVED, matching receipt | COMMITTED |

These are actual process exits and local TCP response loss, not simulated
return-value assertions. Only the successful effect response is dropped;
negative backend probes still return HTTP 403 and authenticated reads work.
The exact child exit code is required. SQLite synchronous=FULL consumption is
committed before dispatch. No automatic retry is performed.

The caller receives DENIED_OR_UNKNOWN_NO_RETRY in each case. A repeated request
while Custody is stopped remains unknown and causes no send. Custody restarts
without the fault flag against the same ledger; replay must return REPLAY_DENIED,
including when the backend effect count is zero. No consumed attempt is released
or converted back to executable authority based on a zero-effect observation.

After restart, a Custody-UID observer calls a dedicated authenticated GET
/reconcile endpoint. Its separate HMAC domain binds the fixed operation ID;
the response contains the current effect count and request-bound receipt, or
null if absent. The root supervisor stops services and independently reads both
SQLite databases to check that this read matches backend state and that the
local crash state is exactly as expected. Reconciliation is read-only: a backend
effect observation does not invent a COMMITTED Bind receipt or silently rewrite
the CONSUMED_UNKNOWN ledger row.

The workflow requires 17 unit tests, the normal 42 observations, and fault suites
of 40/40/45 observations, with zero skips/failures/errors. Reports expose the
fault, local state, terminal-receipt availability, authenticated reconciliation,
source hashes and current observed backend effect count. No signed grant or
private credential is uploaded. The final fault's retained Bind receipt joins
the backend and local ledger; the first two faults deliberately have no terminal
Bind receipt and are not reported as completed Bind adjudications.

## Limits

This proves the specified single-process crash windows and current state of the
local trusted mock backend, with that backend kept running across Custody
restart. It does not prove machine power-loss recovery, filesystem/storage
failure, network partitions of arbitrary length, backend restart durability,
arbitrary crash instruction coverage, distributed CAS or a real Provider's
reconciliation API. An observed zero is current mock state, not universal proof
that a delayed external effect can never appear. Root/kernel/Custody/backend,
source enrollment and synthetic approval remain trusted as described in #494.
Production bypass resistance, independent administration and utility remain
unproved. No real Provider calls, external bank effects or paid/admin settings.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`
