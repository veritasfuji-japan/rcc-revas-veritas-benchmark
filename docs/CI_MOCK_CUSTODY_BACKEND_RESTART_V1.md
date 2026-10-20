# Retained databases across Custody and backend process restarts

Extends #495's normal run and three Custody-only crash runs without removing
them. Three additional independent runs inject the same faults, then restart
both Custody and the mock backend against their original SQLite databases.

Backend startup now has explicit fresh/restart modes. Fresh mode refuses an
existing database; restart mode refuses a missing database before SQLite can
create it. Restart checks SQLite integrity, exactly one valid counter/denials
row, and exact consistency of the counter with the operation ID and request-bound
receipt. Invalid state fails closed; no table is recreated and no state is reset.

After the fault and before backend shutdown, a credentialed Custody-UID observer
reads authenticated reconciliation. Both original services are stopped before
replacement processes start. The root supervisor reads durable rows from both
databases before restart and again after both replacements are running and the
Custody replay has been rejected. These snapshots must be identical, and both
new process IDs must differ from their originals. Authenticated reconciliation
before and after must match the exact original operation and effect receipt.

| Fault | Effect count across both restarts | Custody row | Additional backend probe |
| --- | --- | --- | --- |
| before-post | 0 | CONSUMED_UNKNOWN / null receipt | No effect POST; consumption remains spent |
| backend-response-lost | 1 | CONSUMED_UNKNOWN / null receipt | Authentic grant + valid transport credential duplicate must get HTTP 403 |
| before-client-reply | 1 | MOCK_OBSERVED / exact receipt | Authentic grant + valid transport credential duplicate must get HTTP 403 |

The duplicate backend probes deliberately run as trusted Custody UID and bypass
the frontend/ledger to isolate the backend's retained operation ID deduplication.
They are explicit negative test requests, not automatic recovery retries. Each
must preserve the effect and receipt; only the denial count increases (3 to 4).
No such probe is sent for the zero-effect case, where the backend has not spent
the operation. Custody's retained consumption independently prevents re-execution
of that case. A current zero observation never releases consumption.

The dedicated workflow requires 26 unit tests; existing 42 + 40/40/45 observation
suites; and new 43/44/49 observation suites. Shared controls are repeated in each
run, not claimed as unique test designs. All must have zero skips/errors/failures.
Restart artifacts contain sanitized database rows, operation/receipt hashes,
process IDs and authenticated reconciliation, joined by a report SHA-256; no
credential, grant packet or issuer private key is uploaded.

## Scope

This is two process restarts within one trusted CI VM with the same persistent
files and keys. It does not prove VM/machine reboot, power-loss or disk-failure
recovery, backend database rollback/deletion resistance, independent custody or
administration, distributed CAS, arbitrary crash ordering, or real Provider
idempotency. In the added cases the backend stops after its completed SQLite
transaction; there is no injected backend mid-transaction crash. Root/kernel,
trusted Custody/backend code and source/key enrollment remain the trust boundary.
No production provider capability is connected and utility remains unscored.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`
