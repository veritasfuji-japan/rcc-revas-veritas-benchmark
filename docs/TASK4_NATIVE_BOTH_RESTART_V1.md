# Task4 Native: restart Custody and backend on retained records

The #500 fault fixtures kept the backend alive. Add three independent runs of
the same actual first Native A0 SDK request and the same fixed fault stages:
after consumption, after backend commit with lost HTTP response, and after
durable ciphertext/observed-ledger storage but before the Native reply.

After the Custody fault, SIGKILL the actual backend process. Retain its original
SQLite database, transport credential, issuer key enrollment and network
namespace. Start a new Custody process on its original ledger while backend is
still unavailable. Two identical authentic Native replays must be refused.
Authenticated receipt reconciliation must fail as unavailable without changing
the consumed ledger or restoring permission.

Start a new backend process. It opens the existing database with SQLite
`mode=ro`, validates integrity, the exact expected row count and original A0
request/response receipt binding, and serves authenticated receipt/status GETs.
It refuses all effect POSTs, including a freshly authenticated replay of the
original, issuer-signed A0 packet. Missing/mismatched storage fails startup;
restart cannot create a replacement database or silently reset the effect count.

Check both services have new PIDs, the exact original rows are retained, and
backend database bytes remain unchanged throughout recovery. Then perform two
more Native replays, two idempotent authenticated reconciliations and two final
Native replays: six Native refusals in each fixture, plus one backend HTTP 403.
This uses the same Custody and backend roles, UID/network boundaries and pinned
Native/SDK/VERITAS sources as the preceding proof.

| Fault | Effects after both restarts | Reconciled Custody state | Ciphertext |
| --- | --- | --- | --- |
| after-consume | 0 | CONSUMED_UNKNOWN | 0 |
| backend-response-lost | 1 | MOCK_EFFECT_CONFIRMED_NO_RESPONSE | 0 |
| after-sealed | 1 | MOCK_OBSERVED | 1 |

Absence remains uncertainty and never reauthorizes dispatch. Existing backend
effects join the original request, response and receipt hashes to the retained
Custody record; sealed evidence also joins actual Bind receipts and ciphertext.
An observed effect is not itself a completed Bind COMMIT or a recovered response.

This recovery mode deliberately does not resume the scripted backend's
in-memory dialogue state or accept fresh requests after restart. The Native
driver is interrupted before any SDK response, Native terminal or scorer result
in these fault runs. The separate normal eight-request integration still runs
to completion. Keep all #500 single-backend fault and counter/kernel regressions.

Scope: process restart with retained files on one trusted disposable Linux CI
VM, not VM/power-loss/storage rollback or cross-host/distributed recovery. No
concurrent Native consumption, independent administration, genuine utility,
real-data confidentiality or production-wide bypass-resistance claim.
Root/kernel/Custody/backend/source/key enrollment remain trusted. Recipient
private key is public and synthetic. No raw response recovery is implemented.

No real Provider request, external bank effect, paid approval reuse or
administration setting change.

REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN
