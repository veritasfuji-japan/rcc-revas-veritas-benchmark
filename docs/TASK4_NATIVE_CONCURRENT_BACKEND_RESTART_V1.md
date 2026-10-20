# Task4 Native: backend restart after concurrent response loss

Extend the #504 two-Custody response-loss fixture with a separate run in the
existing offline GitHub Actions workflow. The original run remains mandatory.
Both actual Custody processes verify the same frozen A0 SDK bytes and issuer
grant, observe zero consumption and reach the private barrier before release.
Exactly one consumes; its permitted Bind apply causes one local backend effect
and durable receipt, but the backend drops the HTTP response. The winner exits
89 before replying to Native. The original losing Custody stays alive throughout.

Recovery sequence:

1. Snapshot the one effect and CONSUMED_UNKNOWN row, then SIGKILL the backend.
2. Refuse two identical replays at the survivor while the winner is unavailable.
3. Restart the winner on the same ledger while the backend is still stopped.
   Refuse four replays across both sockets. Attempt authenticated GET-only
   reconciliation: unavailability must preserve the ledger and restore no permission.
4. Restart the backend with a different PID and the same retained SQLite file.
   Open it read-only, validate integrity and the exact single A0 request/receipt
   binding, and serve receipt evidence only. Do not recreate scripted model state
   or permit completion POSTs. A direct authenticated replay is refused with 403.
5. Refuse four more Native replays, then reconcile twice idempotently through
   authenticated GET /receipt/A0. Join the retained receipt to the original
   response-drop marker, operation, request and response hashes. Transition to
   MOCK_EFFECT_CONFIRMED_NO_RESPONSE without restoring dispatch permission.
6. Refuse four further Native replays after confirmation. Require identical
   backend database bytes, exactly one effect and consumption, no ciphertext,
   no completed Bind receipt and no raw response recovery.

All fourteen Native replay attempts are refused. The initial race loser and
direct backend negative POST are separate refusal observations. Exactly one SDK
request is forwarded to two Custody attempts; zero SDK responses, Native terminal
arms and scorer calls complete. Report the actual old/new backend and winner PIDs,
original survivor PID, stopped-backend observations, retained rows and database
hash, and all 37 fail-closed checks as sanitized JSON plus matching JUnit.

The restart reader is restricted to the existing bounded fault fixtures or the
exact enrolled concurrent response-loss fixture. Missing, extra or mismatched
retained effects fail startup; missing databases are never recreated. Unit tests
cover read-only recovery and invalid retained evidence. All prior normal, six
single-Custody fault/restart, successful-concurrency, pre-send winner-crash and
backend-alive response-loss runs remain required with historical pins unchanged.

Scope: one controlled overlap on one trusted CI Linux VM/kernel, shared trusted
Custody UID/credential/ledger/vault, separate Native/issuer/backend UIDs. Root,
kernel, source/key enrollment, Custody and backend are trusted. This is receipt-only
recovery, not resumption of the scripted dialogue or a completed Bind COMMIT.
No distributed CAS, independent administration, power-loss or storage rollback
resilience, real model provenance, genuine utility or original-response recovery
claim. The recipient private key remains public/reproducible synthetic test data.

No real Provider send, external bank effect, paid approval reuse or administration
change. Artifacts exclude raw SDK bodies, grants, credentials, private keys,
ciphertext bytes and SQLite files.

REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN
