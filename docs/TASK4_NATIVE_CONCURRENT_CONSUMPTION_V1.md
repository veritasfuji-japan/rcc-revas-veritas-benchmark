# Task4 Native: two Custody processes contend for one consumption

The pinned Native driver and real SDK produce the unchanged frozen A0 request.
An injected transport sends those same signed bytes concurrently over two fixed
Unix sockets to two actual Custody processes. Both use UID 61106 and one private
SQLite consumption ledger, transport credential and vault. Each checks actual
SO_PEERCRED and the exact issuer signature/scope before participating.

A private service-side barrier requires both processes to observe an empty
consumption ledger and publish their verified request hash, PID, UID and monotonic
arrival timestamp. Complete arrival markers are published with create-only hard
links. Each process records its release time only after seeing the other complete
marker; both must have arrived before either release. This is one controlled
overlap, not a scheduler fairness or load/stress guarantee.

The processes then execute the existing BEGIN IMMEDIATE / unique operation insert
against the same SQLite file. Exactly one must commit consumption and the other
must roll back with REPLAY_DENIED. The winner alone executes actual pinned Bind,
performs the authenticated local HTTP effect and fsyncs ciphertext. Require one
BLOCKED/apply=0 receipt and one COMMITTED/apply=1 receipt, one backend effect,
one consumed row and one ciphertext. Join them to the actual SDK request/response
hashes and winning process outcome.

Native decrypts the single winning ciphertext with the public test recipient,
checks its original scripted bytes and returns it to the real SDK parser. The
driver must then produce the exact next frozen A1 SDK wire. Stop at that second
transport invocation before forwarding it. This fixture returns one SDK response
but completes zero Native terminal arms/scorer calls; it makes no utility claim.
The original normal eight-request Native/scorer integration remains mandatory.

Refuse four identical replays across both sockets, stop both Custody processes,
start two new processes on the same ledger and refuse four further replays.
The backend stays alive in this concurrency fixture; require unchanged ledger
and effect rows across both Custody restarts. Preserve all six previous fault /
both-service restart fixtures and the older counter/kernel regressions.

Scope: two trusted processes with the same Custody UID and shared files on one
trusted Linux CI VM; isolated Native UID; synthetic approval; publicly reproducible
recipient key; local scripted completions. No independent administration,
cross-host/distributed CAS, database rollback or power-loss resilience is claimed.
The concurrent winner is not crashed in this fixture. Older counter winner-crash
evidence does not establish Native concurrent-winner crash behavior.
Root/kernel/Custody/backend/source/key enrollment remain trusted.

No real Provider request, external bank effect, paid approval reuse or
administration setting change. Artifacts exclude raw SDK bodies, ciphertext bytes,
grants, private keys, transport credentials and SQLite files.

REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN
