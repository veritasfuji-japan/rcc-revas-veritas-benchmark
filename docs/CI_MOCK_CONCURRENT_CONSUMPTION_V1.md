# Two Custody processes competing for one consumed operation

Current extension: [consumption winner crash](CI_MOCK_CONCURRENT_CONSUMER_CRASH_V1.md)
adds the explicitly allowed before-post concurrent fault as a separate mandatory
47-observation run. The normal successful concurrent run below remains required.
The current unit suite has 32 cases; other concurrent fault modes remain refused.

Extends #496 without removing the normal, crash, or both-restart suites. The
existing every-PR workflow additionally requires one 47-observation concurrent
run and 30 unit tests, with no skips/errors/failures.

The frontend and normal Custody are sequential servers. Sending concurrent
frontend requests alone would not demonstrate competing database transactions.
This proof instead starts a second trusted Custody process under UID 61106,
using a separate Unix socket and the exact same SQLite ledger. Two distinct
Executor-UID client processes submit the same authentic signed request, one to
each Custody socket. Both Custodies still enforce actual SO_PEERCRED and exact
issuer signature/scope. Clients receive no transport credential or ledger access.

## Actual contention, not just parallel clients

Each Custody records its PID and the kernel device/inode of its ledger after
validation. The root supervisor requires both arrivals before releasing a test
gate. Both attempt BEGIN IMMEDIATE with zero SQLite busy timeout. The first
holds its actual write transaction until the other receives SQLite's locked
OperationalError (SQLITE_BUSY) and records that event in its private directory.
The loser retries only lock acquisition, with a four-second deadline. This is
before its INSERT or network dispatch, not an effect retry.

The winner then inserts CONSUMED_UNKNOWN and commits before invoking real Bind.
The loser subsequently acquires the write lock, encounters the operation ID
primary-key conflict, rolls back and returns REPLAY_DENIED. Both restore the
normal SQLite busy timeout after leaving that transaction. Test gates and event
markers live under the disposable trusted supervisor/Custody filesystem and
cannot be written by Executor. The scheduling gate is enabled only by the
explicit proof flag, with fault/restart modes refused; it is not an approval
mechanism or a production concurrency implementation.

Required results: two Custody PIDs, matching kernel ledger identity, exactly one
busy-process marker, both lock-acquisition markers, two distinct client PIDs,
one MOCK_EFFECT_ONCE response and one REPLAY_DENIED. The winning response must
join the exact request digest, one backend effect, one Custody consumption row,
authenticated reconciliation, and real Bind BLOCKED/BLOCKED/BLOCKED/COMMITTED
receipts with apply counts 0/0/0/1. Only the insertion winner calls Bind/effect.
The replica is then stopped, and ordinary replay before and after primary
Custody restart must still be denied.

## Scope

This proves two contenders in separate local processes sharing one SQLite file
in one trusted CI VM. It is not a test of simultaneous frontend handling,
distributed CAS, multiple machines, independent administrators, arbitrary
numbers of clients, concurrent crash/restart combinations, or a real Provider's
idempotency. The trusted root/kernel, Custody/backend, pinned source and enrolled
synthetic issuer remain the trust boundary. Existing no-credential, peer,
signature, code/file and network refusals are repeated in this run. No private
credential or signed packet is uploaded; concurrency evidence contains only
PIDs, device/inode, sanitized decisions and hashes.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`
