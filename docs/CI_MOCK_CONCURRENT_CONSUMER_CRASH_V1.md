# Competing consumer crashes after durable consumption, before dispatch

Extends #497's two-process SQLite contention proof with one separate mandatory
run combining actual contention and the already proved before-post fault.
The existing normal, crash, both-restart and successful concurrency runs remain.
The unit suite has 32 cases; this additional integration suite has 47 observations,
all required with zero skips/failures/errors.

Two real Executor-UID clients submit the same authentic signed request to two
trusted Custody processes sharing one ledger. Both validate scope/signature and
kernel peer UID. The existing test gate forces a real SQLite write-lock loser
before the winner can commit. Both Custodies are armed with before-post failure,
but only the primary-key INSERT winner reaches the fault: it commits
CONSUMED_UNKNOWN, records its PID in a private post-commit marker and exits 73
before calling Bind or POST. The loser acquires the lock, sees the committed
operation ID, returns REPLAY_DENIED and remains running.

The winner's client receives an actual socket EOF/reset and records
DENIED_OR_UNKNOWN_NO_RETRY without resending. The normal concurrency client
does not accept such errors as success. The supervisor requires exactly one
post-commit winner PID, its exact exit code, the matching caller's unknown
result, a still-running distinct survivor, and an additional authentic request
to that survivor returning REPLAY_DENIED. It does not assume the primary or
replica wins; both orderings use the observed winner identity.

The supervisor then stops the survivor, confirms the stopped frontend path
remains unknown, and restarts the primary Custody without fault/concurrency
flags against the original ledger. Replay must still be refused. Authenticated
backend reconciliation and final independent SQLite reads must show zero effects,
one CONSUMED_UNKNOWN row and no receipt. No terminal Bind artifact is created;
this is not reported as COMMITTED or a completed Bind adjudication. A zero
current effect observation never releases consumption to the survivor.

Sanitized concurrency evidence joins two Custody PIDs, two client PIDs, matching
ledger device/inode, one actual lock-loser PID, both acquired-write-lock markers,
one committed winner, its process exit, and survivor replay result. Its SHA-256
is bound into the run report. No private credential or signed packet is uploaded.

## Limits

This proves only this injected post-consumption/pre-dispatch crash window with
two local processes sharing one SQLite file on a trusted CI VM. Other concurrent
fault windows remain refused by configuration. It does not prove arbitrary
crash timing, distributed CAS, separate machines, independent administrators,
survivor takeover for availability, or real Provider behavior. Both Custodies
share a UID/credential and are trusted; root/kernel/backend/source and synthetic
issuer enrollment remain trusted. SQLite lock-acquisition retries happen only
before consumption/dispatch and are not network effect retries. There are no
real Provider calls, external bank effects, paid or repository admin changes.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`
