# Task4 Native: consumed winner crashes before Bind or dispatch

Extend the #502 two-Custody Native fixture with one additional controlled
overlap. The actual pinned Native driver and SDK produce the original frozen A0
request. Both trusted Custody processes independently validate its exact issuer
signature/scope and kernel peer, observe zero consumption, and reach the same
private service-side barrier before either is released.

Only the process winning the shared SQLite consumption insert writes a durable
crash marker and calls os._exit(88), immediately after consumption commit and
before calling actual Bind or performing HTTP dispatch. The losing process must
return REPLAY_DENIED and stay alive. Native observes exactly one lost IPC response
and one refusal; it aborts before returning any SDK response or creating A1.

The trusted supervisor joins both process IDs, barrier arrival/release timestamps,
request hashes and outcomes to the actual exited winner. Require a single
CONSUMED_UNKNOWN row, zero backend effects, no ciphertext and no completed Bind
receipt. Missing response/Bind evidence is never synthesized.

While the winner remains stopped, verify its socket is unavailable and send two
identical authentic replays to the surviving process. It must refuse both and
must not take over the operation. Restart only the winner on the same ledger
while the original loser stays alive; both fixed sockets must refuse two further
replays each. Reconcile twice using authenticated GET-only backend evidence;
absence must preserve CONSUMED_UNKNOWN and must not restore permission. Ledger
and backend rows must stay unchanged across all six replay attempts and recovery.
The initial losing request is a separate seventh refusal observation.

Keep the previous successful concurrency run, normal eight-request Native/scorer
integration, all six fault/both-service restart fixtures and older counter/kernel
regressions. Historical sources and frozen request/recipient manifests remain
unchanged. Root enrolls the crash mode as a fixed read-only fixture; neither the
signed Native packet nor an untrusted socket caller selects the crash point.

Scope: one controlled two-process overlap on one trusted Linux VM, using the
same Custody UID/credential/SQLite file/vault. Backend stays alive. No distributed
CAS, independent administration, power-loss/storage rollback resilience,
concurrent-winner post-effect response-loss handling, or genuine utility claim.
The new fixture completes zero SDK responses, Native terminals or scorer calls.
Root/kernel/Custody/backend/source/key enrollment remain trusted; recipient key
is public and synthetic. Local backend absence is not an external NO_EFFECT proof.

No real Provider request, external bank effect, paid approval reuse or
administration setting change. Artifacts exclude raw SDK bodies, grants, private
keys, credentials, ciphertext bytes and SQLite files.

REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN
