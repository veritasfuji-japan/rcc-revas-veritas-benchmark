# Task4 Native: concurrent winner loses its backend response

Extend the #502/#503 actual Native two-Custody fixture. Both trusted Custody
processes validate the same frozen A0 SDK wire and issuer signature, observe
zero consumption and reach the private barrier before either release. Exactly
one wins the shared SQLite consumption insert; the other refuses and stays alive.

The winner calls the existing pinned Bind adapter. Inside its permitted apply,
the authenticated local HTTP backend independently checks the grant and wire,
generates the original scripted response, durably commits one effect/receipt,
then closes the HTTP connection without returning that response. The winner's
Bind call fails; it durably marks the interruption and exits 89 before replying
to Native. No successful completed Bind receipt is claimed or synthesized.

The supervisor must join the backend's post-commit response-drop marker and
actual effect row to the request hash, winning PID and consumption row. Require
one effect and one CONSUMED_UNKNOWN row, with no response fields, ciphertext or
completed Bind receipt. Native sees one lost IPC response and one REPLAY_DENIED;
zero SDK responses, Native terminals or scorer calls complete in this fixture.

Refuse two identical replays at the original survivor while the winner is stopped.
Restart only the winner on the same ledger with the loser still alive, then
refuse four more replays across both sockets. Reconcile twice using authenticated
GET-only backend receipt evidence. The exact operation/request/response/receipt
hash binding must transition the ledger to MOCK_EFFECT_CONFIRMED_NO_RESPONSE;
it must not restore execution permission or assert raw-response recovery.
Refuse four further replays after confirmation. All ten replay attempts must
leave the one backend effect unchanged. The initial race loser is a separate
refusal observation.

Reconciliation also refuses to replace a previously confirmed response/receipt
pair with a different hash-valid pair or erase confirmation when evidence is
missing. Existing normal, six fault/restart, successful concurrency and pre-send
winner-crash fixtures remain mandatory, with historical pins unchanged.

Scope: one controlled overlap on one trusted Linux VM, shared trusted Custody
UID/credential/SQLite/vault, distinct Native/backend/issuer UIDs. Backend stays
alive during winner restart. No distributed CAS, independent administration,
power-loss/storage rollback resilience, model provenance, genuine utility,
completed Bind COMMIT after response loss or original response recovery claim.
Root/kernel/Custody/backend/source/key enrollment remain trusted. Recipient key
is public and synthetic. Effect confirmation is limited to this local backend.

No real Provider request, external bank effect, paid approval reuse or
administration setting change. Artifacts exclude raw SDK bodies, grants,
credentials, private keys, ciphertext bytes and SQLite files.

REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN
