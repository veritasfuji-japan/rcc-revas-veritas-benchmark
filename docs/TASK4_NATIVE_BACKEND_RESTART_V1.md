# Retained backend restart after committed effect and response loss

This adds a fresh, closed CI fixture after the response-loss trial in #555.
The original scripted backend commits exactly one A0 effect, then its raw HTTP
response is discarded before TLS sends application bytes. Actual Native SDK,
VERITAS Bind, signed reserve/consume receipts and local unknown consumption are
retained. Custody encrypts/fsyncs the observed zero bytes before parsing fails;
a fresh archive-owner process decrypts that exact observation. APPLY_FAILED and
zero verified response returns do not imply zero effects.

The supervisor now SIGKILLs and waits for **four** actual role processes:
ledger, issuer, Custody and backend. Each reopens with a different PID. The
backend's existing SQLite file is inspected before termination and after reopen:
file/directory device and inode, owner/mode/link count, entire file SHA256,
exact schema, integrity and the original one-row request/response/receipt join
must match. Missing storage, links, substituted schema, extra effects or changed
bytes stop; nothing initializes, resets or repairs a database.

## Explicit read-only retained backend role

The old bounded backend startup only supports fresh creation. This new role
therefore serves **status only**, rather than pretending that restarting the
scripted completion generator restores execution permission. It requires the
root-owned fixture pin captured after the original commit, opens the original
file with O_NOFOLLOW, reads SQLite through its held descriptor with mode=ro and
query_only, and rechecks its identity and bytes. It retires only the backend
UID's stale Unix socket after the supervisor has killed and waited for that
prior process. All POST requests are refused; no model is reconstructed and no
INSERT/UPDATE/CREATE or continuation is available in this role. The pin is an
in-fixture assertion by the same supervisor, not independent storage attestation.

The same Unix TLS transport still verifies kernel peer UID, CA, hostname and
leaf certificate, and authenticated GET /status/A0 reports the same one effect
before and after restart. The issuer remains PENDING, local/external consumption
remains CONSUMED_UNKNOWN at ledger revision 2, repeated actual SDK authorization
stops, and replay of the original signed grant is refused before dispatch.
No second backend POST, effect, grant, raw archive event, model mutation,
Native response, scorer, callback-return marker or retry permission appears.

## Required evidence and isolation

The complete canonical report includes all previous signed grant, ledger gate
journals and original readback/mTLS receipt joins, original SDK bytes, zero-byte
AEAD recovery, policy snapshots and replay outcomes. It additionally records all
four SIGKILL exit statuses, changed PIDs, the retained backend record/pin and
its actual UID/namespace/mode=ro reopen event. Validators join the database row
to the original SDK request and separately generated backend response receipt.

All roles run with dropped capabilities and NoNewPrivs in one fresh loopback-only
network namespace. The same eight-UID IPv4/IPv6 TCP/UDP reject rules and handles
remain installed during execution, four restarts and reconciliation. Baseline,
counter-verified denials before/after, root controls and removal checks remain
mandatory. Seven wrong backend peers are refused before TLS/HTTP. Existing
normal and both ledger acknowledgement-loss cases, plus #555's backend-alive
response-loss trial, remain unchanged and mandatory in the workflow.

41 portable checks and 18 joined actual root checks must pass with zero skips;
the workflow validates the complete report and tested commit. Selected source
pins include the frozen response-loss, acknowledgement-loss and normal profiles
and their dependencies. These are not full runtime attestation.

## Limits

This proves one scripted local effect survives process SIGKILL and read-only
reopen on the same live kernel/filesystem. Power loss, VM or OS reboot, writable
backend continuation, partial responses, later-history faults, real Provider
completion loss, remote GitHub and independent administration are not tested.
The GitHub backend is a local retained SQLite model. No operator VM file, token,
service UID 109, expired approval or host firewall lease is used or changed.
There is no deployment command or new live execution permission.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN** remain in force.
