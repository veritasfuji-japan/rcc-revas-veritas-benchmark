# Live TLS response timeout without restored execution permission

Three fresh closed CI cases extend #557's EOF-prefix trial. The original
scripted backend commits one A0 effect and generates a complete response.
It sends either no application bytes, the original incomplete-header prefix,
or the original half-body prefix through the real Unix TLS connection. It
then **keeps that stream open**, waiting for the client to close it. No sleep,
early server EOF, replacement timeout exception or rewritten framing is used.

The original Custody capture runs with its unchanged socket timeout of 0.7
seconds. An observer records its actual completion classification, bytes,
monotonic start/end, configured timeout and the still-open socket descriptor
before the original transport closes the connection. The backend records when
it began holding the stream and when it actually received EOF from that
client. Validation requires capture completion = timeout and capture end
strictly between those backend observations, in the same isolated namespace.
A lower-bound duration check guards against fabricated immediate timeout;
this is not a real-time scheduling or exact deadline guarantee.

| Case | Bytes sent while stream stays open | Required client result |
| --- | --- | --- |
| empty-timeout | None | Empty capture classified timeout, not EOF |
| headers-timeout | Same strict header prefix as #557 | Exact prefix classified timeout |
| body-timeout | Same original headers and half-body prefix as #557 | Exact prefix classified timeout |

## Archive first, no parser or continuation

The unchanged transport captures the actual bytes, closes its client socket,
then encrypts/fsyncs the original X25519/HKDF/AES-GCM archive. Its existing
completion gate refuses timeout before HTTP parsing begins. A parser observer
must record **no calls**, and there must be no HTTP_PARSE_STARTED or body-release
event. The observer returns the original capture result unchanged; no authority,
consume, SDK, Bind, parser or retry check is substituted.

Real Bind produces BLOCKED for its denied arm and APPLY_FAILED for the allowed
arm when that existing completion gate raises ValueError. Zero verified
response returns are not zero effects: the separate backend row proves one
committed effect. No callback-return marker, completed Bind/archive attestation,
Native SDK response, scorer, terminal, continuation or new permission appears.

A fresh archive owner decrypts the sealed observation and checks its exact
length/digest and timeout classification. Generated, transmitted and observed
bytes stay distinct. Public synthetic generated wire is retained solely for
offline audit, not released to Native; real-data confidentiality is not claimed.

## Four real restarts and same closed controls

Ledger, issuer, Custody and backend are SIGKILLed and waited for, then reopened
with different PIDs. The retained backend role opens only the same pinned
SQLite file read-only, with unchanged device/inode, owner/mode/link count,
whole-file hash, exact schema and one effect row. It serves authenticated
status only and refuses dispatch, rather than reconstructing the completion
model or repairing an uncertain result. Missing or changed storage stops.

Actual SDK reauthorization and original signed-grant replay are refused before
another POST. The issuer stays PENDING, local and signed-ledger consumption
stay CONSUMED_UNKNOWN at revision 2, and read-only reconciliation sees the same
effect receipt without issuing permission. No second effect, backend POST,
model mutation or raw archive event occurs across restart and replay.

The original eight-UID IPv4/IPv6 TCP/UDP reject table remains installed during
execution, timeout, restart and reconciliation. Counter checks, root controls,
unchanged policy handles except counters, seven pre-TLS wrong-peer refusals,
Unix TLS UID/CA/hostname/leaf checks and original signed-ledger mutual TLS /
readback joins remain required. Each case has a distinct supervisor lifetime
and run ID; reuse of a destroyed namespace's inode is allowed.

The mandatory workflow preserves every prior normal, ledger ACK-loss,
zero-response-loss, retained-backend and EOF-prefix trial. It adds 68 portable
checks and 20 joined actual root checks per case with zero skips, complete
canonical report validation and tested-commit provenance. Source pins include
the frozen partial-response profile and its predecessors, not full runtime
attestation. All fixtures use dropped-capability actors and root-owned exports.

## Limits

This proves three first-request, local scripted open-stream timeouts on the
same live kernel/filesystem. It does not cover all offsets, slow-drip streams,
late response release, writable backend continuation, OS/VM reboot or power
loss, real Provider completion loss, remote GitHub or independent storage
administration. Backend waiting has a bounded failure timeout; if the expected
client close is not observed, the proof fails instead of inferring success.
No operator VM file, token, service UID 109, expired approval or host lease is
loaded or changed. There is no deployment or live execution command.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN** remain in force.
