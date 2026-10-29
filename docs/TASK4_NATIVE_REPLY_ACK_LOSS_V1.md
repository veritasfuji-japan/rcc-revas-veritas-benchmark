# Native acknowledgement loss after successful storage v1

This isolated profile kills actual Custody after successful archive return or
after the original handler has finished, immediately before its caller can send
the Native reply. Original storage, consume/Bind/SDK and signed-ledger code is
unchanged. Scoped wrappers call originals once and never fabricate a result.

| Selected SIGKILL point | Actual internal outcome | Native outcome |
| --- | --- | --- |
| after-seal-return | Full original encryption/write/flush/file fsync/close/directory fsync/return; no parser reached | Zero-byte IPC EOF; no SDK response or continuation |
| before-native-reply | Original parse and ID/framing guards, actual committed Bind, signed archive, durable result files, autocommitted MOCK_OBSERVED row and gate effect-returned marker; handler returned to wrapper | Same zero-byte IPC EOF; no Native response, tool observation, scorer or continuation |

The first case retains local CONSUMED_UNKNOWN. The second deliberately retains
local MOCK_OBSERVED, demonstrating that completed internal processing is not
acknowledgement to Native. In both cases issuer stays PENDING/CONSUMED_UNKNOWN
because no Native tool observation arrived. The external signed ledger remains
revision two CONSUMED_UNKNOWN (its single-use consume semantics are unchanged).
One local backend effect remains, never repeated.

## Exact evidence and restart

Both cases capture a complete valid EOF response through the existing total
receive deadline and close the connection. The original archive observer records
15 actual storage events ending in SEAL_RETURN. A separate SEAL_ACK_RETURNED event
records that actual returned metadata. Only the second case reaches PARSED and
CONSUME_RETURNED. Its exact prepared reply, committed row and false in_transaction
are recorded after the original handler returns, before the original sendall.
The current process sends itself SIGKILL; the real Native frame reader observes
zero-byte EOF and stops at BOUNDED_FRAME. No exception unwind is claimed.

The supervisor joins actual -9 exit/PID to the crash intent before killing the
other three roles. All four reopen with new PIDs. Custody's explicit retained
startup checks the selected one-row state and gate journal without initialization,
reset, repair or cached response delivery. Original handlers still reject replay
before any effect. Backend reopens its same pinned database read-only. Repeated
Native request, consume replay, reissue and reconciliation issue no permission.

Separate snapshot workers show unchanged archive bytes/inode/hash across reopens.
Fresh original owner recovery authenticates/decrypts the complete ciphertext in
both cases, without granting permission. For the completed-handler case, validators
also verify the actual Custody Ed25519 archive signature, manifest/grant/request/
response commitments, exact original Bind receipts, returned body, result files,
committed SQLite row and gate effect-returned marker. These are internal evidence;
no signed tool observation or completed Native parent is inferred from them.

## Positive control and limits

The new matching normal profile runs the same observer and handler-return wrapper
without killing. It joins 16 acknowledgement events to 120 storage events, eight
actual SDK steps, two terminals/scorers, sixteen signed mutations and all original
parent/tool/receipt/archive/owner/network checks. SQLite tuple/list containers are
compared through canonical JSON; field values and boolean types stay exact.

CI requires 82 new portable tests, 21 joined normal checks and 24 per failure,
without skips. Portable tests actually SIGKILL processes after real storage and
a labelled same-UID SQLite stand-in handler; that stand-in is not claimed as
original Native execution. Mandatory disposable-root cases delegate the frozen
original handler with separated UIDs, caps/NNP, Unix TLS, Native SDK and signed
ledger. Prior storage and receive controls remain mandatory. The growing combined
job receives a 50-minute execution budget; receive limits, authority and no-retry
conditions are unchanged.

Selected process crashes only, not power loss/reboot, every IPC byte boundary,
arbitrary partial writes, hostile concurrent writers, independent storage/operator
administration or full-runtime attestation. The synthetic root controller knows
fixture keys. Normal Custody keeps its frozen TERM/reopen control. No operator VM,
token, real Provider, remote GitHub backend, persistent host rule, trust store,
live permission or service cutover is changed.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN** remain unchanged.
