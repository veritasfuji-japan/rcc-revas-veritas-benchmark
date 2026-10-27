# Fixed receive deadline under continuous slow-drip response bytes

The frozen #558 capture demonstrates socket inactivity timeouts. Its 0.7-second
wait can be reset by continued bytes. This new **fixture-only transport
collector** adds one fixed two-second monotonic receive deadline. It is an
explicit new adapter; the original capture implementation and all existing
signature, authority, consume, SDK, Bind and continuation source bytes remain
frozen. This is not an operator deployment or production-readiness claim.

The deadline is set once immediately before the receive loop, including the
wait for the first response byte. Each recv uses min(0.7 seconds, time remaining)
and data never extends that deadline. The collector checks the clock both
before and after a read. Even bytes or EOF returned after the deadline are
retained as observed evidence and classified timeout; they never become a
successful response. The existing byte bound is retained, and a 256-read cap
bounds both fragmentation work and trace metadata. The original socket timeout
is restored on exit. Handshake, request write, archive fsync and later recovery
are outside this receive-loop budget; this is not a hard real-time guarantee.

## Actual Native slow-drip cases and fast positive control

| Case | Initial original response prefix | Subsequent response bytes |
| --- | --- | --- |
| headers-drip | Complete status line | One original header byte every 0.15 seconds |
| body-drip | Complete headers and first body byte | One original body byte every 0.15 seconds |

Both use the first actual bounded Native SDK request, the original scripted
backend effect, normal signed reserve/consume receipts and real VERITAS Bind.
The backend commits one A0 effect, then sends unchanged original bytes without
ending the response. Multiple receives finish inside the inactivity wait, yet
the unchanged absolute deadline stops collection. No timeout exception is
fabricated, and no Content-Length or payload byte is repaired.

Each fresh fixture first performs an authenticated GET /status/A0 over the same
Unix TLS transport and the **same new collector**. It must complete quickly
with EOF, status 200 and effect_count=0, without mutation or permission. This
is a read-only positive transport control, not a new Native completion/Utility
score. Portable tests separately exercise a verified-CA/hostname TLS complete
completion frame and both real slow-drip patterns. The original full normal
Native workflow remains mandatory with its own frozen capture implementation.

## Exact evidence and unchanged stopping gates

The report records the single start/deadline, each recv's configured wait and
actual result/time/bytes, and a distinct stop reason (total-deadline, inactivity,
eof, byte-limit, read-count-limit or read-error). Original archive v1 uses the
generic timeout classification; the report's joined trace distinguishes total
expiry from inactivity. The ciphertext alone does not attest which timeout
caused the stop.

Custody archives/fsyncs exactly what it observed before the existing completion
gate refuses parsing. A fresh archive owner decrypts and verifies its digest,
length and timeout classification. Successful sender writes and actual receiver
observations remain separate: received bytes must be an exact prefix of sent
bytes, which must be an exact prefix of the complete generated response. No
claim is made that every successfully sent final byte necessarily arrived.

The captured-response parser is never called, and no body is released to Bind
or Native. Real Bind returns BLOCKED for its denied arm and APPLY_FAILED for the
allowed arm; zero verified returns are not zero effects. The separate backend
row proves one effect. The original client close method is observed closing
the actual socket. Backend EOF/TLS/socket terminal results are kept distinct
and must follow the timeout and client close, rather than being relabeled EOF.

Ledger, issuer, Custody and backend are actually SIGKILLed and reopened under
different PIDs. The retained backend status role reopens the same pinned file
read-only with unchanged identity, bytes, schema and one effect row. Issuer
stays PENDING and local/external consumption stays CONSUMED_UNKNOWN at revision
2. Actual SDK reauthorization and original-grant replay are refused before a
second POST/effect. No callback-return marker, completed Bind/archive attestation,
Native response, scorer, terminal, continuation or retry permission appears.
Read-only reconciliation never repairs the state or restores execution.

All actors share one fresh loopback-only namespace while the original eight-UID
IPv4/IPv6 TCP/UDP reject rules and handles remain installed. Counter-verified
denials, root controls, seven pre-TLS wrong-UID refusals, peer UID/CA/hostname/
leaf checks and original signed-ledger mutual TLS/readback joins are required.
Each case uses a different supervisor lifetime and run ID; destroyed namespace
inode reuse is allowed. Source pins cover the frozen inactivity profile and
its predecessors, not a full runtime or independent administration attestation.

The workflow retains all previous normal and fault cases unchanged, and adds
64 portable checks plus 21 joined actual root checks per case with zero skips,
complete canonical report validation and tested-commit provenance.

## Limits

Two first-request local scripted slow-drip patterns and a fast read-only
control are covered on one live kernel/filesystem. Other drip patterns, every
cut offset, production networks, writable backend continuation, OS/VM reboot,
power loss, real Provider, remote GitHub, independent storage administration
and Utility improvement are not demonstrated. Public synthetic generated wire
is included for offline audit only; real-data confidentiality is not claimed.
No operator VM files, tokens, service UID 109, expired approval or host lease
are loaded or changed.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN** remain in force.
