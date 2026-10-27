# Partial raw response followed by retained restart

Two fresh closed CI cases extend the frozen backend-restart proof in #556.
Each uses the first actual bounded Native SDK request, original signed
reserve/consume receipts, real VERITAS Bind and the original scripted backend.
After that backend commits exactly one A0 effect and generates a complete
response, a backend-only send boundary forwards one unchanged strict prefix
through the real Unix TLS connection. The original handler then closes it.

| Case | Transmitted prefix | Original parser result | Allowed Bind receipt |
| --- | --- | --- | --- |
| headers-cut | Status line and incomplete first header, no body | ValueError from required response validation | APPLY_FAILED, zero verified response returns |
| body-cut | Complete original headers and half the original body | IncompleteRead from original HTTP framing | None: exception propagates to the existing signed gate |

No Content-Length is rewritten, no bytes are padded, and no exception is
translated to make the cases look alike. The existing signed gate sanitizes a
failed callback and the original Native runtime stops. In particular, the
body-cut case does **not** produce an APPLY_FAILED receipt from the frozen
Bind core, whose exception handler does not catch IncompleteRead. The report
requires that absence; it does not fabricate a final Bind outcome. In both
cases zero verified response returns cannot be interpreted as zero effects.

## Exact received evidence before parsing

The original capture receives the actual strict prefix and EOF. Custody seals
those nonempty bytes with the original X25519/HKDF/AES-GCM archive and fsyncs
before the original parser is invoked. A new observer records the parser's
actual exception class and rethrows the same exception. It does not change
signature, authority, consume, parser, SDK, Bind or continuation behavior.

A fresh archive-owner process decrypts the sealed observation and verifies its
exact length and digest. The report joins this observation to the prefix
actually sent, the original generated wire, its body hash and the separate
committed effect receipt. Generated/sent/observed bytes remain distinct. The
report contains the public synthetic generated response solely for offline
framing/prefix audit; this does not demonstrate real-data confidentiality or
release any response to the Native SDK.

## Four actual role restarts without restored execution

Ledger, issuer, Custody and backend are actually SIGKILLed and waited for,
then reopened under different PIDs. The backend reopens only the same pinned
SQLite file read-only, with unchanged device/inode, owner/mode/link count,
whole-file SHA256, exact schema and effect row. Its retained role serves
status only and refuses all POST dispatch; it does not reconstruct a model,
initialize/reset storage, repair unknown outcomes or enable continuation.

The original full grant replay is denied before another network POST. A
repeated actual SDK authorization receives no new grant. Issuer stays PENDING,
Custody and external ledger stay CONSUMED_UNKNOWN at revision 2. One backend
effect remains, with no second POST/model mutation/raw archive event,
callback-return marker, completed Bind/archive attestation, Native response,
scorer, terminal or retry permission. Authenticated status reads before and
after restart merely observe the same effect receipt.

All actors share one fresh loopback-only network namespace while the same
eight-UID IPv4/IPv6 TCP/UDP reject rules and handles remain installed. Counter
checks, root controls, seven wrong Unix-peer refusals before TLS, original
TLS UID/CA/hostname/leaf checks, and signed-ledger mTLS/readback joins remain
mandatory. Each case has a different supervisor lifetime and run ID; namespace
inode reuse after a previous namespace is destroyed is allowed.

The workflow retains all previous normal, ledger ACK-loss, zero-response-loss
and retained-backend trials unchanged. It additionally requires 56 portable
checks, 19 joined root checks per case, zero skips, complete canonical report
validation, and tested-commit provenance. Existing source bytes are frozen;
new source pins include the backend-restart profile and its predecessors.

## Limits

These are two first-request local scripted response prefixes with EOF. They do
not cover every cut offset, timeout, stream protocol or later history, writable
backend continuation, OS/VM reboot or power loss, real Provider completion
loss, remote GitHub, independent storage administration or full runtime
attestation. The GitHub API backend is a retained local SQLite model. Operator
VM files, tokens, service UID 109, expired approval and host lease are not
loaded or changed. This is not a deployment or live execution command.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN** remain in force.
