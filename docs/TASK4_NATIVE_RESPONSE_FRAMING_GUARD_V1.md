# Native closed response framing guard v1

This profile adds an exact byte framing check to explicit new receive paths. The
previous frozen comparison paths remain unchanged; no operator or live client is
switched over.

## Problem and policy

The original parser returns HTTP 200 and the same decoded JSON body for these
synthetic committed responses, despite ambiguous framing:

| Case | Mutation after the backend commits one effect |
| --- | --- |
| duplicate-length | Two identical Content-Length fields |
| conflicting-length | Correct first length, conflicting second length of one |
| transfer-and-length | Content-Length plus Transfer-Encoding: chunked and a complete chunked encoding of the original body |
| trailing-bytes | A complete original response followed by an unconsumed suffix |

The new pure guard requires the closed fixture's exact HTTP/1.1 200 OK status
line, CRLF header separation, token header names, printable ASCII field values,
one canonical decimal Content-Length field with one space after its colon, no
Transfer-Encoding field of any casing, and exactly that many received body
bytes through EOF. It rejects duplicate lengths even if they agree. It does not
choose a first/last length, strip a suffix, decode transfer coding, repair a
header or permit response delivery from a read-only reconciliation.

This is intentionally a Content-Length-only fixture policy, **not a universal
HTTP compatibility implementation**. Valid HTTP variants such as chunked-only
responses are outside this profile. It is not cryptographic Provider response
binding, request smuggling resistance for arbitrary proxies, or a complete RFC
conformance claim. The unchanged original parser/JSON checks and single-ID guard
remain required. A matching parsed ID does not override a framing failure.

## Receive order and complete evidence

The fixed total collector reads the exact TLS bytes. The connection closes and
the original recipient-bound AEAD archive is sealed and fsynced before HTTP
parsing. The original parser returns the decoded body and the unchanged ID guard
checks one exact ID occurrence. The added framing guard then raises its real
AmbiguousFraming ValueError subclass for every negative case, before Bind can
release a response to the SDK. Full raw bytes, individual collector fragments,
clock/deadline data, original parser output, guard refusal and archive joins are
retained for independent validator replay.

The committed backend effect remains one even though Bind reports APPLY_FAILED
and zero verified returned apply calls. The signed ledger remains revision two,
CONSUMED_UNKNOWN. Native receives no model response, performs no scorer call,
and obtains no permission from reconciliation. Ledger, issuer, custody and
backend are actually SIGKILLed and reopened with new PIDs; the backend reopens
its same pinned SQLite file read-only. No mutation retry, reissue, initialization,
rollback or replacement database is allowed. Owner decryption recovers every
observed byte, including the misleading framing or suffix.

## Normal and negative controls

The mandatory new normal control applies both the ID guard and framing guard to
all eight actual SDK steps across both arms. It retains the original two
terminals/scorers, sixteen signed mutations, changing request histories,
parent/tool/archive chain, role separation, network denials, retained restarts,
and replay refusals. Normal custody restart uses the frozen TERM/reopen path;
the negative controls use four-role SIGKILL/reopen.

Portable tests reproduce original-dispatch acceptance with stubbed authority and
transport; those tests are not represented as actual Native UID evidence. They
also check malformed wire policy, case-insensitive framing fields, exact EOF
lengths, observer restoration, refusal ordering, all collection/archive joins,
and modified normal guard metadata. Disposable root CI supplies the actual
separate UID, Unix TLS, kernel policy and Native evidence. It validates 18 joined
normal checks and 22 joined checks per negative case, plus 163 portable tests,
with zero skips required. Previous ID and other receive controls remain mandatory.

## Limits

Only the four listed local scripted mutations and the strict normal fixture are
covered. The full runtime, public HTTP ecosystem, cryptographic response origin,
independent operator approval, administrative adversaries, power loss and reboot
recovery are not attested. Root controls the local synthetic source and keys.
No user VM, token, remote GitHub backend, host policy, live permission, Provider
post, service cutover or OS trust store is touched.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN** remain unchanged.
