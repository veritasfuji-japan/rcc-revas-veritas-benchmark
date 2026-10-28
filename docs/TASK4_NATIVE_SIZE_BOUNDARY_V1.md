# Native raw response size boundary v1

This explicit local fixture verifies the existing fixed total collector's raw
HTTP response size bound together with actual Native authority, Bind, recipient
archive, signed ledger and retained role restarts. It does not modify the frozen
collector, SDK, grants, parser, response ID guard, framing guard or old profiles.

## Exact bounds and deliberate fixture change

The raw limit is **32,768 bytes including headers**, not a 32,768-byte JSON body
allowance. The collector may read exactly one extra sentinel byte to detect an
overflow; it retains at most **32,769 bytes**. Byte overflow is classified as
`limit` / `byte-limit`, not EOF or a transport timeout. It stops without an EOF
probe after that extra byte, even if the entire sent response was 32,769 bytes.

The original local scripted generator runs first. This new fixture then appends
JSON whitespace to its original canonical body **before** the original backend
hashes/commits the effect and constructs the Content-Length response. The JSON
meaning and tools remain the same; the bytes and response digests deliberately
change and are joined through the original signed records. An exact fixture
record retains the original public JSON, both body hashes, target wire size,
backend UID and namespace. Offline validators reconstruct every padded byte.
This is a synthetic size fixture, not a claim about a Provider's response size.

| Actual case | Complete generated raw bytes | Expected collector outcome |
| --- | ---: | --- |
| Normal A0/A2/B0/B2 | 32,767 | EOF, original parser and both guards succeed |
| Normal A1/A3/B1/B3 | 32,768 | EOF, original parser and both guards succeed |
| one-byte-over | 32,769 | 32,769 observed, byte limit, no HTTP parse |
| large-over | 36,864 | First 32,769 observed, byte limit, no HTTP parse |

The normal proof completes all eight actual SDK steps and two terminals/scorers,
with sixteen signed model mutations, changed histories, parent/tool/archive joins,
original network denials and retained restarts/replay refusals. It uses the same
single-ID and exact framing guards from the previous explicit profile. Normal
Custody uses the frozen TERM/reopen path; negative cases SIGKILL/reopen four roles.

## Overflow and uncertainty

Each oversized fixture commits one real local backend effect, sends its generated
wire once, and closes normally. The client collector stops at the first excess
byte. It restores the inactivity timeout, closes its connection and fsyncs the
original recipient-bound encrypted archive of exactly the observed prefix. The
original dispatch completeness/size gate refuses **before HTTP_PARSE_STARTED**;
no parser, response ID guard or framing guard is invoked to rescue an overflow.
No unobserved suffix is represented as received or encrypted.

Bind APPLY_FAILED and zero verified returned apply calls do not mean no effect
occurred. The backend effect remains one, the signed ledger stays revision two,
and issuer/local Custody remain pending/CONSUMED_UNKNOWN without permission.
There are zero Native model responses or scorer calls. Ledger, issuer, Custody
and backend are SIGKILLed and reopened with different PIDs. The backend reopens
the same pinned database read-only. Reconciliation supplies no permission;
reissue, replay, a replacement database and automatic mutation retry are refused.
Owner decryption recovers the exact 32,769 observed bytes with `limit` metadata.

## Evidence and verification

Mandatory disposable-root CI retains complete normal and two overflow reports,
all collector fragments, timings, explicit padding records, original generated
wire, exact observed prefix, close/fsync order, owner recovery, signatures,
model/backend/SQLite identities, kernel counters and actual role restarts.
It requires **20 joined normal** and **24 joined checks per overflow**, plus
**119 portable tests**, all with zero skips. The existing complete controls remain
mandatory. Portable transport/authority stubs are never counted as Native UID
proof; actual Native root cases supply that evidence separately.

The bounded collector also retains its fixed total timeout, inactivity timeout
and maximum 256 read calls. Those independent limits may reject unusually small
or slow fragments before EOF even below the byte cap. The positive boundary
claim covers the actual fast local TLS fixture and the tested fragment schedules,
not arbitrary network segmentation or universal HTTP/Provider compatibility.

## Limits

These are selected source pins and one local synthetic administrative domain.
They do not attest a full runtime, independent operator approval, cryptographic
Provider origin, hostile administrators, power loss, reboot recovery or production
containment. No operator VM, token, real Provider, remote GitHub, host policy,
live permission, OS trust store or service cutover is changed.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN** remain unchanged.
