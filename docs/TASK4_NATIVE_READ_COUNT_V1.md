# Native fragmented-response receive-count boundary v1

This explicit local profile tests the existing fixed collector's maximum **256
receive calls**, including an EOF read. It changes only the selected synthetic
backend TLS application-write/termination schedule. The application HTTP/JSON
bytes, original generator, response digests, SDK, grants, Bind, collector,
recipient archive, parser, ID guard and framing guard remain unchanged.
Previous frozen profiles stay intact; no operator or live-client cutover occurs.

## Selected cases

| Actual case | Data writes / observed data reads | Final read | Result |
| --- | ---: | --- | --- |
| Eight-step normal | 255 each | EOF at read 256 | Normal parser/guards, both Native terminals/scorers |
| complete-at-cap | 256 | Data at read 256, no EOF probe | Full valid wire captured, limit/refusal before HTTP parse |
| prefix-at-cap | 256 one-byte writes | Data at read 256, no EOF probe | Exact first 256 bytes captured, limit/refusal before HTTP parse |

The complete-at-cap case deliberately shows that receiving the whole parseable
body is insufficient: without EOF verified within the bounded receive budget,
original dispatch grants no permission. Neither byte overflow nor inactivity is
the stopping reason. Both negative captures remain below the 32,768-byte raw
size limit and finish before the fixed total deadline. The unchanged collector
reports `limit` / `read-count-limit` and restores its 0.7-second inactivity timeout.

## Real TLS scheduling and EOF

The original backend commits its effect before the new send-boundary wrapper
splits its unchanged valid wire. Each fragment is one actual TLS application
write. All successful writes and exact bytes/timestamps/cumulative lengths are
recorded together; no per-write fsync or artificial sleeps create a timeout test.
Validators require the actual observed receive fragments to equal this selected
write schedule. They do **not** assume that arbitrary TLS writes always map
one-to-one to reads on every TLS stack, network or platform.

The positive fixture sends TLS close_notify via the server unwrap operation,
then records the actual returned/exception outcome when the original client
closes. This makes EOF available as the 256th read. The negative server keeps
the TLS stream open after its 256 writes until the actual client closes; it
records EOF, BrokenPipeError, ConnectionResetError or SSLEOFError truthfully.
No server-side EOF is fabricated and no socket error is relabelled. Full
send/receive/close timestamps join the selected same-run peers.

Portable socket-pair probes exercise the real helper and unchanged collector
under TLS 1.2 and TLS 1.3. They use synthetic ephemeral credentials and stubbed
authority/UID prerequisites; they are mechanics checks, not Native role or
certificate-enrollment proof. The mandatory root Native cases retain the
original kernel UID, CA, hostname and leaf certificate checks, all-actor IP
denials and separate local roles in one disposable CI network namespace.

## Durable refusal and restarts

The client closes, then the original recipient-bound AEAD archive is sealed and
fsynced before the original completeness gate refuses the `limit` capture.
Negative cases invoke no HTTP parser, ID guard, framing guard or SDK response
callback. Owner decryption recovers every observed byte and its `limit` metadata;
the unobserved suffix of prefix-at-cap is never reported as received.

One effect remains committed even though Bind returns APPLY_FAILED with zero
verified returned apply calls. Native receives zero model responses and makes
zero scorer calls. Issuer and local Custody remain pending/CONSUMED_UNKNOWN;
the signed ledger remains revision two. Ledger, issuer, Custody and backend
are actually SIGKILLed/reopened with new PIDs. The same pinned backend database
reopens read-only. Reconciliation issues no permission; replay, reissue,
initialization, replacement database and automatic mutation retry are refused.

The normal control completes all eight actual SDK steps, both terminals/scorers,
sixteen signed mutations, changed request histories, parent/tool/archive joins,
original network denials and restart/replay checks. It uses the frozen normal
Custody TERM/reopen path; the negative cases use four-role SIGKILL/reopen.

## Complete evidence and limits

CI requires **156 new portable tests**, **21 joined normal checks** and **24
joined checks per negative case**, all with zero skips. Complete reports retain
original generated wires, every send and receive fragment, timing/deadline,
close/fsync/owner recovery, signatures, model and SQLite identities, policy
counters and actual role restarts. Prior receive controls remain mandatory.

This is one selected local TLS schedule and source pin set, not universal TLS
record semantics or full-runtime attestation. The byte, inactivity, total-time
and read-count limits are independent; arbitrary segmentation may legitimately
stop a response below the byte cap. No hostile-administrator, independent
approval/storage, power-loss, reboot or production containment claim is made.
No user VM, token, remote GitHub backend, real Provider, host policy, OS trust
store, live permission or service cutover is changed.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN** remain unchanged.
