# Operator observations: signed-ledger restart and controlled response discard

Prepared 2026-10-24 JST against source
`335a3c939fbef7158159853d2891e112718db085`.
This records operator-pasted terminal output from a same-host Linux exercise.
Exact execution timestamps were not captured. This document and its
[public observation record](../evidence/task4_signed_ledger_operator_observations_335a3c9_v1.json)
are based on operator-provided terminal data, not direct independent host
acquisition or an independently reproduced experiment. A later linked issuer
byte record preserves four operator-exported original files, separately decoded,
rehashed and signature-checked as described below.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

## Source and fixed identities

| Item | Observed value |
| --- | --- |
| Execution-source approval metadata | `335a3c939fbef7158159853d2891e112718db085` |
| Approved genesis | `16f730c8d3385537c7816b1a6cdf3ff6b4e1037b` |
| Binding SHA-256 | `c4dc53c6ee2d1e9dbd0b71e0c6c011e5ad07ce78c76c174db118b54bc5fd88b1` |
| Manifest SHA-256 | `ff4180c808fb30e7c3f5c9cfe6f2ccff6be0c35bfed6ec42ab6a90c0dd866f6d` |
| Ledger ID | `568a79d3c6f1a642237a67c92d193f6d8cb3dd831ebf9cf47b00951573adc806` |
| Receipt public-key SHA-256 | `d81fc3e80ba460a264355eb5b479ad6f33ed2e661353344cbce40313bff7af32` |
| Server DER certificate SHA-256 | `b89dbb148c762172c1935a563f17888c49109b72471383d194645e24ed74ed66` |

The implementation baseline is the current merged source at preparation time.
The protected-runtime source bytes were not independently collected here.
`execution_source` and `genesis` are approval/report metadata, not runtime
attestation or fields signed by the existing receipt. The operator later supplied the selected public approval fields, including
the full binding and raw receipt public key. Their hashes match the previously
reported identities. Approval-file bytes and TLS peer mappings were not collected.

The exercise uses the [manual role client](TASK4_SIGNED_LEDGER_CLIENT_V1.md),
[existing-state entry point](TASK4_SIGNED_LEDGER_ENTRYPOINT_V1.md) and
[retained service](TASK4_RETAINED_SIGNED_LEDGER_SERVICE_V1.md).
Issuer and Custody used separate Linux accounts; their clients connected to
the same loopback mTLS listener. The service uses the signed GitHub ledger
backend. This is not an entirely offline or zero-external-network exercise.
No SDK/AI Provider request or real bank effect is represented by these results.

## Observed sequence

| Step | Terminal observation and subsequent reconciliation |
| --- | --- |
| Upgrade | Old listener stopped; new 335a3c9 listener reported backend_verified=true and listener_started=true |
| Local checks | Both role clients completed local check; matching binding/manifest, network_used=false |
| Initial views | Both clients accepted signed views at revision 0, empty attempts |
| A0 reserve | Issuer reported RESERVED, revision 1, one synthetic marker |
| A0 consume | Custody reported CONSUMED_UNKNOWN, revision 2, one synthetic marker |
| A0 ordinary repeat | STOP / exit 1; subsequent signed view remained revision 2 |
| A0 direct repeat | Probe omitted the ordinary client's local attempt claim; exchange returned Denied; signed views before/after were identical at revision 2 |
| Service restart | Existing service stopped and reopened; receipt-key and certificate pins matched; both clients observed A0 consumed at revision 2 |
| A0 direct repeat after restart | Denied; signed views before/after remained identical at revision 2 |
| A1 reserve, response discarded | STOP / exit 1; subsequent signed view showed A1 RESERVED at revision 3 |
| A1 ordinary reserve repeat | STOP / exit 1; subsequent signed view retained A1 RESERVED at revision 3 |
| A1 consume, response discarded | STOP / exit 1; subsequent signed view showed A1 CONSUMED_UNKNOWN at revision 4 |
| A1 ordinary consume repeat | STOP / exit 1; final signed view retained revision 4 and both A0/A1 consumed |

The direct-repeat probes called LedgerClient.exchange without a callback or
LedgerClient.gate. Their printed zero callback count describes that probe code,
not a global effect counter.

Only A0's consumed state was checked across the service restart. A1 was
exercised after that restart; its persistence across another restart was not
tested. This was a process termination/reopen experiment, not power-loss,
backup restoration, administrator rollback, or separate-host testing.

A0 and A1 are fixed synthetic manifest IDs, not benchmark Arm A/B utility
results. Other manifest operations were not exercised in this transcript.

## Controlled response discard and uncertain outcomes

The A1 commands explicitly selected `--discard-mutation-response`.
The client reads the complete service response and then discards it before
receipt validation. This is a controlled client-side fault, not observed packet
loss, server-side acknowledgement suppression, a real network outage, or
proof that the service never signed a receipt.

Despite the client STOP, read-only reconciliation observed the committed
reservation and consumption. STOP must not be treated as proof of no commit or
as permission to retry. CONSUMED_UNKNOWN is a consumed authorization record;
it is not confirmation that an external effect occurred.

The source creates an exclusive retained attempt slot before the initial
network view. Existing slots stop ordinary retries before a socket is opened.
The displayed generic STOP does not independently identify which guard
stopped each actual repeat. No attempt was deleted or reset in the supplied
procedure. The operator subsequently reported journal existence, sizes and hashes below;
issuer journal bytes were later exported and separately verified as described
below. Custody journal contents remain uncollected.

In the reviewed source, the controlled-discard exception occurs before writing
verified-receipts.json/result.json or reaching the fixed in-memory callback.
That is a source-path inference, not a separately captured callback trace.
The final view's synthetic_callbacks=0 applies only to that read operation.

## What the duplicate probes establish

The service implementation requires a consumed operation's prior state to be
RESERVED and its request digest to match before changing state. A0 was already
CONSUMED_UNKNOWN. This is a static server-side guard.

The transport closes on exceptions without detailed logging, and the signed
service and client sanitize errors. Denied can also mean a transport, backend,
or receipt-validation failure. The dynamic result is therefore bounded to:
the duplicate request did not produce verified success, and signed views
before and after showed no state change. The exact server rejection branch
was not dynamically witnessed. Do not upgrade this to a reason-specific
server rejection proof.

The fixed eight-operation request/grant manifest is enforced by the ordinary
client. The underlying server does not independently enforce that manifest's
request allowlist. These probes do not prove isolation against an authorized
alternative client, a host administrator, or a holder of the backend writer
credential.

## Evidence provenance and validation

The JSON record preserves the final custody view's parsed command, signed
statement and signature, plus explicitly labeled summaries of earlier outputs.
It does not preserve original stdout bytes, all earlier signed receipts,
backend commit-chain readbacks, full public-approval file bytes, or source-
installation hashes. A later linked record preserves four original issuer
journal byte sequences; Custody journal bytes remain pending.

Preparation checks cover JSON parsing, command SHA-256 under the contract's
canonical JSON encoding, command/statement nonce and binding agreement,
reported snapshot/receipt equality, final revision/states, signature byte
length, and request/grant hashes against the pinned manifest. Those initial consistency
checks did not verify Ed25519 signatures. A subsequent cryptographic check of
the one preserved final view was executed separately in the assistant environment,
as described below. Earlier operator client success reports are not independently
verified historical signatures.

No private keys, API tokens, TLS private keys or private configuration files
are included. This PR only records observations; it does not run a service,
modify retained state or workflows, grant permission, or authorize a Provider.

## Operator-reported host journal inventory

A later read-only inspection was supplied through terminal output. Each of the
four role/operation suffixes matched exactly one non-symlink directory. All
reported slot names share run ID:

`546d9ab659e2fb54e3dcd20700ab6d8422e0b4d5ef81ef59a2ca622f91fad16c`

This ID was initially parsed from slot names. The later operator-supplied
binding contains the same run ID and hashes to the recorded binding SHA-256. No file was recreated, removed or modified by the supplied
inspection script. The JSON record includes full slot names and explicit
absence records. Exact inspection time was not captured.

| Role / operation | File | Bytes | Reported SHA-256 |
| --- | --- | --- | --- |
| issuer / A0 | `attempt.json` | 340 | `afffac6af0f3ee0808fbffe1bf8c1669c90097d851d5f57ffd37be0093c7d082` |
| issuer / A0 | `verified-receipts.json` | 2737 | `a14f383a82b336e01ab8f2af155b067d0d5b33ea280f2cee6917861fe9889e83` |
| issuer / A0 | `result.json` | 2737 | `dc1401225d92cdaf14e10ad87cb8f40c3df00ef2dc5ebc300aaf40faf8bc16d3` |
| issuer / A1 | `attempt.json` | 340 | `b1d8e07e6d04e1958068dd0299434e50358b59da1525465a19fc139aca111a4f` |
| custody / A0 | `attempt.json` | 340 | `f26b5c3718356f54daca3eb1bf8a48d0e11449b456e72f26c7aab6fb35f41d87` |
| custody / A0 | `verified-receipts.json` | 3084 | `f7211f01e398176a8684620126fbae15a0e4648cad860a0fa779eaa2a342a769` |
| custody / A0 | `result.json` | 3084 | `e077a01950eeacb4fbe20df0a8be71d46ad8df699e4faf86fa46d043672d49d3` |
| custody / A1 | `attempt.json` | 340 | `719c59631f46aa02bb6a9673e13a9067a95e7378227d2ad1781bdbb5607a4edb` |

For both Issuer/reserve A1 and Custody/consume A1, verified-receipts.json and
result.json were reported ABSENT. Only attempt.json was present. This matches
the source path for a complete response discarded before validation and before
the callback. It does not independently establish the precise exception cause
or historical callback count. A0 had all three expected files in each role.

These hashes identify the bytes the operator's script read at inspection time.
Issuer hashes were subsequently recomputed from operator-transferred Base64
bytes and matched all four prior entries. Custody hashes remain operator-
reported, with original bytes and receipt signatures pending. The inventory
alone preserves identifiers; the linked issuer byte record preserves those
four original byte sequences.

## Separate cryptographic check of the final view

On 2026-10-24 JST, the assistant execution environment used Python cryptography
Ed25519PublicKey.verify on the final custody view at revision 4. It did not call
the Linux service or a Provider. The signed bytes are the pinned contract's
`b'TASK4_EXTERNAL_LEDGER_RECEIPT_V1\\0'` domain followed by the statement encoded
using `json.dumps(sort_keys=True, separators=(',', ':'), allow_nan=False).encode()`.
The original source constant and encoding were read at the recorded 335a3c9 pin.

| Check | Result |
| --- | --- |
| Raw receipt public key | `b41a562bd2c5559dd49d7bbdf5e5fab64067737ddbb4cb9f98ffa8ac06d59d92` |
| Raw public-key SHA-256 vs previously reported pin | MATCH |
| Full public binding SHA-256 vs command/statement/report | MATCH |
| Binding run ID vs all four reported slot names | MATCH |
| Source/genesis/certificate approval metadata vs report | MATCH (metadata consistency only) |
| Command digest, nonce/action and reported snapshot | MATCH |
| Ed25519 signature on the preserved final statement | VALID |
| Same signature with statement revision changed from 4 to 5 | REJECTED (InvalidSignature) |
| Canonical final statement SHA-256 | `ffd902e4dd74184150a0349b08d644e37884f6c6ace4c17f0323c4dcf76be0f3` |

The JSON record includes the selected public approval fields and verification
results. This verifies one reconstructed final receipt's signature under a key
whose hash matches the earlier operator-supplied pin. It does not authenticate
the pin through an independent administrator, reproduce the experiment, attest
the host/source, establish historical freshness for earlier receipts, or verify
uncollected Custody journal bytes. No independent human/third-party validation
is claimed. Original issuer journal checks are separately documented below.

## Original issuer journal bytes: separate verification

The operator supplied a Base64 export of issuer A0 attempt.json,
verified-receipts.json, result.json, and A1 attempt.json. The
[issuer byte record](../evidence/task4_signed_ledger_335a3c9_issuer_journal_bytes_v1.json)
preserves the exported byte sequences and verification results. Base64 decoding
in the assistant execution environment reproduced all four recorded lengths and
SHA-256 values, matching the prior inventory. No source-host access or
filesystem metadata attestation was available; the acquisition remains an
operator-supplied export.

The A0 receipt and result files contain the same two signed exchanges: an
empty view at revision 0 and an A0 reservation at revision 1. All four signature
checks passed under the previously pinned public key (two distinct receipts,
each present in both files). The command digest, nonce/action, binding/ledger,
fixed A0 request, expected revision and exact RESERVED snapshot matched.
A reserve statement with a changed revision failed signature verification.

The files differ only in synthetic_callbacks: 0 in verified-receipts.json and
1 in result.json. Those local fields are unsigned marker records, not an
independent callback-count witness. Both attempts bind the same configuration
hash, manifest and binding, with operation IDs A0 and A1; private configuration
contents were not collected or authenticated by that comparison. A1 has no
exported success receipt/result, consistent with the reported absences.

These checks involved no network call, mutation, callback, reset or retry.
They do not verify Custody's original consumption records, A1's missing files,
backend history or independent administration.

## Remaining evidence and integration gates

- Collect the existing Custody A0/A1 public journal bytes where present,
  and independently recompute their reported hashes. Issuer's four exported
  files are preserved and checked above. Retain absence records; do not
  recreate missing files or delete burned slots.
- Validate the Custody journal receipts after collection, using the preserved
  binding and pinned public key, and join them to issuer's verified reservation.
  Neither byte/signature check provides the full backend commit history.
- Establish safe, bounded evidence that distinguishes a specific service
  refusal from transport/backend unavailability.
- Treat host administration, privileged rollback, actual crash/restore,
  separate-host operation, credential/egress denial, Native reservation-before-
  grant / consumption-before-send integration and independent A/B scoring as
  separate open gates.

These observations supplement the historical
[deployment preparation runbook](TASK4_SIGNED_LEDGER_MANUAL_DEPLOYMENT_RUNBOOK_V1.md).
They do not retroactively turn its model tests into remote evidence or close
all deployment/production acceptance conditions.
