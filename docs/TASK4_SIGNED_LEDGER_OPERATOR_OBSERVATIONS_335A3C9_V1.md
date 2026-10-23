# Operator observations: signed-ledger restart and controlled response discard

Prepared 2026-10-24 JST against source
`335a3c939fbef7158159853d2891e112718db085`.
This records operator-pasted terminal output from a same-host Linux exercise.
Exact execution timestamps were not captured. This document and its
[public observation record](../evidence/task4_signed_ledger_operator_observations_335a3c9_v1.json)
are transcript-derived records, not independently collected host artifacts or
an independently reproduced experiment.

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
attestation or fields signed by the existing receipt. The complete binding and
raw service public key have not been collected for this review.

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
the journal contents have not yet been independently collected or verified.

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
protected host journals, backend commit-chain readbacks, the public approval,
or source-installation hashes.

Preparation checks cover JSON parsing, command SHA-256 under the contract's
canonical JSON encoding, command/statement nonce and binding agreement,
reported snapshot/receipt equality, final revision/states, signature byte
length, and request/grant hashes against the pinned manifest. These consistency
checks do not verify Ed25519 signatures. The raw pinned public key was not
collected; independent signature verification remains pending. Operator client
success reports are not a substitute for that verification.

No private keys, API tokens, TLS private keys or private configuration files
are included. This PR only records observations; it does not run a service,
modify retained state or workflows, grant permission, or authorize a Provider.

## Operator-reported host journal inventory

A later read-only inspection was supplied through terminal output. Each of the
four role/operation suffixes matched exactly one non-symlink directory. All
reported slot names share run ID:

`546d9ab659e2fb54e3dcd20700ab6d8422e0b4d5ef81ef59a2ca622f91fad16c`

This is an ID parsed from slot names, not an independent check of the complete
approved binding. No file was recreated, removed or modified by the supplied
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
They have not been independently recomputed from transferred original files,
and file contents, signatures and cross-record bindings remain unverified.
A digest inventory preserves identifiers, not the original evidence bytes.

## Remaining evidence and integration gates

- Collect reviewed public contents of the existing A0/A1 journals where
  present, and independently recompute the operator-reported hashes above.
  Retain absence records; do not recreate missing files or delete burned slots.
- Collect only reviewed public binding/receipt verification material, check
  its pin, and independently validate preserved signatures. A public snapshot
  alone does not provide the full backend commit history.
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
