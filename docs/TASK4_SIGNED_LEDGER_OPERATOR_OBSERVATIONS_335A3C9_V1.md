# Operator observations: signed-ledger restart and controlled response discard

Prepared 2026-10-24 JST against source
`335a3c939fbef7158159853d2891e112718db085`.
This records a same-host Linux exercise from operator-provided terminal output
and Base64 exports. Exact execution times were not captured. Acquisition was
not direct independent host access or independent human/administrator attestation.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

## Result and preserved evidence

The reported A0 reservation/consumption is corroborated by original exported
journal byte sequences: issuer signed revision 0 -> 1, Custody signed revision
1 -> 2, with an exact snapshot join between them. All eight present files
match the previously reported sizes and SHA-256 values. A separately preserved
final signed view at revision 4 retains A0 and A1 as CONSUMED_UNKNOWN.

| Public record | Contents and provenance |
| --- | --- |
| [Observation and verification record](../evidence/task4_signed_ledger_operator_observations_335a3c9_v1.json) | Labeled summaries, reconstructed final custody view, selected public approval fields, reported inventory and separately executed verification results |
| [Issuer byte record](../evidence/task4_signed_ledger_335a3c9_issuer_journal_bytes_v1.json) | Four original file byte sequences preserved as operator-supplied Base64, with issuer-stage verification results |
| [Custody byte record](../evidence/task4_signed_ledger_335a3c9_custody_journal_bytes_v1.json) | Four original file byte sequences from the attached operator export, plus the final joined verification results |

Verification records in earlier stages are historical snapshots; the joined
record describes the completed eight-file collection. Original stdout formatting
of the final view was not retained; its parsed signed statement was preserved.
The raw journal bytes are retained exactly through Base64 rather than
reconstructed from pretty-printed JSON.

## Source and fixed identities

| Item | Observed value |
| --- | --- |
| Execution-source approval metadata | `335a3c939fbef7158159853d2891e112718db085` |
| Approved genesis | `16f730c8d3385537c7816b1a6cdf3ff6b4e1037b` |
| Binding SHA-256 | `c4dc53c6ee2d1e9dbd0b71e0c6c011e5ad07ce78c76c174db118b54bc5fd88b1` |
| Manifest SHA-256 | `ff4180c808fb30e7c3f5c9cfe6f2ccff6be0c35bfed6ec42ab6a90c0dd866f6d` |
| Ledger ID | `568a79d3c6f1a642237a67c92d193f6d8cb3dd831ebf9cf47b00951573adc806` |
| Run ID | `546d9ab659e2fb54e3dcd20700ab6d8422e0b4d5ef81ef59a2ca622f91fad16c` |
| Receipt public-key SHA-256 | `d81fc3e80ba460a264355eb5b479ad6f33ed2e661353344cbce40313bff7af32` |
| Receipt raw public key | `b41a562bd2c5559dd49d7bbdf5e5fab64067737ddbb4cb9f98ffa8ac06d59d92` |
| Server DER certificate SHA-256 | `b89dbb148c762172c1935a563f17888c49109b72471383d194645e24ed74ed66` |

The selected public approval fields include the full binding and raw public key.
Their hashes match the earlier reported pins, and the binding run ID matches all
four reported attempt-directory names. These are consistency checks against
operator-provided approval material, not independent trust-anchor enrollment.
Execution-source/genesis approval metadata are not runtime attestation or fields
signed into the existing receipt. Protected installation hashes, full approval
file bytes and TLS peer mappings were not independently collected.

The exercise uses the [manual role client](TASK4_SIGNED_LEDGER_CLIENT_V1.md),
[existing-state entry point](TASK4_SIGNED_LEDGER_ENTRYPOINT_V1.md) and
[retained service](TASK4_RETAINED_SIGNED_LEDGER_SERVICE_V1.md).
Separate Linux role accounts connected to the same loopback mTLS listener.
The service uses a GitHub-backed ledger; the exercise is not entirely offline.
No actual SDK/AI Provider request, bank effect or benchmark utility measurement
is represented. A0/A1 are synthetic manifest IDs, not benchmark Arm A/B results.

## Observed sequence and limits

| Step | Reported output and subsequent reconciliation |
| --- | --- |
| Upgrade | Old listener stopped; new 335a3c9 listener reported backend_verified=true and listener_started=true |
| Local checks | Both roles completed check with matching binding/manifest, network_used=false |
| Initial views | Both clients accepted signed views at revision 0, empty attempts |
| A0 reserve | Issuer reported RESERVED, revision 1, one synthetic marker |
| A0 consume | Custody reported CONSUMED_UNKNOWN, revision 2, one synthetic marker |
| Ordinary A0 repeat | STOP / exit 1; subsequent signed view remained revision 2 |
| Direct A0 repeat | Probe omitted the ordinary client's attempt claim; Denied; signed snapshots before/after identical at revision 2 |
| Service restart | Existing service stopped/reopened; receipt-key and certificate pins matched; both clients observed A0 consumed at revision 2 |
| Direct A0 repeat after restart | Denied; snapshots before/after identical at revision 2 |
| A1 reserve with response discard | STOP / exit 1; subsequent signed view showed RESERVED at revision 3 |
| Ordinary A1 reserve repeat | STOP / exit 1; subsequent signed view retained revision 3 |
| A1 consume with response discard | STOP / exit 1; subsequent signed view showed CONSUMED_UNKNOWN at revision 4 |
| Ordinary A1 consume repeat | STOP / exit 1; final signed view retained revision 4 and both consumed records |

Only A0's consumed state was checked across the service restart; A1 was
exercised later. No power-loss, VM restore, administrator rollback or
separate-host test is claimed. Other manifest operations were not exercised.
Earlier restart/repeat views are transcript observations, not all preserved as
raw historical receipt files in this PR.

## Original journal bytes and joined verification

Each role exported A0 attempt.json, verified-receipts.json, result.json and
A1 attempt.json. Decoding all eight Base64 entries in the assistant execution
environment reproduced the prior inventory's exact lengths and SHA-256 values.
The decoded bytes also match the contract's canonical JSON encoding.
No Linux service, GitHub ledger, Provider, callback or mutation was invoked by
this verification. Reading or writing this documentation is not an execution
approval.

| Check | Separately executed result |
| --- | --- |
| Present file bytes and prior inventory | 8/8 lengths and SHA-256 match |
| Receipt public-key pin and full binding digest/run ID | Match |
| Original A0 receipts | 4 distinct Ed25519 signatures valid; each appears in both receipt/result files |
| Final reconstructed custody view | 1 additional Ed25519 signature valid |
| Issuer state transition | Empty revision 0 -> A0 RESERVED revision 1 |
| Cross-role join | Issuer reservation snapshot exactly equals Custody's initial signed view |
| Custody state transition | RESERVED revision 1 -> CONSUMED_UNKNOWN revision 2 |
| Final-view join | A0's consumed record exactly matches A0 in the signed revision-4 view |
| Commands | Digest, nonce/action, ledger/binding, expected revision and fixed A0 request/grant match |
| Signature negative control | Modified consume-statement revision rejected with InvalidSignature |
| Local receipt/result files | Differ only in unsigned synthetic_callbacks: 0 -> 1, in each role |
| Attempt records | Matching approved binding/manifest and correct operation/action; within-role configuration digests agree, cross-role digests differ |

There were nine signature checks over five distinct receipts: eight checks for
the two duplicated journal copies of four A0 receipts, plus the final view.
Do not count duplicated copies as independent executions or signatures.

The pinned contract uses
`b'TASK4_EXTERNAL_LEDGER_RECEIPT_V1\0'` followed by
`json.dumps(statement, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()`.
The contract constant/encoding were read at the recorded 335a3c9 source.
The final view's canonical statement SHA-256 is
`ffd902e4dd74184150a0349b08d644e37884f6c6ace4c17f0323c4dcf76be0f3`.
Tampered final-view and issuer reserve revisions were also rejected in the
earlier recorded verification stages.

Receipt signatures cover statements and snapshots. They do not sign the local
callback counter, role-report metadata, configuration hashes or acquisition
provenance. The 0/1 markers are preserved local records, not independent
effect/callback attestations. Matching configuration digests do not authenticate
uncollected configuration contents. The two role keys/TLS identities were not
used here to validate actual grant issuance or real Provider permission.

## Reported inventory and absences

Every role/operation suffix matched one non-symlink attempt directory in the
operator's earlier inspection. Full slot names and all eight hashes are in the
observation JSON; hashes have now been recomputed from exported present bytes.

| Role / action / operation | attempt.json | verified-receipts.json | result.json |
| --- | --- | --- | --- |
| issuer / reserve / A0 | 340 bytes | 2737 bytes | 2737 bytes |
| custody / consume / A0 | 340 bytes | 3084 bytes | 3084 bytes |
| issuer / reserve / A1 | 340 bytes | ABSENT (reported) | ABSENT (reported) |
| custody / consume / A1 | 340 bytes | ABSENT (reported) | ABSENT (reported) |

Present-file exports cannot prove the absence of other files or historical
filesystem metadata. The four A1 success-file absences remain operator-reported.
Do not recreate missing files or delete burned attempt slots.

## Controlled response discard and uncertain outcomes

A1 explicitly used `--discard-mutation-response`: the complete service response
is read, then discarded before receipt validation. This is controlled
client-side discard, not actual packet loss, server-side suppression, a network
outage or proof that the service never signed.

The client stopped while the later signed view showed committed reservation and
consumption. STOP is not proof of no commit and never authorizes automatic
retry. CONSUMED_UNKNOWN is authorization bookkeeping, not confirmed external
effect. The source places discard before verified-receipts.json/result.json and
before the fixed callback; reported file absences are consistent with that path.
The exact failure branch and historical callback count are not independently
traced. The final view's synthetic_callbacks=0 applies only to that read.

## Duplicate probes and trust boundary

The ordinary client creates an exclusive retained attempt slot before network
access; an existing slot stops ordinary retry. The server's static consume guard
requires RESERVED and a matching request before mutation. But STOP/Denied also
covers transport, backend and receipt-verification errors. The transport logs no
detailed reason. Actual repeat observations establish no verified duplicate
success and no observed signed-state change; they do not prove the precise
server rejection branch.

Direct-repeat probes called LedgerClient.exchange without an effect callback.
Their printed zero marker count describes those probes, not a global counter.
The fixed eight-operation request/grant allowlist is client-enforced; the
underlying server does not independently enforce that manifest's first-request
allowlist. Authorized alternative clients, host administrators and backend
credential holders remain within the trust model.

## Open gates and disposition

The original issuer/Custody present-byte collection, rehashing, A0 signature
checks and cross-role snapshot join are complete for these supplied exports.
This makes the bounded observation record reviewable; it is not a promotion to
production or independent third-party validation.

Remaining gates include full backend commit-chain verification, independent
administrator/host/source attestations, safe reason-specific refusal evidence,
actual crash/restore or separate-host tests, credential/egress isolation,
Native reservation-before-grant and consumption-before-send integration,
independent A/B generation/scoring and Final128 remeasurement.

No private key, API token, TLS private key or private configuration contents are
included. Historical preparation and model results in the
[deployment runbook](TASK4_SIGNED_LEDGER_MANUAL_DEPLOYMENT_RUNBOOK_V1.md) are not
retroactively upgraded. No workflow/runtime, retained state or permission change
is made by this PR.
