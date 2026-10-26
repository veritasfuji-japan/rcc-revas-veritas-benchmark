# Native signed-model acknowledgement loss under actor IP denial

This disposable CI extension runs two existing signed-model fault scenarios over
the unchanged bounded Native Unix TLS profile. Each case uses a fresh isolated
network namespace, fresh synthetic enrollment and keys, and the actual first
Native SDK request. It does not operate the user VM or remote GitHub.

| Case | Injected loss boundary | Retained state | Safe continuation |
| --- | --- | --- | --- |
| `api-reserve-ack-lost` | Model CAS commits the reserve, then its API response is lost before verified readback/signature | Revision 1, A0 `RESERVED`; issuer has no grant | No grant, Bind, raw POST, archive or SDK completion |
| `tls-consume-ack-lost` | Reserve is acknowledged; consume commits and is signed, then the TLS receipt is withheld | Revision 2, A0 `CONSUMED_UNKNOWN`; issued grant retained | No Custody callback, Bind, raw POST, archive or SDK completion |

The fault injection is the existing `task4_native_github_mtls_v1` implementation,
not an artificial successful return from a mocked execution gate. The new runner
reuses its actual Native SDK invocation, model CAS/readback witness, mutual TLS,
original policy and single-use gate. It does not alter any existing source file
or authority check. The previous normal profile remains a separate mandatory
positive control in the same workflow; these cases stop at the first completion
and do not claim later-history response-loss coverage.

After the first stop, each fault harness SIGKILLs the actual ledger, issuer and
Custody processes and reopens the same pinned storage with distinct PIDs. The
same original SDK request is refused again. For the consume case, replaying the
retained complete grant is also refused. The model mutation POST count stays
unchanged across repeated attempts; no repair, replacement grant, mutation
retry or cached permission is issued.

The burned gate slot contains `intent.json` and no `verified-receipts.json` or
`effect-returned.json`. Custody's local consumed table, backend effects, raw
POST/event journals, TLS status transcript and raw backend SNI journal remain
empty. The signed external model may already be mutated: absence of a verified
acknowledgement is not evidence that the mutation failed.

## Evidence and controls

The two original read-only view commands run through the unchanged LedgerClient
and mTLS transport. A new observer retains their original commands, nonces,
receipts, signatures, snapshots, actual issuer UID and namespace. It does not
retry or mutate the ledger. The wrapper re-verifies Ed25519 signatures, exact
command/nonce/binding joins and the model's corresponding UID/certificate/TLS
and readback/sign events. The two snapshots are identical across restarts.

For every case, all eight actor UIDs 61101–61108 pass 32 IPv4/IPv6 TCP/UDP
baseline flows, then fail 32 flows with per-flow kernel counter increases. UID 0
passes four control flows. The actual uncertain Native trial and all restarts
run while the same eight-rule policy and handles remain installed. Another 32
counter-joined denials follow. After removing the disposable namespace table,
all 32 baseline flows pass again. UID 61109, the separate ledger, is not an
IP-restricted actor. Seven other actor UIDs are rejected by the backend Unix
socket before TLS/HTTP parsing and before any effect.

The source pins include the unchanged normal profile and its fifteen selected
frozen dependencies, plus the new runner. Root-owned tracked-source exports and
three pinned external code trees are used for dropped-capability role processes.
Only loopback is present in the child; the parent namespace is never used for
rule application. Parent table-name comparison remains a limited negative
control, not full host policy attestation. Fixed retained anchors are retired
only after exact owned-enrollment checks; partial/corrupt anchors are not repaired.

The root workflow requires 22 portable tests and 14 joined checks per fault,
with zero skips, canonical full reports and source/commit joins. It also requires
distinct case namespaces and run IDs. Portable tests include actual Ed25519
signed synthetic view vectors and deliberate changes to signature, nonce,
command, UID, namespace, snapshot, certificate pin, TLS version and sign event.
Full model validation is required in the real root proof.

## Limits

These are two *ledger acknowledgement* losses, not lost raw backend responses
or lost public Provider completions. Neither fault reaches a raw backend POST;
therefore this trial does not prove recovery after a backend effect. The
retained GitHub API backend is a local SQLite model. Local test mTLS and keys
are controlled by one CI administrator, not an independent external witness.
The already-tested normal transport supplies API-shaped Unix TLS only; no DNS
or IP fallback is introduced. No operator token, retained service UID 109 secret,
VM preparation file, expired approval window or host lease is changed.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN** remain in force.
