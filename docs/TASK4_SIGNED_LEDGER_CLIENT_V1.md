# Fixed synthetic manifest and manual role clients

`scripts/task4_signed_ledger_client_v1.py` adds a manual, same-host client for
the existing signed-ledger service. It never initializes keys, enrolls a run,
creates a root, starts a listener, reads a backend token, or invokes a Provider.
It accepts no task payload, request/grant digest, URL, proxy, callback function,
shell command, or alternate host from its command line/configuration.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

## Fixed manifest

The exact canonical JSON fixture is
`fixtures/task4_signed_ledger_synthetic_manifest_v1.json`. Its SHA-256 is:

```text
ff4180c808fb30e7c3f5c9cfe6f2ccff6be0c35bfed6ec42ab6a90c0dd866f6d
```

`manifest` prints the same document/digest without reading configuration or
connecting. Eight operations are ordered A0–A3, B0–B3. Each request digest is
SHA-256 of ASCII `TASK4_SYNTHETIC_REQUEST_V1:<operation>`; each grant digest is
SHA-256 of ASCII `TASK4_SYNTHETIC_GRANT_V1:<operation>`, without a newline.
The only effect is `IN_MEMORY_LIST_APPEND_ONLY`. A successful reserve/consume
appends one fixed marker to a local list; a view never does. These markers are
not actual grant issuance, bank effects, Provider posts, or utility measurements.

The client requires the approved binding's manifest digest to equal this exact
document and supplies only its operation hashes. The existing server binds the
manifest digest as metadata; it does **not** parse this manifest or independently
restrict the first request digest to these eight values. A different authorized
program could submit another digest within the underlying contract. Do not
describe this client restriction as independent service-side manifest enforcement.

## Two configurations and a public approval

Use a reviewed, administrator-controlled module installation, separate Issuer
and Custody accounts, retained private folders outside Git/cloud sync, and the
already-created receipt key/root. Do not run from a user-writable checkout as a
privileged service account. A new installation including this module must be
reviewed after merge; the previous nine-module installation lacks this client.

The root-owned public approval must be canonical JSON **without a trailing
newline**, regular/single-link, mode 0644, under trusted non-writable ancestors.
It has exactly these fields:

| Field | Required value |
| --- | --- |
| `schema` | `task4.signed-ledger-client-approval.v1` |
| `scope` | `SYNTHETIC_SIGNED_LEDGER_ONLY_NO_PROVIDER` |
| `execution_source` | Reviewed 40-hex implementation commit, including this client |
| `genesis` | Separately reviewed and retained parentless signed-ledger root |
| `binding` | Exact six-field contract binding, described below |
| `service_public_hex` | Existing receipt signer's raw 32-byte public key as 64 lowercase hex |
| `server_certificate_sha256` | SHA-256 of the full server DER leaf certificate |
| `peers` | Exact `issuer` and `custody` mappings; each has `certificate_sha256` and `authority_public_sha256` |

The binding fields are `schema` (`task4.external-ledger-contract.v1`),
`ledger_id` (the existing signed adapter's `LEDGER_ID`), fresh 64-hex `run_id`,
the fixed `manifest_sha256`, and distinct actual `issuer_public_sha256` /
`custody_public_sha256`. Each peer authority digest must match that binding.
All three TLS certificate pins must differ. The receipt signer must differ from
both role authority identities. No UNSET, example ID, old experiment ID or old
one-operation metadata root is acceptable.

`execution_source` and `genesis` are owner-approved metadata in this client;
they are not runtime source attestation or fields signed into the existing
receipt. The service's protected installation and existing-state startup must
separately validate source/root. Public approval is trusted administration, not
cryptographically independent human consent or GitHub administrator isolation.

Each role's private canonical configuration has exactly:

| Field | Required value |
| --- | --- |
| `schema`, `scope` | `task4.signed-ledger-client.v1`, synthetic-only scope above |
| `role` | `issuer` or `custody` |
| `approval_file` | Absolute path to the reviewed root-owned public approval |
| `tls_certificate`, `tls_key`, `client_ca` | That account's existing certificate, PEM private key, and CA certificate |
| `authority_key` | That account's existing raw 32-byte Ed25519 authority key |
| `attempt_parent` | Existing retained account-owned 0700 attempt directory |

Private files must be owned by the effective UID, mode 0600, single-link,
regular, bounded, in a private 0700 parent. Descriptor-based no-follow traversal
is shared with the existing entry point. No initialization, path repair or key
generation is available. Check derives the role authority digest from the
existing key; this client does **not** sign or validate a real grant with that
key. Role authority at the service remains the approved TLS-to-authority mapping.

The client loads an exact pinned, currently valid non-CA leaf with clientAuth-only
EKU; TLS and authority keys must differ. OpenSSL loads the certificate/key through
held `/proc/self/fd` descriptors, rejects encrypted keys without prompting and
checks their pairing. A CA/hostname-verified TLS >= 1.2 context connects only to
`127.0.0.1:<explicit-port>` with hostname `task4-ledger.test`; the full server DER
pin is checked before sending any command. Local check is not certificate-chain
or revocation proof: peer authentication is exercised on connection.

## Manual sequence after provisioning and explicit approval

These interface forms use placeholders for actual protected paths/ports; they
are not instructions to regenerate any existing material or approve real effects.

1. Review the manifest, actual source, root, retained receipt public key, role
   authority keys, certificate pins/mappings and fresh run ID. Retain the public
   approval and two private configurations through trusted administration.
2. Run `check --configuration ABSOLUTE_PATH` separately as Issuer and Custody.
   It validates local files/identities only; no socket, attempt or backend request.
3. Use the separate admin CLI to check/inspect/enroll the exact approved binding,
   with its existing local attempt barrier and explicit synthetic acknowledgement.
   This client never performs enrollment or supplies admin credentials.
4. Use the existing service entry point with that exact enrolled binding and
   previously retained receipt key. Review its ephemeral loopback port. Start no
   tunnel, forwarding, externally bound listener or self-hosted Runner.
5. As Issuer, invoke `reserve --configuration ABSOLUTE_PATH --port PORT
   --operation A0 --acknowledge-synthetic-only`. After its exact signed receipt
   is verified, expect one local synthetic issue marker.
6. As Custody, invoke `consume` with the same arguments/configuration for that
   role. Expect one local synthetic send marker and run snapshot revision 2.
7. `view --configuration ABSOLUTE_PATH --port PORT` is read-only and emits a
   signed public snapshot with zero callbacks. Reopening the service/clients
   must preserve the same key/root/run and prior consumption. A view never
   authorizes reissuing or resending an uncertain operation.

`--discard-mutation-response` on reserve/consume deliberately drops the complete
service response **after reading it but before receipt validation**. For a separate
approved B0 case, reserve B0 normally, then consume B0 with this flag: the backend
may have consumed and the service may have signed, but the client stops without
a verified-receipt/result record or callback. Fresh read-only reconciliation must
observe the retained consumption. This is controlled client-side response discard,
not an actual GitHub transport outage or proof that the service produced no signature.

## Attempt retention and public evidence

Before even the initial view in a mutating action, exclusively create/fsync
`<run_id>-<action>-<operation>` under the retained private attempt parent, then
exclusive/fsynced `attempt.json`. Any existing directory, including an empty or
partially written one, prevents a second attempt before a socket is opened.
Issuer may reserve only; Custody may consume only. Invalid ports/operations or
wrong roles stop before claiming. No retry, resume, deletion or reset is supplied.

Each mutation sends at most one view and one mutation, with new nonces and the
viewed expected revision. Existing `LedgerClient` validates every signature,
binding, command digest, nonce, exact attempt and committed revision before the
new client records success. Verified command/receipt pairs and the public
snapshot are fsynced to `verified-receipts.json` before the fixed in-memory
callback; `result.json` retains the post-callback count. If writing that final
result fails, the callback may already have happened: STOP is not evidence of
zero markers. Keep the slot and inspect read-only; never retry to obtain success.

Successful stdout contains only synthetic command/receipt evidence, public
identifiers, counts and no-go markers. Failures print only
`SIGNED_LEDGER_CLIENT_STOP`, nonzero exit; Ctrl-C returns 130. CLI mutation
acknowledgement is required before reading configuration. No secret/token/path or
traceback is exported. A separate reviewed collection procedure is still needed
before sharing anything beyond these bounded synthetic reports.

Local journals and root-owned approvals remain under trusted role/root/host
administration. Users/root who can change configurations, remove attempts or
restore snapshots can defeat local retention. Backend consumption is a separate
barrier; this PR is not privileged rollback, cross-host retention or power-loss proof.

## Validation and limits

62 tests cover fixed manifest/payloads, local faults before network, actual
loopback TLS and signed receipts, normal one-marker transitions, discarded
committed responses, new-process repeat denial, malformed signatures, unavailable
service, wrong server pin, journal races/fsync/write failures, role crossing,
unsafe paths, public-only output and Ed25519 TLS/authority separation. Full-root
Linux CI runs the two-UID subprocess test with separate owned keys and filesystem
denial. Mapped local root may skip only that test. The Git backend is an in-memory
model, not actual GitHub storage, and those fixture keys are disposable.

No actual run enrollment or signed-ledger mutation is performed by this PR.
Existing operator-reported VM preparation, bootstrap and TLS-only handshake
remain separate evidence. Native integration, independent A/B, utility scoring,
Provider credentials/egress isolation and production bypass resistance are open.
