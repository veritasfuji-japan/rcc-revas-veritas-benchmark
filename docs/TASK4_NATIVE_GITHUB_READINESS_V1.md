# Native-specific GitHub read-only readiness

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

PR #537 connected actual Native/Bind to the GitHub adapter through a retained
local API model and actual TLS over AF_UNIX. This increment prepares a separate
Native-specific approval/configuration and a **GET-only** existing-state check.
It does not connect the execution path to remote storage, start a service,
enroll a run, load a receipt signer, create a credential, apply firewall rules
or grant permission to call a Provider.

## Actual remote observation, separate from operator-runtime verification

The [retained connector observation](../evidence/task4_native_github_readonly_observation_v1.json)
was obtained using GitHub connector GETs on 2026-10-24. Ref reads before and
after the observation agreed on head `3b3e0154939cdda1a2863f771946636a316d9574`
of `research/task4-signed-ledger-v1`. GitState validation replays the observed
approved genesis `16f730c8d3385537c7816b1a6cdf3ff6b4e1037b`, root/current trees,
exact decoded blob bytes and GitHub compare metadata. Blob hashes match the
trees; the head was five commits ahead of the approved empty genesis.

At this snapshot there was one registered run, with global revision 5 and run
revision 4. Its binding uses the manual client's fixed-label manifest; A0 and
A1 are CONSUMED_UNKNOWN. It is not a Native-manifest enrollment. The check
therefore must not reinterpret that existing run as Native execution approval.
No remote state was changed.

This evidence is a GitHub connector observation, not a request sent by the new
CLI from the operator VM. It does not verify the operator's credential, installed
package, account, mTLS service, DNS or OS egress restrictions. Metadata fields
are semantic projections; exact decoded ledger blob bytes are preserved and
hashed. These are not raw HTTP response envelopes or independent host/signer
attestation. A stable ref during this observation does not freeze future state.

## Three explicit actions

The module is `scripts.task4_native_github_readiness_v1` and has no serve,
initialize, enroll, reserve, consume, repair or retry action.

| Action | Behavior |
| --- | --- |
| source-manifest | Emit hashes of 11 selected installed source files; no approval creation, token loading or connection |
| check --configuration ... | Validate private configuration and root public approval, Native manifest/keys/UID mapping and selected source bytes; inspect no token contents; open no socket |
| read-existing --configuration ... --allow-github-read | Require the approved nonroot ledger account, read one explicit private token, perform only allowlisted GitHub GETs, and recheck approval/configuration/credential before returning diagnostic state |

`ReadOnlyAPI` rejects every POST/PATCH/DELETE and GET body before SSL context,
socket and authorization-header construction. Even GitState.mutate cannot
transmit through it. The existing fixed API transport supplies the literal
api.github.com:443 endpoint, verified system CA/hostname context, response
bounds, no ambient token/proxy discovery, no redirects and no retry. The trusted
OS CA store/resolver and installed code remain trusted; this is not a hard
wall-clock DNS/header deadline or a sandbox for arbitrary same-process code.

A missing Native run is reported as NATIVE_RUN_ABSENT_NO_ENROLLMENT. An exact
existing binding is reported as observed metadata with its snapshot. Neither
result creates authority. `live_execution_ready`, `execution_permission_issued`,
`service_receipt_verified`, `operator_mtls_verified` and
`production_bypass_resistance_proven` remain false. Expiry is diagnostic in
this read-only command and cannot restore execution permission.

## Private configuration and separately reviewed approval

Configuration is an existing absolute, no-follow, single-link 0600 file owned
by the effective account, in its 0700 directory with trusted ancestors. It has
exactly schema, scope, approval_file and token_file. The scope is
SYNTHETIC_NATIVE_GITHUB_READ_ONLY_NO_EXECUTION; the schema is
task4.native-github-readiness.v1. The future token path must be canonical and
absolute even for a local check.

The approval is a separately created root-owned 0644 public record. This tool
does not generate it or automatically trust its own source-manifest output.
Its exact fields are:

| Field | Required review/join |
| --- | --- |
| schema / scope | task4.native-github-readiness-approval.v1 / the read-only scope above |
| execution_source | Full reviewed 40-hex source label; reported as declared provenance, not Git/build attestation |
| genesis | Independently reviewed existing empty-root Git OID |
| binding | Existing six-field signed-ledger binding with fixed ledger ID and exact Native run/manifest digest |
| native_manifest | Exact bounded closed-local Native manifest, not the manual client's fixed-label manifest |
| issuer_public_hex | Raw public key whose digest matches binding issuer |
| service_public_hex | Raw public receipt-verification key whose digest pins GitState metadata; no private signer is loaded |
| source_sha256 | Exact hashes for the 11 selected MODULES, including this checker; no missing/extra module names |
| roles | Current reviewed profile's four distinct nonroot UIDs: ledger 61109, issuer 61105, Custody 61106, runtime 61108 |
| tls | Planned MTLS_OVER_AF_UNIX_WITH_SO_PEERCRED, CA digest and three distinct role certificate pins |

Custody and runtime public keys come from the exact Native manifest. Issuer,
Custody, runtime and service keys must all be distinct. A mismatched binding,
manual manifest, code byte hash, peer key or incompatible UID mapping stops
before credential loading/network use. The source check covers 11 selected
files; it does not attest the entire dependency closure, interpreter, cached
bytecode, package installation or administrator. Those require separate review.

The token file must be private 0600 with the same no-follow ownership/ancestor
checks. A dedicated fine-grained contents-read-only credential for this single
repository is required by policy; use of the service's write-capable token is
not justified by this check. The command does not discover a token, test its
write permission or attest its GitHub scopes. `credential_permissions_verified`
therefore stays false. No token, private path, HTTP body or raw exception is
printed in the report/error. Ordinary failures produce NATIVE_GITHUB_READINESS_STOP.

## Reviewable communication plan, not applied enforcement

The diagnostic report includes a desired egress plan: external default DENY;
only the approved ledger UID may issue GETs to the fixed GitHub repository and
branch over HTTPS; issuer, Custody and runtime have no planned external egress.
Proxy, redirect and retry are disabled. Native role communication remains the
planned mTLS Unix socket. `os_rules_applied`, `os_egress_verified` and the
plan's `tls_handshake_performed` are false. The last field refers to Native
service mTLS, not the API transport's ordinary HTTPS.

DNS resolver egress still requires separate review. No static GitHub IP list,
blanket OUTPUT rule, active firewall change, credential write or privileged
account creation is performed. The report is concrete configuration review
input, not evidence that an execution service can reach only approved hosts.

## Retained service and separate reader profile

The explicit [retained-signer profile](TASK4_NATIVE_RETAINED_SIGNER_PROFILE_V1.md)
preserves the existing UID 109 service identity and genesis, uses UID 61109
only for read-only diagnostics, and joins issuer/Custody/runtime exports without
requiring a new ledger key. It uses a separate approval schema and three extra
source pins (14 selected files in total). There is no automatic profile fallback
or service reconfiguration. For that profile, `account_matches_reader_uid` is the
read-account check; `account_matches_ledger_uid` refers to service UID 109 and is
false when the reader runs. The retained service is explicitly outside the
checker's desired GET-only egress plan. All runtime/permission flags remain false.

## Validation and operator handoff

The separate [public approval preparation workflow](TASK4_NATIVE_GITHUB_APPROVAL_PREPARATION_V1.md)
builds a candidate from explicit public inputs, rechecks its digest and derived
fields, and separates root-only read-only approval rendering from installation.
It does not generate missing operator keys/context or attest a declared origin.
Readiness configuration/approval files must contain exact canonical JSON bytes
without ordinary pretty-print spacing or a final newline.

53 cases cover local no-token/no-socket checks, exact metadata reads through
model HTTP, mutation denial before connection, Native/manual/profile/hash/key
refusals, private/public file safety, mid-read withdrawal, no retry, sanitized
errors, absent/present Native runs and replay of the real connector observation.
The actual nonroot subprocess case reads its own protected configuration and
root public approval while a different UID is refused; it does not load a token
or connect. Root-capable CI requires all cases without skips. Unit model HTTP
cases substitute the effective ledger-account check in a root-owned fixture;
they do not establish live VM identity or network enforcement.

After separately reviewing/installing a protected package and preparing the
approval/configuration through trusted administration, the operator can use
the installed protected interpreter with these module arguments:

```sh
python -I -B -m scripts.task4_native_github_readiness_v1 source-manifest
python -I -B -m scripts.task4_native_github_readiness_v1 check \
  --configuration /var/lib/veritas-native-ledger/readiness/configuration.json
# Only as the approved nonroot ledger UID, using a separately supplied read token:
python -I -B -m scripts.task4_native_github_readiness_v1 read-existing \
  --configuration /var/lib/veritas-native-ledger/readiness/configuration.json \
  --allow-github-read
```

These examples do not create that path or select the operator's old venv. No
operator-private configuration or token was read during this implementation.
Actual VM read-only preflight, reviewed Native-specific enrollment, credential/
egress evidence and remote backend integration remain separate next steps.
