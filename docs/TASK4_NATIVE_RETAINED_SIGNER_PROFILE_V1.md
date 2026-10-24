# Retain the existing signer and separate the Native read-only account

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

The operator chose to preserve the existing remote genesis and signer. The
reported VM metadata showed the old signing-key directory owned by UID 109,
mode 0700, and a single-link regular 32-byte key owned by UID 109 with mode
0600. The root public pin matched the previously reviewed public fingerprint.
Those commands did not read the private key, establish key-pair correspondence
or provide independent signer/host attestation. No key move, regeneration or
remote initialization follows from those observations.

This explicit **read-only preparation profile** distinguishes the service from
the reader and joins the retained public identity to three Native role exports:

| Profile role | UID | Purpose |
| --- | --- | --- |
| service | 109 | Declared retained signer/service owner; existing private key stays in place |
| reader | 61109 | Separately supplied read-only credential and diagnostic GitHub GETs |
| issuer | 61105 | Prospective Native issuer public-key export |
| custody | 61106 | Prospective Native Custody public-key export |
| runtime | 61108 | Prospective Native runtime public-key export |

The profile does not reconfigure the running service, load its private
configuration/key/token, register a Native run, initialize a ledger, apply role
UID enforcement to Native execution or start a listener. The current service's
manual binding is not made Native-compatible by this change. Existing Native
runtime/Bind/service consumers remain unchanged; the existing closed-local CI
profile still uses UID 61109 as its disposable ledger service. This increment
supplies public preparation and diagnostic-read validation, not a runtime cutover.

## Separate schemas and exact public continuity

The module is `scripts.task4_native_retained_signer_profile_v1`. It has three
public-only actions: `source-manifest`, `identity`, and `verify-public`. There
is no initializer, signer, key migration, token discovery or mutation action.

`identity` reads an explicit **root-owned 0644 public legacy approval** through
the existing bounded, no-follow, single-link reader. The caller supplies its
exact-byte SHA-256, independently reviewed genesis and independently reviewed
service public-key SHA-256. The file is read again before output; changed or
withdrawn bytes stop without retry. It never reads the old private service
configuration, private key, key directory or credential. The result has schema
`task4.retained-service-public-identity.v1` and contains:

- The fixed declared service UID 109, unchanged genesis and service public key/hash.
- The old run ID, exact legacy public-approval bytes as Base64 and their SHA-256.
- The read-only scope `SYNTHETIC_NATIVE_GITHUB_READ_ONLY_NO_EXECUTION`.

Validation reparses the retained bytes, rehashes them and checks the exact old
public schema/scope, binding ledger ID, peer authority/certificate pins and
service-key separation. The old binding is provenance for the retained public
identity only. It is **never** copied into the Native binding or reinterpreted
as new Native authority. A new Native run cannot reuse that legacy run ID.
The record's UID is a reviewed declaration, not a fresh OS observation. A
retained public approval does not establish private/public key correspondence.

The embedded public bytes form an immutable review snapshot. They do not make
later edits to the old public approval an automatic revocation of a separately
created Native read-only approval. Trusted administration must withdraw the
new approval itself when appropriate. The read-only check revalidates that new
approval/configuration/credential during a GET; this still grants no execution.

## Three-key public bundle and Native candidate

The bundle schema is `task4.native-retained-signer-key-bundle.v1`. Its exact
fields are `schema`, `scope`, `run_id`, `retained_service` and `exports`. Scope is
`SYNTHETIC_NATIVE_KEY_PREPARATION_ONLY_NO_EXECUTION`. `retained_service` is the
validated public identity above. `exports` contains exactly **issuer, custody,
runtime**, each using the #540 public export schema under its fixed UID. A new
ledger export or reader export is rejected. Reported Native storage identities
must be distinct and all three Native keys must be distinct from each other
and the retained service public key.

The matching public-preparation input uses the explicit schema
`task4.native-retained-signer-public-preparation.v1`. It has the existing #539
public fields plus `native_key_bundle` and `profile_source_sha256`, and its
`roles` has the five exact entries from the table above. The builder requires:

1. Top-level genesis/service public key exactly match the retained record.
2. Issuer/Custody/runtime public keys match the three exports and the Native
   manifest; their run IDs all match the proposed new Native run.
3. The exact bounded Native manifest, fixed ledger ID, application key
   separation and public TLS certificates pass the existing common validators.
4. All 11 readiness source pins plus three profile/preparer/key-tool source pins
   match the selected installed bytes (14 files total).

The existing #539 `candidate`, `review`, and explicit root-only `render-approval`
actions support this input through a separate schema dispatch. They preserve
exact original input bytes and recompute every derived field. The resulting
approval schema is `task4.native-github-retained-signer-approval.v1`; its extra
fields are the retained identity, canonical Native bundle SHA-256 and the three
profile source pins. Its exact canonical bytes must still fit the existing
8192-byte approval bound. Oversized data stops rather than being truncated or
silently dropped. Root rendering writes only stdout and installs nothing.

The original four-key public-preparation/readiness schemas remain exact and
separate. They cannot silently accept retained-profile fields or role mapping;
the retained profile cannot silently fall back to the disposable four-role
profile. No new ledger private key or key transfer is required by this route.
Use the #540 generator only for the three Native roles when preparing this
profile; it does not need to open the retained service's key.

## Reader UID, service UID and egress-plan scope

The private readiness configuration keeps its existing four-field schema and
read-only scope. It explicitly names the separately reviewed root public
approval and the reader's future private read-token path. The new approval
schema selects the retained profile; an untrusted request cannot change the
role mapping or select an arbitrary service/reader UID.

For the retained profile, `read-existing` requires current UID **61109** before
loading the read token or constructing transport. UID 109 is not granted access
to that reader credential by being the service owner. Local `check` needs no
token file or socket. Its account fields are deliberately distinct:

| Report field | Reader UID 61109 result |
| --- | --- |
| `read_account_uid` | 61109 |
| `service_account_uid` | 109 |
| `account_matches_reader_uid` | true |
| `account_matches_ledger_uid` | false (this historical field refers to service ownership) |

The desired egress plan applies only to the reader and the proposed three
Native client UIDs. Only reader UID 61109 is assigned diagnostic GitHub HTTPS
GETs; the three Native client UIDs have desired external DENY. The retained
service UID 109 is explicitly excluded from this plan and marked as requiring
separate service-egress review. The report does **not** claim that the old
writer credential is GET-only or that this code changed the service's network
policy. No firewall rules are applied or verified.

Actual GETs continue through the same fixed `ReadOnlyAPI`, with no mutation,
redirect, proxy discovery or retry. GitState validates the existing genesis
and its pinned signer metadata before returning diagnostic state. Declaring a
fresh signer in public metadata cannot make it match the existing backend;
the GET check stops on that mismatch. An absent Native run is diagnostic
`NATIVE_RUN_ABSENT_NO_ENROLLMENT`, never an enrollment request or a reset path.
An existing exact Native binding remains observed metadata, not permission.

`retained_private_key_loaded`, `retained_service_uid_observed`,
`service_reconfigured`, `native_runtime_profile_applied`,
`operator_mtls_verified`, `live_execution_ready` and
`execution_permission_issued` all remain false. The selected 14 source hashes
do not attest the interpreter, bytecode, entire dependency closure, VM or
administrator. Public exports remain untrusted provenance until separately
reviewed; they do not prove private-key possession or nonexportability.

## Operator handoff

The earlier protected source ending in `75ea699` does not include this new
profile. Install/review the new source first, then use the explicit namespace
bootstrap in the [public preparation handoff](TASK4_NATIVE_GITHUB_APPROVAL_PREPARATION_V1.md)
if an old regular `scripts` package is also installed. Review fresh source pins;
the changed checker/preparer bytes intentionally invalidate old source maps.
Do not copy an old map or treat a tool's own hash output as independent approval.

```sh
# Arguments only: use a reviewed protected interpreter/package.
python -I -B -m scripts.task4_native_retained_signer_profile_v1 source-manifest
python -I -B -m scripts.task4_native_retained_signer_profile_v1 identity \
  --legacy-approval /etc/veritas-ledger/signed-client-approval-335a3c9.json \
  --expected-sha256 REVIEWED_LEGACY_PUBLIC_APPROVAL_SHA256 \
  --expected-genesis REVIEWED_EXISTING_GENESIS \
  --expected-public-sha256 REVIEWED_EXISTING_SERVICE_PUBLIC_SHA256
python -I -B -m scripts.task4_native_retained_signer_profile_v1 verify-public \
  --document /absolute/reviewed/retained-three-key-bundle.json \
  --expected-sha256 REVIEWED_BUNDLE_BYTES_SHA256
```

The digest/genesis placeholders are not commands to discover a replacement
identity. After separately reviewing a new run ID and generating/reopening only
the three Native role keys, assemble the public bundle/input and use #539's
candidate/review/root-render workflow. Separate preparation is still needed for
the Native archive/leaf/time context and distinct TLS keys/certificates; the
legacy manual manifest and CI fixture keys are not substitutes. No Native
public-preparation file, approval, credential, private key or service was created
on the operator VM while implementing this change.

## Validation

The mandatory root-capable suite has 65 cases covering public identity export,
retained-byte/hash tampering, legacy public schema/peer checks, three-key joins,
new-ledger/reader-key refusal, schema/UID/source confusion, no-token local check,
UID 109 refusal before token/GET, exact GET-only model reads, absent/present
Native metadata, mismatched backend signer, mid-read withdrawal, constant errors
and candidate/root-render/readiness joining. Real-UID subprocess verification
checks local readiness as UID 61109, with no token file, and denial of its private
configuration to UID 109 and UID 61105. This is a configuration/read-only profile
proof; it is not a running service migration or new Native runtime enforcement.
The unit role-file fixtures substitute entry/metadata seams; actual UID behavior
is exercised separately. Local capability-limited runs may skip the subprocess
case; mandatory CI requires all 65 with no skips.
