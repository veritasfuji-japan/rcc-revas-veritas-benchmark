# Native public approval preparation and operator handoff

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

The readiness checker added in #538 requires a separately reviewed Native
manifest, application public keys, public TLS pins, existing genesis and selected
source hashes. Its synthetic CI fixtures and the old manual A0/A1 approval are
not an operator deployment. The new preparation module turns explicit public
inputs into a reviewable candidate, validates that candidate again, and offers
an explicit root-only **read-only approval rendering** action. It never installs
an approval, creates/loads a private key or token, contacts GitHub, registers a
run, changes a firewall, starts a service or calls a Provider.

The module is `scripts.task4_native_github_approval_preparation_v1`. There are
three actions. All require an explicit absolute document path and the SHA-256
of its exact bytes, obtained/reviewed separately from this command.

| Action | Output and boundary |
| --- | --- |
| `candidate` | Candidate envelope with retained original public bytes, proposed readiness approval, source pin and explicit false verification/permission flags. No root requirement and no installation. |
| `review` | Recomputed candidate/approval digests and remaining human review items. It cannot emit an approval. |
| `render-approval` | Exact canonical readiness approval bytes on stdout only. Requires effective UID 0, a pinned candidate digest and `--acknowledge-read-only-approval`. It cannot install the output or grant execution. |

A candidate envelope is rejected as a readiness approval. Root rendering verifies
all derived fields again, including certificate time validity and the currently
installed selected source files. The source JSON is re-read against its digest
before any successful output. Withdrawn/replaced inputs stop; there is no retry.
Ordinary errors emit only `NATIVE_GITHUB_APPROVAL_PREPARATION_STOP` on stderr.
The public JSON parser refuses duplicate keys, NaN/Infinity and oversized input;
file reads reject symbolic links (including ancestors), hard links, writable
parents, unsafe modes and nonregular files. Inputs must be owned by root or the
effective account with mode 0600 or 0644 and trusted ancestors. Root review must
therefore stage candidate bytes into trusted root-owned storage first; it must
not read an untrusted user's mutable directory merely because the digest is known.

## Retained signer alternative

For the existing service UID 109 and separate reader UID 61109, use the explicit
[retained-signer input/approval schemas](TASK4_NATIVE_RETAINED_SIGNER_PROFILE_V1.md).
They preserve the original genesis/service public identity and accept exactly
three Native exports, without a new ledger private key. Candidate/review/root
rendering validate that separate shape and 14 selected source pins; they do not
silently reinterpret the original four-role schema or perform a runtime cutover.

## Required public inputs

The separate [role-local key preparation workflow](TASK4_NATIVE_ROLE_KEYS_V1.md)
creates fixed-role keys once, requires external public/export pins for reopening,
and matches public-only exports to these exact input fields before candidate
review. It does not produce the missing Native archive/leaf context or TLS
certificates, and a public match does not prove VM origin or grant execution.

The exact input fields are listed below. Extra fields, including private-key,
token or custody paths, are rejected. No input is discovered from the operator's
old configuration, CI artifacts, environment or home directory.

| Field | Review requirement |
| --- | --- |
| `schema` | `task4.native-github-public-preparation.v1` |
| `scope` | `SYNTHETIC_NATIVE_GITHUB_READ_ONLY_NO_EXECUTION` |
| `origin` | Literal `OPERATOR_VM_PUBLIC_INPUTS_FOR_REVIEW`; this is a declaration, not attestation |
| `execution_source` | Full reviewed 40-hex source label; not proof of Git provenance or dependencies |
| `genesis` | Independently reviewed existing empty-root Git OID |
| `native_manifest` | Exact existing bounded Native manifest, including its run/time/archive/leaf context, Custody and runtime public keys |
| `issuer_public_hex` / `service_public_hex` | Raw public Ed25519 keys obtained through the intended protected custody/review process |
| `source_sha256` | The readiness checker's exact 11 selected source hashes |
| `roles` | Exact current profile UIDs: ledger 61109, issuer 61105, Custody 61106, runtime 61108 |
| `public_certificates` | Exactly `ca`, `server`, `issuer`, `custody`, each containing one canonical PEM **public certificate** |

The builder derives the binding from the exact Native manifest and public keys;
it does not accept a caller-supplied replacement binding or arbitrary TLS pins.
All four application authority keys must be distinct. All four TLS certificates
and TLS public keys must be distinct, and Ed25519 TLS keys cannot reuse any
application authority key. The root CA must be self-issued, self-signature
verified, currently valid, CA=true and permitted to sign certificates. Each
leaf must be directly signed by that CA, currently valid, CA=false, permitted
for digital signatures and have the exact server/client EKU. The server SAN
must include `task4-ledger.test`. Unhandled critical certificate extensions stop.
Only the public certificates are loaded. Pin equality is not a TLS handshake,
proof of private-key possession, revocation checking, a complete PKIX policy
validation or a live service identity proof. The public CA itself remains an
explicit reviewed trust input. See the cryptography
[certificate verification API](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate.verify_directly_issued_by).

The Native time window is preserved exactly; an expired manifest is not refreshed
or turned into a new execution permission. The resulting approval is still only
for diagnostic reads. Actual execution would require a separately reviewed fresh
context and authority flow. Certificate expiration does stop candidate/review/
rendering, and readiness independently checks its own scope/binding.

## Manual/CI reuse boundaries

The old manual fixed-label manifest is structurally rejected. The already used
manual run `546d9ab659e2fb54e3dcd20700ab6d8422e0b4d5ef81ef59a2ca622f91fad16c`
is always excluded. `candidate --exclude-run-id <64hex>` can add known prior or CI
run IDs; root review must check the complete list against its reviewed inventory.
The list, original public input bytes and every derived field are bound into the
candidate digest. Removing the mandatory exclusion, changing a pin/key/source
report or changing a verification flag is rejected on recomputation.

An explicitly declared CI/model/manual input is refused by its origin field.
**Relabeling arbitrary CI public bytes as operator input is not mechanically
proven false by this tool.** A hash proves byte identity, not origin or authority.
No public-key-only format can prove that the associated private key was generated
or remains on a particular machine. Origin and protected custody require separate
review/evidence; `operator_origin_independently_verified` and
`role_key_possession_verified` remain false, including after root rendering.
This tool neither extracts a CI fixture nor generates new operator keys/context.
Those public inputs must be supplied by a separate reviewed preparation process.
A root acknowledgement is an administrator decision for read-only configuration;
it is not evidence of independent owner approval or reviewer independence.

The candidate retains the exact original input bytes as Base64 and their SHA-256;
review decodes, rehashes and parses them again. Public PEM certificates are not
secret. Nevertheless review public input before publishing a candidate: no host
attestation, issuer signature over the export or third-party custody verification
is supplied here. The preparer's own source hash is pinned separately from the
readiness checker's 11 selected files; neither pin covers the interpreter,
cached bytecode, installed dependency closure or malicious administrator.

## Operator state observed before this change

User-provided VM output showed the following, rather than an execution proof:

- Source `ae9fcce83d0cb96e39184bda5ac59d3fb912d03e` exported under root-owned,
  non-group/other-writable `/opt/veritas-native-readiness-ae9fcce/source`.
- All 11 selected hashes matched the reviewed #538 source. UID 61109 successfully
  loaded them using the existing protected Python 3.12.3 environment with
  cryptography 50.0.0. The environment itself was not independently attested.
- `veritas-native-ledger` was created as UID/GID 61109 with nologin; its state and
  readiness directories were owned by that UID/GID with mode 0700. Other Native
  role accounts were not created in this preparation.
- A proposed configuration at
  `/var/lib/veritas-native-ledger/readiness/configuration-ae9fcce.json` was created
  owned by UID 61109 with mode 0600. Its approval and token paths were placeholders;
  no Native approval or read token was created by these observations.

The initial configuration command used ordinary JSON spacing and a final LF.
The existing readiness parser requires canonical JSON, so that file needs a
create-only canonical successor **before** `check`. Do not overwrite/reuse old
manual approvals to make it pass. Preserve the original and, as UID 61109, read
it through the existing protected `read_file`, parse with duplicate-key refusal,
check the exact four expected fields, then exclusively create a new 0600 file
containing `canonical(cfg)` without a trailing LF. Review its exact paths before
selecting it for a check. This is a formatting correction, not approval issuance.

No assumption is made that the previously observed manual service PID/port is
still current. This implementation performs no operator VM action.

## Separate candidate review and root placement

After installing the **reviewed preparer source** into protected storage and
supplying the required public input bundle, run only the appropriate actions:

```sh
# Using a protected interpreter and the reviewed installed module:
python -I -B -m scripts.task4_native_github_approval_preparation_v1 candidate \
  --document /absolute/reviewed/public-input.json \
  --expected-sha256 INPUT_SHA256 \
  --exclude-run-id KNOWN_PRIOR_OR_CI_RUN_ID
python -I -B -m scripts.task4_native_github_approval_preparation_v1 review \
  --document /absolute/reviewed/candidate.json \
  --expected-sha256 CANDIDATE_SHA256
# Only following explicit human review, from trusted root-owned staged bytes:
python -I -B -m scripts.task4_native_github_approval_preparation_v1 render-approval \
  --document /root/review/native-candidate.json \
  --expected-sha256 CANDIDATE_SHA256 \
  --acknowledge-read-only-approval
```

These are argument examples with digest placeholders, not commands that create
missing operator inputs or directories. The final action is root-only even if
another account knows the candidate digest. It emits the existing readiness
approval schema, not a new execution capability. It does not change a role UID,
read the service signing key or touch GitHub state.

The operator VM currently also has an older regular `scripts` package installed.
Merely prepending a source directory to sys.path did not select the newer
namespace package. For the reviewed protected source tree, explicitly select it
before calling `main([...])` in the protected interpreter with `-I -B`:

```python
import importlib.machinery
import importlib.util
import sys
spec = importlib.machinery.PathFinder.find_spec("scripts", [protected_source])
if spec is None:
    raise SystemExit("SOURCE_PACKAGE_NOT_FOUND")
sys.modules["scripts"] = importlib.util.module_from_spec(spec)
from scripts import task4_native_github_approval_preparation_v1 as preparation
raise SystemExit(preparation.main(explicit_arguments))
```

This selects a source package; it does not attest the environment. Do not run
this bootstrap with a mutable checkout path under root. Review/install the new
preparer first; it was not included in the earlier #538 source export.

After separately rendering/reviewing the approval, trusted administration must
choose the configured public path, create it exclusively (never overwrite) as
root-owned 0644 under trusted non-writable ancestors and verify its exact bytes
and the 8192-byte readiness bound. Only then run local readiness `check` as
UID 61109 using the canonical private configuration. That check needs no token
file and opens no socket. A separately approved contents-read-only credential,
actual VM GET observation, role-key custody, OS egress evidence and remote
Native enrollment/integration remain later steps. Never reuse the old service's
write-capable credential to shortcut this process.

## Validation

The tests use newly generated disposable keys/certificates as fixtures, with
network creation blocked in the unit cases. They cover normal candidate/review/
root-render-to-readiness joining, exact retained bytes, source/key/UID/profile
mismatches, manual/declared CI inputs, prior runs, TLS signatures/purposes/expiry/
key separation, candidate tampering, no-follow bounded file reads, withdrawal,
constant errors and no private key generation/loading during preparation.
A root-capable CI subprocess proves UID 61109 can prepare/review its own protected
public input while its explicit root-render attempt is refused, with no token
or network step. Local restricted environments may skip that capability test;
the mandatory workflow requires the complete suite without skips.
