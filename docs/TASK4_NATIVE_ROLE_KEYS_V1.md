# Operator role-local synthetic keys and public exports

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

The operator VM now has separately owned Native role homes and can load the
#539 public approval preparer. Its canonical readiness configuration was created
and verified with SHA-256
`47ecb7f5088565773a3b6a07d22199be4ca76fb941a86e2770ccdd3b89b5c7b4`.
User-provided `os.access` results showed each of the four accounts could access
its own home and could not traverse the three other homes (12 refusals). These
are bounded directory-access observations, not a claim of network enforcement,
private-key custody, process isolation against root, or production bypass proof.
No operator key was created by those preparation commands.

The new `scripts.task4_native_role_keys_v1` module provides explicit create-once
key preparation and reopen-only inspection under each fixed role. It reuses the
existing receipt-key custody primitive's no-follow file traversal, exclusive
slot creation, parent-before-key fsync, single-link 0600 key validation and
pinned public-key reopening. It adds a durable public record tied to the role,
reviewed run ID and directory/file identities. It has no grant/receipt signing
interface, credential, network, certificate issuer, enrollment or service action.

| Role | UID / GID | Existing private home |
| --- | --- | --- |
| ledger | 61109 | `/var/lib/veritas-native-ledger` |
| issuer | 61105 | `/var/lib/veritas-native-issuer` |
| custody | 61106 | `/var/lib/veritas-native-custody` |
| runtime | 61108 | `/var/lib/veritas-native-runtime` |

Key actions require the exact nonroot effective UID and GID for the selected
role and no supplementary groups except that role's GID. Root is refused;
trusted administration must explicitly invoke the intended account. The CLI
has no arbitrary directory, UID, key import, overwrite, reset, repair, rotation
or retry argument. Role homes must already exist as owned 0700 directories
with trusted ancestors. It never creates or repairs those homes.

## Create once, retain, then reopen using external pins

For each role, the fixed child `native-authority-v1` is exclusively created and
its parent fsynced **before** generating one Ed25519 key. The key remains in
`native-authority-v1/receipt.key`, raw 32 bytes owned by that role with mode 0600.
The generic filename is inherited from the custody primitive; for issuer,
Custody and runtime it is application authority material, not an assertion
that those roles may sign service receipts. TLS requires separate keys later.

The public record `native-authority-public-v1.json` is exclusively created as
0600 in the same private home after key readback, then file/parent fsynced and
read back. It contains schema/scope, role/UID, Ed25519 algorithm, run ID, public
key and its SHA-256, and directory/file device/inode/owner/mode identities.
It contains neither private key bytes nor a private filesystem path. CLI
reports emit that record and its canonical SHA-256, public scope and explicit
false execution/enrollment/origin-verification flags. No private bytes are
printed on success or failure. Ordinary failures emit only `NATIVE_ROLE_KEYS_STOP`.

Every existing slot, even empty or incomplete, blocks initialization. A missing,
malformed or partial public record does not trigger key generation or pin
discovery. A process can stop after retaining the key but before creating the
record; the tool leaves the slot in place and provides no automatic recovery.
A complete disk state with lost stdout also must not be initialized again.
Independent administrative reconciliation would be a separate reviewed action;
no such recovery command is added here.

Inspection requires both the **independently retained public-key SHA-256** and
**public-record SHA-256**, as well as the same role/run ID. It validates the
public record before loading the fixed private key, checks public/private key
consistency, compares retained device/inode identities and re-reads the public
record before output. There is no cached alternative key or signing/effect
callback. Expected pins cannot be omitted or discovered from the key by this CLI.

These limits assume trusted code within each role and a trusted administrator.
A role UID can otherwise read its own key and has ordinary owner rights over
its home. A malicious same-UID process/root can move/remove slots or restore a
filesystem snapshot. This does not establish nonexportability, protected hardware,
secure erasure, cross-host anti-rollback or survival of actual hardware power loss.
Fsync failure and abrupt-process tests are narrower than those claims. Public
key hashes must be retained separately; a hash copied from attacker-controlled
input is not independent enrollment or origin evidence.

## Public bundle verification and exact Native input join

`verify-public` reads one explicit bounded no-follow document against an
independently reviewed exact-byte SHA-256. The bundle has exactly:

- `schema`: `task4.native-role-key-bundle.v1`;
- `scope`: `SYNTHETIC_NATIVE_KEY_PREPARATION_ONLY_NO_EXECUTION`;
- `run_id`: the same reviewed new 64-hex identifier as all role exports;
- `exports`: exactly `ledger`, `issuer`, `custody`, `runtime`, each holding its
  report's `public_export` record, not the entire report or private data.

It validates exact role/UID/scope/algorithm, public-key hashes and reported
storage shapes, rejects shared application keys and shared reported storage,
and returns a public key mapping and record digests. No private key is loaded
and no role assumption is made for this public-only action. The old manual
A0/A1 run ID is rejected. A run ID is a correlation label; choosing one does
not create a Native context, initialize GitHub storage or grant execution.
Do not reuse a known CI/prior run ID or substitute CI exports for operator
material. The module does not independently identify relabeled public exports.

`match-input` additionally reads the #539 Native public-preparation input and
validates it through the existing preparer (including manifest, roles, selected
source files and public TLS certificate checks). It joins:

| Export | Public preparation field |
| --- | --- |
| ledger | `service_public_hex` |
| issuer | `issuer_public_hex` |
| custody | `native_manifest.custody_public` |
| runtime | `native_manifest.runtime_public` |
| shared run ID | `native_manifest.execution.run_id` |

Both exact document hashes are retained in the resulting match report. Both
inputs are re-read before output and withdrawal/change stops without retry.
This lets a human reviewer join the intended public exports to the exact input
bytes subsequently given to the #539 candidate builder. It does **not** install
approval or change #539's root review boundary. The existing candidate builder
still requires explicit public input and does not automatically discover or
trust this bundle. Store/review the match report and the exact two byte hashes
alongside the candidate; this join is not an execution-time authorization gate.

A public bundle can be fabricated, and successful public-only verification is
not proof of private-key possession, actual UID/file state or VM origin.
`operator_origin_independently_verified` and
`key_possession_independently_verified` remain false. The actual role-local
inspection observes a matching retained private/public pair but is not a
third-party attestation of its environment. No public-key-only observation
proves that private bytes cannot be copied or used by trusted administration.

## Existing remote signer is a separate boundary

The already observed remote GitHub genesis is pinned to the old retained
service public key. Generating a fresh `ledger` key does **not** migrate that
root or make the new key its signer. Do not replace the existing public pin,
reset/reinitialize the remote branch or copy a signing secret to make a public
match pass. With a correctly reviewed old service public key in the public
input, a fresh ledger export will intentionally fail `match-input`.

The public-only report therefore always states
`existing_genesis_compatibility_verified=false`. This module produces prospective
role material, not an approved remote signer transition. Keeping the current
remote root requires a separately reviewed retained-signer/UID migration design;
a new root would require its own explicit approval and is not performed here.
The read-only readiness checker itself needs only the approved service public
key, not a newly generated ledger private key. None of these key actions is a
prerequisite or authorization to replace that existing service identity.

## Operator handoff

Install/review the new protected source before running these commands; the
previous `/opt/veritas-native-preparation-14b1cc7/source` does not contain this
new module. Use the same explicit namespace bootstrap documented in
[the #539 handoff](TASK4_NATIVE_GITHUB_APPROVAL_PREPARATION_V1.md) when an older
regular `scripts` package is installed. Neither source path insertion alone
nor a source hash attests the interpreter/dependency closure/cached bytecode.

After reviewing one new run ID and the intended role, invoke initialization
only as that role's account in the protected interpreter:

```sh
python -I -B -m scripts.task4_native_role_keys_v1 initialize \
  --role issuer --run-id REVIEWED_NEW_RUN_ID \
  --acknowledge-create-synthetic-key
python -I -B -m scripts.task4_native_role_keys_v1 inspect \
  --role issuer --run-id REVIEWED_NEW_RUN_ID \
  --expected-public-sha256 INDEPENDENT_PUBLIC_KEY_SHA256 \
  --expected-export-sha256 INDEPENDENT_PUBLIC_RECORD_SHA256
python -I -B -m scripts.task4_native_role_keys_v1 verify-public \
  --document /absolute/reviewed/public-role-bundle.json \
  --expected-sha256 REVIEWED_BUNDLE_BYTES_SHA256
python -I -B -m scripts.task4_native_role_keys_v1 match-input \
  --document /absolute/reviewed/native-public-input.json \
  --expected-sha256 REVIEWED_INPUT_BYTES_SHA256 \
  --public-bundle /absolute/reviewed/public-role-bundle.json \
  --expected-public-bundle-sha256 REVIEWED_BUNDLE_BYTES_SHA256
```

These argument examples contain placeholders and are not a key-generation
instruction for an unreviewed run. Use each of the four fixed role accounts
separately. Persist only public reports to the intended review location and
retain their pins independently. Do not print/upload `receipt.key`, use the
old service's signing key, or treat a public match as Native execution approval.

After this increment, separate operator preparation is still required for the
Native run/archive/leaf context, distinct TLS keys and certificates, review of
all public exports, root read-only approval placement, local `check`, dedicated
read-only GitHub credential and actual read observation/egress evidence. Existing
Native runtime consumers are not changed to load these new keys in this PR.
No operation on the user's VM, real private key, remote ledger or Provider was
performed while implementing this change.

## Validation

Tests cover retained key/public-pair readback, all four role records, explicit
acknowledgement, exact UID/GID/groups, independent pins, existing/partial slots,
key/record modes and substitution, hard/symbolic links, no repair, all five fsync
failure points, parent fsync before generation, concurrent initialization and
abrupt exit after key retention. Public-only tests refuse role/key/run/storage
confusion and join all four keys to a fully validated synthetic Native input,
including refusal of each substituted key and run. Unit file fixtures run as
the test UID and replace only role-entry/metadata seams; they do not constitute
cross-UID custody evidence.

The dedicated root-capable CI case starts fresh interpreters as all four real
UIDs, creates keys in disposable test role homes, verifies pinned reopening and
refusal of repeated initialization, then attempts to open each other role's
actual private key file: all 12 opens must fail with PermissionError (not merely
missing files). Root initialization through a role argument is also refused.
The isolated BASE override is test bootstrap code, not an operator CLI option.
The workflow requires the full 73-case suite without skips; capability-limited
local runs can skip this one actual-UID case. CI keys are disposable test data,
not deployment material or an independent operator-host attestation.
