# Manual existing-state signed-ledger entry point

`scripts/task4_signed_ledger_entrypoint_v1.py` joins the retained receipt key,
fixed GitHub transport, approved configuration and loopback mTLS listener.
It supplies local validation and manual startup for an **already created and
enrolled** synthetic ledger. It does not create those prerequisites.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

## Configuration and custody requirements

The configuration is a canonical JSON object, at most 8,192 bytes, with exactly
the following fields. All paths are absolute and canonical, without symlink
ancestors. A missing or invalid value stops processing; no default or repair
is selected. This table describes a schema, not an approved operator setup.

| Field | Requirement |
| --- | --- |
| `schema` | `task4.signed-ledger-entrypoint.v1` |
| `scope` | `SYNTHETIC_SIGNED_LEDGER_ONLY_NO_PROVIDER` |
| `genesis` | Explicitly approved parentless signed-registry root, lowercase 40-hex OID |
| `receipt_directory` | Existing create-once receipt custody slot |
| `public_pin_file` | Independently retained root-owned public digest file |
| `token_file` | Existing dedicated GitHub writer credential file; no environment discovery |
| `binding` | Exact existing six-field external-ledger binding, including fixed signed ledger ID and fresh approved run ID |
| `tls_certificate`, `tls_key`, `client_ca` | Existing server PEM certificate/key and client CA PEM paths |
| `server_certificate_sha256` | Approved SHA-256 of the complete DER server leaf certificate |
| `peers` | Exactly `issuer` and `custody`, each containing distinct `certificate_sha256` and matching binding `authority_public_sha256` |

Configuration, token and TLS files must be regular single-link files owned by
the effective service UID, mode 0600, in an owned mode-0700 immediate parent.
The public pin is instead root-owned mode 0644 and contains exactly a lowercase
64-hex digest plus one newline. Its ancestors may be root/service-owned but
must not be group/other writable. Private ancestors have the same trust rule;
root-owned sticky ancestors are allowed for private temporary test fixtures.
Receipt-key validation remains in the existing descriptor-based custody loader.

Configuration and public approvals are supplied through trusted administration.
The service UID and root can change their files and remain trusted. File checks
do not prove independent administration, credential isolation against that UID,
memory secrecy, backup safety or rollback resistance. Do not put any of these
files under a Git checkout, home workspace, artifact or synchronized directory.

The token is read only after local key, binding, peer and TLS checks succeed.
Its file is at most 256 bytes: 20-255 ASCII letters/digits/underscores, optionally
followed by one newline. It is never a command-line argument or output value.
No token is issued, refreshed, inferred or selected by this entry point.

The server certificate must match the approved DER pin, have a current validity
period, SAN `task4-ledger.test`, server-auth EKU and non-CA basic constraints.
An Ed25519 TLS certificate cannot reuse the receipt or either authority public
key. Issuer/Custody TLS and authority-key separation still requires approved
client-side custody; only their configured public mappings are available here.
Encrypted TLS keys are rejected without an interactive password prompt.
OpenSSL checks the server certificate/key match. This is not a separate server
chain/revocation audit; clients must verify their approved CA/hostname/DER pin.

Private file reads use no-follow directory descriptors and bounded regular-file
checks. TLS certificate/key descriptors remain open while OpenSSL loads them
through `/proc/self/fd`; replacing a configured path does not redirect that
load. No temporary private-key copy is written. Linux with procfs and the
reviewed cryptography/OpenSSL runtime is required. Runtime source, dependencies,
CA store, environment, root and all service-UID code remain trusted.

## Local check and explicit startup

The CLI has two actions, supplied by an administrator-controlled installation:

| Action | Behavior |
| --- | --- |
| `check --configuration ABSOLUTE_PATH` | Local validation only. Reads protected files, builds TLS/backend objects, reports `backend_verified=false` and `listener_started=false`; no API request or listener |
| `serve --configuration ABSOLUTE_PATH --acknowledge-synthetic-only` | Performs the same local checks, reopens the pinned signer, validates existing backend root/ref/state, confirms the exact approved binding is already enrolled, then binds loopback |

The module must first be installed with its reviewed dependencies in a runtime
that ordinary clients cannot modify. The operator's standalone custody utility
installation is not a full module installation. These interface forms are not
instructions to run against UNSET values or create credentials. A concrete
installation/configuration and owner approval remain necessary before actual use.

Serve without the explicit acknowledgement stops before reading configuration.
Startup uses only backend reads; it never enrolls, bootstraps, mutates, resets,
changes permissions or reinitializes a key. The existing retained startup validates
the root, and a further read confirms the configured enrolled run. These reads
are validation steps, not automatic retries of a failed operation.

Only `127.0.0.1` on an OS-selected ephemeral port is supported. There is no
configured host/port override, remote endpoint, tunnel or self-hosted Runner.
After successful startup, stdout reports the public profile, scope, genesis,
receipt/server public digests, status flags and port. It never reports token,
private keys, file paths, raw configuration or backend responses. `check` output
does not imply remote verification. All failures expose only
`SIGNED_LEDGER_ENTRYPOINT_STOP` with nonzero status; Ctrl-C closes the listener
and exits with status 130. There is no daemon installer or automatic restart.

Client certificates select the configured peer; a wrapper rejects any command
whose binding digest differs from the configured exact run **before** backend
access. Existing service role, revision, nonce, readback and receipt checks remain
required. Per-command state verification continues after startup. No client
command can enroll a run or choose a file, root, token, backend or TLS identity.
The HTTPS transport's timeout/ambiguity limitations remain unchanged; it has no
hard end-to-end wall-clock bound or automatic resend.

## Tests and deployment status

44 tests cover local-only CLI checks, 21 configuration/key/token/TLS faults,
nine file/path faults, missing/changed enrollment and backend unavailability,
real loopback mTLS with configured-run enforcement and consumed replay denial,
descriptor-pinned OpenSSL loading despite path replacement, five server
certificate faults, explicit-start acknowledgement and fresh-process sanitized
CLI behavior. Tests use root-owned public-pin fixtures under sudo and require
no skips in CI. All keys/TLS/token bytes are disposable synthetic fixtures.
The backend is an in-memory GitHub API model; no actual GitHub API transport
request, deployed storage or separate-Runner retention is evidenced here.
CI exports only the JUnit results for this increment, never fixture directories.

The [manual deployment runbook](TASK4_SIGNED_LEDGER_MANUAL_DEPLOYMENT_RUNBOOK_V1.md)
remains `DEPLOYMENT_BLOCKED`: actual dedicated writer credential provisioning,
independent access evidence, approved create-only genesis/enrollment lifecycle,
TLS/role custody, protected module installation, remote access and actual remote
evidence have not been supplied by this PR. It changes no operator VM file,
key, credential, namespace or workflow setting. No Provider or bank call is made.
