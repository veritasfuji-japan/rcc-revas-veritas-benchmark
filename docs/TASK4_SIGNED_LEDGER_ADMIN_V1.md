# Create-only signed-ledger administration

`scripts/task4_signed_ledger_admin_v1.py` supplies separate explicit root creation,
experiment enrollment and read-only inspection for the signed eight-slot ledger.
It does not start a service or authorize Provider execution. All implementation
evidence in this increment is offline and model-backed; remote execution is NOT_RUN.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

## Approval configuration and retained attempts

The administrator-controlled canonical JSON configuration is a private 0600 file
in a service-owned 0700 directory. It has exactly these fields:

| Field | Requirement |
| --- | --- |
| `schema` | `task4.signed-ledger-admin.v1` |
| `scope` | `SYNTHETIC_SIGNED_LEDGER_ONLY_NO_PROVIDER` |
| `receipt_directory` | Existing retained receipt-key slot; no initialization or replacement |
| `public_pin_file` | Independently retained root-owned 0644 public SHA-256 plus newline |
| `token_file` | Existing service-owned 0600 explicit GitHub credential; never a command argument |
| `attempt_parent` | Existing retained service-owned 0700 directory outside the receipt slot |
| `approval_id` | Owner-approved fresh lowercase 64-hex ID; for enrollment it must equal the binding's run ID |
| `genesis` | Null for root creation/probing; explicit owner-approved 40-hex root for enrollment/approved inspection |
| `binding` | Null with null genesis; otherwise the exact six-field binding for the fixed signed ledger ID |

The existing descriptor-based file/key checks apply. Local validation occurs
before credential use or attempt creation. There is no environment credential,
default approval, discovered root, alternate branch or automatic configuration
writer. The file is trusted administration, not a cryptographically independent
owner approval. Fresh consent and correct authority ownership remain operator
responsibilities. All service-UID code, root, source/runtime and GitHub remain trusted.

Before any API request in a mutating action, exclusively create and fsync a local
attempt slot: `bootstrap`, or `enroll-<run_id>`. Write an exclusive 0600
`attempt.json` and fsync it and its directory. The record contains only profile,
scope, action, approval ID and configuration SHA-256. An existing slot always
blocks another attempt, including an empty or interrupted slot. No deletion,
repair, resume or automatic retry is supplied. A failed initial fsync may leave
an empty burned slot; it must not be removed to make another attempt succeed.

Success additionally requires an exclusive fsynced local `result.json` before
stdout reports success. Failure to retain that result stops even if GitHub has
already changed. Retain the attempt parent across service/VM restarts; do not
change it, remove slots or restore an old snapshot to bypass this barrier.
The trusted owner/root can do so, and the journal is not anti-rollback or power-
loss proof. Backend duplicate-run checks are a separate defense, not permission
to retry an uncertain operation after losing local records.

## CLI actions and bootstrap order

The CLI is supplied through an administrator-controlled module installation:

| Action | Effect |
| --- | --- |
| `check --configuration ABSOLUTE_PATH` | Local key/approval/file validation only; no API request or attempt creation |
| `inspect --configuration ABSOLUTE_PATH` | Read-only remote inspection; never creates an attempt, retries a mutation or converts an observed head into approval |
| `bootstrap --configuration ABSOLUTE_PATH --acknowledge-synthetic-only` | One exclusive attempt to create the fixed empty signed namespace |
| `enroll --configuration ABSOLUTE_PATH --acknowledge-synthetic-only` | One exclusive attempt to register the exact approved binding under the approved root |

These are interface forms, not authorization to provision a token, root or
operator configuration. Missing acknowledgement stops before configuration reads.
The actual operator runtime, credential, configuration and public approval record
must be separately prepared and reviewed before any real execution.

Bootstrap uses a separate `BootstrapAPI` profile sharing only the fixed verified
HTTPS mechanics with the normal runtime API. It first queries only the fixed
matching-ref prefix and requires an exact existing ref to be absent. Prefix
siblings are distinguished from the exact ref. Authentication errors, 404,
malformed/duplicate/oversized matches or other failures never mean absence.

It then makes at most three POSTs, each phase burned before opening a connection:

1. Create one tree containing only canonical empty signed `ledger.json`, mode
   100644. No base tree, arbitrary blob/file, deletion or extra field is accepted.
   Compute its blob and tree Git SHA-1 locally and require the exact untruncated ack.
2. Create one parentless commit for that tree, with the fixed synthetic headline
   and approved nonce. No parent, caller-supplied author or arbitrary message is
   accepted. Require exact ack, then read the commit/tree/blob back and verify
   canonical state, signer, blob hash, parentlessness and approval message.
3. Create the exact signed-ledger ref pointing at that verified root. There is
   no update-ref, force, delete, GraphQL mutation or fallback namespace in this
   profile. A concurrent creator produces a conflict and stops this attempt.
   Read back the published ref/root and require it to remain the exact empty root.

The resulting root OID is reported with `owner_genesis_approval_required=true`.
It is not automatically enrolled or adopted by a service. The owner must review
and explicitly retain the actual root for a separate enrollment configuration.
Lost responses may leave orphan objects or a published ref. Read-only inspection
can report the observed head but never treats it as an approved replacement root.

The [GitHub tree](https://docs.github.com/en/rest/git/trees#create-a-tree),
[commit](https://docs.github.com/en/rest/git/commits#create-a-commit) and
[reference](https://docs.github.com/en/rest/git/refs) interfaces define the create
operations and matching-prefix behavior. The normal service API still rejects
all bootstrap endpoints; its only write remains the exact expected-head CAS.

Enrollment uses the existing `SignedGitHubService.enroll`: validate the approved
root/ref/state, reject an existing run even with changed binding, preserve other
runs/consumption, and commit once with expected-head comparison and exact readback.
It emits no execution receipt or callback. A committed-but-unacknowledged result
burns the local attempt and stops. Approved inspection can subsequently report
whether the exact binding exists; that observation is not a new enrollment or
permission to continue execution.

All failures expose only `SIGNED_LEDGER_ADMIN_STOP` and nonzero status. No token,
private bytes, path, raw configuration, server response or traceback is printed.
Success output and retained results contain only public synthetic metadata.
Ctrl-C returns status 130 without a traceback; it does not permit a retry.
TLS, response-size, CA-store and non-hard-wall-clock timeout limits remain those
of the fixed HTTPS transport. No live namespace, credential or Provider is touched
by tests or PR delivery beyond the ordinary source branch/PR itself.

## Evidence and remaining work

48 new offline tests cover normal create/enroll/inspect, all POST response-loss
phases, malformed acknowledgements/readback, ref races, namespace errors, existing
state and consumed-record preservation, durable local attempt ordering/races,
failed result retention, fresh-process repeat denial before networking, scope
and payload rejection, matching approval/run IDs, and Git's independent blob/tree
hash calculation. Tests join the real fixed-host transport code to a fake HTTPS
connection and an in-memory API model. They do not prove remote GitHub behavior,
independent storage administration, separate Runner retention or actual VM power-
loss durability. Root-owned public-pin fixtures run under sudo with no CI skips.
Only JUnit results are exported; all fixture material stays in temporary scratch.

The [deployment runbook](TASK4_SIGNED_LEDGER_MANUAL_DEPLOYMENT_RUNBOOK_V1.md)
remains blocked on actual protected installation, dedicated credential delivery
and access evidence, owner-approved root/enrollment execution, TLS/role custody,
remote reachability and complete remote evidence. Native integration, Provider
credential/egress isolation, independent A/B and utility scoring remain separate.
