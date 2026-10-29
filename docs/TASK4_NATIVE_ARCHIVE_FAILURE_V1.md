# Native original archive failure and acknowledgement v1

This explicit local profile observes the original archive routine's encryption,
exclusive file creation, file fsync and directory fsync. It injects selected
archive-boundary errors and one real permission denial; it does not replace the
routine with a fabricated success/failure result. Previous frozen profiles,
collector deadlines, HTTP/JSON bytes, generator, grants, Bind and SDK remain intact.

## Selected boundaries

| Actual case | Selected mechanism | Visible archive after failure | Acknowledged archive |
| --- | --- | --- | --- |
| normal | Real original encryption, write/flush, file fsync, directory fsync | Yes | Only after both real archive fsync calls return |
| encrypt-failure | Scoped AESGCM.encrypt facade raises ValueError before real encryption | No | No |
| create-denied | Actual UID 61106 has mode 0500 on its archive directory; original exclusive create raises EACCES | No | No |
| file-fsync-failure | Original encryption and write/flush run; exact archive file fd receives injected EIO before its fsync | Yes, but durability unconfirmed | No |
| directory-fsync-failure | Original encryption/write/file fsync run; exact archive directory fd receives injected EIO before its fsync | Yes, but directory durability unconfirmed | No |

Error injection is synthetic and narrowly scoped to the selected archive call.
It is not a claim that a physical disk, machine-wide storage or hardware crypto
failed. Non-archive fsync operations, including custody journals and audit logs,
delegate to the original function. Wrappers restore both crypto and fsync before
reporting the actual returned/raised outcome. No key, private ephemeral material
or credential is logged. The actual create-denied Native case uses no Path.open
stub; the portable permission-error unit simulation is labelled separately.

## Exact ordering and state

Each complete valid response is captured at EOF through the existing fixed total
collector, then the client connection closes. The original sealer is called.
A success requires its real encryption plus file and directory fsyncs to return
before original SEAL_RETURN and SEALED_FSYNCED, HTTP parsing or SDK delivery.
The mandatory normal control audits all 64 archive boundary events across eight
actual SDK steps and retains the original two terminals/scorers, sixteen signed
mutations, changed histories, parent/tool/archive joins and restart/replay checks.

In every negative case the original sealer raises; there is no SEAL_RETURN,
SEALED_FSYNCED, HTTP_PARSE_STARTED or BODY_RELEASED_TO_BIND. The actual parser,
ID guard and framing guard are not invoked to recover permission. Bind reports
APPLY_FAILED with zero verified returned apply calls even though the backend
already committed one local effect. Native receives no model response and makes
no scorer call. Issuer/Custody remain pending/CONSUMED_UNKNOWN; the signed ledger
remains revision two. Read-only reconciliation issues no permission.

Ledger, issuer, Custody and backend are SIGKILLed/reopened with new PIDs. The
backend reopens the same pinned database read-only. Separate Custody snapshot
workers retain the same archive presence/bytes/inode before and after those
restarts. No archive is deleted, overwritten, repaired or resealed. Replay,
reissue, initialization, replacement database and mutation retry remain denied.
Normal Custody uses the frozen TERM/reopen path; negatives use four-role SIGKILL.

## Visibility is not durability or permission

For file/directory fsync failure the original write/flush leaves a complete,
decryptable encrypted file in this process-restart experiment. A fresh separate
recipient-owner process actually decrypts it after the role restarts. This proves
only those observed bytes and that recipient binding; it does not prove successful
fsync, power-loss retention, a successful archive acknowledgement or permission
to deliver/retry. For encryption/create failure there is no archive to recover.
The root-only test export copies existing public synthetic ciphertext to the
owner's recovery directory without changing the original archive.

Snapshots read single-link regular 0600 files through held no-follow descriptors.
Audit events retain archive file/directory descriptor identities, exact cipher
bytes/hash, AAD/header commitments, errno/class, ordering, restoration and actual
kernel UID/namespace. Directory entry size may change on file creation; its
stable identity and actual post-create fsync descriptor are compared separately.
No exception path synthesizes `local_fsync_completed: true`.

## Verification and limits

CI requires **147 new portable tests**, **21 joined actual normal checks** and
**24 joined checks per failure case**, all with zero skips. Portable probes use
real original cryptography and filesystem calls with explicit role/permission
stubs; they are not represented as Native UID evidence. Mandatory disposable-root
cases retain the original UID/capability/NNP, Unix TLS CA/hostname/leaf, signed
ledger, network-denial and archive-owner checks. Prior complete receive controls
remain mandatory. The growing combined CI job gets a 40-minute execution budget;
individual receive deadlines and retry/authority conditions remain unchanged.

Only selected archive failures are covered. File write/flush partial failures,
all possible I/O errors, hostile concurrent writers, hardware failure, independent
operator/storage administration, power loss, VM reboot and full-runtime attestation
are outside this evidence. The root synthetic controller knows fixture keys.
No user VM, token, real Provider, remote GitHub backend, host policy, OS trust
store, live permission or service cutover is changed.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN** remain unchanged.
