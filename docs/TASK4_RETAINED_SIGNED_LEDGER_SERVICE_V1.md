# Retained receipt custody joined to the signed service

`scripts/task4_retained_signed_ledger_service_v1.py` connects the existing
pin-required [custody loader](TASK4_RECEIPT_KEY_CUSTODY_V1.md) to
`SignedGitHubService` and the existing loopback mTLS listener. Previously a
trusted caller had to construct and pass an in-memory signing key itself.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

## Startup interface

`reopen_service(backend, directory, expected_public_sha256)` loads only an
existing private custody slot using an independently approved public digest,
requires that digest to equal the backend's configured signer, constructs the
signed service, and performs `backend.read()` before returning it. The read
validates the existing approved parentless root, current ref, canonical registry
and ancestry. It does not enroll, mutate, discover a root or sign a receipt.
Missing, corrupt, replaced or inaccessible custody, absent/mismatched pins and
backend errors stop startup with `RETAINED_SIGNED_LEDGER_STARTUP_STOP`. There is
no initialization, repair, retry or fallback key. Backend validation runs again
on each exchange under the existing adapter protocol.

`retained_listener(backend, directory, expected_public_sha256, context, peers)`
is a context manager that completes this startup check before binding a socket.
The caller supplies an administrator-controlled server TLS context and exactly
two distinct certificate-to-authority mappings. The existing listener enforces
TLS 1.2 or later, required client certificates, pinned peer lookup and loopback
binding. No client input selects the filesystem path, pin, API, backend or role.
The caller controls the server lifecycle; exiting the context closes the socket.
This interface does not provide a public endpoint or a runtime fault switch.

The supplied `backend` is a trusted `GitState` and API implementation, not
untrusted caller data. Configuration, service source, Python dependencies and
all code with the service UID remain trusted. The explicit administrative
`enroll` method remains separate from startup and the client protocol.

## Validation and exact limits

Fourteen tests cover read-only startup, unchanged key inode/modification time,
eight custody/pin failures before any backend access or socket binding, three
backend failures before binding, real loopback mTLS exchange using the retained
key, issuer role denial, and replay denial after reopening the listener. A further
test in that total starts two fresh Python processes: each reloads the same key,
verifies a signed view with the pinned public key, and rejects previously consumed
state reconstructed from a serialized synthetic Git API fixture. Child output
contains only PID and the public-key digest.

The serialized model is test data, not a deployed durable backend. The TLS test
reopens a listener in the same process; the two-process test exercises key reopen
and service verification without a network listener. Neither proves remote
GitHub behavior, separate Runner retention, independent administration, rollback
resistance or Native integration. Existing uncertainty/readback and role tests
remain required regressions. Test keys and TLS material stay in temporary scratch;
CI exports JUnit results only for this increment.

The every-PR Native offline workflow runs these tests and rejects missing cases,
skips, failures and errors. It obtains no credential and dispatches no manual run.
The real operator VM key and its public pin are not included in source or CI.

## Operator boundary

This is a service construction interface, not a deployable CLI. The operator's
existing custody slot must be retained: do not rerun `init`, replace its key,
reset the old metadata ledger or use an old genesis for this signed namespace.
No operator configuration or private file is changed by this PR.

A [fixed GitHub HTTPS transport](TASK4_SIGNED_GITHUB_API_V1.md) is now available
for explicit backend construction; its tests remain offline. Isolated writer
credentials, an explicitly approved create-only root/enrollment procedure, TLS/role custody and remote
access design remain open gates in the
[deployment runbook](TASK4_SIGNED_LEDGER_MANUAL_DEPLOYMENT_RUNBOOK_V1.md).
The older SQLite reference startup remains unchanged and is not this entry
point. No service is deployed, branch created, Provider called or paid resource
provisioned by this increment.
