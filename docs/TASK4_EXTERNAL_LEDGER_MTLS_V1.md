# Signed reference-ledger transport with loopback mTLS

This increment fills one named gap in the [#518 contract](TASK4_EXTERNAL_LEDGER_CONTRACT_V1.md):
the reference transport previously received an asserted peer identity directly
from test code. The new adapter obtains that identity from an actual,
CA-validated TLS client certificate and an administrator-approved exact
certificate mapping. It supplies real loopback TCP/TLS exchanges and separate
service-process restarts, with zero Provider calls.

It does not connect the [observed GitHub metadata backend](TASK4_GITHUB_LEDGER_OBSERVED_EVIDENCE_V1.md)
to the signed contract. The service still uses #518's private local reference
SQLite file. No running remote service, persistent host, live key custodian,
Native connection, separate Runner or independent administrator is provided.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

## Implemented boundary

`scripts/task4_external_ledger_mtls_v1.py` binds only to `127.0.0.1` on an
OS-selected port. It is an injectable reference adapter, with no external-host
selector or deployment CLI. Each TLS connection carries exactly one permitted
command and at most one receipt, framed by a four-byte unsigned network-order
length. Frames are nonempty and at most the existing MAX_WIRE=8192 bytes. A
connection is closed after the one exchange; additional queued commands are not
processed. There is no HTTP parser, proxy, redirect, role header or retry.

The server requires a CA-valid client certificate. It hashes the entire verified
DER leaf certificate and looks it up in trusted configuration. A CA-valid but
unmapped certificate is rejected. The mapping associates that transport
certificate with the enrolled issuer/Custody public-key digest from #518; the
TLS key and authority/grant key are separate identities. Client JSON cannot
select either role or mapping. #518 then checks the mapped peer against the
requested binding and permits reserve only for issuer, consume only for Custody,
and view for either enrolled peer. Mapping configuration and administrators
remain trusted; this does not prevent them from deliberately assigning roles.

The client verifies the service certificate's CA, fixed hostname
`task4-ledger.test`, and exact DER certificate hash before sending a command.
It presents its own certificate and privately held TLS key. TLS minimum version
is 1.2. The #518 LedgerClient separately verifies the Ed25519 service signature,
nonce, command digest, action, binding, revision and resulting attempt. TLS
success alone never authorizes its callback.

Handshake, frame reads and writes have two-second timeouts. Frame reads share an
absolute deadline across the prefix/body reads, so incoming bytes do not renew
that deadline. The serial reference listener has a bounded backlog and does not
claim denial-of-service resistance. Malformed commands, missing/incorrect
certificates, role crossing, stale revisions, invalid frames, unavailable service
or unverified receipts close/deny the exchange and prevent the callback. No raw
request or exception data is logged by the server. Detailed operational
observability would require a separately reviewed sanitized diagnostic design.

The service opens only pre-existing storage and a pre-existing 32-byte Ed25519
key. Configured files must be regular, single-link, owned by the process user,
mode 0600, in an owned 0700 immediate parent directory. The reference checks
filesystem metadata; it assumes trusted ancestors/administrators and does not
prove protection against concurrent privileged path replacement. There is no
automatic bootstrap, repair, alternate namespace or service-key generation in
the listener. A changed signer is rejected by the registered #518 database.

## Rehearsal and evidence

`scripts/task4_external_ledger_mtls_rehearsal_v1.py` is an explicit synthetic test
administrator. It creates a temporary private directory, test CA/certificates,
service key, one approved binding and SQLite ledger. None of these private files
is uploaded. This test administrator is not an approved enrollment workflow.

Four spawned service processes reopen the same file and signing key:

1. Reserve A0; refuse issuer consume, Custody reserve and an unmapped certificate.
2. After process termination/restart, refuse A0 re-reservation, consume A0, reserve B0.
3. Commit B0 consumption and sign its receipt, but deliberately close the
   connection before returning it. The client receives no acknowledgement and
   executes no callback.
4. Restart again, observe both consumed records at revision 4 and refuse B0 replay.

The service processes have four distinct PIDs and a matching enrolled signer
hash. Total synthetic issuance callbacks=1 and synthetic send callbacks=1;
these callbacks append integers to lists. There is no SDK request or bank effect.
This is a real connection closure after commit/signature, injected by the trusted
rehearsal process; it does not establish arbitrary outage recovery. SIGTERM and
reopen test process continuity, not host reboot, power loss or backup rollback.

34 unit cases cover actual TLS success/denial, CA/hostname/server-pin checks,
unmapped/no/foreign client certificates, wrong service signer, role crossing,
client/server command checks, bounded/truncated frames and deadlines, same-revision
TLS contention, missing/corrupt storage, changed signing key, invalid private-file
configuration, unavailable service and the four-process rehearsal. The existing
Native offline CI requires all cases with zero skips and validates the sanitized
report's nine checks, source/commit hashes, counts and explicit false proof flags.

```sh
python -m pytest -q -o addopts= tests/test_task4_external_ledger_mtls_v1.py
python -m scripts.task4_external_ledger_mtls_rehearsal_v1 --output results/task4-external-ledger-mtls
```

## Deployment and Native gates remain open

The present loopback API cannot accept remote Runner connections. A later
deployment needs a reviewed persistent key custodian/host, reachable authenticated
endpoint, issuer/Custody credential delivery and isolation, retained backend
adapter, approved enrollment/retirement, rollback assumptions and fault evidence
across actual hosts. Only the authority service would hold the backend write
credential and receipt signer; Native/ordinary-agent processes must receive
neither. Those deployment restrictions are requirements, not demonstrated OS/IAM
isolation in this shared-user rehearsal. No GitHub credential is used here.

Connecting the same strict receipt contract to GitHub storage still needs an
eight-slot state adapter and exact commit/readback-before-signing rules. Native
reservation-before-grant and consumption-before-send must then be integrated
without relaxing existing history/scope/recipient/expiry/budget/Bind checks.
Installing Linux on a Mac alone would not satisfy these gates. Nothing in this
increment provisions a host, paid service, Secret, Environment, Ruleset, tag,
manual workflow dispatch or public Provider permission.

Python TLS references: [client/server certificate validation](https://docs.python.org/3.11/library/ssl.html#ssl.CERT_REQUIRED),
[peer certificates](https://docs.python.org/3.11/library/ssl.html#ssl.SSLSocket.getpeercert),
and [handshake timeout](https://docs.python.org/3.11/library/ssl.html#ssl.SSLSocket.do_handshake).
These document the APIs used; the tests supply the local transport observations.
