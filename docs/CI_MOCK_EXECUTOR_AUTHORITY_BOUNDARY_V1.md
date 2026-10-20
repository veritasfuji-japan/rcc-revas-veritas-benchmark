# One-VM CI mock Executor: kernel credential and egress boundary

The description below records #491's original 23-observation mode. The current
every-PR workflow additionally requires `--with-veritas-bind`, fixed VERITAS
sources and PyYAML 6.0.3, and checks 28 observations. See
[the same-run Bind integration](CI_MOCK_EXECUTOR_VERITAS_BIND_V1.md).

Baseline: merged #490, `06345cad5e60e480cc1dc2127f9a9ba44fac0caf`.
Environment chosen by the owner: existing GitHub Actions. No external server,
new account, paid Provider or independently administered infrastructure is used.

This is a bounded next step for A1/A2 in the #490 separation plan. It builds on
the same kernel primitives demonstrated by #370/#412, adding same-agent-UID
host-side direct probes, private-file read denials, multiple arbitrary client
paths, and restarted Executor replay checks in one reconciled run. Historical
sources and their pins remain frozen. This does not rerun the full old suites.

## Concrete deployment and trust

The trusted supervisor is root on one disposable Ubuntu 24.04 Actions VM. It
creates no permanent user accounts: setpriv drops to otherwise-unallocated
numeric UIDs 61101 (agent), 61102 (Executor), 61103 (backend) and 61104 (stranger),
clears supplementary groups/capabilities and sets no-new-privileges. Each role
checks those kernel properties and cannot open the Docker control socket.
The supervisor and kernel are trusted; hostile root, policy administrators,
executor compromise and GitHub account/workflow compromise are outside scope.

The agent runs in its own network namespace with only loopback. The backend
runs in a second namespace with a veth-connected mock TCP service at
10.249.91.2:18491; the Executor uses the host namespace. Actual namespace IDs
must all differ. A host iptables OUTPUT UID rule rejects access to this exact
mock endpoint unless the process is the Executor UID. This is not a global
host Internet firewall; the agent namespace supplies broader no-route isolation.
Additional agent-UID probes run outside that namespace to test the UID rule.

Agent to Executor uses a filesystem AF_UNIX socket: the directory is
Executor-owned, and the Executor checks actual SO_PEERCRED before grant policy.
All roles read a root-owned read-only copy of this one stdlib-only program.
The agent's child process inherits the same UID/network boundary. Role
environments are rebuilt from a minimal PATH/LANG allowlist. No Provider
hostname or external API endpoint is contacted; the IPv6 negative probe uses
the reserved documentation address 2001:db8::1.

## Synthetic authority and credential custody

The host generates fresh random verifier and backend credential bytes for each
run. Owner-only 0700 directories and 0600 files confine the Executor copy to its
UID and backend copy to its UID. The worker must receive actual PermissionError
when reading those files and the private ledger/backend DB. Presence of a
Docker socket is not itself authority: an actual attempted connection must be
denied or the socket absent. No private credential, verifier or bearer grant
is copied into the artifact.

The public fixture packet binds one exact mock target, units=1, revision=0 and
operation ID under a CI_ONLY HMAC grant. The verifier key is shared by trusted
host and Executor, so this is NOT an independent asymmetric issuer or real
human approval. Executor's backend credential is distinct from that verifier.
Backend requests use a separate HMAC domain and must match the exact mock
operation; a network-allowed Executor-UID client without a credential is denied.
There is no arbitrary URL, caller-supplied connection factory or forwarding API.

The Executor commits a unique SQLite CONSUMED_UNKNOWN row BEFORE dispatch. The
backend atomically admits one operation and counter increment, then returns a
bound receipt. Executor records MOCK_OBSERVED only after receipt verification.
Replay before and after Executor restart must fail; restart refuses a missing
or empty consumed ledger. Ambiguous response/transport remains consumed and
must not be retried. This is one local SQLite ledger, not distributed CAS or
proof of exactly-once real external effects.

## Required observations in one run

The report/JUnit must contain 23 true observations: installed kernel UID rule;
agent loopback-only namespace; three distinct namespace IDs; five private-file
read denials; raw IPv4 and IPv6 denial; http.client, urllib and subprocess
denial; same-agent-UID direct denial in the host namespace; Executor-UID network
access with credential rejection; modified/unsigned/extra-forwarding rejection;
wrong UNIX peer rejection; one authorized effect; same-run replay rejection;
restart replay rejection; and exact backend/ledger receipt reconciliation.

The backend must independently report counter=1, one spent record and exactly
one denied unauthenticated request. No blocked direct probe may produce a
backend mutation. Source hashes, checked-out PR HEAD, namespace metadata,
scoped firewall rule, sanitized probe decisions, receipts and JUnit are saved.
Private directories/keys/raw signed packet are transient and removed after the
services stop. The supervisor removes only its exact temporary firewall rule,
named namespaces/veth and generated temporary directory, including on failures.

## Scope that remains open

- No real Provider, real bank, genuine Native model response, Utility scoring,
  external host, cloud IAM or independent administrator/issuer is integrated.
- The original no-Bind mode does not integrate actual VERITAS Bind. The new
  flagged mode integrates it for this mock operation; #487 Native and #412
  evidence remain separate and must not be combined into a Native Task4 claim.
- The three historical real HTTPS helpers are not invoked here. Arbitrary raw,
  alternate-library and child-process connection probes test the boundary; a
  future exact-helper test needs frozen payloads and an exclusively mock target.
- No audit conclusion asserts all IPv6/DNS/proxy/service paths on an enterprise
  deployment were enumerated. No real credential-service endpoint exists here.
- The fixed numeric UIDs and root supervisor belong to this disposable CI VM;
  they do not establish organizational workload identity or protection from an
  administrator. A compromised Executor can read its own synthetic credentials.

`REAL_PROVIDER_NO_GO`, `UTILITY_UNSCORED` and
`PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN` remain. The dedicated every-PR workflow
has contents:read, no Secrets/Environment, no dispatch trigger and no new paid
authority. CI success and downloaded artifact verification must be reported for
the actual PR HEAD before manual review/merge.

Reproduce on a separately approved disposable Linux machine only:

```sh
python -m pytest -q -o addopts= tests/test_ci_mock_executor_authority_boundary_v1.py
sudo /usr/bin/python3 scripts/ci_mock_executor_authority_boundary_v1.py --run --output results/mock-authority
```

The integration command requires root, iproute2, iptables and setpriv. It fails
if prerequisites or required observations are missing; no optional skip is
treated as a passing integration result. Original no-Bind mode is stdlib only;
the flagged mode requires the fixed VERITAS package and PyYAML.
