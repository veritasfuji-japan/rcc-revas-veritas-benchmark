# Operator VM bounded initial-host trial evidence v1

Recording date: 2026-10-26 JST. This freezes the complete operator-pasted result
from the existing Linux VM, using merge commit
`68b7cb258cd9ea69efa7e68cfe3ef7c017372681` (PR #550). This change adds evidence
and read-only replay coverage; it changes no runtime source or host policy.

## Exact record and provenance

`evidence/task4_native_vm_host_trial_v1/report.json` preserves all **19,698 original
canonical bytes**, without an added newline. SHA256:
`e52713763f1c9a9b1573db722bd5078163d7fe0885d32556443f8cc335058fba`.
The four frozen sources, full report validator, gzip CRC/size, canonical encoding
and operator-reported SHA were checked after transfer. Source SHA256 for the
host trial is `5b3fb5f66db043b7c6f348fee15712d9e6df21f088ae5e3e8261cbfd945d3f7e`.

The operator reported a root-only original record at
`/run/veritas-native-host-trial-1jok2f11/report.json`, then an exclusive root-0600
copy at `/etc/veritas-native-ledger/host-trial-68b7cb2.json`, with readback and
parent-directory fsync. These filesystem properties are operator-reported; this
review did not directly access the VM. A locally duplicated Base64 transcription
span was removed before acceptance; only the resulting full gzip CRC, exact
size and original SHA256 match authorized the recovered bytes. No report field
was edited or reconstructed from the summary.

This is transfer-integrity and replay verification, not a signed VM report,
independent operator-origin attestation, full runtime attestation or trusted UTC
clock evidence. The report has monotonic times and a boot ID, without a precise
UTC observation timestamp, kernel release or systemd version. Recording date is
not a claim about an independently verified observation time. The report field
`token` is a random public ownership nonce, not a GitHub/API credential.

## Reported bounded result

| Phase | Records | Required result |
| --- | ---: | --- |
| Before installation | 32 | Five target and three control UIDs succeed |
| Installed target policy | 20 | Five UIDs × TCP/UDP × IPv4/IPv6 denied, each joined to kernel counter increase |
| Installed positive controls | 12 | Root, reader 61109 and service 109 numeric UID banner probes succeed |
| After removal | 32 | All eight numeric UIDs succeed again |

Targets: backend 61103, issuer 61105, custody 61106, archive 61107 and runtime
61108. Their pre-installation process/thread credential vectors and IP socket
counts were empty. Probes were synthetic TCP/UDP over IPv4/IPv6 loopback only;
public Internet egress and DNS were not exercised. This is not full Native actor,
AF_UNIX proxy, inherited other-UID socket, SDK/executor or reader GitHub-only
policy coverage.

The PID-1 child worker was PID **12182**, root with NoNewPrivileges, in the same
reported initial namespace `{device: 4, inode: 4026531840}`. Its boot ID, four
source pins, nonce and monotonic deadline join exactly to the request/result.
The deadline was `321193999373563` ns; completed result was `321194057831988` ns,
**58,458,425 ns after the deadline**. This is completion of that run's guarded
inverse and observation, not an exact deletion timestamp, installed duration
measurement, future recovery bound or hard-real-time guarantee.

Outcome: `REMOVED_EXACT_OWNED_TABLE`. The dedicated host trial table was removed,
the worker exited, and the unrelated-policy fingerprint was reported unchanged:
`1e47755e172a6a44762e36599be900147c8c7300a070f6da91047c8ac0e9a3b7`.
The pinned implementation fingerprints full other-table policy/handles, ignoring
metainfo and live counters; the report retains the digest and comparison outcome,
not complete raw before/after nft rulesets. This evidence does not claim an
independent forensic attestation of those rulesets. No continuous host policy
was left installed by this successful trial.

The existing UID-109 service retained PID **3520**, start ticks **4735517**,
loopback port **53751**, and listening socket inode **28517** through three root
TCP connection controls. These controls verify process/socket identity and TCP
availability. They do not verify application mTLS, a signed ledger receipt,
service external reachability, token permissions or the operator SSH session.

## Keep VM and CI coverage distinct

This VM record contains **one normal bounded trial**. It does not claim that a
controller was killed, a foreign marker/rule was injected, or all root CI tests
ran on the operator VM. PR #550 separately verified 30 disposable root CI tests
with zero skips, including controller SIGKILL in a distinct initial-host trial:
[run 40155668154](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/40155668154),
job `121056427150`, artifact `12584248652`, ZIP SHA256
`d7c7cae91b811985ea2e142c8f7719e8a88d57e897d7bfe4b128fe0ede1f7592`.
Its CI proof must not be relabeled as an operator VM observation.

The eight new portable replay tests verify immutable bytes, four-source closure,
all phase/counter joins, worker identity/deadline, service/socket continuity,
removal/foreign-policy outcome, provenance/coverage boundaries, and NO-GO scope.
The dedicated host-trial workflow runs them without mutation before its unchanged
30-test disposable root suite, rejecting any failure/error/skip in either group.

## Unchanged limits

Real Provider requests: **0**. Native execution and execution permission: **false**.
Worker/manager death, reboot recovery, privileged concurrent replacement,
production bypass resistance, continuous policy enforcement and external
independent demonstration remain unproven. Authority keys and API credentials
were not inputs to this trial. This record does not extend any expired Native
approval, enroll a run, score Utility, or authorize additional mutations.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN**
