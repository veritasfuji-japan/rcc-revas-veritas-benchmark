# Task4 actual systemd isolated egress recovery v1

A session-detached process proved #547's guarded timed inverse. It did not prove
that the operator host's service manager could execute that recovery code in the
right namespace. This change joins actual systemd transient timers/services to
the unchanged #547 worker, using a fresh loopback-only namespace for every case.

The public CLI supports `plan` and explicit
`rehearse --acknowledge-isolated-systemd-test`. It has no host nft-apply mode.
`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN` remains unchanged.

## Operator observation preceding implementation

The operator reported a harmless systemd timer probe on the VM. The registration
command had exited before the result appeared; the worker reported UID 0,
parent PID 1, PID 7489 and `NoNewPrivs=1`. The operator also reported stopping
the temporary units and deleting the marker. No firewall or existing service
was changed. This pasted output is operator-reported evidence, not independent
host attestation or proof that nft recovery ran on the VM.

Earlier inventory reported single primary groups for the five target UIDs,
no processes or IP sockets for those UIDs, and only existing service PID 3520
under UID 109, with zero effective/permitted/ambient capabilities, one TCP
socket and `NoNewPrivs=0`. This does not apply a new confinement profile to that
existing service, prove all sockets or audit privileged proxies/inherited FDs.
SDK agent 61101, executor 61102 and stranger 61104 remain unregistered and outside
this five-UID policy; reader 61109, service 109, root and all other UIDs are also
outside its deny scope.

## Protected staging and namespace identity

The new module pins #545's source and #547's exact source SHA256. For a rehearsal,
root copies only those two files and the new module into a fresh root-owned
0700 directory under `/run`, with exclusive 0600 files. Exact staged bytes are
verified against the captured source pins. Configurations, identity records and
results are bounded root-owned single-link files read through no-follow
ancestor traversal. A source hash establishes byte consistency, not independent
origin or full runtime attestation.

The host supervisor requires UID/GID 0, actual systemd PID 1 and the same network
namespace as PID 1. For each scenario it starts an `unshare --net` supervisor
with loopback only. A transient systemd service explicitly uses
`NetworkNamespacePath=/proc/<isolated-supervisor-pid>/ns/net`; a timer schedules
it after one second. The service uses `NoNewPrivileges=yes`, UMask 0077 and no
standard output/error. It independently verifies before any nft operation:

- Its real parent is PID 1 and its effective UID/GID is root.
- Kernel `NoNewPrivs` is 1.
- Its own namespace equals the live isolated supervisor's pinned namespace.
- That namespace differs from the live host guard anchor and PID 1 namespace.
- The guard anchor still shares PID 1's initial namespace and the isolated
  namespace contains only loopback.
- All staged source/configuration bytes match the expected pins and profile.

A missing/changed namespace or unexpected manager identity stops before nft.
The implementation follows systemd's documented
[NetworkNamespacePath](https://www.freedesktop.org/software/systemd/man/258/systemd.exec.html#NetworkNamespacePath=)
and transient [timer options](https://www.freedesktop.org/software/systemd/man/255/systemd-run.html).
No shell command string is used for service registration; fixed argv carries
an explicit Python bootstrap to avoid an older installed `scripts` package.

## Actual recovery behavior

The systemd service invokes #547's worker directly. That worker owns exclusive
creation and its four-second monotonic waiting interval, then performs its
single guarded inverse. There is no controller apply that can arrive after
cleanup, no cancellation/extension protocol and no retry after an inverse
ownership/inspection refusal. The table is #547's dedicated rehearsal table,
with a fresh 128-bit trial nonce and exactly the five reviewed socket-UID rules.
It is distinct from #546's static host-policy candidate.

| Actual kernel scenario | Required result |
| --- | --- |
| Deadline | Remove only the exact owned table |
| Controller killed after registration and installation | PID 1 worker continues; exact owned table removed |
| Replacement with another nonce | No deletion; replacement remains unchanged |
| Extra rule after installation | No deletion; modified table remains unchanged |
| Pre-existing table name | Stop before registering units; existing table unchanged |

Every case preserves an unrelated canary table. Refusal-case cleanup is done
explicitly by the disposable namespace test harness, not counted as successful
automatic recovery. Transient units carry the per-trial nonce in their Description. Cleanup verifies
that exact Description and Transient=yes before stopping each unit; a name alone
is insufficient, and foreign or non-transient units are left untouched. Exact
owned units are stopped and checked inactive;
root-private staged files are removed only after all cases succeed. Failure
retains private staging for diagnosis instead of claiming successful cleanup.
No global nft flush, host table mutation, interface/route change, existing
service restart or account/credential/key modification is performed.

The full public report includes all five outcomes, worker PIDs/parent identities,
source pins, namespace joins, systemd version, canary preservation and cleanup
results. A strict replay validator joins those fields and rejects host-rule or
execution-permission promotion. Comparing host table names before/after is a
limited negative control: it does not attest that every existing rule's contents
were unchanged or establish absence of omitted privileged activity.

## Validation and remaining boundary

The dedicated mandatory root workflow requires all 39 tests with zero skips:
request/nonce validation, namespace rejection before nft, staged-file protections,
unit-collision checks, report joins and one actual five-scenario systemd/kernel
rehearsal. The whole actual report is retained in its JUnit
`systemd_egress_rehearsal_json` property. Tests without the required root
capabilities or actual systemd PID 1 may skip locally; CI rejects such skips.
A separate actual-manager test creates a harmless, deliberately foreign-tagged
transient timer, verifies cleanup refuses it and leaves it active with unchanged
properties, then removes only that harness-owned test fixture. Its proof is
retained as `systemd_foreign_unit_preserved_json`. Existing #545 network, #546
transaction and #547 watchdog gates stay unchanged.

Creating transient systemd units **is** a bounded host-side mutation; the report
marks that explicitly. The firewall operations remain in isolated namespaces.
No claim of operator-host nft enforcement, reader GitHub-only egress, signer
confinement, real Provider access or Native execution permission follows.

Root/CAP_NET_ADMIN can kill the worker, replace namespaces or race table changes.
Inspection/deletion is not an atomic conditional ownership operation. A lost
guard anchor, manager failure, reboot, power loss or killed watchdog remains
outside the cleanup guarantee. This is not a redundant watchdog or persistence
solution. Before any operator-host policy trial, independently review that
bounded trial's protected source, recovery/failure behavior, fresh complete
actor/process/socket/capability inventory and explicit operator action. Do not
reuse the expired Native approval or run enrollment as part of this rehearsal.
