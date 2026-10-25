# Bounded initial-host UID egress trial v1

This is a new, explicit operator-host mutation mechanism, separate from the
frozen isolated-only v1 tools and the earlier static review candidate. It creates
one nonce-tagged `inet veritas_native_host_trial_v1` table and attempts one guarded
inverse. It does not enroll a run, start Native execution, load credentials or
keys, contact a Provider, or change the existing service configuration.

Status: implementation under review. CI evidence must pass before an operator
trial is proposed. No operator-host trial is claimed by this document.

## Bounded behavior

The fixed targets are backend 61103, issuer 61105, custody 61106, archive 61107,
and runtime 61108. All IPv4/IPv6 output for sockets owned by those UIDs is rejected,
including loopback and DNS. The default chain policy is accept. Root, existing
service UID 109, reader UID 61109 and every other UID are not matched. This is not
an allowlist for reader GitHub egress, a DNS policy, or coverage of SDK/executor
UIDs 61101/61102, inherited other-UID sockets, AF_UNIX proxies or other namespaces.

The operator must supply a freshly checked service PID and loopback port. Before
any policy mutation, the tool requires root, systemd PID 1, the same initial
network namespace, correctly named five role accounts with only their own group,
no existing target UID in any process/thread credential vector, and no target IP
socket in tcp/tcp6/udp/udp6/raw/raw6. Proc races or inaccessible records stop the
trial. The service control pins UID 109, zero effective/permitted/ambient caps,
process start ticks and its owned IPv4 loopback listening socket, then opens a
root TCP connection. It is repeated before/during/after and must retain the same
identity. This is TCP availability, not mTLS/signed application verification or
an SSH-session health test. Synthetic loopback banner probes independently cover
all four TCP/UDP IPv4/IPv6 flows for each of the five target UIDs and three control
UIDs before, during and after the lease. A denial requires a matching UID rule's
kernel packet counter increase, never errno alone.

`prepare` stages four exact source files in a fresh root-only `/run` directory,
with root-owned non-writable deployment ancestors required before copying. The
request fixes boot ID, initial namespace, a random nonce, source digests, service
identity, idle inventory and the full foreign-policy fingerprint. The monotonic
deadline is fixed at request creation plus 15 seconds. A delayed worker cannot
start a fresh lease. No duration, arbitrary rule, namespace or target UID option
is accepted by the public CLI.

`systemd-run --collect --no-block` creates a root oneshot service with NoNewPrivileges,
UMask 0077 and explicit `/proc/1/ns/net`. There is no controller-owned apply step:
the PID-1 child worker rechecks the request, sources, idle targets, service,
foreign policy, namespace and deadline, obtains a nonblocking root-only flock,
checks the batch, then exclusively creates the table. A collision is not repaired
or adopted. The worker alone owns creation and the timed inverse. The controller
cannot cancel, extend, or stop it. No RuntimeMaxSec kills it at the lease boundary.
A 45-second oneshot startup timeout is an outer hang bound, not a second rollback
service or recovery guarantee.

At the monotonic deadline (or following an uncertain create/inspection failure),
the worker makes exactly one inverse attempt. It checks the exact nonce, table,
chain, five rules and all object handles twice, allowing only live counter growth,
then deletes only that table. An altered nonce/rule/handle or an inspection failure
stops deletion. There is no flush, replacement, mutation retry, manual delete
fallback, timer cancellation or service restart. The `/run` flock inode remains
as an empty root-0600 serialization file. Audit stages, request, identity and
results remain root-0600/root-0700 for operator review; they contain no secrets.

All other nft policy objects and handles are fingerprinted before/after, excluding
only metainfo and live packet/byte counter values. Dynamic policy changes can
therefore cause a conservative failure. This is policy-content preservation,
stronger than the historical table-name-only control. It is not protection
against a privileged mutation between inspection and deletion.

## Failure and recovery boundary

A healthy systemd manager and worker are required. Controller SIGKILL is tested;
worker/manager death, reboot, root/net-admin interference, hostile local root,
PID/netns lifetime attacks and hard-real-time scheduling guarantees are not
covered. nft subprocesses have two-second timeouts; an uncertain timeout can
follow a commit. The worker inspects once for guarded cleanup. Its 15-second
lease is a scheduling bound, not a promise that every failure removes the table
at an exact wall-clock instant. If ownership is uncertain the table can remain.

The CLI prints its audit directory before registration. If it returns STOP,
retain that directory and inspect the worker result and current policy through a
separately reviewed recovery procedure. Do not retry, delete a table by name, or
stop a possibly active worker. A console/recovery path and fresh operator review
are required before the first VM trial. This PR does not authorize that trial by
itself and contains no unattended deployment command.

## Commands and evidence

`plan` is a non-mutating declaration. `preflight --service-pid PID --service-port
PORT` reads process/socket/policy state and performs a loopback TCP connection;
it does not load a token, change nft, or create systemd units. Only `trial` with
`--acknowledge-bounded-host-firewall-trial` can mutate, after all preconditions.
Normal success retains a canonical `report.json` next to the request and worker
records. `validate_report` joins the worker's PID-1/NoNewPrivileges/namespace/
boot/source/deadline proof, exact removed outcome, before/during/after controls,
32/20/12/32 probe coverage and all NO-GO limitations.

The dedicated disposable Ubuntu CI job explicitly creates only the five idle
role accounts, runs real kernel nft changes in the runner's initial network
namespace under actual systemd, and requires zero skips. It checks a full normal
trial and kills a separate controller after installation; the surviving worker
must remove its table and preserve an unrelated canary policy. The original
operator VM evidence and all isolated-tool source pins remain unchanged. CI
success does not constitute an operator VM observation or public-network test.

Primary semantics: [systemd-run](https://www.freedesktop.org/software/systemd/man/255/systemd-run.html),
[NetworkNamespacePath and NoNewPrivileges](https://www.freedesktop.org/software/systemd/man/258/systemd.exec.html).
These properties supply the initial namespace and privilege-acquisition policy;
NoNewPrivileges does not remove the root worker's existing net-admin authority.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN**
