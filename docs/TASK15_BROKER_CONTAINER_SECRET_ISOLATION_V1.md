# TASK15_BROKER_CONTAINER_SECRET_ISOLATION_V1 — PR #281

**DRAFT / NOT PROVEN. Real Provider requests, paid usage and native bank effects are prohibited.**

## Central invariant

The trusted-side Task15 mock-only broker runs inside its OWN non-root,
networkless, read-only-root Docker container. Only this broker can mount
the private host-owned directory with its SYNTHETIC credential and SQLite.
The separately containerized worker sees only a signed TEST grant and an
AF_UNIX socket.

Predecessor #280 merged-main SHA:
02e462ba28823a2df5cad05b4320326dcb5b88ee.

## Runtime separation

| Property | Broker | Worker |
|---|---|---|
| Network namespace | none | none |
| Root | read-only | read-only |
| Linux capabilities | all dropped | all dropped |
| no-new-privileges | yes | yes |
| Nonroot identity | host runner UID/GID | 65534:65534 |
| IPC mount | shared socket, rw | shared socket, ro |
| Private credential/SQLite | writable private mount | absent |
| Provider credential | none | none |

Broker source and pinned cryptography/cffi/pycparser dependencies are
installed into a dedicated image built from the immutable Python 3.11.16
slim base SHA-256 recorded in the contract. Only the CI image BUILD may
download packages from PyPI; both RUNTIME containers have no network.
Produced broker image ID and source SHA-256 are archived.

## Test and evidence requirements

- 17 host inspection cases detect privileged Docker configurations,
  capability additions, wrong UID, dangerous mounts, host networking,
  rootfs writes, injected Provider keys and image drift.
- 12 runtime assertions cover two genuinely separate containers,
  broker-only private secret visibility, runtime egress denial,
  worker mount isolation, one signed mock admission, SQLite-first
  durable one-time consumption, replay/target/host-peer refusal,
  and zero Provider usage.
- Preserve four ordered Unix peer-credential decisions and one raw
  SQLite archive with integrity and response SHA-256 verification.
- Preserve test-only signed Ed25519 grant, public test root,
  both raw Docker inspect files and broker image ID.
- Verify exact PR HEAD and downloaded artifact ZIP before manual merge.

Run with GitHub Actions Linux, Docker, Python 3.11 and cryptography:

    python scripts/task15_broker_container_secret_isolation_audit_v1.py --output-dir results

## Explicit boundaries and nonclaims

The host runner, Docker daemon and Linux kernel remain trusted. A
privileged host administrator or same-runner Docker controller can
access private mounts. SO_PEERCRED authenticates Linux UID/GID, not the
unique identity of a specific container; another same-UID process with
socket access and a valid grant remains a concern. This is TEST-only
signing and synthetic credentials, not real operator trust-root
enrollment, Provider secret custody, credential issuance or egress IAM.
Pinning package versions does not independently establish upstream
supply chain provenance.

The request contains the frozen source SHA, not the full native
AgentDojo model payload. No actual OpenAI API call, bank effect, or
billable action is enabled. CI SUCCESS alone is not independent PROVEN.

Next proof rounds should separately cover stronger broker peer identity,
operator trust-root enrollment, actual Provider credential custody,
full wire payload binding, and real Provider egress policy.
