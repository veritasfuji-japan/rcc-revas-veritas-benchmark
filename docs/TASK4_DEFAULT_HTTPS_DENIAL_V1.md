# Default HTTPS helpers in a closed local TLS fixture

Extend #507's retained-helper coverage to each unchanged **default** HTTPS
factory. Use the same first/second/third A request fixtures and helper Git blobs
from [the retained-sender proof](TASK4_RETAINED_SENDER_DENIAL_V1.md). Omit the
transport argument entirely. No socket/client/TLS monkeypatch, caller-selected
connection factory, Provider credential or real Provider request is used.

This is a local test of standard Python HTTPS construction and OS/authentication
denial, not attestation of a public Provider identity or deployed production IAM.

## Externally disconnected topology and test certificates

The trusted root supervisor creates a client namespace and TLS sink namespace
joined only to each other by a private veth pair (10.249.94.1/30 and .2/30), plus
an isolated loopback-only namespace. Both veth ends live inside these namespaces;
neither end connects to the host. Verify the link inventory and IPv4/IPv6 routes:
no external gateway/default route. There is no host egress rule or global trust
store modification. Temporary namespace-local settings and files are removed
when the fixture ends.

Root enrolls a namespace-specific hosts file mapping `api.openai.com` only to
10.249.94.2. Each client must independently resolve exactly that IP before
calling a helper. The standard factories retain their original hostname,
port 443, `/v1/chat/completions` path and fixed request bytes. They reach a local
mock, not the real OpenAI service. No external DNS resolution is needed.

Generate a fresh ephemeral local CA and server key/certificate, with SAN exactly
`api.openai.com`, solely for this closed fixture. `SSL_CERT_FILE` in each role's
minimal environment enrolls the local test CA; the system trust store is not
changed. This proves no association with the public hostname's owner. Store
server key and mock credential under Backend UID 61103, and the matching scoped
mock credential under trusted Custody UID 61106. Native UID 61101 cannot read
these private files or the backend/consumption storage. Source and public
enrollment are root-owned/read-only. Roles have no supplementary groups or
capabilities, require NoNewPrivs and fail if Docker control is available.

The sink namespace alone permits unprivileged port binding so its already
unprivileged Backend can listen on local port 443. The client namespace has an
actual checked UID OUTPUT rule: only Custody UID 61106 may reach .2:443. A
reachable Native negative control is placed directly in the sink namespace by
root; Native cannot move itself there.

## Required observations

| Phase | Actual calls | Acceptance |
| --- | --- | --- |
| Isolated Native UID | Three default helpers | Linux ENETUNREACH (101); no server TLS or HTTP observations |
| Firewalled Native UID in connected client namespace | Three default helpers | Linux ECONNREFUSED (111) under checked UID rule; no server TLS or HTTP observations |
| Custody UID with a different untrusted test CA | First default helper | Actual certificate verification failure; server observes a failed TLS handshake, no HTTP or effect |
| Root-placed reachable Native UID with enrolled CA | Three default helpers | Real TLS, then HTTP 403; backend-owned original body hashes, Host/path and TLS version join to each helper |
| Custody UID with enrolled CA and private mock credential | Actual pinned Bind adapter over standard HTTPS | Three denied Bind scenarios apply zero times; allowed synthetic scenario applies once; one durable mock counter effect and consumption |

CPython audit observations require exactly one standard `HTTPSConnection`
connect and one local socket-connect attempt per helper call. Observe the
original hostname/443 and local IP/443, certificate verification required and
hostname checking enabled. The audit hook guards target/source drift but does
not synthesize network errors or responses; OS rules and the real TLS sink
produce the recorded outcomes. No injection of a substitute transport occurs.

The backend owns HTTP/SNI/failed-handshake evidence. It requires a private
HMAC for GET/status and POST, preserves the exact counter body, and deduplicates
its fixed operation with SQLite. All helper Bearer strings are invalid synthetic
placeholders. After the negative phases, require zero effects and no consumption
database. TLS trust never supplies execution authority.

For the same-sink positive control, reuse unchanged
`ci_mock_executor_veritas_bind_v1.integrate`, external VERITAS pin
`a1d66aef02262cf8a913295270c3aafd159c6adb`, and actual Bind core Git blob
`0f64201e2599495ce4e3991348aa320995716ffc`. Only permitted Bind.apply makes the
authenticated TLS POST. Join its receipt and poststate to one backend row and
one Custody consumption, and require every positive connection's peer DER
fingerprint to equal the enrolled local server certificate. This is a synthetic
counter operation; it is not the Native Task4 model/tool trajectory.

Six network denials, three TLS/HTTP denials, one bad-CA control, three denied
Bind scenarios and one positive Bind scenario are distinct observations. The
new suite requires 20 unit cases and 16 matching no-skip integration checks.
Keep all prior Native, retained-sender and kernel regressions in the existing
Actions job. Proof artifacts carry hashes, receipts and sanitized observations,
not request/response bodies, keys, credentials, certificate PEMs or databases.

## Scope and reproduction

One disposable trusted Linux root/kernel/Custody/backend, root-managed source,
namespace, hosts and CA enrollment. No independent administration, arbitrary
hostile Custody/root defense, real Provider TLS/credential deployment, exhaustive
route/B-variant coverage, distributed CAS, real-data confidentiality or genuine
utility claim. The default factories are observed only under this explicitly
enrolled local hostname/CA arrangement. Existing Native SDK proofs remain
separate; Native Task4 over this TLS gateway is not claimed integrated. The
public/reproducible recipient fixture remains synthetic.

Use the exact dependency/pinned VERITAS setup in the existing Native offline
workflow, on a disposable supported Linux root runner only:

```sh
sudo -n "$(command -v python)" -m scripts.task4_default_https_denial_v1 \
  --run --output results/task4-default-https-denial
```

Fresh certificates, keys, namespace/interface names and process IDs vary across
runs. Check exact source pins, route/UID rules, source/fixture hashes, JUnit,
backend body/receipt joins and API/upload/download artifact digests. A local
certificate containing a public hostname is never evidence of that Provider's
identity, real inference or permission to dispatch.

No paid approval reuse, external bank effect, real Provider send, Secrets,
Environment, Ruleset, tag or workflow-administration change is authorized.

REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN
