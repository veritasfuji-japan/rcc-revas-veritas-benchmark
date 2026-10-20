# Task4 Native SDK to OS-separated Bind Custody and local HTTP

Historical #499 introduction. For the current evidence matrix, updated test
counts, integrated fault/concurrency/restart results and remaining research and
production gates through #505, see the
[Task4 Native proof checkpoint](TASK4_NATIVE_PROOF_CHECKPOINT_V1.md).
The original counts and untested-fault statements below describe #499's scope.

The existing #487 Native proof and #494–#498 kernel mock proof previously ran
as separate experiments. This additive integration sends the actual eight
frozen Native SDK request bodies through a new separate-UID Custody adapter,
real pinned VERITAS Bind, and a networked local scripted response backend.
Historical source pins and the previous proof suites remain unchanged.

## One execution chain

The pinned #325 driver starts independent scripted A/B Native sessions. Its
actual OpenAI SDK serialized bytes must match the unchanged #486 eight-entry
manifest, including output cap 256. UID 61105 generates a fresh Ed25519 key and
signs only those eight request hashes, target and fixed public test recipient.
Root enrolls its public key; Native UID 61101 gets grants and public key only.

Native uses an injected httpx transport with no HTTPTransport fallback, sending
the original bytes over Unix IPC to Custody UID 61106. Custody checks bounded
exact packets, actual SO_PEERCRED, independent signature and frozen wire hash.
It durably consumes the arm/ordinal before any mock network effect. Each request
executes actual pinned Bind twice: authority-denied must BLOCK with zero apply,
then the synthetic permitted case must COMMIT with exactly one apply. Only that
apply makes the authenticated HTTP POST to a private-network backend UID 61103.
The backend independently verifies the grant and transport HMAC and deduplicates
the operation before producing a pinned local #325 scripted response.

Custody encrypts and fsyncs the original response with the unchanged #457 vault
before returning ciphertext. Native decrypts it with #487's deliberately public
test recipient, verifies exact equality with the original scripted reference,
then passes those returned bytes to the real SDK parser. The original local
callable remains a reference oracle; it is not the returned response source.
The unchanged Native trajectory and detached AgentDojo scorer execute for each
selected arm, and #456's response journal seals that same-run lineage.

This is an additional Bind boundary for scripted completion dispatch, alongside
the Native tool's existing Bind boundary. It is not an authorization adapter for
a real Provider or a claim that all existing Native custody protocols were
replaced. The old #483 consume/attach/read service remains in its own regression.

## OS controls and evidence

The Native/issuer network namespace has only loopback; backend has a private
veth and no external route; host OUTPUT permits the mock TCP destination only
for Custody UID. Roles drop supplementary groups and capabilities and require
NoNewPrivs. Services import root-owned read-only git-archive source trees for
this repository and all three verified external package pins, using explicit
paths rather than relying on editable-install hooks for an isolated UID.
Native actually fails to read Custody/backend credentials and databases or the
issuer private key, overwrite the trust key or tracked service source, connect by IPv4/IPv6 or HTTP, and
connect from a child process. A separate root-placed Native-UID probe in the
backend namespace reaches HTTP but receives 403 without transport credentials.
A stranger UID with an authentic request fails the Custody kernel-peer check.

All eight normal replays and eight replays after Custody restart are refused.
Signature, actual-wire and caller-selected destination mutations are refused.
The supervisor stops services and joins each request/response/backend receipt,
Custody row, ciphertext file hash and two actual Bind receipts. It uploads only
sanitized hashes, Bind receipts, checks and JUnit: no raw SDK body, response,
grant, private key, credential or database. The dedicated existing Native Actions
job requires 19 unit tests and 22 OS/integration observations with zero skips.

## Limits

This is one trusted Linux CI VM, scripted completions and an in-memory banking
simulator. Root/kernel/Custody/backend, pinned source and synthetic key enrollment
remain trusted. Custody and backend are not independently administered. The
recipient private key is publicly reproducible: real-data confidentiality is
not proved. Native retains a local scripted reference oracle, not a real model.
Scorer execution is observed but genuine utility stays unscored. No real Provider
endpoint is contacted, no paid approval reused and no external bank effect occurs.
Crash/concurrency proofs #495–#498 remain separate counter-based tests; those
fault combinations are not newly proved for this eight-request adapter. There
is no cross-runner CAS, arbitrary malicious-Custody defense or production-wide
route coverage claim.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`
