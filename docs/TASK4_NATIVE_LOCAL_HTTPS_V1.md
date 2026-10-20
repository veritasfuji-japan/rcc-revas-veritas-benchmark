# Task4 Native through closed local HTTPS

## Result required

Run the existing eight-request Task4 Native SDK → separate-UID Custody →
actual pinned VERITAS Bind → backend → sealed original response → Native parser
and detached scorer path through verified local TLS, on the same live backend
that rejects the three unchanged historical default HTTPS helpers.

This closes the integration gap between #507's injected-local-transport Native
proof and #508's default HTTPS denial plus synthetic counter positive. The
transport carries the existing signed packet to `/effect`, not the original
Provider API protocol. The inner exact SDK wire and original scripted response
hashes remain joined to the existing Native journal and scorer inputs.

## Isolation and transport

`python -m scripts.task4_native_os_custody_v1 --run --local-https --output
results/task4-native-local-https` requires disposable Linux CI root and a fresh
checkout output directory. The flag is exclusive with faults, concurrency and
the prior retained-sender fixture. Existing modes and assertions continue to run
separately in the same existing Actions workflow.

A root-owned exact read-only marker selects the local fixture in child roles.
Native/issuer use a loopback-only namespace; Custody uses a client namespace;
backend uses the other end of a private veth pair. The pair has no host interface
or external/default gateway. All three namespaces receive an ephemeral hosts
mapping of `api.openai.com` to `10.249.94.2`. Namespace-only OUTPUT rules admit
Custody UID 61106 to port 443 and reject other UIDs. Root records/checks the
IPv4/IPv6 route and link inventory and the installed UID rule. Backend's low-port
sysctl is namespace-specific. No host firewall, global hosts or trust store change.

An ephemeral local CA enrolls a leaf with that exact DNS SAN. Each Custody call
uses standard HTTPSConnection, CERT_REQUIRED and hostname checking. DNS and
connected peer must be the enrolled local IP; every successful call records the
leaf fingerprint and TLS version. TLS does not grant execution authority: the
existing private HMAC credential, exact Ed25519 grant, fixed wire hash, consume
ledger and actual Bind adjudication still apply.

The CA and hosts mapping are **local test infrastructure**, not public Provider
identity, access to the public endpoint, or real Provider credentials. Backend
UID 61103 alone receives its private server key; no key/cert/credential/SQLite
database or raw packet/response is uploaded. Public recipient private material
remains reproducible test material and proves no real-data confidentiality.

## Required negative and positive observations

Before any Native request consumes permission:

- Three original default helpers in the isolated namespace fail with real
  ENETUNREACH; the same three under the client UID firewall fail ECONNREFUSED.
  No TLS/HTTP backend observation is permitted during these phases.
- A reachable Custody-UID helper with the wrong local CA fails certificate
  verification before HTTP. It has no permission-bearing transport credential.
- The three helpers placed by trusted root in the backend namespace establish
  verified TLS and receive HTTP 403. Server-owned original body hashes must
  match each frozen A request and unchanged helper blob. Transport arguments are
  omitted; the existing Python audit hook records factories/context/socket events.
- Durable backend effects and Custody consumption counts must both still be zero.
- The existing Native reachable no-credential probe also receives TLS/HTTP 403.

Then require eight actual Native fixed requests, eight BLOCKED/apply=0 plus
COMMITTED/apply=1 Bind pairs, eight backend effects, eight durable consumptions
and eight original-response AEAD ciphertexts. Join outer packet hashes between
Native ephemeral files, backend-owned POST observations and Custody TLS calls;
join response wrapper hashes between backend and Custody; join inner SDK request
and response hashes to Bind, ledger, ciphertext, Native parser and scorer journal.
Complete both scripted A/B Native terminals and invoke the original detached
scorer twice. Deny eight original replays and eight after Custody restart.

Require the backend POST sequence to be exactly four DENIED (three helpers plus
the Native probe), then eight EFFECT_COMMITTED. TLS event counts must agree with
all recorded Custody calls, the four reachable denials and one bad-CA handshake.
The normal 22-check report is hash-linked to a separate 16-check TLS report with
matching zero-skip JUnit; 29 unit cases reject missing/substituted evidence and
untrusted fixture enrollment. CI validates both reports against the audited source.

## Limits

One trusted CI root/kernel/source-enrollment/Custody/backend, private local CA and
scripted Native responses. It does not test HTTPS fault/restart/concurrency modes;
those remain separately tested over the historical local HTTP fixture. Custody
restart here retains the same backend and test keys. It proves neither independent
administration, exhaustive production routes, distributed CAS, real Provider
dispatch, genuine model inference nor Utility improvement. Scorer execution on
scripted responses does not constitute genuine model scoring.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN**
