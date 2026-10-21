# Provider-shaped SDK wire and first raw HTTP ingress (closed local TLS only)

## Selected #511 gap

Exercise the G1 wire/G4 first-ingress boundary without the signed `/effect`
wrapper, public network, real API key or model inference. This is a separate
boundary prototype. It does not replace the existing Native/Custody/actual Bind
proof or connect this new transport into that full trajectory. Those proofs run
unchanged in the same existing Actions workflow. Live gates remain open.

## Request, key and network contract

Use pinned OpenAI SDK 1.109.1 / httpx 0.28.1 and the original public first-round
Task4 A request parameters already frozen in the retained-sender fixture. The
SDK serializes the request; a no-network preparation transport captures its
exact bytes once. Root enrolls that hash and a fresh local execution label. No
Native bank/tool action or scorer is invoked by this boundary fixture.

The sender's fixed transport admits only POST to the fixed chat/completions URL
with the exact enrolled original SDK body. It sends those bytes, not a control
packet, to `/v1/chat/completions`, with a separately private **synthetic** Bearer
credential, JSON content type and exact run/slot client request ID. The SDK sees
only a public placeholder credential; it receives neither the private Bearer
nor a configurable URL, proxy or transport factory. SDK max_retries=0 and
httpx trust_env=False; one transport invocation is required per call.

Native preparation UID 61101 uses a loopback-only namespace. Sender UID 61106
and TLS backend UID 61103 use a private veth pair, with no host interface or
external/default gateway. Namespace-only UID OUTPUT rules reject non-sender
clients. All three namespace hosts files map `api.openai.com` only to the local
test IP. Every admitted TLS peer must match that IP, enrolled local certificate
fingerprint and hostname with CERT_REQUIRED. The local CA/hosts entry proves no
public Provider identity. No global trust-store, hosts or firewall change.

No live credential loader or paid enable switch exists. CLI run is restricted
to fresh checkout output under trusted disposable Linux root. Child roles use
read-only root-exported tracked source, no capabilities/groups, NoNewPrivs and
a minimal environment. The actual backend receives only the test credential;
no Provider account or billing control is contacted.

## Capture and irreversible attempt ordering

The supervisor creates/enrolls the private ledger once before attempts. Senders
require that retained database in read-write-existing mode; missing storage is
never silently recreated. Each of twelve separately enrolled fault slots consumes a SQLite unique
run/slot record with synchronous FULL before any socket. All records remain
CONSUMED_UNKNOWN, even on success: this prototype grants no further step or
recovery permission. Restarting a sender process and replaying a slot cannot
open a socket. This local twelve-slot fault plan is not a new research grant,
full issuer/deployment policy, distributed CAS or real Provider idempotency.

After sending the request, read decrypted TLS socket bytes directly, without
calling HTTPResponse/getresponse or JSON/SDK parsing. Capture through EOF, a
read error/timeout or the bounded raw-wire limit plus one byte. Encrypt the
exact observed bytes **including raw status/header bytes**, fsync the exclusive
envelope file and its directory, and durably record SEALED_FSYNCED before any
HTTP header/framing or semantic parser begins.

Only then parse the captured in-memory HTTP wire, require full framing, success
status/request ID and model-shaped completion, and return its body to the real
SDK parser. One successful synthetic completion is delivered. No Native/scorer
result or actual model Utility is claimed. EOF alone is not valid HTTP framing;
truncated Content-Length is rejected after sealing.

A size-limit capture is a prefix, timeout/read-error capture is incomplete, and
an empty capture is only an observation of no received bytes. None proves no
remote effect, no billing or a complete response. Never reconstruct missing
bytes. No parser/SDK continuation occurs for a partial capture. A real archive
I/O failure also blocks all parsing; its attempt remains consumed, with no
false claim of a durable response archive.

## Archive recipient and evidence

A separate owner UID 61107 creates a fresh ephemeral X25519 private key in its
0700 directory/0600 file. Root enrolls only its public key before attempts.
Each envelope uses a fresh sender ephemeral X25519 key and nonce, HKDF-SHA256
and AES-GCM, authenticating run/slot/request/recipient/raw hashes, observed size
and capture-completion metadata. The sender cannot read the owner's private
key; Native cannot read either private credential, server key or owner key.

After attempts, root copies ciphertext only into owner-controlled recovery.
The owner decrypts and checks every exact observed-wire hash/size and metadata;
plaintext, private keys, credentials, envelopes, raw requests, response bytes
and SQLite files are not artifacts. This fresh private test recipient differs
from the old public/reproducible fixture key, but proves no live key enrollment,
rotation, owner approval or independence from trusted root. Root/kernel/sender/
backend/owner/source enrollment remain trusted components on one CI VM.

## Required observations

- Isolated Native ENETUNREACH, client-namespace UID-firewall ECONNREFUSED and a
  reachable invalid-credential HTTP403; four private-read refusals per placement.
- Twelve consumed scenarios: success, 403, malformed JSON, malformed HTTP status,
  missing response request ID, truncated body, oversized wire, timeout prefix,
  dropped response, archive write failure, exit after consume, exit after seal.
- Exactly one unauthorized probe POST then eleven authenticated API-shaped POSTs;
  the after-consume crash has no socket. Server-owned request/full-wire/prefix
  hashes join the sender's observed-wire and owner recovery receipts.
- Ten recoverable envelopes. Archive failure uses a root-owned non-writable
  directory and real EACCES. Crash exits 88/89 are actual process exits before
  network and after fsync respectively; neither permits parsing/retry.
- Twelve fresh-process replay refusals, unchanged backend POST and durable event
  digests; exactly one real SDK response release and no automatic retries.
- Every HTTP/JSON parse event follows SEALED_FSYNCED. Durable sender events join
  UID/PID, verified peer, original wire hash, archive receipt and release decision.

The existing every-PR Native workflow adds 33 unit tests and 17 integration
checks/JUnit. Unit tests exercise framing/partial capture, AEAD metadata/key
tampering, durable duplicate refusal, actual pinned SDK serialization/parser and
false-green evidence rejection. Privileged OS/TLS assertions run only in the
dedicated disposable CI fixture; unit test doubles are not OS evidence.
The minimal common CI skips only the SDK-specific test if its optional SDK
dependencies are absent. The dedicated workflow installs the pins and requires
all 33 unit cases and all 17 integration cases with zero skipped cases.

This advances bounded G1/G4 evidence only. Integrating this archive/transport
with Native, actual Bind, reviewed adaptive run-bound authority, full deployment
credential/egress controls, live recipient custody and fresh cost consent remains
separate work under the [restart audit](TASK4_PROVIDER_RESEARCH_RESTART_GAP_AUDIT_V1.md).
No new public Provider request, spend, administrative setting or automatic merge
is authorized.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN**
