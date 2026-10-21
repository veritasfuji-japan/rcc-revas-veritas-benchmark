# Native bounded continuation in closed local TLS

This increment connects a distinct Native profile of the #515 continuation contract to the actual pinned SDK, Native banking simulator, Custody, real pinned Bind core and encrypted first HTTP ingress. It grants no live permission.

## Contract and execution

The historical nine-field / three-request in-memory rehearsal remains unchanged. The new explicit six-field / four-request Native profile fixes the initial trusted task/date/target, model, tool schemas, temperature and output cap (256). It permits at most four requests and 256,000 serialized bytes per arm, with at most 64,000 bytes per request. These are byte limits, not verified Provider token or billing ceilings.

Only `--run --local-https --raw-ingress success --bounded-native` enrolls this profile. The existing frozen eight-request mode, frozen source blobs, README and retained scope remain unchanged. The first Native request is enrolled by its trusted initial message and parameter hashes; future request hashes are computed from actual SDK bytes, never prelisted.

Three Ed25519 keys are generated under distinct unprivileged UIDs: issuer 61105, Custody 61106 and trusted Native runtime 61108. The ordinary probe agent remains UID 61101. Root owns the enrollment, code export, local CA, recipient hash and 300-second window. AF_UNIX `SO_PEERCRED` permits only the trusted runtime at the issuance and execution sockets. The runtime is a trusted observer/executor, not an arbitrary Python-code sandbox: model output is data. A compromise of this trusted runtime can forge tool observations; root/kernel compromise is also outside this proof.

The issuer first validates the exact expected message history and fixed parameters, then durably reserves the request in a private SQLite file before returning a signature over its exact bytes/hash, arm, ordinal, manifest, parent receipt, recipient, endpoint and validity. A pending request cannot receive a second grant. Custody independently verifies the signature and enrolled context against the actual clock, requires contiguous previously observed steps, and durably consumes the arm/ordinal before Bind or any socket.

The actual pinned Bind core executes a BLOCKED counterfactual (zero apply calls), followed by the synthetic local permission case (COMMITTED, one apply). Custody sends the unwrapped SDK JSON to the private local API-shaped TLS endpoint with its private synthetic credential. The existing raw-ingress implementation captures status, headers and body, encrypts to a fresh private owner, and fsyncs file and directory before any HTTP/JSON/SDK parser.

After Bind commits, Custody signs the exact grant/body/archive/Bind join. The pinned Native driver parses the body and executes its actual in-memory read or protected banking action. At the next SDK call, the trusted runtime signs the exact tool result that the Native codec put on the wire. The issuer requires both independent-role signatures, reconstructs the normalized assistant message and matched tool result, and advances only that arm. A terminal response has an authenticated empty tool suffix and closes issuance.

The responder is synthetic: it uses the original scripted actions, changes response/call IDs and assistant text (including an untrusted proposed date), and lets actual Native tool returns determine future requests. Independent starts are exercised for A and B, with two actual detached native scorer invocations. These are diagnostic scripted executions: Utility remains UNSCORED and no genuine independent model inference is claimed.

## Evidence and limits

The existing Actions job runs the new unit tests and a separate closed-network integrated fixture. Evidence joins all eight issuer reservations, Custody consumptions, actual Bind pairs, local API posts, raw archives, owner recoveries and signed history receipts. Fifty issuer IPC refusals cover changed date/tools/parent, pending reissuance, forged/reused observation and terminal reissuance. Ordinary-agent private-key reads and wrong-peer RPCs fail at the OS boundary. Eight immediate and eight post-Custody-restart replays create no new posts or ingress events.

Only sanitized JSON and JUnit are uploaded. Private keys, credentials, plaintext histories, raw bytes, database files and ciphertexts stay in the ephemeral fixture. No public test key is used on this new response path; the legacy inner-public-key proof is exercised separately, not represented as real-data confidentiality.

This fixture does not add cross-job/directory enrollment, issuer restart recovery, distributed CAS, anti-rollback storage, independent administration, public Provider credential provisioning or live network policy. The trusted root can create a fresh fixture and reset state. The manifest is synthetic test enrollment, not independent owner permission. The dedicated local CA/hosts mapping does not attest public OpenAI identity. The actual Native bank tool authority remains the pinned Native RCC/VERITAS policy; a model-request grant is never banking authority. Existing fault modes remain under their original contracts; this increment adds the successful changing-history integration rather than claiming all fault combinations have been exercised.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`
