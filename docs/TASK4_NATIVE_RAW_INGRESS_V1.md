# Native / actual Bind / first raw API HTTP ingress (closed local TLS)

## Change from #512

Connect the #512 socket capture and raw archive into the existing actual Task4
Native driver, separate-UID Custody and pinned VERITAS Bind adapter. This is a
new explicit `--local-https --raw-ingress MODE` fixture; old modes and their
workflow gates remain required. No public Provider or paid mode is added.

The Native SDK produces the unchanged eight signed, capped, frozen request
bodies. Custody verifies the signature and consumes its retained SQLite row
before Bind. The real pinned Bind first blocks with zero apply calls, then
admits one API-shaped POST. `/v1/chat/completions` receives the original SDK
JSON bytes with a private synthetic Bearer and root-enrolled run/slot ID.
The API POST contains no `/effect` packet, signature wrapper or HMAC header.
Separate authenticated GET status calls remain local control-plane evidence.

## Receive and Native continuation

Custody reads decrypted socket bytes before HTTP header/body/JSON parsing.
Reuse #512's bounded capture and AEAD archive, with exclusive file write,
file fsync and directory fsync before parsing. A distinct owner UID generates
the fresh private raw-archive key; root enrolls its public hash before issuing
the synthetic grants and starting Custody. Owner recovery receives ciphertext
only and returns hashes/lengths, never plaintext. Native cannot read this key.

After the raw archive is durable, validate HTTP framing, status, request ID and
completion shape. Return the exact scripted body to Bind, verify its backend
receipt and postcondition, and retain the existing inner AEAD before the Native
SDK parses it. All eight server/client request/response hashes join Bind
receipts, Custody/backend rows, inner ciphertext and Native response journal.
The unchanged Native driver reaches two scripted terminals and invokes both
detached scorers. These are synthetic continuations, not genuine model Utility.

## Twelve required independent scenarios

Success completes all eight original A/B steps, eight effects and eight raw
archives, with eight immediate and eight post-Custody-restart replay denials.
Each other scenario starts a fresh environment and stops the real Native SDK
at its first A0 transport invocation: 403, malformed HTTP/JSON, missing ID,
truncated body, oversize, timeout, dropped response, real archive EACCES,
exit after consumption, and exit after raw archive fsync. No failed scenario
returns a body to the SDK, completes a Native terminal or invokes a scorer.

The local scripted backend records one synthetic effect for each admitted
POST even if its response is invalid or lost. That observation must not reset
consumption or authorize retransmission. Non-crash faults are replayed twice
before restart and twice after; exit 88/89 faults replay twice after restart.
POST/event digests must remain unchanged. Backend restart, two-Custody races
and durable issuer restart are covered by their existing separate fixtures,
not claimed in this new combined transport fixture.

## Boundaries that remain open

- The raw key is a fresh private CI key, not live recipient provisioning.
  Its enrollment is root-controlled and **not in the old signed grant**.
  The existing inner Native AEAD still uses the public reproducible fixture
  recipient named by that grant. No real-data confidentiality claim follows.
- Eight fixed scripted requests, historic trial scope/date and model labels
  remain unchanged. They are not a fresh adaptive research grant or live run.
- The synthetic Bearer is derived from the private test credential only;
  no live key loader, Provider environment, billing or external bank is used.
- Root/kernel, sender, backend, owner and source enrollment remain trusted on
  one disposable CI VM. Local TLS CA/hosts prove no public Provider identity,
  independent administration, distributed CAS or production bypass resistance.
- Empty/partial/timeout/oversize archives are observations only. A failed
  archive is not reported as durable; all such attempts remain consumed.

Existing GitHub Actions runs all twelve root fixtures and independently checks
the evidence digests, source hashes, zero Provider/real-bank counts and JUnit.
Keys, Bearers, raw request/response bytes, ciphertext and databases are ephemeral
and excluded from artifacts. Only sanitized evidence and test reports remain.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN**
