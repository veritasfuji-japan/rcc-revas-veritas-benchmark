# Native backend commit followed by raw response loss

The new disposable root CI trial uses the first actual bounded Native SDK
request, normal signed-ledger acknowledgements, real VERITAS Bind and the
unchanged Unix TLS transport. A new backend-only send-boundary adapter drops the
raw HTTP response **after** the original backend handler commits its SQLite
effect and records the generated response, immediately before TLS application
bytes would be sent. It leaves the original handler's validation, scripted
response generation, effect write and spent-operation check intact.

The adapter checks the separately visible durable effect and original backend
log before recording one deliberate drop. It forwards zero HTTP response bytes;
TLS handshake bytes are outside that count. Custody still records the actual
bytes it receives: an empty raw response. Those zero bytes are encrypted and
fsynced before HTTP parsing fails. A fresh archive-owner UID decrypts the sealed
record and confirms the exact observed length and digest. The produced response
hash and the observed empty-wire hash remain distinct evidence.

## Required outcome

- The ledger has acknowledged reserve and consume: revision 2 and A0
  `CONSUMED_UNKNOWN`. Both original signed mutation receipts are verified.
- Custody's callback has started and durably recorded one local unknown
  consumption; the backend has exactly one durable effect.
- Real Bind records BLOCKED for its denied arm, then APPLY_FAILED when the
  allowed arm loses the response. The frozen adapter's `apply_calls` counts
  **verified response returns**, so its value 0 is not evidence of zero effects.
  The backend's separate durable row demonstrates that one effect occurred.
- Custody has `intent.json` and `verified-receipts.json`, but no
  `effect-returned.json`. No completed Bind/Native archive attestation, SDK
  response, terminal, scorer or continuation is produced.
- Ledger, issuer and Custody are SIGKILLed and reopened against the same pinned
  files. The backend stays alive as the separate effect witness. The repeated
  SDK request receives no new grant; replay of the original full grant is
  refused by the retained local consumption. No second POST, effect, model
  mutation or raw archive event appears.
- Two authenticated read-only backend status requests observe the same single
  effect/receipt before and after restart. They do not repair state, release a
  response, issue permission or enable retry. The issuer remains PENDING and
  both local/external consumption remain unknown.

## Explicit uncertain-state reopen adapter

The existing bounded Custody `--restart` path expects eight completed requests;
it cannot be reused unchanged for this one-row uncertain state. The new
fixture-only role therefore verifies the original retained enrollment, both
original ledger receipt signatures/nonces/binding/request/grant, absence of a
callback-return marker, SQLite integrity, and exactly one matching A0 unknown
row with all result fields NULL. It then retires only the same UID's stale Unix
socket after the supervisor has killed/waited for that exact prior process.

It invokes the original retained-mode Custody handler, which reopens the pinned
existing DB and retains all original admission, grant and replay checks. There
is no initializer, DB reset, count relaxation in an existing module, replacement
key or alternate-directory fallback. Missing/corrupt/mismatched storage stops.
The new adapter is only available inside the explicit fresh root-owned fixture;
it is not an operator deployment command. Backend restart is not tested.

## Evidence and controls

The full canonical report retains the original SDK packet, public signed grant,
issuer policy snapshots, local consumed row, backend effect/response-loss log,
raw archive events and fresh owner recovery, both role gate journals, model
commit/readback/mTLS events, two original signed ledger view receipts, and
read-only reconciliation results. All request and grant byte digests are joined
without replacing the original SDK serialization with canonicalized JSON.

All application roles share one fresh isolated network namespace with only
loopback. The unchanged eight-UID reject policy remains installed throughout
execution, restart, replay and read-only reconciliation. The report joins 32
baseline successes, 32 counter-verified IPv4/IPv6 TCP/UDP denials before and
after the trial, four root controls, unchanged policy handles except counters,
and 32 successes after disposable table removal. Seven other actor UIDs are
refused by the backend Unix socket before TLS/HTTP. TLS backend UID/CA/hostname/
leaf checks and real ledger mutual TLS are unchanged.

Source pins cover the existing acknowledgement-loss profile, its normal profile
and fifteen selected dependencies. The new code does not change existing
source files. Root-owned tracked-source exports and pinned external code are
used by dropped-capability role processes. Each isolated child must differ from
its live parent; PID/start ticks identify its process lifetime. Parent table-name
comparison is a limited negative control, not full host-policy attestation.

The mandatory Native workflow retains the previous positive normal case and
two ledger acknowledgement-loss cases. The new trial requires 26 portable tests
and 16 joined checks with zero skips and complete report replay.

## Limits

This is one fully dropped local HTTP response at A0 after a scripted backend
effect. Partial-response loss, later-history faults, backend process restart,
real Provider completion loss, remote GitHub and independent administration are
not claimed. The GitHub API backend remains a local retained SQLite model.
All enrollment and keys belong to the closed synthetic CI fixture. Operator VM
files, tokens, service UID 109, expired readiness window and host lease are not
loaded or changed. Read-only observation is not new execution permission.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN** remain in force.
