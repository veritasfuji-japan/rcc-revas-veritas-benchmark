# Invalid complete responses within the fixed Native receive deadline

PR #560 proves that eight normal Native responses can pass the new fixed total
receive deadline and complete the original bounded Native sequence. This profile
adds two negative controls: EOF within the same deadline is necessary but does
not make an invalid response acceptable.

The exact two cases are:

| Case | Injected outbound wire | Original parser failure |
| --- | --- | --- |
| `malformed-json` | HTTP 200 with a correct Content-Length and request ID, but the body is `{bad json` | `JSONDecodeError` |
| `missing-id` | Original valid completion body with correct Content-Length, but no `X-Request-Id` header | `ValueError` |

An explicit fixture-only send-boundary adapter transforms the original generated
response after the original scripted backend has durably committed its one A0
effect. It uses the existing response generator to construct the invalid full
wire and sends it once over the existing authenticated Unix TLS connection. The
original handler closes normally. This is neither a partial response nor a
network timeout. The backend retains its original request/response receipt; that
receipt cannot authorize acceptance of the corrupted outbound response.

The explicit receive adapter calls the frozen PR #559 `bounded_capture` collector:
one two-second monotonic deadline, at most 0.7 seconds per inactivity wait, the
existing byte limit and maximum receive-call count. It delegates the original
dispatch. The unchanged parser runs only after the original AEAD seal and both
file and directory fsync have completed. The observer records and re-raises the
exact original exception; it does not translate errors, repair JSON or headers,
return a fabricated body, retry, or issue replacement permission. All temporary
capture/seal/parser/connection dependencies are restored in `finally`.

## Mandatory disposable root proof

The workflow runs both cases, the previous slow-drip cases and the full eight-step
normal positive control. Each new case uses its own root-owned read-only source
export, synthetic keys and live isolated loopback network namespace. The parent
namespace remains distinct. All eight application actor UIDs are denied IPv4 and
IPv6 TCP/UDP IP egress with exact ordered nft rules and matching kernel counters.
The supervisor removes only its isolated owned table. No host policy is applied.

Run only on a disposable workflow runner with unused fixture UIDs and no existing
retained fixture anchors, never as an operator VM setup instruction:

```bash
sudo -n "$(command -v python)" -m scripts.task4_native_deadline_invalid_v1 \
  --run --fault malformed-json \
  --output results/task4-native-deadline-invalid/malformed-json \
  --acknowledge-isolated-deadline-invalid-test
```

For each case the complete report must establish:

- The actual first original Native SDK request reached verified reserve and
  consume receipts before the one real synthetic backend effect.
- The complete invalid wire was received through EOF strictly before the fixed
  deadline; all receive fragments, waits, digests and lengths join exactly.
- Capture returned before the real socket/connection closed. The original seal
  returned after durable archive creation and before the original parser refused.
  Fresh archive-owner UID recovery matches exactly the transmitted invalid bytes.
- Original Bind records `BLOCKED` then `APPLY_FAILED`, with zero verified response
  callbacks returned. This does not mean that no backend effect happened.
- No response body reaches Native: zero model responses, scorer calls or
  continuation; no completed Bind result or archive-observation receipt is issued.
- Ledger, issuer, Custody and backend are actually SIGKILLed and reopened with
  new PIDs. The backend reopens the same pinned inode/hash/schema read-only and
  supports no POST. The original effect remains exactly one, the issuer remains
  pending, and the signed ledger remains at revision two with unknown outcome.
- Repeating the original SDK authorization and replaying the original grant do
  not restore dispatch. Read-only authenticated reconciliation before and after
  restart observes one effect and issues no execution/retry permission.
- Original signed receipts, API-model commit/readback order, authenticated peers,
  grants, nonces, raw wire and retained storage are validated together.

The complete canonical JSON includes the original valid generated wire, the
actual invalid transmitted wire, backend/local rows, archive-owner recovery,
four capture/close/seal/refusal events, original parser exception, signed journals,
model history, PID exits/reopens, IP denials and policy evidence. The offline
validator reconstructs the exact injected wire, parses the original valid wire,
and replays the original refusal on the received invalid bytes. Root JUnit's 21
joined checks are emitted only after all report validation succeeds. The 94
portable checks and both actual-root cases are mandatory with zero skips.

## Limits

Only the first A0 request and these two response defects are covered. This is not
all malformed framing, incorrect-ID substitution, arbitrary completion schemas,
Provider streaming, or real Provider behavior. It does not claim to prevent a
backend effect when the acknowledgement is invalid. Raw EOF classification is
preserved in the archive; the external collection trace supplies deadline timing.
The supervisor's pinned storage record is not independent storage attestation.

No operator files, tokens, service cutover, remote GitHub, real Provider, VM reboot,
power-loss, production containment or live execution permission is involved.
The existing expired operator approvals remain outside this proof.
REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN remain unchanged.
