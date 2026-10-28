# Well-formed response with another operation ID

The fixed total receive deadline and successful JSON parsing do not establish that
an acknowledgement belongs to the operation being executed. This profile tests
the existing exact response-header check after parsing, without changing that
check, the parser, authority, Native SDK, Bind or single-use consumption.

The actual first Native request is A0. After the original scripted backend commits
one A0 effect and generates its valid response, an explicit fixture send adapter
changes only `X-Request-Id: native-local-A0`:

| Case | Transmitted ID | Original parser | Original dispatch |
| --- | --- | --- | --- |
| `other-step-id` | `native-local-A1` | Returns HTTP 200 and the original body | Refuses ID mismatch |
| `other-arm-id` | `native-local-B0` | Returns HTTP 200 and the original body | Refuses ID mismatch |

Only that single header value changes. The wire length, Content-Length, status,
JSON completion body and body digest remain identical to the original generated
response. Both values are syntactically valid fixture IDs. No A1 or B0 effect is
created to manufacture the test; these are header substitutions, not a claim of
replaying a genuinely generated response from another completed operation.

The frozen PR #559 collector receives the complete wire through EOF within its
single two-second monotonic deadline, with at most 0.7 seconds inactivity wait and
the existing byte/read limits. The original dispatcher closes the connection and
seals/fsyncs the exact received raw bytes before calling the original parser.
The parser succeeds and returns the substituted ID unchanged. The original
`task4_native_bounded_unix_egress_v1.dispatch` then checks it against the expected
`native-local-A0` and raises its original ValueError before `BODY_RELEASED_TO_BIND`.

The new adapter observes the successful parser return and the dispatch exception;
it does not replace that comparison, synthesize the exception, repair the header,
release a body or retry. It restores capture/seal/parser/connection dependencies
in `finally`. The original Bind produces APPLY_FAILED with no verified response
callback returned. That result does not imply no effect: the backend's committed
A0 effect remains exactly one.

## Mandatory disposable root CI

The workflow preserves all previous timeout/slow-drip, malformed-JSON/missing-ID
and eight-step normal controls. Both new cases run separately with actual role
UIDs, trusted read-only source exports and exact external Git pins, live distinct
loopback-only network namespaces, verified Unix TLS, and all eight actor UID IP
egress denials. Only the owned isolated table is removed. No host rules change.

Run only on the disposable workflow runner with unused fixture UIDs and absent
retained fixture anchors, never as an operator VM procedure:

```bash
sudo -n "$(command -v python)" -m scripts.task4_native_response_id_binding_v1 \
  --run --fault other-step-id \
  --output results/task4-native-response-id-binding/other-step-id \
  --acknowledge-isolated-response-id-binding-test
```

Each complete report must join:

- The actual original first Native SDK request, signed grant, verified reserve and
  consume receipts, authenticated role peers, original API-model commits/readback
  and one committed backend effect.
- The original generated wire and exact header-only substituted wire, collector
  fragments/waits/deadline, socket closure, original fsynced AEAD archive, fresh
  archive-owner recovery and the successful original parser's exact body digest.
- Five ordered events: CAPTURE, CLOSE, SEALED, PARSER_RETURNED, BINDING_REFUSED.
  The parser returns HTTP 200 with the case's substituted ID. The original
  dispatch then refuses with ValueError; no BODY_RELEASED_TO_BIND occurs.
- Zero Native responses, scorer calls, observation receipts or continuation;
  local and external ledger unknown state, pending issuer and revision two.
- Four actual SIGKILL exits and new ledger/issuer/Custody/backend PIDs. The backend
  reopens the same pinned inode/hash/schema/effect read-only, without POST support.
  Repeated authorization and original-grant replay do not restore dispatch.
  Authenticated read-only reconciliation observes one effect and grants no retry.
- Before/after actor IP denials, exact policy handles, root controls, seven
  rejected wrong backend peer UIDs, and unchanged live parent namespace.

The complete canonical JSON includes all wire, trace, receipt, model, retained
storage, restart and policy evidence. The validator replays the original parser
on both original and received wires, verifies the unchanged body digest and exact
other-operation header, and validates the entire no-retry state across restart.
The 105 portable checks include the unchanged original dispatch exercised with a
correct-ID positive control and both wrong-ID negatives using stubbed transport
prerequisites; those tests do not claim actual Native/UID execution. Mandatory
actual-root CI supplies that evidence and emits 22 joined checks per case only
after full validation, with zero skips.

## Limits

This covers header substitution for the first A0 request with A1/B0 IDs only.
`X-Request-Id` is an application header check, not a cryptographically signed
Provider request/response binding. Arbitrary body substitution, duplicate or
ambiguous headers, actual cross-response replay, streaming, public Provider
behavior and all response schemas are outside this proof. A successful parser
alone provides no execution permission.

No real Provider, remote GitHub, operator files/tokens, service cutover, live
permission, host-trial lease integration, independent storage attestation, VM
reboot, power-loss or production containment is claimed. The operator's existing
expired approvals remain outside the fixture.
REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN remain unchanged.
