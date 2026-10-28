# Occurrence-preserving Native response ID guard

The frozen comparison path checks `dict(headers).get('X-Request-Id')`. Converting
a list of header occurrences to a dictionary loses duplicate same-case fields.
The original parser accepts duplicate headers; when the final exact-case value
is the expected A0 ID, the frozen dispatch comparison can pass. A differently
cased conflicting field can also be ignored by that exact-case dictionary lookup.
The portable regression test exercises this original dispatcher with stubbed
transport/authority prerequisites, then demonstrates refusal with the new guard.
It is not an actual Native/UID claim about the old vulnerable path.

## Added check and explicit integration

`task4_native_response_id_guard_v1.require_one_id` preserves the parsed header
list and compares header names case-insensitively. It requires exactly one
`X-Request-Id` occurrence and one bounded ASCII ID token (1–128 characters, letters,
digits, dot, underscore, colon or hyphen, starting with a letter/digit). It never
chooses first/last, trims values, splits a comma list, combines duplicates or
normalizes an ID value. Missing, duplicate, conflicting, comma-separated,
whitespace-containing, non-ASCII and oversized parsed values are refused with
`AmbiguousResponseId`, a ValueError subclass handled by the original Bind core.
Unrelated header occurrences remain unchanged.

A valid single token still must pass the original exact operation-ID comparison.
The guard does not replace signature verification, grant consumption, the exact
operation match, or any authorization decision. It supplies no repair or retry.

The new explicit receive adapters retain the frozen fixed total collector,
original connection closure, AEAD seal and file/directory fsync, and original
HTTP/JSON parser. Only after the original parser returns successfully does the
added guard inspect the full occurrence list. Failure occurs before a response
can be returned to Bind or Native. All temporary transport dependencies are
restored in `finally`.

Frozen previous profiles stay byte-for-byte unchanged as comparison fixtures.
The new guard is applied to the new negative and normal proof paths, not silently
to the old reports, operator VM or a live Provider client.

## Four actual negative cases

The first actual SDK request is A0. An explicit fixture send adapter changes only
its response-ID header section after the original backend commits one A0 effect.
Status, Content-Length, JSON completion body and body digest remain unchanged.
The original parser succeeds in all four cases:

| Case | Parsed ID values, in occurrence order | Guard outcome |
| --- | --- | --- |
| `duplicate-id` | A0, A0 in two same-case headers | Refuse duplicates |
| `conflicting-ids` | A1, A0 in two headers | Refuse conflicting occurrences |
| `mixed-case-ids` | A1 in lowercase header, A0 in normal-case header | Refuse both occurrences |
| `combined-ids` | One value: `native-local-A1, native-local-A0` | Refuse comma list |

All symbolic IDs in the table are the fixture strings `native-local-A0`/`A1`.
The correct value is last in the conflicting cases so a last-value dictionary
check cannot masquerade as successful structural validation. Equal duplicates
are refused as well. Ordering variants and token/shape negatives are portable
checks; these four exact arrangements are the actual-root cases.

Each complete report joins CAPTURE → CLOSE → SEALED → PARSER_RETURNED →
ID_GUARD_REFUSED. Exact received fragments, waits, fixed deadline and full wire
match transmitted bytes and fresh archive-owner recovery. The original parser's
HTTP 200 result and unchanged body digest are preserved, together with the full
ID occurrence list. The new guard raises its real AmbiguousResponseId. The
original dispatcher never reaches BODY_RELEASED_TO_BIND; the original Bind
records BLOCKED then APPLY_FAILED with zero verified response callbacks returned.
There are zero Native responses, scorer calls or continuation. One committed
backend effect remains; rejection does not imply no effect occurred.

All four roles are actually SIGKILLed and restarted with new PIDs. The backend
reopens the same pinned inode/hash/schema/effect read-only without POST support.
The issuer remains pending, the signed ledger stays at revision two/unknown,
repeated authorization and original-grant replay do not restore dispatch, and
read-only reconciliation grants no permission.

## Full guarded normal control

`task4_native_response_id_guard_normal_v1` runs the same added guard on all eight
real changing-history Native POST responses. Each must have one ID occurrence,
pass the original exact operation match, reach durable archive/owner recovery,
continue the original signed archive/tool/parent chain and finish both Native
terminals/scorers. The original sixteen signed model mutations, fifty issuer IPC
negatives, ledger/issuer kill-and-reopen terminal refusals, Custody reopen and
sixteen total replay refusals remain mandatory. Every PARSED event contains the
actual guard result; offline validation replays the guard on the collected bytes
and applies all previous full normal report validators.

## Mandatory disposable CI and scope

The workflow runs 154 portable checks, the guarded eight-step normal proof with
17 joined checks, and four negative proofs with 22 joined checks each, all with
zero skips. Every root proof uses actual separate role UIDs, a fresh live isolated
loopback network namespace, trusted read-only source exports and external pins,
verified Unix TLS and eight actor UID IPv4/IPv6 TCP/UDP denials joined to kernel
counters. Only its isolated owned table is removed; no host rules change.
Previous normal, malformed/missing/wrong-ID and slow-drip controls stay mandatory.

Explicit proof entry points (disposable runner only, never operator VM setup):

```bash
sudo -n "$(command -v python)" -m scripts.task4_native_response_id_guard_normal_v1 \
  --run --output results/task4-native-response-id-guard/normal \
  --acknowledge-isolated-response-id-guard-normal-test
sudo -n "$(command -v python)" -m scripts.task4_native_ambiguous_response_id_v1 \
  --run --fault conflicting-ids \
  --output results/task4-native-response-id-guard/conflicting-ids \
  --acknowledge-isolated-ambiguous-response-id-test
```

This is a closed Native application-ID guard, not a universal HTTP parser, full
HTTP framing validator, cryptographic Provider response binding, or proof for all
headers/body substitutions/streaming. It validates the occurrence/value list
returned by the original parser; it does not claim canonical raw-header syntax
or detection of every transformation that parser performs. The guard's token
policy is the reviewed fixture policy, not a public Provider compatibility claim.
Status reconciliation retains its authenticated read-only transport.

No real Provider, remote GitHub, operator files/tokens, service cutover, live
permission, host-trial integration, independent storage/admin attestation, reboot,
power-loss or production containment is claimed. Expired operator approvals stay
outside the fixture. REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN remain unchanged.
