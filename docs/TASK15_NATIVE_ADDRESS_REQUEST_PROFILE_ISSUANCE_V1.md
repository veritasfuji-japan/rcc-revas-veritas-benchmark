# Task15 native address request profile issuance V1

The bounded street/city projection in #216 does not prove when the request was
captured or who supplied it. This profile binds the trusted harness's acquisition
to a locally issued context before its generation adapter is called. It captures
one immutable native-normalized proposal for both arms, without dispatch authority.

| Bound item | Identity |
| --- | --- |
| Complete original request | OriginalRequestEnvelope digest, including all other goals |
| Address projection | Frozen mapper policy, implementation blob and mapping digest |
| Native definition | AgentDojo commit, user-tool/parser blobs, field titles, normalized shape and scope digest |
| Immediate pre-state | Canonical whole-state SHA-256; exact native user-account fields |
| Case/proposal | Task15 case ID and ordinal zero |
| Captured candidate | Full RCC kind/name/arguments/content/metadata and V1.1 pairing identity |
| Issuance | Domain-separated HMAC, source ID, session ID and owned registry |

## Lifecycle

`capture_from_generator` issues the context first, invokes the independently
owned generation/normalization adapter exactly once and captures its result
without repair. The adapter receives no key, registry or context argument.
Invalid issuance never calls it. Generation exceptions, including cancellation,
close the context's capture slot. The lower-level issuance/capture APIs require
the same trusted harness sequencing; the method name alone cannot establish
that no proposal existed outside this harness before issuance.

Capture first authenticates an exact registered context, then consumes its one
capture attempt before checking caller scope/state and candidate. A rejected
first proposal or authenticated scope/state failure cannot be repaired in the
same slot. Unauthenticated token substitution does not consume an authentic
slot. Reissuance for the same case/ordinal is prohibited; other ordinals are
outside V1. Parallel issuance and capture each have one winner out of 32.

Both arms can read the same captured binding repeatedly. Request, definition,
case, ordinal, state, complete candidate and binding substitution fail closed.
Capture-slot consumption is an in-memory evidence lifecycle; it is not durable
authorization consumption or effect single-use proof.

## Native and authority boundary

The profile accepts only the exact four native-normalized `update_user_info`
arguments, with both names null and the street/city exactly matching the
request-derived projection. It never adds password, region/postal storage,
standing-order, refund/date, Task13 or other-tool permission. Region/postal data
remain in request evidence. The existing full-line validator remains unchanged.

Fixed native identities are not configurable by the candidate. The audit
verifies them against pinned native source, schema titles, parameter model and
the #216 mapper. The profile itself does not load or enforce the actual runtime
native implementation; the future controlled runner must do so at its boundary.
Native normalization remains a trusted caller responsibility and is exercised
with the original native parser in this provider-free audit.

Every verification result has `runtime_admission_activated`,
`full_action_admissible`, `execution_permission` and `native_dispatch_authorized`
false. No Bind, resolver or Final128 path imports this module. Historical
candidates stay blocked; the audit creates fresh scripted request profiles,
never retroactive profiles for the five frozen cases.

## Trust assumptions and proof limits

The harness owns original-request/state acquisition, source ID, key, registry,
case/ordinal selection and generation adapter outside model/tool reach. HMAC
proves local issuance only. It does not authenticate a real user, establish
external-state truth, prevent arbitrary compromise of the same Python process
or implement a remote issuer/trust root. A canonical supplied-state comparison
is not a physical-world freshness guarantee.

No clock, expiry, revocation, execution consumption, external effect or native
governance chain is proved here. Program order is exercised with scripted
callbacks, not a real provider. Safe-to-relax-now and historical recovery remain
zero; no Utility or injection result is remeasured. Development evidence is not
held-out or independent external validation and does not prove production readiness.

## Next Rule-of-One

`TASK15_NATIVE_ADDRESS_PROFILE_CONTROLLED_RUNNER_V1`: connect this pre-issued
profile to the exact native normalized candidate, unchanged RCC/Bind chain and
actual controlled sink. Verify the profile and current pre-state at final
dispatch, preserve existing constraints outside the explicitly proved address
projection, and prove same-candidate/same-state native effects for both arms.
Do not infer full Task15 recovery or authorize standing-order/refund effects.
