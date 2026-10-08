# Task15 frozen OpenAI wire controlled standing-order adapter V1

The single invariant is preservation across the injected wire seam: the owned
full request, actual native tool schemas, one first rent proposal, identical
candidate/prestate and each arm's actual native result/error/history remain
linked through the frozen OpenAI request helper and native AgentDojo codec.
Wire hashes and messages never confer execution authority.

`Task15ControlledStandingOrderWireAdapter` owns an injected client element and
the unchanged #225 trajectory. Its local attempt is reserved before validation
or generation. Competing attempts fail without closing the winner's active
wire. Every exit of the owned attempt seals the wire, including raw native
preparation failure after successful response decoding. The #225 trajectory
retains its unchanged profile-before-query, common readonly RCC prefix,
captured-candidate fork, #224 native Bind/final sink and failure closure.

The element uses the unchanged `create_completion_once` and actual native
`_message_to_openai`, `_function_to_openai` and
`_openai_to_assistant_message`. Request configuration remains
`gpt-4.1-mini-2025-04-14`, temperature 0, tool_choice auto, one attempt per query.
The proof uses only an injected recording fake. No OpenAI SDK client is
constructed, credential accessed or real provider/network call authorized.

Before each common query, the previous decoded history and exactly one native
tool result must match the original call ID/proposal. Prefix results must be
successful readonly calls. Continuations require the captured rent history;
A/B each add their own actual value/error. A refused B result is serialized
by the unchanged native codec as its error text. Every other wire field stays
exact. Parsed argument objects, rather than JSON key order, are used only
when comparing argument strings re-encoded after artifact JSON sorting.

Owned system/user messages, client identity, phases/ordinals, native schema
identity and transport payload immutability are checked. Strict JSON decoding
rejects duplicate keys at every depth, NaN/infinity/overflow and nonobjects.
Unknown functions, IDs, extra choices, multiple tool calls, refusal/role
responses, absent protected proposals and any nonterminal continuation close
the attempt. The unchanged native runner then validates raw argument shape
and scalars before normalization; no arguments are repaired or invented for
a utility condition.

The fresh fixture uses the same bounded request/state/case scope as #225 with
a new local key/registry and wire-specific call IDs. It does not reissue a
historical context. Two common native reads expose the existing scheduled
ledger and attacker instructions. One rent proposal forks through unchanged
A/B native execution, then five recording-fake requests in total finish two
terminal continuations. The positive pair executes once per arm; eight
ineligible pairs keep the unrepaired shared candidate and B dispatches zero.

The audit reproduces all 696 previous dedicated tests and recomputes native
RCC read histories, full native transitions, native Bind receipts and legacy
predicates via the pinned #225 audit. It independently reconstructs request
histories/tool schemas with the actual codec and verifies each transport and
decoded-response hash. Fifteen exception/cancellation observations cover all
five query phases; completed cloned native effects are recomputed and retained
without rollback, retry or no-effect reclassification. Thirty-two parallel
attempts produce one five-request population and one dispatch per arm.

The owned acquisition, local key/registry, injected query/transport adapter,
module configuration, native benchmark authority and private sink hooks remain
trusted Python harness assumptions. A detached generation view is not a Python
sandbox. This proves neither real provider behavior nor real user/external
ledger authenticity, durable global ownership, expiry/revocation or general
infrastructure bypass resistance. Direct standalone use of the low-level
element does not establish native execution or actual-result authenticity.

Earlier address execution, refund authority and full Task15/Final128 execution
remain unproven. Existing issuer/runner/trajectory/resolver/validator/policy and
Final128 CLI files remain unchanged. Provider/client/database/scorer-derived
authority/repair/external effect/V13 reuse and historical recovery remain zero.
Utility/injection are not remeasured; held-out/external validation and production
readiness are not claimed. Signatures/local context IDs/decision timestamps are
outside deterministic byte-identity claims.

Next Rule-of-One after human manual merge:
`TASK15_STANDING_ORDER_NATIVE_SCORER_OBSERVATION_BOUNDARY_V1`.
