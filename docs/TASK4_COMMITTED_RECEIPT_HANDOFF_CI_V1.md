# PR #311 — Committed Consumption Receipt & Fail-Closed Handoff V1

## What this PR actually proves

The #310 test used independent PostgreSQL sessions to consume one synthetic
Task4 grant. #311 attaches an *offline-only receipt* to that mutation **in
the same SQL transaction**.

A separate \`task4_311_fixture_handoff\` database role can invoke a
\`SECURITY DEFINER\` function that checks a committed receipt, the exact
winning attempt, issuer-owned date context and frozen wire SHA, model,
Task4 case, and cost estimate against the consumed grant.

**The handoff cannot observe a successful uncommitted transaction.**
If the caller rolls back, both consumption and receipt disappear. A
function returning \`true\` inside an outer transaction is not proof of
commit. If a client loses the commit ACK, the later independently
queried receipt can reconcile its **test-only** DB state without a
second consume.

## Technical differences from #310

The CI initializes unchanged PR #310 SQL and then creates the #311
receipt schema, two new fixture-only DB login roles, and tightly
granted consume/verify functions.

In this isolated test DB, EXECUTE is explicitly revoked from the
old #310 \`consume_offline_fixture_once\` entrypoint, preventing the
previous fixture consumer from consuming a grant *without the new receipt*.
This does **not** change #310's source or prove that a privileged
admin cannot bypass the schema.

The test matrix includes twelve parallel attempts (one winner),
separate verification connections, uncommitted invisibility,
rollback, lost ACK without reuse, wrong case/context/wire/model/cost,
forged attempt IDs, expired fixture grants, privilege denial,
and a demonstration that a privileged database owner can still
bypass unprivileged controls.

## What green CI must NOT imply

1. This is a **CI PostgreSQL service** with intentionally public
   fixture passwords, not a managed protected issuer or durable
   production authorization store.
2. Receipt SHA-256 is **unkeyed**, recomputed inside a database whose
   administrator is trusted in the test. It is NOT a signed,
   independently attestable external evidence record.
3. An observed committed fixture receipt only means the synthetic
   DB transaction succeeded. It **never** grants Provider
   permission or establishes execution eligibility.
4. There is **no Provider SDK**, no remote POST, no bank tool,
   no new human approval, no real account billing control, and
   no actual native VERITAS Bind effect or Final128 score.
5. A remote Provider timeout after actual POST is a fundamentally
   different ambiguity from a PostgreSQL commit timeout. A
   remotely ambiguous operation must never be retried simply
   because an earlier DB state looked unconsumed.

## Remaining prerequisite work

Before any prospective real Provider call, select and independently
audit a protected issuer and production store, the no-bypass
credential/egress boundary, genuine spent-grant semantics
across runners, fresh model pricing/account spending controls,
remote failure/reconciliation and real response provenance. A
new explicit human approval with the exact proposed call and
financial scope is required. This PR cannot issue such approval.

**Draft only. No live API send, no bank effect, no automatic merge.**
Review exact-HEAD dedicated PostgreSQL CI, JUnit, report JSON, ZIP
SHA-256 and all existing checks before merging.

Base main:
\`5d49b4a7c7e28ec9fd497a1e3f0b2ddaa5f82617\`.
The third real-Provider permission remains consumed at
\`95ff6be8c5875ed3827a00fe71fb54bd9de48130\`.
