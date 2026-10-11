# #307 — Future real-Provider consent/evidence boundary V1 (**DEFAULT DENY**)

**Rule of One:** A future Task4 real model request may be *proposed* but may
never be issued or sent by this PR. Rehearse only the durable single-use
and evidence-recording shape **entirely offline** using the labelled fake
response from the unchanged #304 bounded fixture.

## Baseline and explicit scope

Base: PR #306 merged main
\`cd683bb392cc871d79d145c3ae9cc3194f8af2a9\`.
The exact #303 date issuer/wire, #304 synthetic fixture parser, #305
independent RCC/native VERITAS Bind simulation, and #306 real SDK
\`httpx.MockTransport\` are **unchanged and source blob pinned**.

The third historically approved real-provider two-call run has been
consumed permanently:
\`refs/tags/task4-third-two-real-provider-v1-consumed\` at
\`95ff6be8c5875ed3827a00fe71fb54bd9de48130\`.
CI checks that tag, but #307 neither creates a new protected tag nor
accepts the old consent phrase. The proposed one-call future contract
is a *planning request*, not a spend allowance.

## Two separate boundaries (do not conflate them)

1. **Real execution decision: unconditional DENY.**
   \`future_live_dispatch_decision()\` cannot return ALLOW. This
   module has no OpenAI client, HTTPS transport, credentials reader,
   real Provider sender, Bank adapter, native Bind caller, or manual
   approval issuance path. Changing JSON fields such as
   \`human_approval_for_this_future_round_granted\` to \`true\`
   fails closed. There is no CLI flag for live sending.

2. **Local-only rehearsal:** the gate builds one fresh synthetic
   issuer-owned date context and frozen wire, creates an exclusive
   \`O_CREAT|O_EXCL\` file, fsyncs the initial consumed-event
   **before** validating or handling a fake model response, and
   reuses the existing #304 strict local-only completion and #303
   pre-Bind recheck. Its journal has an event-hash chain, final
   no-effect outcome, and explicit \`server_request_id=null\`.
   Errors/interruptions record \`OFFLINE_UNKNOWN_STOP_NO_RETRY\`
   and **cannot be retried** even with a different local issuer
   instance on the same journal file.

## Why this does not grant Provider evidence or execution

Local file creation is **not** a cross-machine durable permit
consumption record. Rewriting the file can forge the unkeyed hashes;
therefore the chain proves only internal structural consistency in
this one offline test, not adversarial tamper resistance or identity.

An offline \`chat.completion\`-shaped fixture with zero synthetic
usage cannot attest Provider origin, real token charges, external
date truth, or model output quality. \`evidence_promotion_decision()\`
also always DENIES for any purported real Provider evidence.

The cost profile is inherited from the **historical estimate** in
#306 (not verified current pricing): 10,000 hypothetical input
tokens + 256 hypothetical output tokens = $0.0044096 under frozen
old assumptions, local threshold $0.005. It is **not an enforceable
billing limit** and no paid call is made.

## Separate future prerequisites (not provided by #307)

New explicit case/model/request-hash/call-limit/cost-scoped operator
consent; new independent protected consumption token/ledger; real
project billing/egress constraints and fresh rates; production
issuer-owned real-time clock; non-retriable dispatch on uncertainty;
verified Provider-origin request/response/usage receipts; immutable
same-session candidate/prestate to RCC and real VERITAS Bind;
independent scoring after a successful observation.

Each remains **unproven and unauthorized**. These require a new
reviewed PR and explicit human permission before *any* real POST.

## CI evidence and release rule

The dedicated workflow installs only pytest and uses a source-pinned
offline path. A broad negative test suite attempts forged human consent,
lifted cost ceilings, altered wire/date and model parameters, spoofed
response IDs, candidate redirection, expired context, partial and
replayed attempts, and fabricated evidence. It emits JUnit/logs/a
bounded report containing explicit ZERO actual calls and effects.
Generic CI skips these dedicated tests without masking the dedicated
suite's result.

**DRAFT — NOT MERGEABLE BASED ON INTENT ALONE.** Check exact HEAD
dedicated CI, JUnit, JSON, ZIP SHA-256 and every existing CI check.
Even successful merge grants no ability or permission to invoke a
real Provider or bank.
