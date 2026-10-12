# Task4 #369 — SDK provider-shaped transport: offline mock-only boundary

## What is actually exercised
- Pinned OpenAI SDK 1.109.1 serializes real Chat Completions request bytes,
  with httpx 0.28.1 and local tiktoken 0.12.0 o200k_base.
- Two independently enrolled arms (A and B), four distinct SDK-generated
  requests each, are consumed by the #365 SQLite one-use ledger through #366.
- Attempt consumption happens **before** the transport calls its in-memory
  httpx.MockTransport fake responder. Replayed raw bodies, bad endpoint,
  bad Authorization, oversized/malformed JSON, upstream exception and
  negative mock status cannot create an additional fake response.
- Constructing the boundary with a live httpx.HTTPTransport is rejected.
- A direct bypass using a separate HTTPTransport to **127.0.0.1** and a
  raw Python socket.connect is caught by a **test-only Python socket tripwire**.
- The dedicated CI provides no real Provider credentials, no Provider POST,
  no external banking effects, and no genuine model completions.

## Critical limits / nonclaims
The Python socket patch applies only within designated test contexts. It is
not an operating-system network namespace, firewall, IAM policy, durable
shared authority, service mesh, container network policy, or tamper-resistant
deny of an uncooperative process. A separate process may bypass it.
Even a supplied MockTransport handler can be malicious outside this
single-process test arrangement.

No production execution authority, Provider hard token/spend cap, genuine
independent A/B model responses, native Task4 scoring, Final128 outcome,
or bank effect is demonstrated by this PR. Historical spent Provider
approval is not reused; live API operation requires fresh explicit approval
and external infrastructure enforcement.

## Follow-on proof
Use an isolated container/network namespace with external IAM/credentials
and egress deny-by-default, showing both authorized broker-mediated actions
and unauthorized direct processes are refused by independently observable
network/auth boundaries; bind each effect to one-use receipts.
