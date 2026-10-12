# Task4 #368 — MockTransport pre-response one-use admission

The actual pinned OpenAI SDK invokes httpx.MockTransport, whose handler
consumes a local SQLite attempt **before** invoking the scripted mock
response. Four requests per A/B arm are expected, with separate session
IDs, raw wire hashes and pinned tiktoken measurement. Failure in the
handler does not yield a fake response or release the consumed attempt.

Scope is strictly offline MockTransport interception. The local scripted
response can unlock continuation; this is not genuine independent LLM
generation, a network enforcement boundary, a distributed authority,
or evidence of production IAM bypass resistance. No Provider calls,
credentials, live spending authorization or real bank effects.
