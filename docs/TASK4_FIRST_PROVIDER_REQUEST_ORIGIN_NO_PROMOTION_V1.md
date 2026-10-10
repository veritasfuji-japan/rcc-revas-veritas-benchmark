# TASK4_FIRST_PROVIDER_REQUEST_ORIGIN_NO_PROMOTION_V1 — PR #291

**DO NOT EXECUTE LIVE PROVIDER.**

Merged predecessor #290: \`5e194563645cda3a122021ed640676662408bf2d\`.

#290 established two separately owned TEST clients for one canonical-identified
Task4 native DirectAttack case, recording five fake model-wire requests each.
The first protected send_money proposal in both source histories came from a
**deterministic scripted** client. The third request included real native
injected tool data, but preceding *assistant model outputs were fake*.

## The remaining issue

Starting a genuine Provider evaluation using the third request from #290
would falsely make two scripted model-generated tool calls look like genuine
earlier Provider responses. It would not establish independent A/B
generation. The correct new source is the **very first model query**
for each arm: developer metadata with test-owned execution date, unchanged
original Task4 user request and native tool declarations, with no fabricated
assistant or tool return.

Both first queries may be **identical byte-for-byte**. Independent model
source identity must be established independently of the wire-request hash,
with separately captured Provider request/response event IDs, durable
request ownership, actual model returns and arm-specific execution. At this
stage only separate synthetic source identities and two first-query manifests
are archived; real sampling authenticity is NOT demonstrated.

## One invariant

This offline gate reads complete TEST-only Task4 #290 source evidence,
revalidates its native lineage, and exports **nonexecuting first-query**
manifests for A and B. It forbids:
- promoting the fake postread/third request to a real-model source;
- calling the historical V13 5 USD ceiling or another untrusted label
  a fresh spend approval;
- supplying an OpenAI client, credential, approval or Provider response;
- spoofing model version, user request, dated metadata or native tools;
- allowing a scorer or fake Provider success label to issue execution
  rights or count as a new Utility gain.

18 adversarial tests require this invariant and archive original synthetic
source histories, two candidate first-query hashes, JUnit and a separate
handoff proof JSON. All real Provider calls and costs are 0.

## Scope / next

This is a **readiness blocker** that prevents a false inference from prior
synthetic work. It does not implement any HTTPS client, real external human
consent, new actual A/B sample, real model availability validation,
production model credentials, canonical Final128 scorer or new attack
evaluation. The previous V13 Utility 64/128 is unchanged.

The next step requiring meaningful user approval is an actual **small,
single canonical case** real model run starting separately at each arm's
first request, then continue with true model-generated read-only tool
calls, native tool returns, frozen request, RCC/Bind, full score and
durable response/usage audit. Fresh explicit consent and a new budget
cap are mandatory; neither old V13 permission nor a synthetic grant may
be reused.

CI green != independent PROVEN; manual merge only after exact HEAD all
checks and downloaded artifact verified.
