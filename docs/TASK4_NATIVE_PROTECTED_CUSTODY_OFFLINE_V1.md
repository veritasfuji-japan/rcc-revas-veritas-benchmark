# Original Native SDK to protected custody — selected offline path

Base: merged #483, `f2f1d8915f700e6904cf87a753241393626a4695`.
Disposition: **SCRIPTED_NATIVE_ONLY / REAL_PROVIDER_NO_GO / UTILITY_UNSCORED**.

## What changes

The new entrypoint is `scripts.task4_native_protected_custody_v1`. It uses the
original capped SDK driver (#325), request admission (#470), pre-parser encrypted
transport class (#471), vault (#457), raw response journal (#456), and pure
provenance comparison (#459). It does **not** call #471's original orchestration
function, whose legacy lifecycle was identified in #482. Its explicit orchestration
is adapted from that frozen source and starts #483 custody instead.

`ProtectedAdapter` translates the existing **in-memory** consume/attach/read
interface into exact signed #483 packets. It does not expose an unsigned socket
or forward to #458. Each consume binds the original capped SDK request hash;
attachment binds that consumed receipt, recipient and exact envelope hash;
readback verifies the returned ciphertext hash. Compatibility decision strings
are local responses to existing callers, never Provider execution grants.

The parent owns an ephemeral **synthetic** signer and recipient key. The custody
process receives only the signer public key and recipient digest. This entrypoint
does not include #475/#481's separate signer process or #472's additional worker;
those earlier fixtures remain unchanged. The relevant independent component here
is the local custody process, not independent operational IAM or issuer authority.

## Required dedicated-CI observations

| Observation | Required result |
|---|---|
| Original capped SDK requests | A/B four each, eight total; cap 256 on actual wire |
| Protected consume and attach | Eight each; signatures verified inside #483 |
| Local scripted Native terminals / scorers | Two / two; genuine Utility remains UNSCORED |
| Broker lifecycle | Initial process and a restarted process, each distinct from parent |
| Restart read / replay refusal | Eight exact ciphertext recoveries / eight denied consumes |
| Parent socket connects | Exactly 32, all to the registered protected socket |
| Child socket binds | One protected UNIX bind per process, acknowledged at bootstrap |
| Legacy parent entrypoint attempts | Zero in the selected successful run |
| External Provider / bank effects | Zero |

The dedicated test exercises the complete Native path. A second standalone run
writes hash-only evidence. Reports contain source pins, request/response/ciphertext
hashes and counters; no plaintext, keys, sockets or databases are uploaded.

## What the listener evidence does and does not mean

Parent tripwires cover #458 `action`, `Broker`, `spawn_server`, `main`, `run_demo`
and ordinary `subprocess.Popen`. A Python audit hook rejects parent listeners,
DNS and unapproved socket connections; only the registered protected socket is
allowed. Each **fresh** custody child installs its own audit hook before serving:
one exact AF_UNIX listener is allowed, and ordinary subprocess launches, DNS and
outbound connects are rejected. Multiprocessing's interpreter startup is required
and remains possible. The hook is installed anew in those controlled children;
it is not implicitly inherited by arbitrary descendants.

These are bounded Python-level regression observations, **not OS enforcement**,
not a census of every process/socket on the machine, and not proof against raw
syscalls, native extensions, arbitrary child processes or same-UID malicious code.
The child bootstrap records its bind; it does not provide an independent signed
end-of-life process attestation. Historical entrypoints (including #481's original
Native path and #458 CLI) remain executable outside this selected runner.

## Failure semantics and limitations

Missing/wrong receipts fail before re-signing. A tampered envelope is checked by
#483 against the consumed request and pinned recipient. Read corruption is checked
both by #483 and the adapter. Unknown responses fail closed; missing storage is
not initialized during restart. Because #483 returns generic DENY, replay evidence
combines the observed refusal with the existing consumed DB row in this local
harness; it does not identify the server's internal denial reason. The parent can
read that DB, emphasizing that same-UID storage is not independently protected.

Broker verification does not validate the AES-GCM tag without a recipient key.
Recipient recovery compares decrypted response SHA with the original scripted
response from the same run. This neither authenticates a real model response nor
measures genuine Utility. Both arms use the frozen local scripted sources.

Existing source files and pins remain unchanged. The new runner checks original
#471 dependency pins plus explicit hashes for #471 and #483 code. Its fixture
signatures have no operational expiry/revocation service. Network/IAM/credential
isolation, cross-Runner CAS, immutable storage, real Provider provenance and
production-wide non-bypassability remain **NOT PROVEN**. #321/#427 stay unresolved.

## Validation

Local unit tests exercise real signatures and SQLite through a mocked transport;
they are not process/socket evidence. The full Native test is gated by
`TASK4_NATIVE_CUSTODY_PROOF=1` and runs in dedicated GitHub CI with frozen public
AgentDojo/RCC/VERITAS sources. CI has read-only repository permissions, no Secret
reference, no protected Environment and no workflow_dispatch. A pass must be tied
to the current HEAD, Run, Job and downloaded evidence. Do not infer success merely
from this specification or a skipped local integration test.
