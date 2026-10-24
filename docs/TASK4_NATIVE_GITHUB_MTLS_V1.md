# Actual Native/Bind with a retained GitHub API model and mutual TLS

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

This explicit closed-local profile replaces the #536 SQLite reference ledger
service with the existing `SignedGitHubService` / `GitState` adapter and real
mutual TLS, while retaining the actual Native issuer, Custody, VERITAS Bind,
model-side closed TLS and pre-parser encrypted archive path. No operator `/opt`
service, approved remote run, credential or remote GitHub ref is modified.

The GitHub API is an injected **local model**, persisted in private SQLite under
the separate ledger UID 61109. It implements the existing fixed REST/GraphQL
routes and expected-head commit semantics through the existing ModelGitAPI.
There is no HTTP client, API token or remote endpoint in this increment.
Remote GitHub deployment, cross-runner persistence, independent administration
and production bypass resistance remain unproved.

## Preserve the closed namespaces

Issuer and Custody run in different existing network namespaces. Opening a new
TCP route between them would change that boundary. Instead the ledger's TLS
frames travel over the enrolled AF_UNIX socket. TLS performs actual handshakes,
CA/hostname validation, client certificate validation and exact leaf pinning.
SO_PEERCRED reciprocally authenticates the ledger UID and connects each client's
OS UID to its enrolled issuer/Custody certificate. A valid client certificate
from the other role is insufficient. These are actual TLS connections, not a
mocked certificate check, but they do not prove remote TCP/mTLS connectivity.

The root disposable fixture generates a CA in memory and distinct server,
issuer and Custody leaves. The CA private key is not retained. Role leaf keys
and CA/certificate copies are exclusive 0600 files in the existing role's 0700
directory. Runtime loading uses descriptor-pinned no-follow reads, a pinned CA
digest, role certificate pin and leaf-purpose checks. The existing authority
and receipt signing keys are separate from these TLS keys. Root enrollment
pins the Native binding, service signer, model genesis, TLS mapping and retained
database identity. No model/RPC field selects a transport, enrollment or fault.

The old reference-ledger profile remains separately runnable. An enrolled new
profile cannot opt out of GitState or TLS through a missing counterpart marker,
changed ledger ID, substituted CA/certificate, missing key or damaged storage.

## Commit, read back, sign, then issue or dispatch

The existing independent fsynced intent still precedes any ledger exchange.
`GitState` validates the approved empty genesis, fixed namespace, branch, blob
hash, whole registry and ancestry. Mutations use the existing expected-head CAS
and require an exact API acknowledgement and commit readback before the service
signs a receipt. Native signing and Bind dispatch retain their previous receipt
validation, durable retention and fresh admission checks.

The model serializes an API call using a SQLite write lock. It durably stores
the new commit and ref before returning or injecting a lost API response.
Subsequent audit writes only append events; they cannot restore an old cached
ref. A freshly constructed service reopens the same genesis, signer and model
history without re-enrollment. This is process persistence on one trusted host,
not privileged rollback or physical power-loss resistance.

The retained model trace records expected heads, commits, exact blob readbacks,
signature nonces/revisions, TLS versions and certificate/UID/command hashes.
The normal proof joins those records to every original signed gate receipt and
the original Native request/grant/Bind/archive chain. Trace records are local
fixture evidence, not independent GitHub or administrator attestation.

## Three complete CI profiles

| Profile | Required observed behavior |
| --- | --- |
| Normal | Eight actual Native requests, 16 mutations, 32 original gate receipts, 18 model commits including genesis/enrollment; exact readback before every signature; actual Bind/TLS/archive joins; ledger/issuer SIGKILL and Custody restart; final revision 16 after replay probes |
| API reserve acknowledgement lost | Model reserve commits, mutation response fails before readback/signing, no Native grant is issued; Native local DB rolls back but its independent attempt stays burned; all three services are SIGKILLed/reopened; explicit repeat stops without another model mutation |
| TLS consume acknowledgement lost | Actual Native grant is issued after verified reserve; model consume commits and its receipt is signed but discarded before TLS frame delivery; no local consume/Bind/model POST/archive follows; all three services reopen; explicit Native and original Custody replay probes remain stopped at revision 2 |

The two faults are fixed root-enrolled disposable fixture controls, never client
commands. Their actual first Native SDK bytes are observed before issuer RPC;
the original grant, when issued, is retained by the trusted runtime solely for
an explicit negative replay probe. No cached-grant recovery or automatic retry
is enabled. Both cases check that model commit counts and mutation request
counts remain unchanged across replays, not merely that a STOP was printed.

An absent final record still does not independently prove zero effects. Fault
results join the enforced handler stop with local issuer/consume state, backend
POST/archive observations, durable intent and retained signed/model state.
Utility stays unscored; scripted Native scorer calls confer no live permission.

## Validation

26 new unit/integration cases cover actual Native issuer/Custody handlers with
the signed GitHub adapter, expected-head contention, retained model reopening,
malformed/lost mutation acknowledgements, corrupt readback, complete-grant
consume binding, TLS file/pin/enrollment refusals and readback witness rejection.
Three cases perform actual TLS-over-Unix connections: valid issuance, the other
role's CA-valid certificate, and missing client certificate. A host that blocks
sockets may skip those locally; the mandatory Native CI requires zero skips.
Unit fixtures otherwise share the test UID and inject the model transport.

The mandatory workflow executes all three root-capable, separate-UID/netns
profiles on the frozen Native/Bind sources. Generated reports must be inspected
before claiming this profile verified. The reports explicitly identify the API
as a local model and the ledger TLS transport as AF_UNIX, and retain NO-GO flags.

```sh
python -m pytest -q tests/test_task4_native_github_mtls_v1.py
# Disposable root-capable Linux CI with the existing frozen _pins only:
sudo -n "$(command -v python)" -m scripts.task4_native_os_custody_v1 \
  --run --local-https --raw-ingress success --bounded-native --retained-bounded \
  --signed-ledger-native --signed-github-native \
  --output results/native-github-mtls-normal
# Separate fresh disposable fixture, optionally add one fixed fault:
# --signed-github-fault api-reserve-ack-lost
# --signed-github-fault tls-consume-ack-lost
```

The next deployment step must separately review the real GitHub backend and
remote mTLS topology, fresh Native-specific binding/approval, permissions and
egress. This local model does not authorize reusing the operator's synthetic
label manifest or changing the existing remote run.
