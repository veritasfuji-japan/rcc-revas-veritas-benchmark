# Fixed GitHub API transport for the signed synthetic ledger

The signed adapter and retained-key startup previously required an injected API
without supplying its HTTPS implementation. `scripts/task4_signed_github_api_v1.py`
adds that implementation. It is not a deployment command or authority approval.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

## Interface and allowed requests

`approved_backend(token, genesis, signer_sha256)` constructs a `GitState` with an
explicit `API` instance. Construction makes no connection. The existing
`reopen_service` or `retained_listener` can receive this backend; they still load
only the existing pinned key and validate the approved root before service use.
There is no default token, genesis or signer, environment token discovery,
credential-file loader, root initializer, branch creator, enrollment CLI or
automatic service launch. All three inputs are trusted administrative inputs.

The explicit token must be 20-255 ASCII letters, digits or underscores. This
profile accepts the conventional GitHub token syntax; future formats require
review rather than relaxed header validation. Tokens are kept in process memory,
not written or logged. All code with the service UID and its memory are trusted.

The only host is `api.github.com`, port 443. HTTPS uses the platform's default
verified CA store, hostname verification and TLS 1.2 or later. `http.client` has
no proxy discovery or redirect/retry machinery. No host, URL, TLS context or
socket injection option is exposed. The host's CA store, service environment,
Python runtime and source remain trusted; this is not OS/IAM credential isolation.

| Method | Allowed path and operation |
| --- | --- |
| GET | Exact repository Git commit, tree or blob path with a lowercase 40-hex OID |
| GET | Exact `git/ref/heads/research/task4-signed-ledger-v1` in the fixed repository |
| GET | Exact comparison from the supplied approved genesis to a lowercase 40-hex OID |
| POST | `/graphql`, one exact `createCommitOnBranch` query shared with the signed adapter |

The repository is `veritasfuji-japan/rcc-revas-veritas-benchmark`. The mutation
requires the exact `branchName` form for the fixed signed-ledger branch, an
expected-head OID, 64-hex mutation nonce, fixed headline, and exactly one
`ledger.json` addition. File contents must be canonical base64 of the bounded,
canonical signed-ledger state with the approved signer and synthetic scope.
Additional operations, variables, input fields, deletions, files, branch IDs,
arbitrary messages, other repositories/refs and path/query escapes stop before
any connection or token use. GET requests cannot carry a body. Raw object reads
are not proof of ancestry: the existing `GitState` validation supplies that check.

The fixed REST version header is `2022-11-28`, retaining the reviewed adapter's
version profile. GitHub's [API version documentation](https://docs.github.com/en/rest/about-the-rest-api/api-versions)
lists the version behavior and retirement response. The
[CommittableBranch reference](https://docs.github.com/en/graphql/reference/git#committablebranch)
defines `branchName`, and the
[commit mutation reference](https://docs.github.com/en/graphql/reference/commits#createcommitonbranch)
defines `expectedHeadOid`. The prior schema fixture and actual earlier metadata
experiment remain separate evidence; no real API execution of this transport
has been performed by this increment.

## Response, ambiguity and cleanup

Each call makes at most one request. Only HTTP 200 JSON objects are accepted.
Redirects, authentication errors, conflicts, rate limits and server errors stop
without following locations, refreshing credentials or retrying. The transport
requests identity encoding and rejects compressed responses, duplicate lengths,
ambiguous framing, invalid/duplicate/nonfinite JSON and GraphQL errors, including
errors inside an HTTP 200 response. The signed adapter still validates the exact
mutation acknowledgement and REST readback before signing any mutation receipt.

Request bytes are limited to 128 KiB, response bytes to 1 MiB, and ledger blobs
to the existing 65,536-byte limit. Content-Length is checked before body reads;
unadvertised overflow is detected with at most one byte beyond the response cap.
The existing comparison endpoint has no automatic pagination. If its response
exceeds the cap, processing stops rather than increasing the limit or retrying.

Socket blocking operations use a 10-second timeout; the body loop checks a
10-second deadline between reads. This is **not a hard end-to-end wall-clock
deadline**: DNS, response headers and HTTP parser subreads can exceed that time
under incremental progress. Hard process/request supervision remains deployment
work. No cancellation is interpreted as rollback or permission to resubmit.
Responses and connections close on both success and failure. Errors expose only
`SIGNED_GITHUB_API_STOP`; token, raw server text, request body/headers and original
traceback details are suppressed. There is no diagnostics or raw response export.

A failed POST may already have committed. The transport never reconstructs an
acknowledgement, retries or grants execution. Existing read-only reconciliation
and consumed-state rejection remain required; a later view is not a mutation
acknowledgement or callback permission.

## Tests and remaining deployment gates

82 offline tests cover the allowlist, exact query/body, explicit token validation,
verified TLS-context construction and fixed host, ignored proxy/token/endpoint
environment settings, redirects/status failures, malformed/oversized responses,
framing, timeouts, sanitized errors and closure. Five cases exercise the real
stdlib HTTP parser over a local socket pair, including content length, chunked,
EOF and incomplete responses. They bypass TLS only in test code and are not
remote HTTPS evidence. Other transport tests use an injected fake connection.

An integration case joins the transport to retained-key startup, the signed
service and an in-memory GitHub model. One normal reserve/consume gets one issue
and one send callback. Another consume commits in the model and then times out:
it produces no mutation signature/callback or retry, and a reopened service
rejects replay. These callbacks are synthetic integer-list updates. No actual
GitHub service, Provider or external bank receives a request in these tests.
CI runs all 82 cases with zero skips and exports JUnit only for this increment.

Remaining gates include credential delivery and independent writer isolation,
explicit create-only genesis/enrollment approval, TLS/role custody, deployable
manual service entry point, remote access and actual remote commit/readback/fault
evidence. See the [deployment runbook](TASK4_SIGNED_LEDGER_MANUAL_DEPLOYMENT_RUNBOOK_V1.md).
This PR does not select a token, create a state branch, reuse the old metadata
genesis, alter an operator VM/key, dispatch a workflow or authorize Provider use.
