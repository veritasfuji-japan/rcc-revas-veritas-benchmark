# Actual retained sender and alternate-client denial at a local OS boundary

Follow the #506 checkpoint's R2/P2 direction with a bounded test of actual
retained helper functions. This does not deploy a real Provider sender or close
independent administration. Reuse the #499–#505 Native/Custody/backend UID,
namespace, firewall and credential separation in one additional normal run.
All earlier normal/fault/restart/concurrency runs remain required.

## Actual calls, original source and inputs

Invoke unchanged `send_exactly_once`, `once` and `one_post` from the historical
first/second/third Task4 capture modules. Their exact Git blobs are checked by
the probe, and their original fixed-body guards are not patched or relaxed.
Use the A request for each helper; this does not test every B variant or caller.
The frozen fixture contains only the three historical request dictionaries,
including synthetic banking task text and previously recorded message history.
It is not a new model response, secret, authority grant or spending consent.

| Helper | Original request SHA-256 | Historical module Git blob |
| --- | --- | --- |
| first | `3c9ef1c4fa4d58f8969df723b40b99298fc08a9d44acfc6609f086fc0d7c5b13` | `2594ce305cd3f9e7f683fdf60edc63ea5e76abb6` |
| second | `f154c06de41bc0ae4c1a56ece0c5d01c30e456a41842ade683a70accd6cf8e3a` | `5c4c40ce13627358bdd9a6c31d45d9bf8e93ad19` |
| third | `c373ddc49a912852f39a75679e6e3f45d999f14cbfd4d3a5414f156a038726a8` | `f44f6fc2b87cd3061c50837a603747f95159259f` |

Fixture SHA-256:
`d865f923bcee5b72e41e95ed988f660096424a9826ea6d74ff0c778a72e3e021`.
Inputs were extracted from these historical artifact ZIPs; canonical request
hashes independently match the unchanged helpers' constants:

| Artifact ID | ZIP SHA-256 |
| --- | --- |
| 11672698922 | `d6dfceccdfc5e3e1b5270d61798b334f17a9792ae9492fced3ac66dc93aef6b3` |
| 11674814494 | `5e060179f7c0419d5a2b3d49587dba4d1e93f7adc8c0a41ddac1bb689813a609` |
| 11676881211 | `bbc7ba1a16aaac67aed75bdbb7a5abc71bfa978599e1cfc42700779377e838f4` |

Each helper uses its existing explicit transport parameter. The transport makes
a real `HTTPConnection` to only `10.249.91.2:18492`, preserving original body
bytes and adapting `/v1/chat/completions` to the mock `/effect` path. Record that
the factory and request method each execute exactly once; source validation
failure before socket I/O cannot pass. The supplied Bearer string is an invalid
synthetic placeholder, not a credential. The default Provider HTTPS/TLS factory
is never invoked and this test does not validate it.

Additional routes are real httpx and urllib clients with environment proxies
disabled, plus urllib in a fresh isolated Python child under the same Native UID.
Socket/client calls are not monkeypatched to deny them. All destinations are
fixed local mock addresses; no real Provider or external bank endpoint is called.

## Three phases, then an admitted positive run

| Phase | Actual attempts | Required observation |
| --- | --- | --- |
| Native UID in loopback-only Native namespace | Six routes | Six network errors; backend observation file still absent |
| Same Native UID in host namespace | Same six routes | Six network errors under the actual UID firewall rule; backend observation file still absent |
| Same Native UID deliberately placed in reachable backend namespace | Same six routes | Six actual HTTP 403 responses; independently recorded backend body hashes match the six probes |

The reachable phase is a defense-in-depth negative control, not an assertion
that Native can normally move itself into that namespace. Root controls role
placement. HTTP reachability alone supplies neither the private HMAC transport
credential nor a valid native request envelope. A legacy Bearer header does not
authorize this mock backend. The normal direct-403 check is supplied by these
six reachable probes in this additional run; prior fixtures retain their check.

Require zero backend effects and zero Custody consumptions after all 18 negative
attempts. Then execute the complete existing eight-request Native→Custody→actual
Bind→mock HTTP chain in that same service lifetime. Require eight effects,
consumptions, ciphertexts and joined Bind/lineage records, normal and restarted
replay refusal, two scripted Native terminals and two scorer invocations.
Utility remains UNSCORED. The backend owns six denial observations followed by
eight admitted POST observations; root joins the latter body hashes to the exact
Native packet files and normal evidence. A dead sink or universally broken
sender cannot satisfy the positive control.

The additional report requires 12 checks and matching zero-skip JUnit; new unit
tests reject incomplete routes/phases, uncalled helpers, changed source, wrong
UID/body/status and substituted/missing/extra backend observations. Keep the
existing 65 Native unit cases and all earlier proof counts unchanged.

## Limits and reproduction

This narrows the retained-helper coverage gap for this concrete mock deployment.
It does not establish repository-wide route closure, default Provider TLS
behavior, real credential/project protection, independently administered IAM or
egress, hostile Custody/backend/root resistance, cross-runner CAS, actual Provider
effects, genuine utility or production bypass resistance. Root/kernel, source
and key enrollment, Custody and backend remain trusted. Public/reproducible
recipient material remains synthetic; no real-data confidentiality claim.

Run only on a disposable supported Linux root runner after the exact pinned
dependency setup in the existing Native offline Actions workflow:

```sh
sudo -n "$(command -v python)" -m scripts.task4_native_os_custody_v1 \
  --run --retained-senders --output results/task4-retained-sender-denial
```

The root-enrolled fixture cannot be requested through an untrusted Native packet;
it is incompatible with fault/concurrency modes. Runtime artifacts contain
sanitized hashes, UID/denial observations, Bind receipts and JUnit, not raw
requests/responses, grants, keys, credentials, ciphertext bytes or databases.
The public historical input fixture is tracked separately for reproducibility.
No old approval is reused; no Secrets, Environments, Rulesets, tags, workflow
administration or paid execution is changed.

REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN
