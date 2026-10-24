# Task4 operator VM read-only readiness evidence v1

## Result

After PR #542 was merged, the operator deployed source commit
`410e66283628f379ed421024f714fc0a7ac01954` on the Linux VM and reported
successful local configuration checking and an explicit GitHub GET-only read
of the existing signed-ledger backend. The retained genesis and service signer
were preserved. The proposed Native run was absent and was not enrolled.

This is **operator-reported read-only preparation evidence**. It does not prove
a running Native signed-ledger deployment, independent VM attestation, transport
receipt verification or production bypass resistance.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN` remains unchanged.

## Evidence and integrity

The operator pasted public terminal JSON and file digests into the working
conversation. No direct VM file access or independent capture was available.
The two public readiness records were reconstructed as canonical JSON (sorted
keys, compact separators, ASCII, no terminal LF) and matched **exactly** to the
operator's reported file SHA256 values:

| Bundled record | Bytes | SHA256 |
| --- | ---: | --- |
| [Local check](../evidence/task4_native_operator_vm_readonly_v1/local-check.json) | 2354 | `13a64d40a2fbdab0b751cbf8d45b1128aca4adece393a904654d495ece0e8751` |
| [GitHub read](../evidence/task4_native_operator_vm_readonly_v1/read-existing.json) | 2506 | `d07c07783494035abb9efb232cc07c4652df840ed2085dbbe60f3fed7d9fa4f0` |

The [index](../evidence/task4_native_operator_vm_readonly_v1/index.json) records
this provenance, role IDs, context, upstream public artifact digests and
limitations. Other artifact entries are explicitly **digest-only operator
reports**, not bundled byte evidence independently rehashed here. Reproducing
a public JSON digest establishes consistency with the pasted record, not its
origin, a trusted VM clock, a private key signature or the absence of omitted
activity. No precise observation timestamp was emitted by these records.
The recording date is 2026-10-25 JST; it is not a measured request timestamp.

No token value, token digest, private key, private-key encoding, grant secret or
credential-containing command is included. The local token's reported UID 61109
and mode 0600 do not establish its GitHub permissions. The operator reported
creating a dedicated fine-grained Contents/Metadata read-only token; the
checker correctly retains `credential_permissions_verified: false`.

## Operator preparation sequence

The operator reported the following create-once steps and successful readbacks:

1. Installed protected source and matched the material producer SHA256
   `96a52bab317fbaebb5b8fdd154ff1163beeddd177326c16f710617ab87d4164f`.
2. Retained the original service authority under UID 109 and the existing
   genesis, independently of reader UID 61109. Generated/reopened only the
   three Native Ed25519 authority keys under issuer, custody and runtime.
3. Provisioned backend UID/GID 61103 and archive UID/GID 61107 after checking
   collisions; prepared their 0700 homes and a separate root-owned 0700 CA
   directory. Existing issuer/custody/runtime/reader homes were also private.
4. Created four role-local P-256 TLS keys/CSRs and one X25519 archive recipient.
   Pinned inspection succeeded under each of their five material owners.
   Public records alone were combined under root control.
5. Created a separate root-private CA and four role/run-bound leafs. Each TLS
   role installed only its own certificate into its new preparation slot.
   No existing authority key, service configuration, OS trust store or listener
   was changed by these steps. These statements describe the reported tool
   actions, not an independent whole-host audit.
6. Assembled the Native manifest and a public candidate from the retained
   identity, three Native authority exports, actual public recipient bytes and
   local scripted API leaf. Saved/reviewed the candidate, rendered the exact
   read-only approval under root and installed a successor reader configuration.
7. Passed local `check` without loading a credential or using the network.
   Subsequently saved the dedicated token locally through hidden input and
   invoked `read-existing` explicitly as reader UID 61109.

The service/issuer/custody/backend installed leaf DER fingerprints and material
export digests are retained as operator-reported metadata in the index. CSR/
certificate creation and private/public matching are not a live mTLS handshake.
The backend's `api.openai.com` certificate belongs to the **isolated local
scripted fixture** profile; it does not authenticate the public Provider or
permit any public Provider request.

## Observed check results

| Field | Local check | GitHub read |
| --- | --- | --- |
| Reader / retained service UID | 61109 / 109 | 61109 / 109 |
| `account_matches_reader_uid` | true | true |
| `account_matches_ledger_uid` | false | false |
| `reviewed_source_bytes_match` | true | true |
| Credential loaded | false | true |
| Network used | false | true |
| Existing backend verified | false | true |
| Native context window | CURRENT | EXPIRED |
| Native run present | null (not checked remotely) | false |
| Native execution / Provider POSTs | false / 0 | false / 0 |
| Remote mutations attempted | 0 | 0 |

The false ledger-account comparison is expected: the process is the separate
reader, not the retained signer. `backend_verified: false` in the local result
also is expected because no backend read was made.

The GitHub read record reports:

- Repository `veritasfuji-japan/rcc-revas-veritas-benchmark`, branch
  `research/task4-signed-ledger-v1`, API host `api.github.com`, HTTPS port 443.
- Eight GET requests through the reviewed read-only client. Its API rejects
  non-GET methods or bodies; redirect/proxy/retry are disabled in that path.
  This record is a client report, not an independent packet capture.
- Existing genesis `16f730c8d3385537c7816b1a6cdf3ff6b4e1037b` and observed head
  `3b3e0154939cdda1a2863f771946636a316d9574`.
- Proposed Native run
  `647245272da05e5f50422e84ee00b21d3d4cbb3fdf989d1d6d0095d167e467b2`,
  binding SHA256 `c0c3ebaf9369ac97bf075f3ffd93119c8fa23b61a1a37f5ddfd538df6479d36e`
  and Native manifest SHA256
  `e8ca3f390e26535afd8662bf55a679b01341e2b3da21041dc7e2e058611f35e3`.
- `NATIVE_RUN_ABSENT_NO_ENROLLMENT`, `observed_snapshot: null` and no mutation
  attempt. Absence is a valid diagnostic outcome, not a request to enroll or
  permission to initialize, reset, repair or retry the ledger.

The source match covers **14 selected files**, not all dependencies, the Python
runtime or host integrity. The new material producer hash is retained separately.
`backend_verified: true` concerns the existing approved remote state read. It
is not a signed service receipt or Native effect confirmation:
`service_receipt_verified`, `operator_mtls_verified`,
`retained_service_uid_observed` and `retained_private_key_loaded` are all false.

## Window and execution boundary

The recorded context is `[1792856599, 1792856899)`, exactly 300 seconds.
The local check reported CURRENT; by the GitHub read it reported EXPIRED.
Neither result refreshes or changes those timestamps. Read-only diagnosis of
this retained, expired context is supported; neither the candidate nor the
installed diagnostic approval is permission to execute with it.

A future execution requires a separately reviewed valid context/binding and
actual runtime enforcement. Do not edit these historical files to claim a
fresh window or reinterpret the absent Native run as approved execution.

## Remaining gates

| Gate | Status in this VM evidence |
| --- | --- |
| Token capabilities independently checked | Not verified; successful GET does not prove lack of write permissions |
| OS default-deny egress rules installed/observed | Not verified; `os_rules_applied` and `os_egress_verified` are false |
| DNS resolver policy / existing signer UID 109 egress | Separate review required; UID 109 is outside the diagnostic plan |
| Actual operator mTLS handshake and receipt | Not performed/verified |
| Native runtime profile applied | false |
| Existing service reconfigured for new Native binding | false |
| Fresh execution-time authority and durable gate integration | Not established by this read-only observation |
| Remote Native enrollment / Native execution / utility scoring | Not performed |
| Production bypass resistance | Not proven |

The egress JSON is a **desired plan**. `default_external_egress: DENY` is not an
observed firewall result. Its four UID entries describe reader/issuer/custody/
runtime only; they do not silently install rules for new backend/archive roles,
root CA or the retained signer. A complete operator policy needs explicit
coverage, ownership, review and observed denials before a production claim.

The closed-local integration source still declares `LEDGER = 61109` and its
provisioning path is a disposable research fixture. It is not an operator
migration tool for the retained signer at UID 109. This record must not be used
to relabel that fixture as a live retained-signer runtime deployment.

## Separate CI evidence

PR #542's reviewed CI head was
`77484a9310edb74fe7ea52532d2a65cf7f139a58`. Its mandatory root-capable run
[40106304759](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/40106304759)
passed all 64 material-preparation cases with zero skips. Artifact `12564539838`
ZIP SHA256 was
`de024c239a7e4eb0bd97ce7b1f237290d9596a9ab600224fbbc514470fd954a5`;
its JUnit files were downloaded and checked when the implementation was reviewed.
The 37 actual PermissionError private-read denials were against **temporary CI
homes**. They are not 37 newly observed operator-VM denials and are not firewall,
mTLS or production bypass proof. The operator records above are a separate
source of evidence.

## Recheck the bundled records

This is an artifact integrity check, with no token, imports of execution code,
network access or authorization side effects:

```sh
python - <<'PY'
import hashlib, json
from pathlib import Path
root = Path('evidence/task4_native_operator_vm_readonly_v1')
index = json.loads((root / 'index.json').read_bytes())
for name, expected in index['bundled_records'].items():
    raw = (root / name).read_bytes()
    value = json.loads(raw)
    assert raw == json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')
    assert len(raw) == expected['size_bytes']
    assert hashlib.sha256(raw).hexdigest() == expected['sha256']
    assert value['execution_permission_issued'] is False
    assert value['real_provider_posts'] == value['remote_mutations_attempted'] == 0
    assert value['provider_dispatch'] == 'DENY' and value['utility'] == 'UNSCORED'
    print(name, 'canonical bytes and operator-reported digest match')
PY
```

No runtime, schema validator, workflow, authority policy or token handling is
changed by this evidence-only addition.
