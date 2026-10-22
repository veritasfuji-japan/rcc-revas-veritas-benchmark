# Observed GitHub metadata ledger evidence and Native integration gates

Reviewed 2026-10-22 JST. This document records two manually dispatched exercises
of the [research metadata protocol](TASK4_GITHUB_LEDGER_RESEARCH_V1.md), using
the real GitHub API and six separate hosted jobs per exercise. The source was
merged #521, `e49c02c575697f4ff6e45c6e2cd6f109f5945f8a`; its tree
`80d6123e8a7cd82189bf26d5463a98ecf9e5b86e` matched the reviewed PR tree.
These observations concern synthetic metadata and callbacks only.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

## Fixed identities and execution history

| Item | Reviewed value |
| --- | --- |
| Repository | `veritasfuji-japan/rcc-revas-veritas-benchmark` |
| Workflow | `.github/workflows/task4-github-ledger-research-v1.yml` |
| State ref | `refs/heads/research/task4-retained-ledger-v1` |
| Approved parentless genesis | `e71487da54ce8d4096c68e836ea19956cec54d6d` |
| Ledger ID | `c0a56a92807f96c314b72875de1cc5b68714409ba479c1a7c7c8111136db3bb0` |
| State schema / scope | `task4.github-metadata-ledger.v1` / `SYNTHETIC_METADATA_ONLY_NO_PROVIDER` |
| Protocol source SHA-256 | `a12b7051deab3dbe2a99da0a3887f8ac157118f02f278db2feb156bdeb3422a6` |
| Manual workflow SHA-256 | `208e21418a43a03886e9030b9a4dd80baa40f255bfd61d97d7460585eddd7038` |

Bootstrap [39584774958](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39584774958)
created the approved genesis. The first exercise
[39585508504](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39585508504)
failed before reservation at revision 0 because the implementation sent the
invalid `refName` input. The original server validation message was not retained.
#521 corrected the typed input to `branchName` and added bounded diagnostics.
That failed exercise remains a failure; it was not rerun or counted as proof.

| Exercise | Run (attempt 1) | Started JST | Authorization ID |
| --- | --- | --- | --- |
| Normal, fault `none` | [39696866365](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39696866365) | 2026-10-22 08:59:06 | `8b3a033a02f30d7f4ce29ce965603ef08b327960c434acfbaae380fbff6818da` |
| Controlled response discard, fault `lost-ack` | [39698633021](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39698633021) | 2026-10-22 09:15:49 | `57f492ce622e737f24577a7c516b60a28314d958966eada6f1e3d2ea0b0b9750` |

Both runs completed successfully on the same source commit and approved genesis.
Each had six successful exercise jobs and one expected skipped bootstrap job.
No replacement namespace, bootstrap, registry reset or failed-job rerun was used.

## Job observations

| Stage | Normal job ID | Response-discard job ID | Observed behavior |
| --- | --- | --- | --- |
| reserve | `119556260571` | `119562090789` | Enroll and reserve the distinct approved ID in one retained expected-head commit |
| observe | `119556382394` | `119562229456` | Actual same-state write with contents-read job token rejected by GitHub with `FORBIDDEN`; head/state unchanged |
| contender 1 | `119556498973` | `119562341967` | Same reservation head rejected by GitHub with `STALE_DATA`; STOP, zero callbacks |
| contender 2 | `119556499004` | `119562341992` | One consumption commit; normal ACK_VERIFIED and one callback, or ACK_DISCARDED_STOP and zero callbacks |
| replay | `119556629055` | `119562469490` | Fresh trusted writer sees consumed state; duplicate enrollment and consume rejected locally without a mutation |
| verify | `119556759433` | `119562597837` | Read-only join of reports and exact retained state; backend_metadata_checks_passed=true |

Each final report records six distinct Linux boot-ID hashes, including the
verifier. They identify separate hosted job boot witnesses, not attested hardware
or independent administrators. Both contenders used the same reservation head;
the evidence does not require simultaneous scheduling. The stale request was
submitted to GitHub, rather than merely rejected by a local model. The replay
probe is a trusted-client state-machine rejection, not a claim that an arbitrary
repository writer cannot bypass that client.

Normal execution produced exactly one synthetic callback returning integer 1.
In the fault exercise, the successful-looking mutation response was deliberately
discarded before acknowledgement validation. The retained record was consumed,
but both candidates stopped and total callbacks were zero. This is controlled
response-discard injection, not an observed network outage or packet loss.
The workflows have no automatic mutation retries. Neither exercise dispatched
an SDK/Provider request or performed a real bank operation.

## Retained commit chain

Each row below records the commit's parent link, verified through the Git API.
The snapshots retain prior run records.

| Commit | Parent | State after commit |
| --- | --- | --- |
| `e71487da54ce8d4096c68e836ea19956cec54d6d` | none | revision 0, empty registry (approved genesis) |
| `3cc9f60737b98460ff21e355f9bbeb5dba2e28c4` | `e71487da54ce8d4096c68e836ea19956cec54d6d` | revision 1, normal ID reserved |
| `4e85e200fa8fccd08af01b01c0693d7674b5ca7c` | `3cc9f60737b98460ff21e355f9bbeb5dba2e28c4` | revision 2, normal ID CONSUMED_UNKNOWN, candidate 2 |
| `9fed46f3dc0903914a0638ec8b53e81fcc96d71f` | `4e85e200fa8fccd08af01b01c0693d7674b5ca7c` | revision 3, normal record retained, fault ID reserved |
| `91d64382a3e03be2ce5914bbdb19f977afad77d5` | `9fed46f3dc0903914a0638ec8b53e81fcc96d71f` | revision 4, both IDs CONSUMED_UNKNOWN, candidate 2 |

Final inspection found exactly two retained records. Both bind the reviewed
source commit, their distinct Actions execution IDs, and the fixed synthetic
request/grant hashes. CONSUMED_UNKNOWN is bookkeeping and does not imply a send.
This is an observation of the chain at review time; administrators could later
restore an older valid descendant. No durable independent anti-rollback witness,
backup/restore experiment or privileged-history attack has been proven.

## Independently downloaded evidence

All twelve ZIPs were downloaded independently of the workflow verifier. For each,
SHA-256 matched both the GitHub artifact API digest and the upload-job log; ZIP
CRC and member paths passed inspection. Each contained one JSON report. Review
joined source commit/hash, run/genesis/authorization identities, six distinct boot
witnesses, callback counts and the retained Git API state. Artifact retention is
finite; the digest below identifies reviewed bytes but does not preserve them or
make a later missing artifact verifiable.

| Run | Artifact name suffix (`task4-github-ledger-`) | Artifact ID | ZIP SHA-256 |
| --- | --- | --- | --- |
| Normal | reserve | `12391127525` | `cedcaa0ee960fd1f7fa18cbeaf17ce8d837287856c2c62604979e764b88c5582` |
| Normal | observe | `12391287475` | `1840c9d74aabab207588b7b05d05ee706332af17c15d76db6cdc332631d88cc2` |
| Normal | contend-1 | `12390502896` | `3aedccd8cddf68777327ad5dd6d032af6f3e7f51f77038c80a3b781c2233ea18` |
| Normal | contend-2 | `12390737225` | `27fc7e7fe8226396e1227c0945836b991bf145f4da6b9c14a6b1e6fa19dc58e9` |
| Normal | replay | `12390892919` | `9fe5693e867661bf94cdd2785b8819131035b5729b89fdd67edc164753edd2e4` |
| Normal | verified | `12391018045` | `35366b8d7e625f06a37d6833913e2b6c811b25f1d169bcb9ebb0546c0b422c7b` |
| Discard | reserve | `12391434349` | `ebe2cfb9fde47195b37fc5d136b82cd55e8fa017ea14e6aac6a0889692f44dbe` |
| Discard | observe | `12392185437` | `13a23d88a523ff3b6441e6311629039ebabd48d44919a7b50a0f963c1356b7fa` |
| Discard | contend-1 | `12391747177` | `701fb9f5b4daaa2846d8585284ea006e1a897c3d95498f498c922b8b13646d6d` |
| Discard | contend-2 | `12392305289` | `fe18b32755f0175ce8b7a733d5d8fb8dec2fc9e6d42dcfb05913f6bdd445f604` |
| Discard | replay | `12391214954` | `d969653db69aec109e421abe6cf984f9c039304c2583574aa5b515b6f91b1e3e` |
| Discard | verified | `12392390032` | `fa383b99fe5293a8b226792dd5d3471929ddb7f070ec5817bf021880295bf90a` |

## Gates before Native integration

The backend evidence establishes a bounded retained metadata transition and
GitHub job-token permission probe across actual hosted jobs. It does not implement
the [#518 signed authority contract](TASK4_EXTERNAL_LEDGER_CONTRACT_V1.md).
Both final reports explicitly keep native_integration_proven,
cross_runner_native_authority_proven, signed_service_proven,
independent_administration_proven and production_bypass_resistance_proven false.
PR CI's remote_experiment_executed=false remains correct for PR CI itself.

| Open gate | Required reviewable evidence |
| --- | --- |
| Approved authority binding and lifecycle | One independently approved namespace and manifest/run binding, distinct issuer/Custody key digests, all A0-A3/B0-B3 slots, retained registry/tombstones, bounded capacity and explicit retirement; no caller-selected reset or alternate namespace |
| Authenticated authority service | Defined trusted writer/signer deployment and access boundary; stable pinned service public key; authenticated issuer/Custody roles supplied by transport, not caller JSON; bounded signed acknowledgements binding nonce, command, action, revision and exact state |
| Durability and administrator model | Crash and restore behavior, retention/key lifecycle, privileged rollback assumptions or an independent monotonic witness; fail closed on unavailable/corrupt state without fallback |
| Actual Native boundaries | Retained reservation inside actual policy after existing checks and before signing; retained consumption inside actual Custody after verification and before send; preserve scope/history/recipient/expiry/budget checks and existing frozen Bind behavior |
| Cross-runner integration and faults | Actual Native issuer/Custody on separate fresh runners retain one approved authority; competing requests, restart, lost acknowledgement, callback failure and replay refuse reissue/resend, with exact source and state evidence |

These are implementation acceptance conditions, not fulfilled checkboxes or a
request to provision paid services. A concrete design must resolve the trusted
writer/signer and role boundary before wiring the metadata API into Native. A
GitHub Verified commit or TLS connection cannot replace the service receipt.
Existing repository write tokens are broad authority; code and administrators
holding them remain trusted. One successful read-only probe does not audit all
historical workflows or establish credential/network isolation for a Provider.

Actual Sender credential/egress isolation, historical workflow administration,
private archive/recipient lifecycle, independent A/B generation, current pricing
and fresh owner consent remain separate live gates in the
[restart gap audit](TASK4_PROVIDER_RESEARCH_RESTART_GAP_AUDIT_V1.md).
This documentation change neither authorizes a Provider call nor changes a
workflow, key, Secret, Environment, Ruleset, tag or state branch.
