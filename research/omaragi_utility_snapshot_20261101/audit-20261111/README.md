# PR #590 — follow-up to the November 9 audit

Audit reference: [Takeshi's complete comment](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/590#issuecomment-6738860939).

**Scope:** the exact reviewed commit `4328be1d35d6494458708af6bd85a62d837aa8ca`. This follow-up preserves its `SNAPSHOT.zip`, manifest, saved results, CSVs, source snapshots and locks. It adds observed audit evidence and a minimal offline inspection procedure. It does not change RCC/REVAS, experiment/authorization conditions, historical scores, or the future Task1 G vs G+P experiment. No workflow was approved and no merge was performed.

## 1. Public archive identity and all entries

The GitHub blob was downloaded again at the exact commit and compared with the local Git export: **7,253,100 bytes**, SHA-256 **`085de648b4fbd53643e20f20bc9ed3ab7dc8634b9307581cf815d5d5dbba8a51`**. Git blob SHA: `8cfe4fbe03c698034798fe1a38194c50fa829299`.

The original pinned verifier completed successfully against all **3,595** archive entries and their manifest size/hash records, 1,664 locked records and 66 source pins. Its observed output is [baseline-offline.json](observed/baseline-offline.json). The separate existing-`cryptography` run verified **160 grant signatures**: [baseline-signatures.json](observed/baseline-signatures.json). The latter did not install packages or call a provider.

The new minimal procedure also ran successfully against the current inspection helper: [current-offline.json](observed/current-offline.json). This is stored-evidence integrity checking, **not** a new Native-scoring run, external independent reproduction, or new held-out/G vs G+P result.

## 2. Exact comparison of the two derived public grant views

The author locally compared the public views with the withheld original enrollment files in the sealed private review archive. The private archive and both original files matched the previously declared hashes. The [observed comparison](observed/grant-view-comparison.json) establishes:

- Exactly one original top-level field was removed: `owner_origin`.
- Exactly one top-level reference field was added: `owner_origin_public_reference`; it exactly matches the declared hash-only/public flags, not a new approval.
- All other fields are equal under canonical encoding.
- All **160 signed payloads have identical canonical bytes**, and all **160 signatures have identical bytes** before/after the transformation. Both 80-grant list hashes are recorded for both views.

No private approval values, original records or app database are published in this comparison. A public reader without the originals cannot independently repeat the private-original comparison or authenticate the owner/issuer. Public signatures prove the preserved binding, not the right to grant authority or present authorization.

## 3. Confidentiality, source and publication-rights review

See [publication-review.json](observed/publication-review.json) and the [AgentDojo license check](observed/agentdojo-license-review.json).

- All 3,595 entries were scanned for the recorded OpenAI/GitHub credential, signing-private-key and long authorization-header patterns: **0 matching files**. An email-shaped-value scan also found 0 matching files. These bounded checks do not prove that every possible secret or personal string is absent.
- The 1,154 provider request and 1,154 response records were structurally inventoried. They are SDK request/response data rather than transport authorization headers. Response/call identifiers and fingerprints are technical metadata, not authenticated evidence of a person or a license grant.
- All 1,664 recorded prestates' user-account fields, bank balances, IBANs and scheduled transactions match the public synthetic AgentDojo fixture. Direct transaction-list equality initially failed; 416 lists were subsequently traced to a source-defined injection-vector marker substitution. The remaining generated/attack strings are not represented as independently authenticated inputs. No evidence was changed to make these comparisons pass.
- The frozen AgentDojo MIT license was checked byte-for-byte against the current official upstream license. Its copyright/permission notice is supplied as [AgentDojo-MIT-LICENSE.txt](third-party/AgentDojo-MIT-LICENSE.txt), adjacent to this archive. Do not distribute the ZIP alone while discarding applicable notices.
- The code inventory contains 28 unique implementation hashes. Five modules are byte-identical to the upstream benchmark at `6e6cf796ec302b4a5eddcb06990094f5ec1e2cbe`; the other paths are contributor additions. No whole-file hash matches a pinned VERITAS Core source file. This exact-file comparison is not a proof that no derivative expressions exist. The VERITAS Core EULA is proprietary; no open redistribution right is inferred from visibility.
- The research owner explicitly authorized this publication/audit task for the contributor's own material. That authorization cannot confer third-party rights. The reviewed benchmark tree has no general license/notice file establishing a blanket redistribution grant. **Maintainer confirmation of the publication/reuse basis for the five upstream benchmark modules and the upstream source document remains open.** No additional such source content is introduced by this audit.
- Historical code retains 9 local-path literals; the files behind those paths are not bundled. No private Notes, AEGIS package, inbox conversation, approval original, credentials or private signing keys were added.

### Concrete metadata finding and narrowly scoped correction

Two opaque private approval identifier literals existed in the original **inspection helper's scanner**, outside `SNAPSHOT.zip`. They were unnecessary to reproduce in current source. The current helper now compares digests of candidate identifiers; it no longer contains those literal values. The change is explicit and only concerns the privacy scanner, not the archived mechanism or experimental evidence.

[identifier-redaction-check.json](observed/identifier-redaction-check.json) records the old/new helper hashes, 10 positive contexts, 3 negative contexts and scan-equivalence checks on all 3,595 archived files. The cited historical commit still contains the old literals. **No Git-history erasure is claimed or attempted.** Owner/maintainer disposition of that historical metadata remains a review item; it is not silently described as removed from history.

## 4. Minimal offline procedure

Prerequisite: an already obtained copy of the snapshot directory and an installed Python 3.9+ standard library. Download/Git acquisition is a separate preparation step; the following verification does not need a GitHub login, API key, network, paid model, private source archive, package installation or `sudo`.

From the current PR checkout:

```sh
SNAPSHOT_PYTHON="$(command -v python3)"
SNAPSHOT_DIR="research/omaragi_utility_snapshot_20261101"
env -i "$SNAPSHOT_PYTHON" -I -B -S \
  "$SNAPSHOT_DIR/audit-20261111/offline_verify.py" "$SNAPSHOT_DIR" \
  --expected-verifier-sha256 da98a0c70b81d181ac9b94eed040c312ca804789a1308d0752524ad328fd4c89
```

To check the exact original reviewed commit, provide an already exported copy of its snapshot directory and omit the override (the original helper hash is the default):

```sh
env -i "$SNAPSHOT_PYTHON" -I -B -S \
  "$SNAPSHOT_DIR/audit-20261111/offline_verify.py" \
  /path/to/export-of-4328be1/research/omaragi_utility_snapshot_20261101
```

`offline_verify.py` checks the fixed ZIP, manifest and selected helper hashes before execution. It disables site initialization and bytecode writes, uses an empty supplied environment, and adds Python audit guards denying network/process creation, write opens and filesystem mutations. Allowed reads are the selected snapshot directory and the Python standard library. Python/macOS added `LC_CTYPE` and `__CF_USER_TEXT_ENCODING` during the observed run; only those benign locale/encoding keys are permitted, and their values are not published. No secret environment keys were present.

The observed guards recorded **no denied-operation attempts**, and no archived runner or Native scorer was imported. This is a bounded aid for the pinned inspected program, **not an OS sandbox or an adversarial-isolation proof**. The no-dependency route checks grant/scope identities but does not cryptographically verify signatures; the separate optional existing-`cryptography` output is above.

## 5. Commands, observed outputs and failures

[commands.json](observed/commands.json) records argv, supplied environment, exit codes, stdout/stderr hashes, failed attempts and corrections. Successful stdout files are copied byte-for-byte. Only private host path prefixes in the public command transcript are normalized; complete original logs remain local. [OUTPUT_MANIFEST.json](observed/OUTPUT_MANIFEST.json) identifies the published output files.

Preparation first encountered a system-Python incompatibility with `tarfile.extractall(filter=...)`; export was retried with explicit validated file/directory-only members. The first two guarded-wrapper attempts stopped because Python/macOS populated an initially empty environment with locale/encoding variables. Both failures and the final successful retry are recorded. Only the new wrapper's explicit environment check was corrected; no archive data or score was adjusted.

## Remaining gates

1. Maintainer confirmation of upstream benchmark material's publication/reuse basis; no blanket third-party permission is asserted.
2. Owner/maintainer disposition of the identifiers still present in the old commit; current-source redaction is not history removal.
3. Pattern/structural checks and partial fixture correspondence are not an exhaustive confidentiality certification. Private approval authenticity and full input provenance are outside this public subset.
4. The maintainer retains control of any CI approval and merge. Broad Actions remain unapproved. A new Native-score run, external reproduction, fresh held-out evaluation and Task1 G vs G+P remain separate work.

## 日本語要約

指定コミットのZIP本体、全3,595エントリ、固定出力とmanifestの照合は通過しました。非公開原本とのローカル比較では、2つの公開ビューの`owner_origin`除去と参照追加だけを確認し、160件の署名対象payloadと署名バイトが不変でした。秘密情報・モデル呼出し・sudoを使わないオフライン検証手順と実出力を添付しています。

一方、公開コードの検査文字列に残っていた2件の非公開識別子は、現在のヘルパーでハッシュ照合に変更しました。過去コミットから消去したとは主張しません。AgentDojoのMIT表示は確認・添付しましたが、上流benchmarkの5モジュールと文書の公開・再利用根拠については、maintainerの確認が必要です。機密性の無条件認定、Native scorer独立再実行、G vs G+Pの新規結果とは扱わず、CI承認・マージは行っていません。
