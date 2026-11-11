# Publication scope and provenance

This is a **new public subset**, not a replacement for the original sealed evidence or for the review ZIP shared privately on 2026-11-01. Original evidence and the author's working checkout remain preserved. Historical status fields such as `emails_sent=false` describe their original observation time; they are not rewritten to describe this later publication.

## Included

- Byte-preserved current model requests, SDK response JSON and usage, locked case-arm execution JSONL, final system outputs, injected prestates, poststates, Native receipts and official score files.
- Byte-preserved historical implementation/source snapshots, source/dependency hashes and recorded local audits. Paths inside historical code are source text, not included host files or instructions to acquire private data.
- Earlier date-free and feedback ablation records, scores, sources, aliases and controls, including neutral/negative evidence. Historical-matched A98/B68/C104 is a **manifest/score reference only**, not its complete trajectory archive.
- Separate TEST controls. These are not real-provider measurements.
- Two derived public grant views. Their signed payloads, signatures, keys, proposal references and scope identities are preserved; the `owner_origin` object containing private app record identifiers, ordinals and timestamps is removed. `EVIDENCE_MANIFEST.json` records the original and derivative hashes separately.
- The unchanged pre-approval proposal. Its `REVIEW_ONLY` and `actual_owner_approval` fields are historical proposal state, not a live approval or a contradiction manufactured by changing that old document.

## Withheld or omitted

- Raw app approval export, exact private chat/question anchor and full chat-history database.
- Original full enrollment files and the old report containing raw private message identity. Their original hashes remain source references. Public views do not satisfy the original enrollment-byte hash and do not independently establish the issuer's right to grant authority.
- Whole cumulative cost ledger, consumed-effect SQLite database, authentication caches, credentials and private signing keys. Aggregate usage, estimated protocol cost and actual recorded effect fields remain in historical records where relevant.
- Private correspondence, send receipts, personal RCC/REVAS Notes and third-party AEGIS material.
- Duplicate `cases/*.json` copies where complete locked `execution_records.jsonl` remains included.
- Complete old provider payloads and the full Native dependency trees. Their identities/relevant summaries remain references; this subset cannot independently reauthenticate private source provenance or reinstall every historical runtime dependency.

The manifest lists every omitted entry from the already curated private review ZIP, plus an explicit account of material that was already excluded from that source archive. An omission/hash list is provenance, not publication of the omitted content.

## What public verification establishes

`verify_snapshot.py` checks archive identity, all included bytes, original output/manifest locks, score accounting, same-run comparisons, shared prestates, state hashes, payment/effect counts and optional grant signatures. It does not import or execute archived runners, read the user's app database, acquire credentials, grant authority, invoke a provider or recompute Native Utility. Original local Native regrading is a **recorded result**, not newly executed external replication.

Private approval-origin authenticity remains outside the public subset. Cryptographic signature validity is not proof of owner identity, an independent issuer, present authorization, production isolation or actual bank authority. Historical approvals and consumed grants must not be reused.

This PR adds an archival reference. It neither adopts the engine into current production/research execution nor changes the original policy, scorer, V13 artifact, contributor source management, existing IP arrangements or future collaboration membership. A fresh same-condition ablation, live Arm A, held-out evaluation and Task1 G vs G+P remain separate work.

## November 11 audit addendum

The [maintainer-audit follow-up](audit-20261111/README.md) records actual exact-commit checks, publication-source review and limits. Two private identifier literals in the original inspection helper (outside the archive) have been replaced with digest matching in current source; the original commit and all historical evidence are preserved. Maintainer confirmation of upstream benchmark publication/reuse rights and disposition of the historical metadata remain explicit open gates. No unverified third-party source body or private approval original is added by this follow-up.
