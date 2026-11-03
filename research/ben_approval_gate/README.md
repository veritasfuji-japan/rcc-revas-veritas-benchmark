# Ben research proposal compatibility gate (offline)

**Research-only format classifier. Not an authority validator, issuer authenticator, Bind gate, or production permission grant.**

This checks explicit no-authority markers and synthetic case identifiers/hashes. A passing format result **does not** prove owner approval, issuer provenance, signature validity, revocation, atomic single-use, or provider effect. It never calls a model, bank, or provider.

From repository root:

```bash
python -m unittest discover -s research/ben_approval_gate/tests -v
python -m research.ben_approval_gate.approval_gate path/to/local/private_proposal.json --report /tmp/ben_review.json
```

The collaborator's original proposal and logs are **not included**; only synthetic tests are committed to avoid publishing research artifacts without permission. Do not promote research-only records into live authorization.

Before receipt-level integration: independently authenticate issuer/trust root; verify scope (recipient, amount, date, operation, target), expiry and revocation at execution time; prove atomic consumption under concurrency and replay; reconcile effects using externally anchored evidence. Keep legacy authority conditions unchanged and score new owner-approved research conditions separately.
