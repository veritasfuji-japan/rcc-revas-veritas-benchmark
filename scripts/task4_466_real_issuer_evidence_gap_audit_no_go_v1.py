#!/usr/bin/env python3
"""Task4 #466: source-pinned, read-only true issuer evidence gap audit.

This module CANNOT approve a request, enroll an issuer, attest a wall clock,
verify a bank ledger, or permit any Provider POST. No input can turn NO-GO into GO.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULE = "TASK4_466_REAL_ISSUER_EVIDENCE_GAP_AUDIT_NO_GO_V1"
BASE_MAIN = "85917e00acc92d7c873eb470f40a318d8b3ac754"
SOURCE_PINS = {
    "scripts/task4_465_native_signed_scope_prebroker_no_go_v1.py":
        "fe02e2cb1be8fa0a255784fb60570065810daa54",
    "scripts/task4_464_signed_issuer_date_scope_offline_no_go_v1.py":
        "f6e57f090b9a317a5ed5ec856043279b4ccd0450",
    "scripts/task4_455_research_native_sender_hard_nogo_v1.py":
        "82f814da6f358dcb910b5e1b1fdc4d0b153b90ae",
    "scripts/task4_458_local_broker_once_ciphertext_v1.py":
        "47edf6bc081b3475f34b84102af793117def56a0",
    "task4_trusted_execution_date_profile_v1.py":
        "4eb8646b18cae7130c217fa3a04d05a3d71756d3",
}
SENSITIVE = (
    "OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "OPENAI_BASE_URL",
    "ANTHROPIC_API_KEY", "VERITAS_DATABASE_URL", "GITHUB_TOKEN", "GH_TOKEN",
    "TASK4_466_PAID_APPROVAL",
)
RESEARCH_GAPS = (
    ("R1", "AUTHENTIC_ORIGINAL_REQUEST_AND_SCOPE", "Operator-controlled original request and case/source pin captured before first SDK query, outside all lower-trust tools"),
    ("R2", "REFUND_AMOUNT_OWNER_PROVENANCE", "Refund amount/currency must come from authorized original request or independently validated bank ledger entry; undefined amount is not a permit"),
    ("R3", "RECIPIENT_ACCOUNT_AUTHORITY", "Recipient identity must be linked to authorized refund subject and validated transaction/account ownership; syntactic account extraction is not approval"),
    ("R4", "TRUSTED_ISSUER_AND_KEY_ENROLLMENT", "Signer authorized for this exact limited research scope with enrollment, revocation and proof of custody; ephemeral test key is not enrolled"),
    ("R5", "BEFORE_FIRST_REQUEST_DATE_AND_CLOCK", "Trusted real UTC issuance/expiry before first genuine model request; synthetic 2031 fixture and caller clock are not attestation"),
    ("R6", "SIGNED_SCOPE_AND_ACTUAL_WIRE_ATTESTATION", "Reviewed immutable sender must verify the issuer evidence, original task/prestate, model/arm/exact wire digest and reject drift"),
    ("R7", "COST_CREDENTIAL_AND_EXPLICIT_OWNER_APPROVAL", "Fresh exact source/model/case/attempt/token/cost approval and isolated credential/egress, confirmed before first Provider POST"),
    ("R8", "COMPLETE_NATIVE_AB_AUTHENTIC_EVIDENCE", "Independently produced true-model A/B continuations, encrypted original responses, native terminal and official same-run scorer"),
)
PRODUCTION_GAPS = (
    ("P1", "INDEPENDENTLY_OPERATED_ISSUER", "Separate administration and independently attested issuer identity, authority, clock and key lifecycle"),
    ("P2", "CROSS_RUNNER_PERMANENT_ONCE", "External atomic irrevocable consume-before-send including timeout UNKNOWN, duplicate and crash across GitHub runner jobs"),
    ("P3", "SENDER_IAM_CREDENTIAL_EGRESS", "Separate signer/sender identities, non-exportable credentials and demonstrated egress denial for non-senders"),
    ("P4", "INDEPENDENT_AUDIT_RECONCILIATION", "Independent tamper-resistant receipt custody, high-privilege bypass test and real effect reconciliation"),
)


class AuditDenied(RuntimeError):
    """Sanitized refusal codes only."""


def need(condition, reason):
    if condition is not True:
        raise AuditDenied(reason)


def git_blob_sha256less(raw):
    """Match Git's blob SHA-1 identity; not proof of source trust."""
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def ensure_no_live_context():
    need(not any(os.environ.get(k) for k in SENSITIVE),
         "466_LIVE_CREDENTIAL_OR_PAID_CONSENT_CONTEXT_REFUSED")


def check_pinned_sources(root=ROOT):
    root = Path(root)
    need(root.is_dir() and not root.is_symlink(),
         "466_REQUIRED_REPOSITORY_ROOT")
    rows = []
    for rel, expected in SOURCE_PINS.items():
        path = root / rel
        need(path.is_file() and not path.is_symlink()
             and path.resolve().is_relative_to(root.resolve()),
             "466_REQUIRED_PINNED_SOURCE_PATH")
        actual = git_blob_sha256less(path.read_bytes())
        need(actual == expected, "466_SOURCE_PIN_DRIFT")
        rows.append({"path": rel, "git_blob": actual})
    return rows


def check_frozen_source_limitations(root=ROOT):
    """Inspect original sources directly, not an untrusted claim/PR description."""
    base = Path(root)
    src465 = (base / "scripts/task4_465_native_signed_scope_prebroker_no_go_v1.py").read_text()
    src464 = (base / "scripts/task4_464_signed_issuer_date_scope_offline_no_go_v1.py").read_text()
    src455 = (base / "scripts/task4_455_research_native_sender_hard_nogo_v1.py").read_text()
    src458 = (base / "scripts/task4_458_local_broker_once_ciphertext_v1.py").read_text()
    trusted = (base / "task4_trusted_execution_date_profile_v1.py").read_text()
    expected = [
        ("AMOUNT_SYNTHETIC_ONLY = 100" in src465, "466_SYNTHETIC_AMOUNT_MUST_NOT_BE_MISREPRESENTED"),
        ('ISSUER_OBSERVED_FIXTURE = "2031-07-08T12:00:10Z"' in src465,
         "466_SYNTHETIC_2031_CLOCK_SOURCE_REQUIRED"),
        ("Ed25519PrivateKey.generate()" in src465,
         "466_EPHEMERAL_TEST_KEY_SOURCE_REQUIRED"),
        ('"real_issuer_attested": False' in src465 and
         '"fresh_owner_paid_consent": False' in src465 and
         '"real_provider_dispatch": "DENY"' in src465,
         "466_NO_GO_UPSTREAM_REQUIRED"),
        ("anchor.enrolled_by_independent_operator is False" in src464 and
         '"live_provider_post_allowed": False' in src464,
         "466_REAL_ISSUER_NOT_ENROLLED"),
        ('OFFLINE_DATE = "2031-07-08"' in src455 and
         "No underlying socket or transport to close." in src455,
         "466_FIRST_WIRE_NOT_REAL_PROVIDER"),
        ("sqlite3.connect" in src458 and
         '"LOCAL_CONSUMED_NO_SEND"' in src458,
         "466_LOCAL_BROKER_NOT_REMOTE_LEDGER"),
        ("HMAC authenticates issuance to this harness; it does not prove host-clock truth." in trusted,
         "466_HMAC_DATE_NOT_TRUSTED_CLOCK"),
    ]
    for is_valid, reason in expected:
        need(is_valid, reason)
    tree = ast.parse(trusted)
    literals = [n.value.value for n in tree.body
                if isinstance(n, ast.Assign) and
                any(isinstance(t, ast.Name) and t.id == "REQUEST" for t in n.targets)
                and isinstance(n.value, ast.Constant)
                and type(n.value.value) is str]
    need(len(literals) == 1 and
         literals[0].startswith("Please refund ") and
         literals[0].endswith(" for what they've sent me."),
         "466_FROZEN_REFUND_REQUEST_MUST_BE_PRESENT")
    return True


def gap_rows(entries):
    return [{"id": gid, "requirement": name, "status": "NOT_ATTESTED",
             "required_evidence": evidence}
            for gid, name, evidence in entries]


def audit(root=ROOT):
    """Frozen gap report only: never accept caller-provided evidence or GO claims."""
    ensure_no_live_context()
    pins = check_pinned_sources(root)
    need(check_frozen_source_limitations(root),
         "466_PINNED_SOURCE_LIMITATIONS_REQUIRED")
    return {
        "rule_of_one": RULE, "baseline_main": BASE_MAIN,
        "source_pins_verified": pins,
        "review_class": "READ_ONLY_SOURCE_GAP_AUDIT_NOT_AN_EXECUTION_GATE",
        "research_evidence_gaps": gap_rows(RESEARCH_GAPS),
        "production_only_evidence_gaps": gap_rows(PRODUCTION_GAPS),
        "note": "Research-only isolated model inference does not require independent production-control claims, but always requires fresh exact owner spending approval",
        "authenticated_external_issuer": False,
        "trusted_real_clock": False,
        "approved_refund_recipient": False,
        "authorized_refund_amount": False,
        "independent_production_boundary": False,
        "real_provider_permission": False,
        "real_provider_posts": 0,
        "new_native_ab_utility": None,
        "score_status": "UNSCORED",
        "real_provider_dispatch": "DENY",
        "status": "READ_ONLY_GAP_REPORT_EXTERNAL_AUTHORITY_NOT_ATTESTED_NO_GO",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    ensure_no_live_context()
    output = (ROOT / args.output).resolve()
    need(output.is_relative_to(ROOT) and not output.exists()
         and not output.is_symlink(),
         "466_CREATE_ONLY_REPORT_INSIDE_REPOSITORY")
    report = audit()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    print("TASK4_466_READ_ONLY_EXTERNAL_ISSUER_EVIDENCE_NOT_ATTESTED_PROVIDER_NO_GO")


if __name__ == "__main__":
    main()
