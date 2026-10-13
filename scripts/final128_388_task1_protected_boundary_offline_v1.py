#!/usr/bin/env python3
"""#388 review-only Task1 protected runner contract; NEVER a live entry point.

Reads an untrusted review-spec and repository workflow *source*. Simulates
once-only consumption solely in memory. No external refs, GitHub write API,
Provider client, secret reads, model calls, native scoring, or live grant.
A plan, screenshot or spoofed approval field cannot become execution authority.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
from hashlib import sha256
import json
from pathlib import Path
import re

from scripts import final128_387_legacy_manual_provider_quarantine_audit_v1 as legacy

SCHEMA = "veritas.final128.task1-protected-dispatch-review-only.v1"
REPO = "veritasfuji-japan/rcc-revas-veritas-benchmark"
ENV = "task1-real-model-pilot"
MODEL = "gpt-4.1-mini-2025-04-14"
TAG = "refs/tags/final128-task1-first-two-real-responses-v1-consumed"
CONTRACT = Path("contracts/FINAL128_388_TASK1_PROTECTED_BOUNDARY_REVIEW_ONLY_V1.json")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
RUN_RE = re.compile(r"^[1-9][0-9]{5,19}$")
SECRET_BINDING = re.compile(r"\$\{\{\s*secrets\.OPENAI_API_KEY\s*\}\}")
ENV_DECL = re.compile(r"(?m)^    environment:\s*([A-Za-z0-9_-]+)\s*$")

class Denied(ValueError):
    pass

def need(ok, reason):
    if ok is not True:
        raise Denied("388_" + reason)

def strict_pairs(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, "DUPLICATE_JSON_KEY")
        value[key] = item
    return value

def expected_contract():
    return {
        "schema": SCHEMA,
        "deployment": "NOT_INSTALLED_NO_PROVIDER_DISPATCH",
        "proposed_job": {
            "repository": REPO,
            "event": "workflow_dispatch",
            "branch": "refs/heads/main",
            "actor": "veritasfuji-japan",
            "environment": ENV,
            "credential": "ENVIRONMENT_SECRET_ONLY_OPENAI_API_KEY",
            "model": MODEL,
            "max_first_provider_attempts": 2,
            "proposed_spend_ceiling_usd": "1.00",
            "max_run_attempt": 1,
            "no_automatic_retry": True,
            "global_single_use_tag": TAG,
            "consume_outcome_unknown": "STOP_PERMANENTLY_NO_RETRY",
            "provider_step": "ABSENT_IN_THIS_PR",
        },
        "manually_observed_not_machine_attested": {
            "required_reviewers": True,
            "reviewer": "veritasfuji-japan",
            "prevent_self_review": False,
            "wait_timer_minutes": 10,
            "admin_bypass_allowed": False,
            "allowed_branches": ["main"],
            "repository_openai_secret_removed": True,
            "task1_environment_openai_secret_present": True,
        },
        "externally_unverified": {
            "authenticated_fresh_one_case_consent": True,
            "independent_review_or_comparable_external_auth": True,
            "trusted_protected_issuer_and_credential_bound_runner": True,
            "immutable_once_tag_enforcement_and_bypass_resistance": True,
            "effective_provider_project_hard_spend_stop": True,
            "authenticated_tls_provider_receipts_and_native_scoring": True,
        },
    }

def validate_contract(payload):
    """Strict equality: even an asserted newly 'verified' boolean is DENIED."""
    need(type(payload) is dict, "CONTRACT_OBJECT_REQUIRED")
    need(payload == expected_contract(), "CONTRACT_DRIFT_OR_CLAIMED_PROOF")
    # Protects against JSON true = Python int equality and substituted types.
    def typed_equal(a, b):
        if type(a) is not type(b):
            return False
        if type(a) is dict:
            return a.keys() == b.keys() and all(typed_equal(a[k], b[k]) for k in a)
        if type(a) is list:
            return len(a) == len(b) and all(typed_equal(x, y) for x, y in zip(a, b))
        return a == b
    need(typed_equal(payload, expected_contract()), "TYPE_CONFUSION")
    return True

def load_contract(path=CONTRACT):
    p = Path(path)
    need(p.is_file() and not p.is_symlink(), "CONTRACT_REGULAR_FILE_REQUIRED")
    raw = p.read_bytes()
    need(0 < len(raw) <= 20_000, "CONTRACT_SIZE_BOUND")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs)
    validate_contract(value)
    return value

@dataclass(frozen=True)
class Candidate:
    repository: str = REPO
    event: str = "workflow_dispatch"
    ref: str = "refs/heads/main"
    actor: str = "veritasfuji-japan"
    environment: str = ENV
    model: str = MODEL
    run_attempt: int = 1
    main_sha: str = "a"*40
    run_id: str = "38227769501"
    max_calls: int = 2
    max_usd: str = "1.00"

def validate_candidate(c):
    need(type(c) is Candidate, "CANDIDATE_TYPE")
    checks = (
        (c.repository == REPO, "REPOSITORY"),
        (c.event == "workflow_dispatch", "EVENT"),
        (c.ref == "refs/heads/main", "BRANCH"),
        (c.actor == "veritasfuji-japan", "ACTOR"),
        (c.environment == ENV, "ENVIRONMENT"),
        (c.model == MODEL, "MODEL"),
        (type(c.run_attempt) is int and c.run_attempt == 1, "RETRY"),
        (type(c.main_sha) is str and SHA_RE.fullmatch(c.main_sha) is not None, "SHA"),
        (type(c.run_id) is str and RUN_RE.fullmatch(c.run_id) is not None, "RUN_ID"),
        (type(c.max_calls) is int and c.max_calls == 2, "CALLS"),
        (type(c.max_usd) is str and c.max_usd == "1.00", "PROPOSED_SPEND"),
    )
    for valid, reason in checks:
        need(bool(valid), "CANDIDATE_" + reason)
    return True

class FakeGlobalOnce:
    """In-memory negative test seam; NOT a GitHub issuer or immutable tag."""
    def __init__(self):
        self.terminal = None
        self.attempts = 0

    def consume(self, failure="none"):
        need(failure in ("none", "unknown_before_write", "unknown_after_write",
                         "rejected"), "BAD_FAKE_FAILURE")
        need(self.terminal is None, "GLOBAL_REPLAY_OR_UNKNOWN_RETRY_DENIED")
        self.attempts += 1
        self.terminal = "UNKNOWN_STOP_NO_RETRY"
        if failure == "unknown_before_write":
            raise Denied("388_FAKE_ISSUER_UNKNOWN_BEFORE_WRITE")
        if failure == "unknown_after_write":
            raise Denied("388_FAKE_ISSUER_UNKNOWN_AFTER_WRITE")
        if failure == "rejected":
            raise Denied("388_FAKE_ISSUER_REFUSED")
        self.terminal = "FAKE_CONSUMED_NOT_AUTHORITY"
        return self.terminal

def simulate_only(*, candidate, fake, claims=None, failure="none"):
    validate_candidate(candidate)
    need(type(fake) is FakeGlobalOnce, "FAKE_ONLY_EXACT_TYPE")
    need(claims is None or type(claims) is dict, "CLAIMS_UNTRUSTED_OBJECT")
    # Deliberately ignore all self-attested approvals and receipt assertions.
    result = fake.consume(failure=failure)
    return {
        "outcome": result,
        "attempts_in_this_process": fake.attempts,
        "fake_global_tag_only": TAG,
        "asserted_approval_and_receipts_discarded": True,
        "actual_github_ref_created": False,
        "real_provider_calls": 0,
        "real_native_scorer_calls": 0,
        "real_budget_hard_cap_proven": False,
        "environment_secret_accessed": False,
        "permission_to_call_provider": False,
    }

def source_inventory(files):
    """Source-only; cannot read the enabled/disabled GitHub workflow state."""
    need(type(files) is dict and all(type(k) is str and type(v) is str
                                   for k, v in files.items()), "WORKFLOW_SET")
    task1 = []
    task4 = []
    for path, source in sorted(files.items()):
        if not (path.startswith(".github/workflows/") and
                path.endswith((".yml", ".yaml"))):
            continue
        for job, body in legacy.jobs(source):
            match = ENV_DECL.search(body)
            if not match:
                continue
            if match.group(1) == ENV and SECRET_BINDING.search(body):
                task1.append({"path": path, "job": job})
            if match.group(1).startswith("task4-real-provider-"):
                task4.append({"path": path, "job": job})
    return {
        "source_workflows_scanned": len(files),
        "task1_environment_secret_binding_jobs_found": task1,
        "task4_environment_jobs_found_not_modified": task4,
        "source_inventory_is_not_admin_state": True,
    }

def audit(*, spec, files):
    validate_contract(spec)
    inventory = source_inventory(files)
    return {
        "schema": SCHEMA,
        "status": "TASK1_LIVE_DISPATCH_DENIED_NOT_INSTALLED",
        "review_only_contract_sha256": sha256(json.dumps(spec, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode()).hexdigest(),
        "inventory": inventory,
        "manual_ui_observations_not_authenticated_to_runner": True,
        "reviewer_self_review_permitted_independent_approval_not_proven": True,
        "operator_claims_can_never_authorize": True,
        "provider_project_hard_spend_cap_verified": False,
        "trusted_protected_singleton_issuer_verified": False,
        "actual_environment_approval_on_paid_job_verified": False,
        "actual_task1_provider_posts": 0,
        "actual_native_scorer_runs": 0,
        "new_utility_score": None,
        "execution_authorized": False,
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--contract", default=str(CONTRACT))
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    spec = load_contract(args.contract)
    data = audit(spec=spec, files=legacy.actual_workflows("."))
    target = Path(args.output)
    need(target.parent.is_dir() and not target.is_symlink(), "OUTPUT_PARENT")
    target.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")
    print("388_TASK1_BOUNDARY_REVIEW_ONLY_NO_PROVIDER_NO_SCORE")
    print("388_TASK1_POTENTIAL_BOUND_JOBS=" +
          str(len(data["inventory"]["task1_environment_secret_binding_jobs_found"])))

if __name__ == "__main__":
    main()
