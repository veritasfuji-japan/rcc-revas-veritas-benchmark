"""Offline-only audit of a pinned Task1 real-GitHub negative-probe snapshot.

Checks integrity and the *limited* GitHub tag Ruleset denial claim.
Never contacts GitHub or an AI provider and never writes a remote ref.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REL = "evidence/final128_task1_github_denial_run_38254439093_v1.json"
EVIDENCE = ROOT / REL
SHA_FILE = ROOT / (REL + ".sha256")
REPO = "veritasfuji-japan/rcc-revas-veritas-benchmark"
HEAD = "9cb4345545dd17e9071d248ea8102f7d455e8c7f"
TAG = f"refs/tags/final128-task1-real-ab-once-v1-{HEAD}-38254439093"


class EvidenceInvalid(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise EvidenceInvalid(reason)


def validate_snapshot(doc):
    require(doc.get("schema_version") == "final128-task1-real-github-denial-evidence-v1", "SCHEMA")
    require("not a VERITAS runtime execution-boundary proof" in doc.get("claim_scope", ""), "OVERCLAIM")
    p = doc["provenance"]
    for key, expected in {
        "repository": REPO, "run_id": 38254439093, "job_id": 114828743640,
        "main_head_sha": HEAD, "run_attempt": 1, "workflow_event": "workflow_dispatch",
        "run_conclusion": "success", "job_conclusion": "success",
        "job_name": "isolated-negative-probe",
        "explicit_consent_in_job_log": "I AUTHORIZE ISOLATED TAG WRITE PROBE",
        "run_created_at_utc": "2026-10-12T13:15:37Z",
    }.items():
        require(p.get(key) == expected, "PROVENANCE_" + key)
    require(p.get("run_url") == f"https://github.com/{REPO}/actions/runs/38254439093", "RUN_URL")
    require(p.get("job_url") == f"https://github.com/{REPO}/actions/runs/38254439093/job/114828743640", "JOB_URL")

    rules = doc["ruleset_readback"]
    require(rules.get("id") == 24921425 and rules.get("enforcement") == "active", "RULESET_ACTIVE")
    require(rules.get("target") == "tag", "RULESET_TARGET")
    require(rules.get("include") == ["refs/tags/final128-task1-real-ab-once-v1-*"], "RULESET_PATTERN")
    require(rules.get("exclude") == [], "RULESET_EXCLUSIONS")
    require(set(rules.get("rule_types", [])) == {"update", "deletion", "non_fast_forward"}, "RULESET_ACTIONS")
    require(rules.get("bypass_actors") == [] and rules.get("current_user_can_bypass") == "never", "RULESET_BYPASS")

    log = doc["probe_job_log"]
    require(log.get("tag_ref") == TAG and log.get("creation_status") == 201, "TAG_CREATION")
    require(log.get("readback_unchanged") is True, "PROBE_READBACK")
    require(log.get("runner_reported_no_provider_calls") is True, "PROBE_PROVIDER_REPORT")
    for phase, markers in (
        ("update", ("cannot update this protected ref", "cannot force-push to this tag")),
        ("delete", ("cannot delete this tag",)),
    ):
        event = log.get(phase, {})
        require(event.get("http_status") == 422, phase.upper() + "_STATUS")
        msg = event.get("api_message", "").lower()
        require("repository rule violations found" in msg, phase.upper() + "_RULESET_SOURCE")
        require(all(marker in msg for marker in markers), phase.upper() + "_EXPLICIT_DENIAL")

    readback = doc["post_run_git_ref_readback"]
    require(readback.get("ref") == TAG and readback.get("object_sha") == HEAD, "LIVE_READBACK")
    require(readback.get("object_type") == "commit", "READBACK_OBJECT_TYPE")
    require(readback.get("url") == f"https://api.github.com/repos/{REPO}/git/ref/tags/{TAG.removeprefix('refs/tags/')}", "READBACK_URL")
    limitations = doc.get("limitations", [])
    require(len(limitations) >= 5 and any("No independent third-party" in s for s in limitations), "LIMITATIONS")
    return {"status": "PASS", "claim": "GITHUB_TAG_RULESET_UPDATE_DELETE_DENIAL_ONLY",
            "run_id": 38254439093, "job_id": 114828743640, "head_sha": HEAD,
            "tag_ref": TAG, "no_remote_execution": True}


def verify_bytes(payload, sha_line):
    expected_line = sha_line.strip().split("  ")
    require(len(expected_line) == 2 and expected_line[1] == REL, "CHECKSUM_RECORD")
    actual = hashlib.sha256(payload).hexdigest()
    require(actual == expected_line[0], "CHECKSUM_MISMATCH")
    result = validate_snapshot(json.loads(payload))
    result["evidence_sha256"] = actual
    return result


def verify_files():
    return verify_bytes(EVIDENCE.read_bytes(), SHA_FILE.read_text(encoding="utf-8"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", help="Optional local output JSON path (no external effects)")
    args = parser.parse_args()
    report = verify_files()
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report:
        path = Path(args.report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
