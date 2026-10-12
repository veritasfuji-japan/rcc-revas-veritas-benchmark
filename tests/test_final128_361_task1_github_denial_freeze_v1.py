"""Negative-control tests for the offline frozen evidence audit."""
import copy
import json
import pytest
from scripts.final128_361_task1_github_denial_freeze_v1 import (
    EVIDENCE, SHA_FILE, EvidenceInvalid, validate_snapshot, verify_bytes, verify_files
)


def fixture():
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def test_frozen_evidence_sha256_and_semantics():
    result = verify_files()
    assert result["status"] == "PASS"
    assert result["no_remote_execution"] is True


def test_tampering_fails_against_pinned_sha():
    data = EVIDENCE.read_bytes().replace(b"Cannot delete this tag", b"Cannot delete any tag")
    with pytest.raises(EvidenceInvalid, match="CHECKSUM_MISMATCH"):
        verify_bytes(data, SHA_FILE.read_text())


@pytest.mark.parametrize("change,error", [
    (lambda d: d["probe_job_log"]["delete"].update(api_message="Cannot delete this tag"), "DELETE_RULESET_SOURCE"),
    (lambda d: d["probe_job_log"]["update"].update(http_status=200), "UPDATE_STATUS"),
    (lambda d: d["probe_job_log"].update(readback_unchanged=False), "PROBE_READBACK"),
    (lambda d: d["post_run_git_ref_readback"].update(object_sha="a"*40), "LIVE_READBACK"),
    (lambda d: d["ruleset_readback"].update(enforcement="evaluate"), "RULESET_ACTIVE"),
    (lambda d: d["ruleset_readback"].update(bypass_actors=[{"id":1}]), "RULESET_BYPASS"),
    (lambda d: d["provenance"].update(run_id=12345), "PROVENANCE_run_id"),
])
def test_semantic_negative_controls(change, error):
    d = copy.deepcopy(fixture())
    change(d)
    with pytest.raises(EvidenceInvalid, match=error):
        validate_snapshot(d)
