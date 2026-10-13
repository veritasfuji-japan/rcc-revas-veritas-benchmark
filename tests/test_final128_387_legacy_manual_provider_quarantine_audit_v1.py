"""#387: identify active legacy manual Provider endpoints without modifying freeze."""
from __future__ import annotations
from pathlib import Path
import os
import pytest
from scripts import final128_387_legacy_manual_provider_quarantine_audit_v1 as m

def source(*,manual=True,secret=True,stopped=False,extra_job=False):
    event="workflow_dispatch:" if manual else "push:"
    credential="OPENAI_API_KEY" if secret else "NO_PROVIDER"
    gate=("    if: "+"$"+"{{ false }}\n") if stopped else ""
    extra=("\n  secondary:\n    runs-on: ubuntu-latest\n"
           "    steps:\n      - run: echo denied-by-audit\n") if extra_job else ""
    return ("name: Historical Manual\non:\n  "+event+"\n"
      "jobs:\n  primary:\n"+gate+"    runs-on: ubuntu-24.04\n"
      "    env:\n      OPENAI_API_KEY: "+"$"+"{{ secrets."+credential+" }}\n"
      "    steps:\n      - run: python scripts/historical.py\n"+extra)

def files_fixture(old=None):
    return {m.ROOT+"/"+n:(source() if old is None else old) for n in m.LEGACY}

@pytest.mark.parametrize("manual,secret,expected",[
    (True,True,True),
    (True,False,False),
    (False,True,False),
    (False,False,False),
])
def test_manual_provider_detection(manual,secret,expected):
    assert m.is_manual_provider(source(manual=manual,secret=secret)) is expected

@pytest.mark.parametrize("stopped,extra_job,expected",[
  (True,False,True),(False,False,False),
  (True,True,False),(False,True,False),
])
def test_static_main_branch_block_not_github_disabled_status(stopped,extra_job,expected):
    assert m.source_blocks_all_jobs(source(stopped=stopped,extra_job=extra_job)) is expected

@pytest.mark.parametrize("expr",[
    "true",
    "always()",
    "github.event_name == 'workflow_dispatch'",
    "inputs.confirmation == 'RUN'",
    "!false",
    "fromJSON('true')",
    "0",
    "null",
])
def test_any_non_literal_false_expression_is_not_treated_as_disabled(expr):
    txt=source(stopped=True).replace("if: "+"$"+"{{ false }}",
                   "if: "+"$"+"{{ "+expr+" }}")
    assert m.source_blocks_all_jobs(txt) is False

def test_all_exact_legacy_sources_exist_and_contain_original_manual_secrets():
    current=m.actual_workflows(".")
    assert len(current)>=330
    assert len(m.LEGACY)==15
    for name in m.LEGACY:
        path=m.ROOT+"/"+name
        assert path in current
        assert m.is_manual_provider(current[path])
        assert len(m.jobs(current[path]))==1

def test_source_inventory_correctly_reports_admin_disable_not_did_disable():
    report=m.audit(files=files_fixture())
    assert report["legacy_historical_workflows_source_unchanged"]==15
    assert report["manual_provider_secret_workflows_detected"]==15
    assert report["manual_provider_source_jobs_without_static_stop"]==15
    assert len(report["github_actions_disable_targets"])==15
    assert report["github_actions_workflow_state_verified"] is False
    assert report["github_workflow_disable_operations_performed"]==0
    assert report["all_provider_bypasses_closed"] is False

def test_other_unknown_legacy_provider_is_appended_to_action_list():
    fs=files_fixture()
    extra=m.ROOT+"/new-secret-provider.yml"
    fs[extra]=source()
    report=m.audit(files=fs)
    assert extra in report["github_actions_disable_targets"]
    assert report["manual_provider_secret_workflows_detected"]==16

def test_false_gate_alone_removes_source_flag_without_claiming_hard_stop():
    data=m.audit(files=files_fixture(source(stopped=True)))
    assert data["manual_provider_source_jobs_without_static_stop"]==0
    assert data["all_provider_bypasses_closed"] is False
    assert data["github_actions_workflow_state_verified"] is False

def test_history_missing_or_changed_is_rejected():
    fs=files_fixture()
    fs.pop(m.ROOT+"/"+m.LEGACY[0])
    with pytest.raises(m.Denied,match="HISTORICAL_WORKFLOW_MISSING"):
        m.audit(files=fs)
    fs=files_fixture(source(manual=False))
    with pytest.raises(m.Denied,match="HISTORICAL_PROVIDER_WORKFLOW_DRIFT"):
        m.audit(files=fs)

def test_base_requires_immutable_sha_and_cannot_read_arbitrary_paths():
    for sha in ("main","1"*39,None,True):
        with pytest.raises(m.Denied,match="EXACT_BASE_SHA_REQUIRED"):
            m.read_base_file(".",sha,m.ROOT+"/sample.yml")
    with pytest.raises(m.Denied,match="PATH_OUTSIDE_WORKFLOWS"):
        m.read_base_file(".","a"*40,"secrets/openai.key")

def test_actual_main_git_blobs_remain_identical_to_exact_PR_base_if_available():
    base=os.environ.get("FINAL128_387_BASE_SHA")
    if base is None:return
    report=m.audit(files=m.actual_workflows("."),base_sha=base,root=".")
    assert report["legacy_historical_workflows_source_unchanged"]==15
    assert all(x["historical_source_matches_exact_base"] for x in report["historical_original_source_evidence"])
    assert report["all_provider_bypasses_closed"] is False
    assert report["github_repository_provider_secrets_revoked"] is False
    assert report["new_provider_calls"]==0

def test_read_only_auditor_cannot_revoke_secrets_or_dispatch_provider():
    code=Path(m.__file__).read_text()
    for bad in ("http.client.HTTPSConnection(","requests.post(",
                "from openai import","gh api -X PUT","gh api -X POST"):
        assert bad not in code
