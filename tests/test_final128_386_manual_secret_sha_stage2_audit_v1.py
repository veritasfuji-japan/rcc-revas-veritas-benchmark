"""#386 offline exact-diff Actions pinning validation and fail-closed controls."""
from __future__ import annotations
from pathlib import Path
import os
import pytest
from scripts import final128_386_manual_secret_sha_stage2_audit_v1 as m

PATH=m.PATHS[0]
def pre():
    return """name: Manual Provider Development
on:
  workflow_dispatch:
    inputs:
      confirmation:
        type: string
permissions:
  contents: read
jobs:
  testing:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: test -n "$OPENAI_API_KEY"
      - uses: actions/upload-artifact@v4
"""
def post():
    return m.transformed_base(pre())[0]

def test_exact_transformation_has_6_pins_and_none_other():
    s,n=m.transformed_base(pre())
    assert n==6
    assert s==post()
    assert "actions/checkout@v4" not in s
    assert "actions/setup-python@v5" not in s
    assert "actions/upload-artifact@v4" not in s
    assert s.count("11d5960a326750d5838078e36cf38b85af677262")==4

def test_staged_fixture_recognizes_secret_workflow_remains_unprotected():
    report=m.validate_exact_stage2_change(PATH,pre(),post())
    assert report["unchanged_except_exact_sha_pinning"] is True
    assert report["mutable_action_refs_replaced"]==6
    assert report["manual_trigger_still_present"] is True
    assert report["provider_secret_context_still_present"] is True
    assert report["protected_environment_bound_to_job"] is False
    assert report["manual_secret_workflow_not_approved_for_paid_run"] is True

@pytest.mark.parametrize("changes",[
    lambda s:s.replace("workflow_dispatch:", "push:"),
    lambda s:s.replace("contents: read","contents: write"),
    lambda s:s.replace("actions/checkout@","evil/checkout@",1),
    lambda s:s.replace("actions/upload-artifact@","actions/checkout@",1),
    lambda s:s.replace("runs-on: ubuntu-24.04","runs-on: ubuntu-latest"),
    lambda s:s.replace("jobs:\n","jobs:\n  forged:\n    runs-on: ubuntu-latest\n",1),
    lambda s:s.replace("test -n","test -z"),
    lambda s:s.replace("secrets.OPENAI_API_KEY","secrets.UNAPPROVED_BILLING_KEY"),
    lambda s:s.replace("run: test -n","run: echo UNSAFE && test -n"),
    lambda s:s+"\n  environment: task1-real-model-pilot\n",
    lambda s:s+"\n  permissions: write-all\n",
    lambda s:s.replace("actions/checkout@11d5960a326750d5838078e36cf38b85af677262","actions/checkout@v4",1),
])
def test_any_other_content_change_denied(changes):
    with pytest.raises(m.Refused,match="ONLY_APPROVED_SHA_REPLACEMENTS"):
        m.validate_exact_stage2_change(PATH,pre(),changes(post()))

def test_missing_original_uses_refused():
    old=pre().replace("actions/checkout@v4","actions/checkout@v5",1)
    with pytest.raises(m.Refused,match="EXPECTED_SIX"):
        m.validate_exact_stage2_change(PATH,old,m.transformed_base(old)[0])

def test_wrong_path_refused_even_when_same_bytes():
    with pytest.raises(m.Refused,match="WORKFLOW_NOT_IN_STAGE2"):
        m.validate_exact_stage2_change(".github/workflows/ci.yml",pre(),post())

def test_stage2_does_not_treat_self_approval_as_protected_authority():
    report=m.validate_exact_stage2_change(PATH,pre(),post())
    assert report["no_provider_execution_performed"] is True
    assert report["explicit_token_writes_found"] is False

def test_base_must_be_exact_git_sha_before_subprocess():
    for ref in ("main","a"*39,"",True,None):
        with pytest.raises(m.Refused,match="BASE_SHA_REQUIRED"):
            m.base_file(".",ref,PATH)

def test_must_not_read_out_of_scope_legacy_files():
    with pytest.raises(m.Refused,match="UNSCOPED_BASE_READ"):
        m.base_file(".","a"*40,".github/workflows/ci.yml")

def test_stage2_path_set_contains_only_four_selected_secret_manual_tasks():
    assert m.TASKS==(2,12,13,15)
    assert len(m.PATHS)==4
    assert len(set(m.PATHS))==4
    assert len(m.PINNED_ACTIONS)==3

def test_real_repo_stage2_files_have_exact_pinned_actions():
    fs=m.inventory.scan_directory(".")
    selected={f["path"]:f for f in fs if f["path"] in m.PATHS}
    assert set(selected)==set(m.PATHS)
    for f in selected.values():
        assert len(f["uses"])==6
        assert all(u["kind"]=="PINNED_ACTION_SHA" for u in f["uses"])
        assert f["manual_trigger_present"] is True
        assert f["secret_context_mentioned"] is True
        assert f["explicit_write_scopes"]==[]

def test_exact_real_base_and_head_diff_when_env_provided():
    base=os.environ.get("FINAL128_386_BASE_SHA")
    if base:
        report=m.audit_stage2(".",base)
        assert report["stage2_pinned_action_references"]==24
        assert report["remaining_manual_secret_workflows_without_protected_environment_in_stage2"]==4
        assert report["new_unsafe_reference_keys"]==[]
        assert report["actual_paid_provider_requests"]==0
        assert report["repository_wide_sha_enforcement_ready"] is False
        assert report["real_issuer_single_use_verified"] is False

def test_static_checker_has_no_live_provider_or_github_write_operations():
    code=Path(m.__file__).read_text()
    for forbidden in ("from openai import","http.client.HTTPSConnection(","requests.post(",
         "gh api -X POST","workflow_dispatch:","GITHUB_TOKEN: $"):
        assert forbidden not in code
