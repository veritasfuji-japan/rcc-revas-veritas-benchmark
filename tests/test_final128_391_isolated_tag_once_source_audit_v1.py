"""#391 read-only source and rule protection negative tests."""
from __future__ import annotations
import ast
from pathlib import Path
import pytest
from scripts import final128_391_isolated_tag_once_source_audit_v1 as m

def rule():
    return {
       "id":m.RULESET_ID,"name":"Task1 Single-Use Protection",
       "target":"tag","enforcement":"active",
       "conditions":{"ref_name":{"include":[
           "refs/tags/final128-task1-real-ab-once-v1-*",
           "refs/tags/final128-task1-first-two-real-responses-v1-consumed"
       ],"exclude":[]}},
       "rules":[{"type":"deletion"},{"type":"update"},{"type":"non_fast_forward"}],
       "bypass_actors":[],"current_user_can_bypass":"never",
    }

def workflow():
    return m.WORKFLOW.read_text(encoding="utf8")

def test_pinned_workflow_not_executed_by_tests():
    p=m.source_contract(workflow())
    assert p["status"]=="STAGED_ISOLATED_GITHUB_WRITE_NOT_EXECUTED"
    assert p["actual_github_tag_posts_in_this_audit"]==0
    assert p["task1_live_provider_authorized"] is False

@pytest.mark.parametrize("before,after",[
    ("workflow_dispatch:", "push:"),
    ("  contents: read","  contents: write"),
    ("      contents: write","      contents: read"),
    ("cancel-in-progress: false","cancel-in-progress: true"),
    ("task1-real-model-pilot","wrong-environment"),
    ("I AUTHORIZE ONE TEST-ONLY GITHUB TAG CREATE NO PROVIDER", "DISPATCH"),
    ("GITHUB_RUN_ATTEMPT","GITHUB_REPO"),
    (m.TAG,"refs/tags/final128-task1-first-two-real-responses-v1-consumed"),
    ('method="POST"','method="DELETE"'),
    ('method="GET"','method="PATCH"'),
    ('urllib.request.urlopen(post, timeout=12)', 'urllib.request.urlopen(post, timeout=100)'),
])
def test_any_workflow_drift_fails_closed(before,after):
    src=workflow()
    assert before in src
    with pytest.raises(m.Denied,match="EXACT_GIT_BLOB_MISMATCH"):
        m.source_contract(src.replace(before,after,1))

@pytest.mark.parametrize("addition",[
    "    - uses: actions/checkout@v4",
    "      OPENAI_API_KEY: secrets.OPENAI_API_KEY",
    "      run: gh api -X PATCH",
    "      run: curl https://api.openai.com/v1/responses",
    "  push:",
])
def test_unsafe_addition_fails_closed(addition):
    with pytest.raises(m.Denied):
        m.source_contract(workflow()+"\n"+addition+"\n")

def test_ruleset_scope_observed_is_not_mutation_proof():
    x=m.ruleset_status(rule(),"absent")
    assert x["configured_rule_covers_isolated_tag"] is True
    assert x["source_readiness_for_later_separate_manual_probe"] is True
    assert x["actual_tag_immutability_proven_by_this_readback"] is False
    assert x["github_write_from_this_check"] is False

@pytest.mark.parametrize("change",[
    "inactive","pattern","exclude","bypass","current_bypass",
    "no_delete","no_update","no_nonff","wrong_id","wrong_target","wrong_name",
])
def test_ruleset_defect_refuses_positive_observation(change):
    d=rule()
    if change=="inactive": d["enforcement"]="disabled"
    elif change=="pattern":d["conditions"]["ref_name"]["include"]=["refs/tags/elsewhere-*"]
    elif change=="exclude":d["conditions"]["ref_name"]["exclude"]=[m.TAG]
    elif change=="bypass":d["bypass_actors"]=[{"actor_id":1}]
    elif change=="current_bypass":d["current_user_can_bypass"]="always"
    elif change=="no_delete":d["rules"].pop(0)
    elif change=="no_update":d["rules"].pop(1)
    elif change=="no_nonff":d["rules"].pop(2)
    elif change=="wrong_id":d["id"]=1
    elif change=="wrong_target":d["target"]="branch"
    elif change=="wrong_name":d["name"]="Wrong"
    x=m.ruleset_status(d,"absent")
    assert x["configured_rule_covers_isolated_tag"] is False
    assert x["source_readiness_for_later_separate_manual_probe"] is False

@pytest.mark.parametrize("status",["absent","present","unknown"])
def test_ref_status_does_not_promote_authority(status):
    x=m.ruleset_status(rule(),status)
    assert x["actual_tag_immutability_proven_by_this_readback"] is False
    assert x["source_readiness_for_later_separate_manual_probe"] is (status=="absent")

def test_inline_python_compiles_but_not_executed():
    s=workflow()
    body=s.split("          python - <<'PY'\n",1)[1].split("          PY\n",1)[0]
    py="\n".join(line[10:] if line.startswith("          ") else line for line in body.splitlines())
    ast.parse(py)
    assert py.count('method="POST"')==1
    assert py.count('method="GET"')==1
    assert 'method="DELETE"' not in py
    assert 'method="PATCH"' not in py

def test_only_allowlisted_get_paths():
    for url in ("https://api.openai.com/v1/responses",
      "https://api.github.com/repos/other/repo/git/refs",
      m.ROOT+"/git/refs",m.RULE_URL+"?delete=true"):
        with pytest.raises(m.Denied,match="CLOSED_READ_URL_SET"):
            m.public_get(url)

def test_ci_is_non_mutating():
    s=Path(".github/workflows/final128-391-isolated-tag-source-readonly-audit-v1.yml").read_text()
    assert "on:\n  pull_request:" in s
    assert "workflow_dispatch:" not in s
    assert "permissions:\n  contents: read" in s
    assert "persist-credentials: false" in s
    assert "environment: task1-real-model-pilot" not in s
    assert "secrets.OPENAI_API_KEY" not in s

@pytest.mark.parametrize("omitted",["bypass_actors","current_user_can_bypass"])
def test_missing_public_bypass_field_is_unknown_not_clearance(omitted):
    r=rule()
    r.pop(omitted)
    x=m.ruleset_status(r,"absent")
    assert x["rule_scope_and_prohibition_fields_observed"] is True
    assert x["bypass_fields_complete"] is False
    assert x["bypass_status"]=="UNKNOWN_MISSING_FIELDS"
    assert x["configured_rule_covers_isolated_tag"] is False
    assert x["source_readiness_for_later_separate_manual_probe"] is False
