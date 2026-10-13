"""#392 test-only GitHub ref expected-denial logic; no live writes or dispatch."""
from __future__ import annotations
import ast
from pathlib import Path
import pytest
from scripts import final128_392_isolated_tag_negative_source_audit_v1 as m

@pytest.fixture
def workflow():
    return m.WORKFLOW.read_text(encoding="utf8")

def tag():
    return {"ref":m.REF,"object":{"type":"commit","sha":m.SHA}}

def rule():
    return {
      "id":24921425,"name":"Task1 Single-Use Protection",
      "target":"tag","enforcement":"active",
      "conditions":{"ref_name":{"include":["refs/tags/final128-task1-real-ab-once-v1-*"],
                                 "exclude":[]}},
      "rules":[{"type":"deletion"},{"type":"non_fast_forward"},{"type":"update"}],
      "bypass_actors":[],"current_user_can_bypass":"never",
    }

def classifiers(workflow):
    tree=ast.parse(m.embedded(workflow))
    names={"explicit_duplicate_denial","explicit_ruleset_denial"}
    selected=[node for node in tree.body if isinstance(node,ast.FunctionDef)
              and node.name in names]
    assert {x.name for x in selected}==names
    standalone=ast.fix_missing_locations(ast.Module(body=selected,type_ignores=[]))
    env={}
    exec(compile(standalone,"<isolated-392-offline-classifiers>","exec"),env)
    return env

def test_exact_source_and_staging_only(workflow):
    v=m.source_contract(workflow)
    assert v["workflow_exact_blob_sha"]==m.BLOB
    assert v["manual_negative_probe_staged_only"] is True
    assert v["actual_github_mutations_or_attempts_by_this_audit"]==0
    assert v["task1_paid_provider_authorized"] is False

@pytest.mark.parametrize("before,after",[
    ("workflow_dispatch:", "push:"),
    ("  contents: read","  contents: write"),
    ("      contents: write","      contents: read"),
    ("task1-real-model-pilot","unprotected"),
    ("cancel-in-progress: false","cancel-in-progress: true"),
    ("GITHUB_RUN_ATTEMPT","GITHUB_RUN_ID"),
    ("GH_NEGATIVE_TEST_TOKEN","OPENAI_API_KEY"),
    (m.CONSENT,"AUTOMATIC"),
    (m.REF,m.PRODUCTION_REF),
    (m.SHA,"0"*40),
    (m.DIFFERENT_SHA,"f"*40),
    ('call("POST", ROOT,','call("DELETE", ROOT,'),
    ('call("PATCH", TAG_URL,','call("PATCH", ROOT,'),
    ('call("DELETE", TAG_URL)','call("DELETE", ROOT)'),
    ('assert_unchanged("AFTER_UPDATE")','assert_unchanged("AFTER_DUPLICATE")'),
    ('assert_unchanged("AFTER_DELETE")','print("not checked")'),
    ('assert_unchanged("BEFORE")','print("not checked")'),
    ("urllib.request.build_opener(NoRedirect())","urllib.request.build_opener()"),
])
def test_any_source_change_must_be_re_reviewed(workflow,before,after):
    assert before in workflow
    with pytest.raises(m.Denied,match="SOURCE_BLOB_PIN"):
        m.source_contract(workflow.replace(before,after,1))

def test_fixed_test_tag_and_ruleset_are_only_configuration_observation():
    e=m.validate_observation(tag(),rule())
    assert e["current_tag_matches_creation_proof"]
    assert e["rule_matches_test_tag_and_has_prohibitions"]
    assert e["bypass_status"]=="NO_BYPASS_OBSERVED"
    assert e["real_negative_mutation_experiment_executed"] is False
    assert e["task1_paid_provider_authorized"] is False

@pytest.mark.parametrize("bad",[
 "wrong_sha","wrong_ref","wrong_type","missing_tag","rules_disabled",
 "rules_different","rule_excludes","rules_missing_delete","rules_missing_update",
 "rules_missing_non_ff","rules_bypass_target","rules_wrong_type",
 "rule_bad_id","rule_bad_name",
])
def test_tag_or_ruleset_mismatch_denied(bad):
    t,r=tag(),rule()
    if bad=="wrong_sha":t["object"]["sha"]="1"*40
    elif bad=="wrong_ref":t["ref"]=m.PRODUCTION_REF
    elif bad=="wrong_type":t["object"]["type"]="tag"
    elif bad=="missing_tag":t={}
    elif bad=="rules_disabled":r["enforcement"]="disabled"
    elif bad=="rules_different":r["conditions"]["ref_name"]["include"]=["refs/tags/elsewhere-*"]
    elif bad=="rule_excludes":r["conditions"]["ref_name"]["exclude"]=[m.REF]
    elif bad=="rules_missing_delete":r["rules"].pop(0)
    elif bad=="rules_missing_update":r["rules"].pop(2)
    elif bad=="rules_missing_non_ff":r["rules"].pop(1)
    elif bad=="rules_bypass_target":r["target"]="branch"
    elif bad=="rules_wrong_type":r["rules"]=[]
    elif bad=="rule_bad_id":r["id"]=1
    elif bad=="rule_bad_name":r["name"]="Else"
    with pytest.raises(m.Denied):
        m.validate_observation(t,r)

@pytest.mark.parametrize("missing",["bypass_actors","current_user_can_bypass"])
def test_unavailable_bypass_data_is_unknown_not_allowed(missing):
    r=rule()
    del r[missing]
    e=m.validate_observation(tag(),r)
    assert e["bypass_metadata_complete"] is False
    assert e["bypass_status"]=="UNKNOWN_MISSING_PRIVILEGED_FIELDS"
    assert e["real_negative_mutation_experiment_executed"] is False

@pytest.mark.parametrize("bypass",[
    [{"actor_id":1}], [{"actor_type":"OrganizationAdmin"}]
])
def test_observed_bypass_is_not_silently_accepted(bypass):
    r=rule()
    r["bypass_actors"]=bypass
    e=m.validate_observation(tag(),r)
    assert e["bypass_status"]=="BYPASS_OR_PRIVILEGE_PRESENT"

@pytest.mark.parametrize("status,body,expected",[
  (422,{"message":"Reference already exists"},True),
  (422,{"message":"Validation Failed","errors":[{"code":"already_exists"}]},True),
  (403,{"message":"Reference already exists"},False),
  (422,{"message":"Validation Failed"},False),
  (422,{"errors":[{"code":"unprocessable"}]},False),
  (201,{"ref":m.REF},False),
  (500,{"message":"Reference already exists"},False),
  (401,{"message":"Bad credentials"},False),
])
def test_duplicate_requires_explicit_already_exists_denial(workflow,status,body,expected):
    f=classifiers(workflow)["explicit_duplicate_denial"]
    assert f(status,body) is expected

@pytest.mark.parametrize("phase,status,body,expected",[
 ("UPDATE",422,{"message":"Repository rule violations found: Cannot update this protected ref"},True),
 ("UPDATE",403,{"message":"Repository rule violations found: Cannot force-push to this tag"},True),
 ("DELETE",422,{"message":"Repository rule violations found: Cannot delete this protected ref"},True),
 ("DELETE",403,{"message":"Repository rule violations found: Cannot delete this tag"},True),
 ("UPDATE",422,{"message":"Cannot update this protected ref"},False),
 ("DELETE",422,{"message":"Cannot delete this protected ref"},False),
 ("UPDATE",403,{"message":"Forbidden"},False),
 ("DELETE",403,{"message":"Forbidden"},False),
 ("UPDATE",200,{"message":"Repository rule violations found: Cannot update this protected ref"},False),
 ("DELETE",204,{"message":"Repository rule violations found: Cannot delete this tag"},False),
 ("UPDATE",500,{"message":"Repository rule violations found: Cannot update this protected ref"},False),
 ("DELETE",401,{"message":"Bad credentials"},False),
 ("DELETE",422,{"message":"Repository rule violations found: Cannot update this protected ref"},False),
 ("UPDATE",422,{"message":"Repository rule violations found: Cannot delete this protected ref"},False),
])
def test_ruleset_denial_classifier_fail_closed(workflow,phase,status,body,expected):
    f=classifiers(workflow)["explicit_ruleset_denial"]
    assert f(status,body,phase) is expected

def test_no_network_mutation_in_audit_script():
    text=Path(m.__file__).read_text(encoding="utf8")
    for forbidden in (
      'method="POST"','method="PATCH"','method="DELETE"',
      "import openai","from openai import","subprocess.run(",
      "requests.post(","gh api -X POST","GITHUB_TOKEN",
    ):
        assert forbidden not in text

def test_get_url_allowlist_denies_provider_and_mutating_endpoints():
    for bad in ("https://api.openai.com/v1/responses",
                m.ROOT+"/git/refs",
                m.TAG_URL+"?force=true",
                "http://api.github.com/repos/"+m.REPO):
        with pytest.raises(m.Denied,match="ONLY_TWO_PUBLIC_GET_URLS"):
            m.public_get(bad)

def test_pr_ci_is_non_dispatchable_and_readonly():
    text=Path(".github/workflows/final128-392-isolated-tag-negative-source-readonly-audit.yml").read_text()
    assert "on:\n  pull_request:" in text
    assert "workflow_dispatch:" not in text
    assert "permissions:\n  contents: read" in text
    assert "persist-credentials: false" in text
    assert "environment: task1-real-model-pilot" not in text
    assert "secrets.OPENAI_API_KEY" not in text
    assert "contents: write" not in text
