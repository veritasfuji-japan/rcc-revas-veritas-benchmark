"""#393 frozen evidence verification (no Provider, no GitHub mutations)."""
from __future__ import annotations
import copy
from pathlib import Path
import pytest
from scripts import final128_393_task1_tag_denial_evidence_readback_v1 as m

@pytest.fixture
def f():
    return m.fixture()[0]

@pytest.fixture
def run(f):
    r=f["source_run"]
    return {k:r[k] for k in (
        "id","event","head_branch","head_sha","run_attempt",
        "created_at","run_started_at","updated_at","status","conclusion")} | {
        "actor":{"login":r["actor"]},
        "triggering_actor":{"login":r["triggering_actor"]},
    }

@pytest.fixture
def jobs(f):
    arr=[]
    for j in f["completed_jobs"]:
        x={k:j[k] for k in (
            "id","name","status","conclusion","started_at","completed_at")}
        x["steps"]=[{"name":n,"conclusion":"success","status":"completed"} for n in j["steps"]]
        arr.append(x)
    return {"total_count":2,"jobs":arr}

@pytest.fixture
def approvals(f):
    return [{"state":x["state"],"comment":x["comment"],
             "user":{"login":x["user"]},
             "environments":[{"name":x["environment"],
                              "id":x["environment_id"],
                              "can_admins_bypass":x["can_admins_bypass"]}]}
            for x in f["completed_environment_approval_records"]]

@pytest.fixture
def live(run,jobs,approvals):
    return {
      "run":run,"jobs":jobs,"approvals":approvals,
      "tag":{"ref":m.TAG,"object":{"type":"commit","sha":m.TAG_SHA}},
      "ruleset":{
        "id":m.RULESET,"name":"Task1 Single-Use Protection",
        "target":"tag","enforcement":"active",
        "conditions":{"ref_name":{"include":["refs/tags/final128-task1-real-ab-once-v1-*"],
                                  "exclude":[]}},
        "rules":[{"type":"deletion"},{"type":"non_fast_forward"},{"type":"update"}],
        "bypass_actors":[],"current_user_can_bypass":"never",
      },
    }

def test_exact_file_blob_frozen_and_scope_preserved(f):
    d,sha=m.fixture()
    assert len(sha)==64
    assert d["verdict"]==m.VERDICT
    assert d["limitations"]["globally_atomic_once_issuer_proven"] is False
    assert d["limitations"]["paid_task1_authorized"] is False
    assert d["limitations"]["independent_third_party_reviewer_observed"] is False
    assert d["limitations"]["raw_http_denial_response_bodies_archived"] is False

def test_workflow_source_sha_pinned_to_run(f):
    assert f["source_run"]["workflow_git_blob_sha"]==m.WORKFLOW_BLOB
    assert m.git_blob(Path(m.WORKFLOW).read_text())==m.WORKFLOW_BLOB

def test_full_synthetic_live_frozen_projection_matches(f,live):
    e=m.validate_live(f,live)
    assert e["current_run_job_and_approvals_match_frozen_evidence"] is True
    assert e["current_exact_test_tag_still_unchanged"] is True
    assert e["historic_raw_job_log_lines_replayed_from_public_get"] is False
    assert e["independent_signed_attestation_proven"] is False
    assert e["paid_task1_authorized"] is False
    assert e["actual_github_tag_write_attempts_from_this_auditor"]==0

@pytest.mark.parametrize("key,bad",[
 ("id",1),("event","push"),("head_branch","wrong"),("head_sha","f"*40),
 ("run_attempt",2),("actor","different"),("triggering_actor","other"),
 ("conclusion","failure"),("status","queued"),("workflow_git_blob_sha","0"*40),
 ("workflow_path","test.yml"),
])
def test_frozen_run_mutation_denied(f,key,bad):
    x=copy.deepcopy(f)
    x["source_run"][key]=bad
    with pytest.raises(m.Denied):
        m.validate_fixture(x)

@pytest.mark.parametrize("job,key,bad",[
 (0,"id",0),(1,"id",4),(0,"name","wrong"),(1,"name","wrong"),
 (0,"conclusion","failure"),(1,"status","waiting"),
 (1,"started_at","2026-10-13T13:00:00Z"),
])
def test_frozen_job_mutation_denied(f,job,key,bad):
    x=copy.deepcopy(f)
    x["completed_jobs"][job][key]=bad
    with pytest.raises(m.Denied):
        m.validate_fixture(x)

@pytest.mark.parametrize("user,key,bad",[
 (0,"user","other"),(1,"user","other"),(0,"state","rejected"),
 (0,"environment","production"),(1,"environment_id",1),
 (1,"can_admins_bypass",True),
])
def test_frozen_approval_mutation_denied(f,user,key,bad):
    x=copy.deepcopy(f)
    x["completed_environment_approval_records"][user][key]=bad
    with pytest.raises(m.Denied):
        m.validate_fixture(x)

@pytest.mark.parametrize("index,key,bad",[
 (1,"message","WRONG"),(2,"message","WRONG"),
 (3,"message","WRONG"),(4,"message","WRONG"),
 (5,"message","WRONG"),(0,"job_id",3),
 (4,"timestamp_utc","2020-01-01T00:00:00Z"),
])
def test_log_marker_mutation_denied(f,index,key,bad):
    x=copy.deepcopy(f)
    x["selected_log_markers"][index][key]=bad
    with pytest.raises(m.Denied):
        m.validate_fixture(x)

@pytest.mark.parametrize("phase,key,bad",[
 (0,"phase","restore"),(0,"http_status",201),
 (1,"method","POST"),(1,"http_status",200),
 (2,"decision","SUCCESS"),(2,"expected_same_ref_after",False),
])
def test_negative_results_not_overpromoted(f,phase,key,bad):
    x=copy.deepcopy(f)
    x["negative_operations"][phase][key]=bad
    with pytest.raises(m.Denied):
        m.validate_fixture(x)

@pytest.mark.parametrize("key,bad",[
 ("ref",m.REPO),("sha","f"*40),("type","tag"),
 ("before_after_each_mutation_verified_by_completed_workflow",False),
])
def test_frozen_test_tag_mutation_denied(f,key,bad):
    x=copy.deepcopy(f)
    x["live_tag_at_freeze"][key]=bad
    with pytest.raises(m.Denied):
        m.validate_fixture(x)

@pytest.mark.parametrize("key",[
 "paid_task1_authorized","globally_atomic_once_issuer_proven",
 "independent_third_party_reviewer_observed",
 "production_tag_bypass_resistance_proven",
 "official_final128_utility_remeasured",
 "raw_http_denial_response_bodies_archived",
])
def test_unproven_claim_cannot_be_flipped_to_proven(f,key):
    x=copy.deepcopy(f)
    x["limitations"][key]=True
    with pytest.raises(m.Denied):
        m.validate_fixture(x)

@pytest.mark.parametrize("part,key,bad",[
 ("run","head_sha","1"*40),("run","conclusion","failure"),
 ("run","run_attempt",2),("run","event","push"),
 ("jobs","total_count",3),("tag","ref","refs/tags/other"),
 ("ruleset","enforcement","disabled"),
 ("ruleset","target","branch"),("ruleset","name","another"),
])
def test_live_changes_refused(f,live,part,key,bad):
    d=copy.deepcopy(live)
    d[part][key]=bad
    with pytest.raises(m.Denied):
        m.validate_live(f,d)

@pytest.mark.parametrize("mut",[
 "remove_delete","remove_update","remove_nonfastforward",
 "nonmatching_include","exclude_tag","alter_tag_sha","tag_type",
 "incomplete_jobs","wrong_step_status","wrong_approval",
])
def test_live_negative_evidence_mismatch_denied(f,live,mut):
    d=copy.deepcopy(live)
    if mut=="remove_delete":d["ruleset"]["rules"].pop(0)
    elif mut=="remove_update":d["ruleset"]["rules"].pop(2)
    elif mut=="remove_nonfastforward":d["ruleset"]["rules"].pop(1)
    elif mut=="nonmatching_include":d["ruleset"]["conditions"]["ref_name"]["include"]=["refs/tags/else-*"]
    elif mut=="exclude_tag":d["ruleset"]["conditions"]["ref_name"]["exclude"]=[m.TAG]
    elif mut=="alter_tag_sha":d["tag"]["object"]["sha"]="f"*40
    elif mut=="tag_type":d["tag"]["object"]["type"]="tag"
    elif mut=="incomplete_jobs":d["jobs"]["jobs"].pop()
    elif mut=="wrong_step_status":d["jobs"]["jobs"][1]["steps"][1]["conclusion"]="failure"
    elif mut=="wrong_approval":d["approvals"][1]["user"]["login"]="stranger"
    with pytest.raises(m.Denied):
        m.validate_live(f,d)

@pytest.mark.parametrize("key",["bypass_actors","current_user_can_bypass"])
def test_missing_privileged_bypass_not_claimed_safe(f,live,key):
    d=copy.deepcopy(live)
    del d["ruleset"][key]
    e=m.validate_live(f,d)
    assert e["current_ruleset_bypass_fields_status"]=="UNKNOWN_MISSING_FIELDS"
    assert e["global_task1_once_proven"] is False

def test_explicit_privileged_bypass_refused(f,live):
    d=copy.deepcopy(live)
    d["ruleset"]["bypass_actors"]=[{"actor_type":"OrganizationAdmin"}]
    with pytest.raises(m.Denied):
        m.validate_live(f,d)

@pytest.mark.parametrize("bad",[
 "https://api.openai.com/v1/responses",
 m.ROOT+"/git/refs",
 m.ROOT+"/actions/runs/"+str(m.RUN_ID)+"/rerun",
 m.URLS["run"]+"?write=1",
 "http://api.github.com/repos/"+m.REPO,
])
def test_public_read_only_url_allowlist_denies_non_exact(bad):
    with pytest.raises(m.Denied,match="ONLY_FIVE_PUBLIC_GET_URLS"):
        m.public_get(bad)

def test_source_has_no_http_write_path_or_credentials():
    src=Path(m.__file__).read_text()
    for token in ['method="POST"','method="PATCH"','method="DELETE"',
                  "Authorization","GH_TOKEN","GITHUB_TOKEN",
                  "OPENAI_API_KEY","requests.post(","subprocess.run("]:
        assert token not in src

def test_dedicated_pr_ci_cannot_dispatch_or_write():
    p=Path(".github/workflows/final128-393-tag-denial-evidence-readonly-freeze-v1.yml")
    text=p.read_text()
    assert "on:\n  pull_request:" in text
    assert "workflow_dispatch:" not in text
    assert "permissions:\n  contents: read" in text
    assert "persist-credentials: false" in text
    assert "contents: write" not in text
    assert "environment:\n      name: task1-real-model-pilot" not in text

def test_strict_json_rejects_duplicate_key_and_nan():
    with pytest.raises(m.Denied):
        m.strict_json(b'{"id":1,"id":2}')
    with pytest.raises(m.Denied):
        m.strict_json(b'{"id":NaN}')
