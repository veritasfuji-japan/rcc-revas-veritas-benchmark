"""#390 refusal tests: immutable scope, observed vs attested, no Provider."""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import json
import pytest

from scripts import final128_390_environment_approval_readback_v1 as m

def evidence():
    f,h=m.snapshot()
    assert len(h)==64
    return f

def remote_fixture():
    run={**m.RUN,"run_started_at":m.RUN["started_at"],
         "actor":{"login":"veritasfuji-japan"}}
    run.pop("started_at",None)
    jobs={"total_count":2,"jobs":[{
        **{k:v for k,v in j.items() if k!="steps"},
        "steps":[{"name":name,"status":"completed","conclusion":"success"}
                 for name in j["steps"]]} for j in m.JOBS]}
    reviews=[{"user":{"login":x["user"]},
              "state":x["state"],"comment":x["comment"],
              "environments":[{"name":x["environment"],
                               "id":x["environment_id"],
                               "can_admins_bypass":x["can_admins_bypass"]}]}
             for x in m.REVIEWS]
    return run,jobs,reviews

def test_frozen_fixture_exact_and_limits():
    f=evidence()
    assert m.validate_fixture(f) is True
    assert f["completed_run"]["head_sha"]==m.SHA
    assert f["historical_pending_observation_not_replayable"][
        "independent_third_party_can_reproduce_prior_waiting_now"] is False
    assert f["proof_boundary"]["paid_task1_execution_authorized"] is False

@pytest.mark.parametrize("section,key,value",[
    ("completed_run","status","waiting"),
    ("completed_run","conclusion","failure"),
    ("completed_run","head_sha","a"*40),
    ("completed_run","actor","another-user"),
    ("completed_run","run_attempt",2),
    ("completed_run","run_attempt",True),
    ("historical_pending_observation_not_replayable","wait_timer_minutes",1),
    ("historical_pending_observation_not_replayable",
     "original_pending_response_persisted_as_signed_raw_evidence",True),
    ("historical_pending_observation_not_replayable",
     "independent_third_party_can_reproduce_prior_waiting_now",True),
    ("proof_boundary","self_review_permitted",False),
    ("proof_boundary","global_atomic_oneuse_issuer_proven",True),
    ("proof_boundary","account_hard_budget_cap_proven",True),
    ("proof_boundary","paid_task1_execution_authorized",True),
    ("proof_boundary","independent_reviewer_observed",True),
    ("proof_boundary","new_native_utility_measurement",True),
])
def test_unsupported_promotion_or_scope_tamper_denied(section,key,value):
    bad=deepcopy(evidence())
    bad[section][key]=value
    with pytest.raises(m.Denied):
        m.validate_fixture(bad)

@pytest.mark.parametrize("section,key,value",[
    ("completed_jobs",0,"unexpected-job"),
    ("completed_approval_records",1,"another-user"),
])
def test_job_or_review_identity_forgery_denied(section,key,value):
    bad=deepcopy(evidence())
    if section=="completed_jobs":bad[section][key]["name"]=value
    else:bad[section][key]["user"]=value
    with pytest.raises(m.Denied):
        m.validate_fixture(bad)

def test_zero_tolerance_to_extra_field():
    bad=deepcopy(evidence())
    bad["trusted_attestation"]="PROVEN"
    with pytest.raises(m.Denied,match="FIXTURE_SHAPE"):
        m.validate_fixture(bad)

def test_duplicate_json_key_or_invalid_number_denied():
    with pytest.raises(m.Denied,match="DUPLICATE_JSON_KEY"):
        m.json_strict(b'{"state":"approved","state":"false"}')
    with pytest.raises(m.Denied,match="NONFINITE_JSON"):
        m.json_strict(b'{"value":NaN}')

def test_actual_rest_projection_passes_and_never_grants_authority():
    run,jobs,reviews=remote_fixture()
    r=m.validate_live(run=run,jobs=jobs,reviews=reviews)
    assert r["public_github_rest_readback_matches_frozen_subset"] is True
    assert r["approval_exact_timestamp_unavailable"] is True
    assert r["historical_waiting_status_not_replayable_from_current_api"] is True
    assert r["third_party_immutable_provenance_verified"] is False
    assert r["actual_paid_provider_calls_in_probe"]==0
    assert r["task1_live_authorized"] is False
    assert r["production_bypass_proven"] is False

@pytest.mark.parametrize("kind",[
    "run-status","run-head","run-branch","run-event","run-attempt",
    "preflight-fail","marker-fail","new-job","fake-job-step",
    "missing-review","new-review","different-reviewer",
    "fake-bot-comment","env-bypass","different-env",
])
def test_readback_deviation_denied(kind):
    run,jobs,reviews=remote_fixture()
    if kind=="run-status":run["status"]="waiting"
    elif kind=="run-head":run["head_sha"]="b"*40
    elif kind=="run-branch":run["head_branch"]="unsafe"
    elif kind=="run-event":run["event"]="push"
    elif kind=="run-attempt":run["run_attempt"]=2
    elif kind=="preflight-fail":jobs["jobs"][0]["conclusion"]="failure"
    elif kind=="marker-fail":jobs["jobs"][1]["conclusion"]="failure"
    elif kind=="new-job":
        jobs["total_count"]=3
        jobs["jobs"].append(deepcopy(jobs["jobs"][0]))
    elif kind=="fake-job-step":jobs["jobs"][1]["steps"][1]["name"]="Provider POST"
    elif kind=="missing-review":reviews.pop()
    elif kind=="new-review":reviews.append(deepcopy(reviews[0]))
    elif kind=="different-reviewer":reviews[1]["user"]["login"]="someone-else"
    elif kind=="fake-bot-comment":reviews[0]["comment"]="two minute wait timer"
    elif kind=="env-bypass":reviews[1]["environments"][0]["can_admins_bypass"]=True
    elif kind=="different-env":reviews[0]["environments"][0]["name"]="default"
    with pytest.raises(m.Denied):
        m.validate_live(run=run,jobs=jobs,reviews=reviews)

def test_only_exact_three_public_get_urls_permitted():
    for url in (
        "https://api.openai.com/v1/responses",
        m.ENDPOINTS["historical_pending"],
        m.ENDPOINTS["run"]+"/../git/refs",
        m.ENDPOINTS["run"]+"?token=secret",
        "http://api.github.com/repos/other/repo",
    ):
        with pytest.raises(m.Denied,match="ONLY_FIXED_READBACK_URLS"):
            m.public_get(url)

def test_no_provider_or_auth_logic_in_auditor():
    source=Path(m.__file__).read_text(encoding="utf8")
    for token in (
        "from openai import", "import openai", "secrets.OPENAI_API_KEY",
        "gh api -X POST", "workflow_dispatch:", "Authorization: Bearer",
        "requests.post(", "GITHUB_TOKEN", "subprocess.run(",
    ):
        assert token not in source

def test_pr_ci_is_readonly_and_not_dispatchable():
    source=Path(".github/workflows/final128-390-task1-environment-evidence-readback-v1.yml").read_text()
    assert "on:\n  pull_request:" in source
    assert "workflow_dispatch:" not in source
    assert "environment: task1-real-model-pilot" not in source
    assert "secrets.OPENAI_API_KEY" not in source
    assert "permissions:\n  contents: read" in source
    assert "persist-credentials: false" in source
