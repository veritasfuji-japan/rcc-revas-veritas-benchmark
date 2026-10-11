"""#328 separate local networked server simulates remote GitHub create-only CAS.

NO real GitHub token, GitHub ref, Provider token, Provider POST or real effect.
"""
from __future__ import annotations
import copy
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import task4_328_remote_mock_github_cas_v1 as m
from scripts import task4_328_remote_mock_report_v1 as proof

@pytest.fixture(scope="module")
def report():
    return proof.remote_emulation_report()

@pytest.fixture()
def mock_server(tmp_path,monkeypatch):
    for k in m.SENSITIVE:monkeypatch.delenv(k,raising=False)
    server=proof.LocalRemoteServer(tmp_path)
    server.start()
    try:yield server
    finally:server.stop()

def direct(port,body=None,*,headers=None,path=None,method="POST",raw=None):
    req=raw if raw is not None else m.raw_json(m.BODY if body is None else body)
    h=headers or {"Authorization":m.FAKE_HEADER,"Content-Type":"application/json"}
    c=HTTPConnection("127.0.0.1",port,timeout=5)
    try:
        c.request(method,path or m.API_PATH,body=req,headers=h)
        x=c.getresponse();payload=json.loads(x.read())
        return (x.status,payload)
    finally:c.close()

def test_independent_client_processes_share_only_server_side_mock_cas(report):
    assert report["separate_python_client_processes"]==16
    assert report["remote_mock_atomic_create_successes"]==1
    assert report["remote_mock_duplicate_refusals"]==15
    assert report["server_process_restart_then_new_client_duplicate_refused"] is True
    assert report["remote_commit_then_lost_http_response_marked_unknown"] is True
    assert report["retry_after_lost_response_and_server_restart_rejected"] is True
    assert report["backend_race_record"]==report["backend_unknown_record"]
    assert report["backend_race_record"]["ref"]==m.REF
    assert report["backend_race_record"]["body_sha"]==m.sha(m.BODY)
    assert [x["process_exit_code"] for x in report["race_processes"]].count(0)==1
    assert [x["process_exit_code"] for x in report["race_processes"]].count(3)==15
    assert report["missing_response_client"]["process_exit_code"]==4
    assert report["after_crash_refused_client"]["process_exit_code"]==3
    assert report["actual_github_remote_ref_writes"]==0
    assert report["actual_distinct_github_actions_runs_tested"]==0
    assert report["real_github_ref_cas_guarantee_proven"] is False
    assert report["remote_backend_independent_admin_immutability_proven"] is False
    assert report["real_model_api_posts"]==report["new_final128_scores"]==0
    assert report["real_provider_dispatch"]=="DENY"
    without=dict(report);signature=without.pop("report_sha256")
    assert m.sha(without)==signature

def test_real_git_ref_scope_consistent_and_not_random():
    assert m.REF.startswith("refs/heads/offline-test-ledger/task4-328-")
    assert m.BODY=={"ref":m.REF,"sha":m.PARENT_MAIN}
    assert m.frozen_scope()["arms"]==["A","B"]
    assert m.frozen_scope()["source_case"]==m.SOURCE_CASE
    assert m.frozen_scope()["base_merged_main"]==m.PARENT_MAIN
    assert len(m.REF.split("-")[-1])==32
    assert m.API_PATH=="/repos/veritasfuji-japan/rcc-revas-veritas-benchmark/git/refs"

def test_direct_duplicate_mock_create_returns_201_then_422(mock_server):
    status,body=direct(mock_server.port)
    assert status==201
    assert body["test_only_mock_ref_created"] is True
    assert body["real_provider_post_allowed"] is False
    status,body=direct(mock_server.port)
    assert status==422
    assert body["real_provider_post_allowed"] is False
    assert len(m.backend_rows(mock_server.db))==1

@pytest.mark.parametrize("attack",[
    "wrong_repo_path","wrong_post_verb","missing_auth",
    "wrong_auth","missing_content_type","modified_ref",
    "modified_commit_sha","extra_payload_field","absent_payload_field",
    "duplicate_json_key","malformed_json","malformed_unicode","empty_body",
    "large_body"
])
def test_untrusted_remote_create_ref_post_denied_without_leasing(mock_server,attack):
    url=m.API_PATH;verb="POST"
    headers={"Authorization":m.FAKE_HEADER,"Content-Type":"application/json"}
    body=copy.deepcopy(m.BODY)
    buf=None
    if attack=="wrong_repo_path":url="/repos/attacker/other/git/refs"
    elif attack=="wrong_post_verb":verb="PUT"
    elif attack=="missing_auth":headers.pop("Authorization")
    elif attack=="wrong_auth":headers["Authorization"]="Bearer real-secret-not-allowed"
    elif attack=="missing_content_type":headers.pop("Content-Type")
    elif attack=="modified_ref":body["ref"]="refs/heads/main"
    elif attack=="modified_commit_sha":body["sha"]="0"*40
    elif attack=="extra_payload_field":body["force"]=True
    elif attack=="absent_payload_field":body.pop("ref")
    elif attack=="duplicate_json_key":buf=b'{"ref":"bad","ref":"worse","sha":"'+m.PARENT_MAIN.encode()+b'"}'
    elif attack=="malformed_json":buf=b'{"ref":'
    elif attack=="malformed_unicode":buf=b'\xff'
    elif attack=="empty_body":buf=b''
    elif attack=="large_body":buf=b' '*2100
    status,response=direct(mock_server.port,body,headers=headers,
                           path=url,method=verb,raw=buf)
    assert status not in (201,422)
    assert response["real_provider_post_allowed"] is False
    assert m.backend_rows(mock_server.db)==[]

def test_remote_lease_survives_server_termination_without_worker_db_access(mock_server):
    first=mock_server.worker(0)
    assert first["process_exit_code"]==0
    mock_server.stop()
    mock_server.start()
    denied=mock_server.worker(1)
    assert denied["process_exit_code"]==3
    assert m.backend_rows(mock_server.db)[0]["ref"]==m.REF

def test_post_commit_reply_loss_is_unknown_then_refused(mock_server):
    lost=mock_server.worker(0,drop=True)
    assert lost["state"]=="UNKNOWN_OR_MOCK_REJECTED_NO_RETRY"
    assert lost["process_exit_code"]==4
    assert len(m.backend_rows(mock_server.db))==1
    mocked_followup=mock_server.worker(1)
    assert mocked_followup["process_exit_code"]==3

@pytest.mark.parametrize("port",[-1,0,65536,True,"80",None])
def test_invalid_local_mock_port_is_refused(port):
    with pytest.raises(m.Denied):
        m.try_once(port=port,worker="worker-1")

@pytest.mark.parametrize("worker",["../main","other","worker-","worker-10000",
                                    "worker-1\n",True,1,None])
def test_invalid_worker_or_path_like_identity_rejected(worker):
    with pytest.raises(m.Denied):
        m.try_once(port=12345,worker=worker)

@pytest.mark.parametrize("key",m.SENSITIVE)
def test_any_existing_real_github_or_provider_secret_denied(key,monkeypatch):
    monkeypatch.setenv(key,"not-allowed")
    with pytest.raises(m.Denied):m.try_once(port=12345,worker="worker-1")
    monkeypatch.delenv(key,raising=False)

def test_mock_unknown_on_network_failure_no_external_fallback():
    # Local ephemeral unused socket: no remote server -> terminal UNKNOWN.
    listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    listener.bind(("127.0.0.1",0))
    port=listener.getsockname()[1]
    listener.close()
    r=m.try_once(port=port,worker="worker-1")
    assert r["http_status"] is None
    assert r["state"]=="UNKNOWN_OR_MOCK_REJECTED_NO_RETRY"
    assert r["real_provider_post_allowed"] is False

def test_live_provider_and_actual_github_refs_remain_denied_in_contract():
    c=json.loads((ROOT/"contracts/TASK4_328_REMOTE_GITREF_MOCK_OFFLINE_V1.json").read_text())
    assert c["rule_of_one"]==m.RULE
    assert c["exact_main_parent_sha"]==m.PARENT_MAIN
    assert c["test_only_git_ref"]==m.REF
    assert c["git_rest_create_ref_path"]==m.API_PATH
    assert c["external_http_hosts_allowed"]==["127.0.0.1"]
    assert c["backend_authority"]=="SINGLE_LOCALHOST_CAS_EMULATOR_PROCESS_NOT_GITHUB_API"
    for k in (
        "actual_github_ref_created","github_api_write_token_used",
        "cross_github_actions_runs_verified",
        "remote_delete_and_recreate_impossible",
        "independently_administered_lease","actual_provider_sender_present",
        "new_live_user_spend_authorization","production_single_use_proven"):
        assert c[k] is False
    assert all(c[k]==0 for k in ("actual_github_refs_written","actual_openai_posts",
                                 "new_genuine_model_scores"))
    assert c["real_provider_dispatch"]=="DENY"

def test_workflow_does_not_write_git_refs_or_expose_credentials():
    wf=(ROOT/".github/workflows/task4-328-remote-cas-emulation-offline-v1.yml").read_text()
    for forbidden in (
        "workflow_dispatch:","pull_request_target:","repository_dispatch:",
        "secrets.","contents: write","GITHUB_TOKEN:","GH_TOKEN:",
        "environment: task4-provider-protected"):
        assert forbidden not in wf
    assert "persist-credentials: false" in wf
    assert "contents: read" in wf
    assert 'OPENAI_API_KEY: ""' in wf
    assert "pull_request:" in wf
    s=(ROOT/"scripts/task4_328_remote_mock_github_cas_v1.py").read_text()
    assert 'HTTPConnection("127.0.0.1"' in s
    assert "https://api.github.com" not in s
    assert "https://api.openai.com" not in s
