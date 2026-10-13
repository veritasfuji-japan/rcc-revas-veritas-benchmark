"""#383 immutable-protocol-ref, offline fake atomic create/no replay, DENY live."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json,os,socket
from pathlib import Path
import pytest

from scripts import final128_383_task1_global_once_issuer_gate_offline_v1 as m
from scripts import final128_382_first_two_responses_once_transport_v1 as prev

SHA="a"*40
RUN="38352912345"

@pytest.fixture(autouse=True)
def empty_secrets_and_block_network(monkeypatch):
    def fail(*args,**kw):pytest.fail("383_CI_CANNOT_ACCESS_REAL_NETWORK")
    monkeypatch.setattr(socket.socket,"connect",fail)
    monkeypatch.setattr(socket.socket,"connect_ex",fail)
    monkeypatch.setattr(socket,"create_connection",fail)
    for key in ("OPENAI_API_KEY","TASK4_OPENAI_API_KEY","ANTHROPIC_API_KEY",
                "OPENAI_BASE_URL","GH_TOKEN","GITHUB_TOKEN"):
        monkeypatch.delenv(key,raising=False)

def context(**fields):
    return replace(m.candidate_context(main_sha=SHA,run_id=RUN),**fields)

def test_proposed_tag_is_global_singleton_not_per_sha_or_run():
    a=m.proposed_git_ref_create_request(context())
    b=m.proposed_git_ref_create_request(
        m.candidate_context(main_sha="b"*40,run_id="38352999999"))
    assert a["body"]["ref"]==b["body"]["ref"]==m.PROTOCOL_REF
    assert a["body"]["sha"]!=b["body"]["sha"]
    assert m.PROTOCOL_REF==prev.CONSUMED_REF
    assert a["method"]=="POST"
    assert a["path"]=="/repos/veritasfuji-japan/rcc-revas-veritas-benchmark/git/refs"
    assert a["expected_status"]==201
    assert a["protocol_wide_ref_not_derived_from_sha_or_run"] is True
    assert a["external_post_executed"] is False
    assert a["real_authorization_granted"] is False

def test_context_is_explicitly_untrusted_proposal_not_execution_approval():
    plan=m.inspect_candidate(context())
    assert plan["status"]=="EXACT_SCOPE_CANDIDATE_NOT_TRUSTED"
    assert plan["candidate_main_sha"]==SHA
    assert plan["candidate_run_id"]==RUN
    assert plan["original_first_wire_sha256"]
    assert plan["max_first_model_attempts_proposed"]==2
    assert plan["local_reservation_estimate_usd_not_provider_hard_cap"]=="0.0104192"
    assert plan["requested_total_usd_max_not_billing_cap"]=="1.00"
    assert plan["new_utility_scores"] is None
    assert plan["live_dispatch_authorized"] is False
    assert plan["trusted_issuer_configuration_verified"] is False
    assert plan["real_global_single_use_ref_created"] is False
    assert len(plan["unverified_external_gates"])>=9
    assert plan["fresh_real_operator_approval_observed"] is False

def test_real_github_tag_is_never_created_by_module(tmp_path):
    store=m.OfflineOnlyFakeGitRefs()
    report=m.rehearse_offline_atomic_once(
        ctx=context(),store=store,evidence_path=tmp_path/"issuer.jsonl")
    assert store.attempts==1
    assert store.snapshot()=={m.PROTOCOL_REF:SHA}
    assert report["status"]=="OFFLINE_FAKE_SINGLETON_CONSUMED_NOT_REAL"
    assert report["local_fake_create_attempts"]==1
    assert report["actual_paid_provider_calls"]==0
    assert report["actual_native_scorer_calls"]==0
    assert report["real_github_ref_created"] is False
    assert report["permission_to_call_provider"] is False
    assert report["github_ruleset_live_verified"] is False
    assert report["fresh_operator_approval_verified"] is False
    assert report["official_utility_or_attack_scores"] is None

def test_fsync_audit_hash_chain_and_no_plaintext_authorization(tmp_path):
    store=m.OfflineOnlyFakeGitRefs()
    proof=m.rehearse_offline_atomic_once(
        ctx=context(),store=store,evidence_path=tmp_path/"issuer.jsonl")
    path=tmp_path/"issuer.jsonl"
    events=[json.loads(x) for x in path.read_text().splitlines()]
    assert [e["event"]["phase"] for e in events]==[
        "PROPOSED_CONTEXT_ACCEPTED_SCOPE_ONLY",
        "BEFORE_FAKE_ATOMIC_REF_CREATE_NO_RETRY",
        "FAKE_REF_CREATED_NOT_PROTECTED",
        "OFFLINE_REHEARSAL_ENDED_LIVE_DENIED",
    ]
    old="0"*64
    for i,e in enumerate(events):
        assert e["sequence"]==i and e["previous_sha256"]==old
        expected=m.digest({
          "sequence":i,"previous_sha256":old,"event":e["event"]})
        assert e["record_sha256"]==expected
        old=expected
    assert old==proof["local_audit_chain_tip_sha256"]
    assert "Bearer " not in path.read_text()
    assert "OPENAI_API_KEY" not in path.read_text()
    assert "APPROVE_TASK1" not in path.read_text()
    assert path.stat().st_mode & 0o077 == 0

def test_no_local_same_logpath_replay(tmp_path):
    path=tmp_path/"issuer.jsonl"
    st=m.OfflineOnlyFakeGitRefs()
    m.rehearse_offline_atomic_once(ctx=context(),store=st,evidence_path=path)
    with pytest.raises(m.Blocked,match="LOCAL_EVIDENCE_REPLAY_DENIED"):
        m.rehearse_offline_atomic_once(ctx=context(),store=st,evidence_path=path)
    assert st.attempts==1

def test_global_singleton_blocks_different_run_and_sha(tmp_path):
    st=m.OfflineOnlyFakeGitRefs()
    m.rehearse_offline_atomic_once(
        ctx=context(),store=st,evidence_path=tmp_path/"A.jsonl")
    new_run=context(run_id="38352999999",main_sha="b"*40)
    with pytest.raises(m.Blocked,match="FAKE_GITHUB_REF_CREATE_REFUSED"):
        m.rehearse_offline_atomic_once(
            ctx=new_run,store=st,evidence_path=tmp_path/"B.jsonl")
    assert st.attempts==2
    assert st.snapshot()=={m.PROTOCOL_REF:SHA}
    bad_journal=(tmp_path/"B.jsonl").read_text()
    assert "FAKE_CONSUMPTION_UNKNOWN_OR_REFUSED_STOP" in bad_journal
    assert "BEFORE_FAKE_ATOMIC_REF_CREATE_NO_RETRY" in bad_journal

@pytest.mark.parametrize("fault,should_exist",[
    ("prewrite_unknown",False),
    ("postwrite_unknown",True),
    ("server_reject",False),
])
def test_unknown_or_refused_creates_permanent_no_retry_local_journal(
        tmp_path,fault,should_exist):
    st=m.OfflineOnlyFakeGitRefs(fault=fault)
    path=tmp_path/"issuer.jsonl"
    with pytest.raises(m.Blocked):
        m.rehearse_offline_atomic_once(
            ctx=context(),store=st,evidence_path=path)
    assert st.attempts==1
    assert (m.PROTOCOL_REF in st.snapshot()) is should_exist
    assert "FAKE_CONSUMPTION_UNKNOWN_OR_REFUSED_STOP" in path.read_text()
    with pytest.raises(m.Blocked,match="LOCAL_EVIDENCE_REPLAY_DENIED"):
        m.rehearse_offline_atomic_once(
            ctx=context(),store=st,evidence_path=path)
    assert st.attempts==1

def test_concurrent_local_workers_only_one_can_create_tag(tmp_path):
    st=m.OfflineOnlyFakeGitRefs()
    def run(i):
        try:
            m.rehearse_offline_atomic_once(
                ctx=context(run_id=str(38352912345+i)),
                store=st,evidence_path=tmp_path/f"worker{i}.jsonl")
            return "success"
        except m.Blocked:
            return "blocked"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(run,range(2)))
    assert sorted(results)==["blocked","success"]
    assert st.attempts==2
    assert len(st.snapshot())==1
    assert list(st.snapshot())==[m.PROTOCOL_REF]

@pytest.mark.parametrize("key,val",[
    ("repository","attacker/repo"),
    ("ref","refs/heads/feature"),
    ("main_sha","bad"),
    ("main_sha","A"*40),
    ("run_id","local-run"),
    ("run_id","0"),
    ("run_attempt",2),
    ("run_attempt",True),
    ("event","pull_request"),
    ("event","push"),
    ("actor","attacker"),
    ("environment","unprotected"),
    ("case_id","banking:task4"),
    ("model","other-model"),
    ("max_usd","2.00"),
    ("max_usd",1),
    ("max_calls",4),
    ("max_calls",True),
])
def test_all_untrusted_proposal_scope_changes_refused(key,val):
    with pytest.raises(m.Blocked):
        m.inspect_candidate(context(**{key:val}))

def test_untrusted_json_or_approvals_cannot_be_candidate_context():
    for raw in (
        {"repository":m.REPO,"approved":True},
        True,None,"I APPROVE TASK1 A/B ONE RUN UP TO USD 1",
    ):
        with pytest.raises(m.Blocked,match="CONTEXT_TYPE"):
            m.inspect_candidate(raw)

def test_wrong_store_type_refused_without_a_mutation(tmp_path):
    for fake in ({},None,object(),{"create_ref":True}):
        with pytest.raises(m.Blocked,match="LOCAL_FAKE_STORE_EXACT_TYPE"):
            m.rehearse_offline_atomic_once(
                ctx=context(),store=fake,
                evidence_path=tmp_path/"will-not-be-created.jsonl")
    assert not (tmp_path/"will-not-be-created.jsonl").exists()

@pytest.mark.parametrize("claim",[
  None,True,{"approved":True},
  {"tag_was_created":True,"environment_protected":True,
   "project_limit_verified":True},
  "I APPROVE TASK1 A/B ONE RUN UP TO USD 1",
])
def test_fake_receipt_or_old_approval_never_authorizes_live(claim):
    with pytest.raises(m.Blocked,match="REAL_PROTECTED_ISSUER"):
        m.live_execution_gate(claim)

def test_fake_store_mode_rejects_invalid_fault():
    with pytest.raises(m.Blocked,match="BAD_FAULT_MODE"):
        m.OfflineOnlyFakeGitRefs(fault="live-github")

def test_journal_rejects_secret_material(tmp_path):
    journal=m.OfflineJournal(tmp_path/"journal.jsonl")
    try:
        for value in (
            {"api_key":"something"},
            {"secret_value":"something"},
            {"authorization":"Bearer fake"},
            {"operator_phrase":"grant"},
        ):
            with pytest.raises(m.Blocked,match="PROTECTED_MATERIAL"):
                journal.add(value)
    finally:
        journal.close()

def test_no_live_workflow_api_client_or_secret_loader_in_module():
    code=Path(m.__file__).read_text()
    assert "if __name__" not in code
    assert "http.client.HTTPSConnection(" not in code
    assert "requests.post(" not in code
    assert "OpenAI(" not in code
    assert "gh api -X POST" not in code
    assert "import httpx" not in code

def test_policy_does_not_elevate_prior_351_or_382_permission():
    assert prev.prepare_two_first_packets()["live_dispatch_authorized"] is False
    assert m.inspect_candidate(context())["real_global_single_use_ref_created"] is False
    assert m.inspect_candidate(context())["live_dispatch_authorized"] is False
