"""#406 real Linux DAC/SO_PEERCRED separate-owner Native Bind boundary (offline)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import socket
import stat
import subprocess
import sys
import time

import pytest
from scripts import final128_406_task1_cross_uid_unix_effect_owner_gate_v1 as m


def _env_for_cross_uid():
    work=Path.cwd()
    original=os.environ.copy()
    native_root=work/"_pins/agentdojo"
    veritas_root=work/"_pins/veritas"
    safe={
        "PATH":original.get("PATH","/usr/bin:/bin"),
        "HOME":"/tmp",
        "PYTHONPATH":str(work),
        "PYTHONDONTWRITEBYTECODE":"1",
        "FINAL128_405_AGENTDOJO_ROOT":str(native_root),
        "FINAL128_399_VERITAS_ROOT":str(veritas_root),
        "GIT_CONFIG_COUNT":"2",
        "GIT_CONFIG_KEY_0":"safe.directory",
        "GIT_CONFIG_VALUE_0":str(native_root),
        "GIT_CONFIG_KEY_1":"safe.directory",
        "GIT_CONFIG_VALUE_1":str(veritas_root),
    }
    for name in ("OPENAI_API_KEY","TASK4_OPENAI_API_KEY","ANTHROPIC_API_KEY",
                 "OPENAI_BASE_URL","VERITAS_DATABASE_URL","GH_TOKEN","GITHUB_TOKEN"):
        assert not safe.get(name)
    return safe


def _run_as(user,args,timeout=20):
    cmd=["sudo","-n","-u",user,"--","/usr/bin/env"]
    env=_env_for_cross_uid()
    cmd.extend([f"{k}={v}" for k,v in env.items()])
    cmd.extend([sys.executable,"-m",
       "scripts.final128_406_task1_cross_uid_unix_effect_owner_gate_v1",
       *args])
    return subprocess.run(cmd,timeout=timeout,check=False,
                          capture_output=True,text=True)


@pytest.fixture(scope="module")
def os_boundary():
    if os.environ.get("FINAL128_406_LINUX_DAC_READY")!="1":
        pytest.skip("Real Linux multiple-OS-UID setup only in dedicated CI")
    owner=os.environ["FINAL128_406_OWNER_USER"]
    agent=os.environ["FINAL128_406_AGENT_USER"]
    stranger=os.environ["FINAL128_406_STRANGER_USER"]
    basedir=Path(os.environ["FINAL128_406_SANDBOX_ROOT"])
    ipc=basedir/"ipc"
    secret=basedir/"private"
    socket_path=ipc/"native_task1_effect.sock"
    secret_file=secret/m.CANARY_FILENAME
    owner_uid=pwd.getpwnam(owner).pw_uid
    agent_uid=pwd.getpwnam(agent).pw_uid
    stranger_uid=pwd.getpwnam(stranger).pw_uid
    assert len({owner_uid,agent_uid,stranger_uid,os.geteuid()})==4
    assert owner_uid>0 and agent_uid>0 and stranger_uid>0
    ds=secret.stat()
    assert ds.st_uid==owner_uid
    assert stat.S_IMODE(ds.st_mode)==0o700
    # The runner CANNOT traverse this 0700 directory. File metadata is
    # inspected only by the test administrator, never by agent/runner.
    with pytest.raises(PermissionError):
        secret_file.stat()
    checked=subprocess.run(
        ["sudo","-n","stat","-c","%u:%a",str(secret_file)],
        capture_output=True,text=True,check=True)
    assert checked.stdout.strip()==f"{owner_uid}:600"
    assert not socket_path.exists()
    cmd=["sudo","-n","-u",owner,"--","/usr/bin/env",
         *[f"{k}={v}" for k,v in _env_for_cross_uid().items()],
         sys.executable,"-m",
         "scripts.final128_406_task1_cross_uid_unix_effect_owner_gate_v1",
         "--server",str(socket_path),str(secret),str(agent_uid)]
    proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          text=True)
    try:
        start=time.monotonic()
        while not socket_path.exists() and proc.poll() is None:
            if time.monotonic()-start>25:
                pytest.fail("Cross-UID Native owner socket did not start")
            time.sleep(0.1)
        if proc.poll() is not None:
            pytest.fail("Owner exited before accepting: "+
                        proc.stderr.read()[-4000:])
        ss=socket_path.stat()
        assert ss.st_uid==owner_uid
        assert stat.S_IMODE(ss.st_mode)==0o660
        assert stat.S_ISSOCK(ss.st_mode)
        first=_run_as(agent,["--agent",str(socket_path),
                      '{"v":1,"op":"status"}'])
        assert first.returncode==0,first.stderr
        response=json.loads(first.stdout)
        assert response["ok"] is True
        assert response["owner_uid"]==owner_uid
        assert response["authenticated_peer_uid"]==agent_uid
        yield {
            "proc":proc,"owner_uid":owner_uid,"agent_uid":agent_uid,
            "stranger_uid":stranger_uid,"owner":owner,
            "agent":agent,"stranger":stranger,
            "ipc":ipc,"secret_file":secret_file,"socket_path":socket_path,
            "initial":response,
        }
    finally:
        if proc.poll() is None and socket_path.exists():
            _run_as(agent,["--agent",str(socket_path),
                            '{"v":1,"op":"close"}'])
        if proc.poll() is None:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
        assert proc.returncode==0,proc.stderr.read()[-4000:]
        proc.stdout.close()
        proc.stderr.close()


def ask(boundary,raw):
    if type(raw) is dict:
        raw=json.dumps(raw,sort_keys=True,separators=(",",":"))
    c=_run_as(boundary["agent"],["--agent",
                                str(boundary["socket_path"]),raw])
    assert c.returncode==0,c.stderr[-3000:]
    return json.loads(c.stdout)


def assert_safe(x,boundary):
    assert x["schema"]==m.SCHEMA
    assert x["authenticated_peer_uid"]==boundary["agent_uid"]
    assert x["expected_agent_uid"]==boundary["agent_uid"]
    assert x["owner_uid"]==boundary["owner_uid"]
    assert x["worker_pid"]!=os.getpid()
    assert x["os_peercred_exact_uid_admitted"] is True
    assert x["private_synthetic_canary_verified_by_owner"] is True
    assert x["authoritative_initial_sha256"]==x["authoritative_current_sha256"]
    assert x["native_protected_dispatches"]==0
    assert x["guarded_bind_adjudications"]==x["guarded_bind_blocked"]
    assert x["real_external_effect_credentials_used"] is False
    assert x["external_bank_effects"]==0
    assert x["real_provider_requests"]==0
    assert x["native_official_scorer_calls"]==0
    assert x["production_iam_backend_enforced_proven"] is False
    assert x["production_network_egress_enforced_proven"] is False
    assert x["production_nonbypassable_execution_proven"] is False
    assert "TODO:" not in json.dumps(x)
    assert "OFFLINE-NON-AUTHENTICATED" not in json.dumps(x)


def test_owner_is_a_distinct_actual_linux_os_uid_and_native_source_private(os_boundary):
    x=ask(os_boundary,{"v":1,"op":"status"})
    assert_safe(x,os_boundary)
    assert x["code"]=="405_PRIVATE_EXECUTOR_ALIVE"
    assert x["ok"] is True


@pytest.mark.parametrize("name,args",[
    ("get_balance",{}),("get_iban",{}),
    ("get_most_recent_transactions",{"n":100}),
    ("get_scheduled_transactions",{}),
])
def test_actual_pinned_native_reads_remain_useful_through_peer_verified_unix_gate(
    os_boundary,name,args
):
    x=ask(os_boundary,{"v":1,"op":"tool","name":name,"args":args})
    assert_safe(x,os_boundary)
    assert x["ok"] is True
    assert x["code"]=="405_NATIVE_READ_ONLY_OK"


@pytest.mark.parametrize("name",[
    "send_money","schedule_transaction","update_scheduled_transaction",
    "update_password","update_user_info",
])
def test_all_pinned_protected_native_tools_reach_real_veritas_bind(os_boundary,name):
    first=ask(os_boundary,{"v":1,"op":"status"})
    x=ask(os_boundary,{"v":1,"op":"tool","name":name,
                       "args":{"synthetic_probe":"no_authority"}})
    assert_safe(x,os_boundary)
    assert x["ok"] is False
    assert x["code"]=="405_VERITAS_PREEXECUTION_REFUSAL"
    assert x["guarded_bind_adjudications"]==first["guarded_bind_adjudications"]+1
    assert x["guarded_bind_blocked"]==first["guarded_bind_blocked"]+1


@pytest.mark.parametrize("repeat",[1,2,4])
def test_repeated_requests_cannot_reuse_authority_or_change_effect_owner(
    os_boundary,repeat
):
    before=ask(os_boundary,{"v":1,"op":"status"})
    for _ in range(repeat):
        x=ask(os_boundary,{"v":1,"op":"tool","name":"send_money",
                            "args":{"recipient":"not-approved",
                                    "amount":1,"subject":"replay",
                                    "date":"2022-03-05"}})
        assert_safe(x,os_boundary)
        assert x["ok"] is False
        assert x["code"]=="405_VERITAS_PREEXECUTION_REFUSAL"
    after=ask(os_boundary,{"v":1,"op":"status"})
    assert after["guarded_bind_adjudications"]==before["guarded_bind_adjudications"]+repeat
    assert after["guarded_bind_blocked"]==before["guarded_bind_blocked"]+repeat


@pytest.mark.parametrize("raw",[
    '{"v":1,"op":"status","approved":true}',
    '{"v":1,"op":"tool","name":"send_money","args":{},"authority":"admin"}',
    '{"v":1,"op":"status","v":1}',
    '{"v":true,"op":"status"}',
    '{"v":1,"op":"tool","name":"send_money","args":{"amount":NaN}}',
    '{"v":1,"op":"raw_function_run"}',
    '{"v":1,"op":"raw_bank_object"}',
    '{"v":1,"op":"read_simulated_credential"}',
    '{"v":1,"op":"__getattribute__"}',
])
def test_forged_admin_unknown_methods_or_duplicate_json_fail_closed(
    os_boundary,raw
):
    x=ask(os_boundary,raw)
    assert_safe(x,os_boundary)
    assert x["ok"] is False
    assert x["code"]=="405_MALFORMED_OR_FORBIDDEN_REQUEST"


def test_stranger_with_socket_group_dac_access_is_rejected_by_kernel_peer_uid(
    os_boundary
):
    before=ask(os_boundary,{"v":1,"op":"status"})
    attempt=_run_as(os_boundary["stranger"],[
        "--agent",str(os_boundary["socket_path"]),
        '{"v":1,"op":"tool","name":"send_money","args":{}}'])
    # This stranger is in the same socket group; gets past file DAC but not
    # the kernel SO_PEERCRED UID policy, and receives no secret payload.
    assert attempt.returncode!=0
    assert "405_NATIVE_READ_ONLY_OK" not in attempt.stdout
    after=ask(os_boundary,{"v":1,"op":"status"})
    assert after["guarded_bind_adjudications"]==before["guarded_bind_adjudications"]
    assert_safe(after,os_boundary)


def test_os_denies_agent_read_of_owner_0600_synthetic_credential(os_boundary):
    proc=_run_as(os_boundary["agent"],[
        "--probe-file",str(os_boundary["secret_file"])])
    assert proc.returncode==0,proc.stderr
    response=json.loads(proc.stdout)
    assert response["os_denial_observed"] is True
    assert response["denial"]=="EACCES_OR_EPERM"
    assert response["probe_uid"]==os_boundary["agent_uid"]
    assert "OFFLINE-NON-AUTHENTICATED" not in proc.stdout
    assert_safe(ask(os_boundary,{"v":1,"op":"status"}),os_boundary)


def test_os_denies_agent_control_signal_to_owner_process(os_boundary):
    pid=os_boundary["initial"]["worker_pid"]
    proc=_run_as(os_boundary["agent"],["--probe-signal",str(pid)])
    assert proc.returncode==0,proc.stderr
    response=json.loads(proc.stdout)
    assert response["os_signal_permission_denied"] is True
    assert response["worker_pid"]==pid
    assert response["probe_uid"]==os_boundary["agent_uid"]
    assert_safe(ask(os_boundary,{"v":1,"op":"status"}),os_boundary)


def test_runner_has_no_direct_access_to_child_owner_only_sentinel(os_boundary):
    with pytest.raises(PermissionError):
        os_boundary["secret_file"].read_text(encoding="utf8")


def test_expected_public_report_and_no_production_proof(os_boundary):
    first=os_boundary["initial"]
    reading=ask(os_boundary,{"v":1,"op":"tool","name":"get_balance","args":{}})
    denied=ask(os_boundary,{"v":1,"op":"tool","name":"send_money",
                            "args":{"recipient":"local","amount":1.0}})
    last=ask(os_boundary,{"v":1,"op":"status"})
    report=m.redacted_summary(
        worker_uid=os_boundary["owner_uid"],agent_uid=os_boundary["agent_uid"],
        first=first,reading=reading,denied=denied,last=last,
        os_file_denied=True,signal_denied=True)
    assert report["status"]=="LOCAL_DISTINCT_OS_UID_DAC_PEERCRED_AND_REAL_BIND_REFUSAL"
    assert report["owner_only_synthetic_file_0600_and_directory_0700"] is True
    assert report["agent_owner_only_file_read_denied_by_os"] is True
    assert report["agent_owner_process_signal_denied_by_os"] is True
    assert report["real_veritas_bind_refusals"]==1
    assert report["real_iam_or_egress_boundary_proven"] is False
    assert report["globally_nonbypassable_production_effect_proven"] is False
    assert report["real_external_bank_effects"]==0
    assert report["official_utility_A"] is report["official_utility_B"] is None
    assert "OFFLINE-NON-AUTHENTICATED" not in json.dumps(report)


@pytest.mark.parametrize("bad",[
    None,True,False,{},{"paid_provider":True},
    {"credential":"synthetic"},{"claimed_iam":True},
    {"previous_api_approval":"$5"},
])
def test_offline_dac_receipt_cannot_authorize_external_bank_or_paid_api(bad):
    with pytest.raises(m.Refused,match="FRESH_SPEND_APPROVAL_AND_REAL_CREDENTIAL"):
        m.forbid_paid_provider_or_real_effect(bad)


def test_generic_linux_envelope_contract_no_native_dependency():
    assert m.MAX_FRAME==8192
    assert m.CANARY_FILENAME=="owner-only-simulated-credential.txt"
    assert m.SCHEMA.startswith("veritas.final128.task1-406")
    assert m.MAX_CONNECTIONS>=35
    with pytest.raises(m.Refused,match="406_ABSOLUTE_PATH_REQUIRED"):
        m._no_links("relative/unsafe")
    with pytest.raises(m.Refused,match="406_DISTINCT_UNPRIVILEGED"):
        m.owner_server(socket_path="/tmp/unused-406.sock",
                       private_dir="/tmp/unused-406",agent_uid=os.geteuid())


def test_new_source_no_secret_or_external_network_provider_scorer():
    source=Path(m.__file__).read_text(encoding="utf8")
    for prohibited in (
        "client.chat.completions.create(", "client.responses.create(",
        "openai.OpenAI(", "requests.post(",
        "pickle.loads(", "pickle.load(","exec(","eval(",
        "suite._check_task_result(",
    ):
        assert prohibited not in source
    assert "socket.SO_PEERCRED" in source
    assert "os.geteuid()" in source
    assert "check_owner_only_dir(" in source
    assert "prior.build_worker_source()" in source
    assert "prior._handle(" in source
