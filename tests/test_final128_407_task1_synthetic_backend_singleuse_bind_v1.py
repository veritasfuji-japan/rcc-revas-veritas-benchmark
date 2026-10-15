"""#407: real 3-principal Linux mock effect and pinned VERITAS Bind integration."""
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
from scripts import final128_407_task1_synthetic_backend_singleuse_bind_v1 as m

FULL_PIN="a75aba7631d3ca5fb7ab938965c97ead2f9ff84b"
VERITAS_PIN="a1d66aef02262cf8a913295270c3aafd159c6adb"


def _public_env():
    root=Path(os.environ["FINAL128_407_PROJECT_ROOT"])
    native=root/"_pins/agentdojo"
    veritas=root/"_pins/veritas"
    return {
        "PATH":os.environ.get("PATH","/usr/bin:/bin"),
        "HOME":"/tmp",
        "PYTHONPATH":os.pathsep.join((str(root),str(native/"src"),str(veritas))),
        "PYTHONDONTWRITEBYTECODE":"1",
        "FINAL128_405_AGENTDOJO_ROOT":str(native),
        "FINAL128_399_VERITAS_ROOT":str(veritas),
        "GIT_CONFIG_COUNT":"2",
        "GIT_CONFIG_KEY_0":"safe.directory",
        "GIT_CONFIG_VALUE_0":str(native),
        "GIT_CONFIG_KEY_1":"safe.directory",
        "GIT_CONFIG_VALUE_1":str(veritas),
    }


def _as(user,*args,timeout=18):
    cmd=["sudo","-n","-u",user,"--","/usr/bin/env"]+[
        f"{key}={value}" for key,value in _public_env().items()
    ]+[sys.executable,"-m",
       "scripts.final128_407_task1_synthetic_backend_singleuse_bind_v1",*args]
    return subprocess.run(cmd,capture_output=True,text=True,
                          timeout=timeout,check=False)


def _start(user,*args):
    cmd=["sudo","-n","-u",user,"--","/usr/bin/env"]+[
        f"{key}={value}" for key,value in _public_env().items()
    ]+[sys.executable,"-m",
       "scripts.final128_407_task1_synthetic_backend_singleuse_bind_v1",*args]
    return subprocess.Popen(cmd,stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,text=True)


def _wait_socket(proc,path):
    start=time.monotonic()
    while (subprocess.run(["sudo","-n","test","-S",str(path)],
                          capture_output=True).returncode!=0
           and proc.poll() is None):
        assert time.monotonic()-start<25,"407 isolated service startup timed out"
        time.sleep(0.1)
    assert proc.poll() is None,proc.stderr.read()[-4000:]


def _client(user,path,request):
    if type(request) is dict:
        request=json.dumps(request,sort_keys=True,separators=(",",":"))
    result=_as(user,"--client",str(path),request)
    return result


def _ask(user,path,request):
    p=_client(user,path,request)
    assert p.returncode==0,p.stderr[-3000:]
    reply=json.loads(p.stdout)
    assert reply["schema"]==m.SCHEMA
    assert reply["real_external_bank_effects"]==0
    assert reply["paid_model_provider_calls"]==0
    assert reply["native_task1_state_unchanged"] is True
    assert reply["production_backend_IAM_network_enforced_proven"] is False
    assert reply["real_human_authorization_used"] is False
    return reply


def run_crossuid_e2e_fixture():
    if os.environ.get("FINAL128_407_LINUX_READY")!="1":
        pytest.skip("Only in dedicated actual 4-Linux-UID CI")
    names={
        "backend":os.environ["FINAL128_407_BACKEND_USER"],
        "gateway":os.environ["FINAL128_407_GATEWAY_USER"],
        "agent":os.environ["FINAL128_407_AGENT_USER"],
        "stranger":os.environ["FINAL128_407_STRANGER_USER"],
    }
    uids={key:pwd.getpwnam(value).pw_uid for key,value in names.items()}
    assert len(set(uids.values())|{os.geteuid()})==5
    assert all(value>0 for value in uids.values())
    sandbox=Path(os.environ["FINAL128_407_SANDBOX_ROOT"])
    backend_socket=sandbox/"backend_ipc"/"backend.sock"
    gateway_socket=sandbox/"gateway_ipc"/"gateway.sock"
    owner_marker=sandbox/"backend_private"/"synthetic-fake-marker.txt"
    assert subprocess.run(["sudo","-n","test","-f",str(owner_marker)],
                          capture_output=True).returncode==0
    # A different OS principal must fail a direct file read.
    denied_file=subprocess.run(["sudo","-n","-u",names["agent"],
                                "cat",str(owner_marker)],
                               capture_output=True,text=True)
    assert denied_file.returncode!=0
    backend=_start(names["backend"],"--backend",str(backend_socket),
                   str(uids["gateway"]))
    gateway=None
    try:
        _wait_socket(backend,backend_socket)
        gateway=_start(names["gateway"],"--gateway",str(gateway_socket),
                       str(backend_socket),str(uids["agent"]),str(uids["backend"]))
        _wait_socket(gateway,gateway_socket)
        # Full independent principal check, including backend direct bypass.
        before=_ask(names["agent"],gateway_socket,{"v":1,"op":"status"})
        assert before["gateway_uid"]==uids["gateway"]
        assert before["backend_uid"]==uids["backend"]
        assert before["authorized_agent_uid"]==uids["agent"]
        assert before["backend_counter"]==0
        assert before["backend_effect_count"]==0
        assert before["backend_grant_consumed"] is False

        direct=_client(names["agent"],backend_socket,
                       {"v":1,"op":"apply","target":m.TARGET,
                        "units":m.UNITS,"grant":m.GRANT})
        assert direct.returncode!=0
        stranger=_client(names["stranger"],gateway_socket,
                         {"v":1,"op":"execute","target":m.TARGET,
                          "units":m.UNITS,"grant":m.GRANT})
        assert stranger.returncode!=0
        after_bypass=_ask(names["agent"],gateway_socket,{"v":1,"op":"status"})
        assert after_bypass["backend_state_sha256"]==before["backend_state_sha256"]

        native_probe=_ask(names["agent"],gateway_socket,
                          {"v":1,"op":"native_probe"})
        assert native_probe["ok"] is False
        assert native_probe["code"]=="407_TASK1_REAL_BIND_BLOCKED"
        assert native_probe["native_task1_real_bind_blocks"]>=1
        assert native_probe["backend_counter"]==0

        denial_cases=[
            {"v":1,"op":"execute","target":m.TARGET,"units":m.UNITS,"grant":"forged"},
            {"v":1,"op":"execute","target":m.TARGET,"units":8,"grant":m.GRANT},
            {"v":1,"op":"execute","target":"wrong","units":7,"grant":m.GRANT},
            {"v":1,"op":"execute","target":m.TARGET,"units":True,"grant":m.GRANT},
            {"v":1,"op":"execute","target":m.TARGET,"units":7,
             "grant":m.GRANT,"admin":True},
            {"v":1,"op":"issue_grant","target":m.TARGET,"units":7,"grant":m.GRANT},
            {"v":1,"op":"backend_apply","target":m.TARGET,"units":7,"grant":m.GRANT},
            {"v":1,"op":"execute","target":m.TARGET,"units":7},
            {"v":False,"op":"status"},
        ]
        denials=[]
        for case in denial_cases:
            x=_ask(names["agent"],gateway_socket,case)
            assert x["ok"] is False
            assert x["backend_counter"]==0
            assert x["backend_effect_count"]==0
            assert x["backend_state_sha256"]==before["backend_state_sha256"]
            denials.append(x)
        # Genuine frozen VERITAS execute_bind_adjudication commits exactly
        # one source-authorized synthetic effect at separately owned backend.
        authorized={"v":1,"op":"execute","target":m.TARGET,
                    "units":m.UNITS,"grant":m.GRANT}
        applied=_ask(names["agent"],gateway_socket,authorized)
        assert applied["ok"] is True
        assert applied["code"]=="407_BIND_COMMITTED_BACKEND_ONCE"
        assert applied["bind_final_outcome"]=="COMMITTED"
        assert applied["bind_receipt_sha256"]
        assert applied["effect_receipt_sha256"]
        assert applied["backend_counter"]==7
        assert applied["backend_effect_count"]==1
        assert applied["backend_grant_consumed"] is True
        assert applied["backend_state_sha256"]!=before["backend_state_sha256"]
        # Even the *authorized gateway UID* cannot replay the consumed
        # grant at the separately owned sink. This is stronger than only
        # checking the gateway's in-memory replay flag.
        backend_repeat=_client(names["gateway"],backend_socket,
            {"v":1,"op":"apply","target":m.TARGET,
             "units":m.UNITS,"grant":m.GRANT})
        assert backend_repeat.returncode==0,backend_repeat.stderr[-1200:]
        sink_repeat=json.loads(backend_repeat.stdout)
        assert sink_repeat["schema"]==m.SCHEMA
        assert sink_repeat["ok"] is False
        assert sink_repeat["code"]=="407_BACKEND_UNBOUND_OR_CONSUMED"
        assert sink_repeat["state_sha256"]==applied["backend_state_sha256"]
        replay=_ask(names["agent"],gateway_socket,authorized)
        assert replay["ok"] is False
        assert replay["code"]=="407_GATE_SINGLEUSE_REPLAY_DENIED"
        after=_ask(names["agent"],gateway_socket,{"v":1,"op":"status"})
        assert after["backend_counter"]==7
        assert after["backend_effect_count"]==1
        assert after["backend_state_sha256"]==applied["backend_state_sha256"]
        assert replay["backend_state_sha256"]==applied["backend_state_sha256"]
        assert after["bind_receipt_sha256"]==applied["bind_receipt_sha256"]
        assert after["effect_receipt_sha256"]==applied["effect_receipt_sha256"]
        report=m.redacted_report(
            start=before,end=after,replay=replay,denials=denials,
            native_refusal=native_probe,
            agent_uid=uids["agent"],gateway_uid=uids["gateway"],
            backend_uid=uids["backend"])
        assert report["gateway_real_veritas_bind_committed"]==1
        assert report["mock_backend_applied_effect_count"]==1
        assert report["backend_owned_atomic_singleuse_consumption"] is True
        assert report["task1_native_readonly_policy_still_enforced"] is True
        assert report["global_nonbypassable_execution_proven"] is False
        assert report["production_credential_or_IAM_network_proven"] is False
        assert "synthetic-fake-marker" not in json.dumps(report)
        Path("results").mkdir(exist_ok=True)
        Path("results/final128-407-redacted-native-ab.json").write_text(
            json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf8")
        return report
    finally:
        if gateway is not None:
            if gateway.poll() is None:
                closed=_client(names["agent"],gateway_socket,{"v":1,"op":"close"})
                assert closed.returncode==0,closed.stderr[-1000:]
            gateway.wait(timeout=12)
            assert gateway.returncode==0,gateway.stderr.read()[-3500:]
            gateway.stdout.close()
            gateway.stderr.close()
        if backend.poll() is None:
            closed=_client(names["gateway"],backend_socket,{"v":1,"op":"close"})
            assert closed.returncode==0,closed.stderr[-1000:]
        backend.wait(timeout=12)
        assert backend.returncode==0,backend.stderr.read()[-3500:]
        backend.stdout.close()
        backend.stderr.close()


def test_genuine_crossuid_bind_commit_and_once_only_backend():
    report=run_crossuid_e2e_fixture()
    assert report["status"].startswith("OFFLINE_DISTINCT_UID_REAL_BIND_COMMITTED")
    assert report["bind_receipt_sha256"]
    assert report["effect_receipt_sha256"]
    assert report["backend_state_initial_sha256"]!=report["backend_state_final_sha256"]
    assert report["real_external_bank_effects"]==0
    assert report["real_human_authorization_used"] is False


@pytest.mark.parametrize("bad",[
    None,True,{},{"operator_real_approval":True},
    {"production_iam":True},{"old_api_budget":"$5"},
])
def test_local_synthetic_grant_never_implies_real_authority(bad):
    with pytest.raises(m.Refused,match="FRESH_SPEND_AND_REAL_EXTERNAL_EFFECT"):
        m.deny_real_external_provider_or_bank(bad)


@pytest.mark.parametrize("bad",[
    None,False,True,1,[],set(),
])
def test_gateway_protocol_serializes_only_json_object(bad):
    with pytest.raises(m.Refused,match="STRICT_CLIENT_OBJECT"):
        m._frame(bad)


@pytest.mark.parametrize("bad",[
    "../relative",None,True,10,"",
])
def test_unix_backend_is_only_absolute_socket_path(bad):
    with pytest.raises(m.Refused):
        m.socket_query(bad,{"v":1,"op":"status"})


def test_fixed_mock_authority_does_not_reference_agentdojo_native_bank_writes():
    assert m.UNITS==7
    assert m.TARGET.startswith("offline://")
    assert m.GRANT.startswith("offline-fixture-grant")
    assert "send_money" not in m.TARGET
    assert m.SCHEMA.startswith("veritas.final128.task1-407")
    assert m.MAX_CONN>=10
    assert m.MAX_FRAME<=8192


def test_source_contains_real_bind_and_backend_peer_identity_check():
    code=Path(m.__file__).read_text(encoding="utf8")
    for expected in (
        "execute_bind_adjudication(",
        "ReferenceBindAdapter",
        'if peer["uid"]!=gateway_uid:',
        'if peer["uid"]!=agent_uid:',
        "consumed=True",
        "counter+=UNITS",
        "return False",
        "prior.build_worker_source()",
        "REAL_BIND_COMMIT_AND_EXTERNAL_MOCK_LEDGER_DID_NOT_RECONCILE",
    ):
        assert expected in code
    for dangerous in ("client.chat.completions.create(",
                      "client.responses.create(","requests.post(",
                      "pickle.loads(","exec(","eval(",
                      "suite._check_task_result("):
        assert dangerous not in code
