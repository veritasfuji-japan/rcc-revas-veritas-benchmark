"""#408: crash/restart actual Linux processes with durable mock backend journal."""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import time

import pytest
from scripts import final128_408_task1_durable_mock_backend_crash_recovery_v1 as m

def env():
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

def command(user,module,*argv):
    return ["sudo","-n","-u",user,"--","/usr/bin/env"]+[
        f"{key}={value}" for key,value in env().items()
    ]+[sys.executable,"-m",module,*[str(x) for x in argv]]

def start(user,module,*argv):
    return subprocess.Popen(command(user,module,*argv),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,text=True)

def call(user,path,request):
    return subprocess.run(command(
        user,"scripts.final128_407_task1_synthetic_backend_singleuse_bind_v1",
        "--client",str(path),json.dumps(request,sort_keys=True,separators=(",",":"))),
        capture_output=True,text=True,timeout=15,check=False)

def ask(user,path,request):
    response=call(user,path,request)
    assert response.returncode==0,response.stderr[-2800:]
    obj=json.loads(response.stdout)
    assert obj["schema"]==m.prev.SCHEMA
    return obj

def wait_socket(process,socket_path):
    start_time=time.monotonic()
    while (subprocess.run(["sudo","-n","test","-S",str(socket_path)],
                          capture_output=True).returncode!=0
           and process.poll() is None):
        assert time.monotonic()-start_time<25,"408 distinct-UID service startup timed out"
        time.sleep(0.1)
    assert process.poll() is None,process.stderr.read()[-3500:]

def terminate(proc,code=None):
    if proc is None:
        return
    if proc.poll() is None:
        proc.kill()
    result=proc.wait(timeout=12)
    if code is not None:
        assert result==code,proc.stderr.read()[-3500:]
    proc.stdout.close()
    proc.stderr.close()

def cleanup_socket(p):
    subprocess.run(["sudo","-n","rm","-f","--",str(p)],check=True)

def run_scenario(scenario):
    if os.environ.get("FINAL128_408_LINUX_READY")!="1":
        pytest.skip("Only pinned cross-UID 407+408 dedicated CI")
    assert scenario in m.FAIL_MODES
    names={
        "backend":os.environ["FINAL128_407_BACKEND_USER"],
        "gateway":os.environ["FINAL128_407_GATEWAY_USER"],
        "agent":os.environ["FINAL128_407_AGENT_USER"],
        "stranger":os.environ["FINAL128_407_STRANGER_USER"],
    }
    uids={key:pwd.getpwnam(value).pw_uid for key,value in names.items()}
    assert len(set(uids.values())|{os.geteuid()})==5
    sandbox=Path(os.environ["FINAL128_407_SANDBOX_ROOT"])
    backend_socket=sandbox/"backend_ipc"/f"durable408-{scenario}.sock"
    gateway_socket=sandbox/"gateway_ipc"/f"gate408-{scenario}.sock"
    dbfile=sandbox/"backend_private"/f"durable408-{scenario}.sqlite3"
    assert subprocess.run(["sudo","-n","test","!","-e",str(dbfile)],
                          capture_output=True).returncode==0
    token={"v":1,"op":"execute","target":m.TARGET,
           "units":m.UNITS,"grant":m.GRANT}
    first_backend=None; first_gate=None
    backend=None; gateway=None; third_backend=None
    try:
        first_backend=start(names["backend"],
            "scripts.final128_408_task1_durable_mock_backend_crash_recovery_v1",
            "--durable-backend",backend_socket,uids["gateway"],dbfile,scenario)
        wait_socket(first_backend,backend_socket)
        first_gate=start(names["gateway"],
            "scripts.final128_407_task1_synthetic_backend_singleuse_bind_v1",
            "--gateway",gateway_socket,backend_socket,uids["agent"],uids["backend"])
        wait_socket(first_gate,gateway_socket)
        initial=ask(names["gateway"],backend_socket,{"v":1,"op":"status"})
        assert initial["durable_mock_sqlite"] is True
        assert initial["counter"]==0 and initial["effect_count"]==0
        assert initial["last_effect_receipt_sha256"] is None
        # The agent and unrelated group-member still cannot address sink.
        wrong=call(names["agent"],backend_socket,{"v":1,"op":"apply",
                "target":m.TARGET,"units":m.UNITS,"grant":m.GRANT})
        assert wrong.returncode!=0
        stranger=call(names["stranger"],gateway_socket,token)
        assert stranger.returncode!=0
        owner_private_read=subprocess.run(
            ["sudo","-n","-u",names["agent"],"cat",str(dbfile)],
            capture_output=True)
        assert owner_private_read.returncode!=0

        original_native=ask(names["agent"],gateway_socket,
                             {"v":1,"op":"native_probe"})
        assert original_native["code"]=="407_TASK1_REAL_BIND_BLOCKED"
        assert original_native["backend_effect_count"]==0
        # An untrusted malformed/forged grant cannot trigger the fault.
        forged=ask(names["agent"],gateway_socket,{
            "v":1,"op":"execute","target":m.TARGET,
            "units":m.UNITS,"grant":"forged"})
        assert forged["ok"] is False
        assert forged["backend_effect_count"]==0

        attempt=call(names["agent"],gateway_socket,token)
        if scenario==m.NO_FAIL:
            assert attempt.returncode==0,attempt.stderr[-2500:]
            applied=json.loads(attempt.stdout)
            assert applied["ok"] is True
            assert applied["code"]=="407_BIND_COMMITTED_BACKEND_ONCE"
            assert applied["bind_final_outcome"]=="COMMITTED"
            assert applied["backend_effect_count"]==1
            assert applied["backend_counter"]==m.UNITS
            bind_result="COMMITTED"
            crash_code=0
            # A clean owner restart also must preserve consumption.
            assert ask(names["agent"],gateway_socket,
                       {"v":1,"op":"close"})["ok"] is True
            assert first_gate.wait(timeout=12)==0,first_gate.stderr.read()[-1500:]
            assert ask(names["gateway"],backend_socket,
                       {"v":1,"op":"close"})["ok"] is True
            assert first_backend.wait(timeout=12)==0,first_backend.stderr.read()[-1500:]
        else:
            assert attempt.returncode!=0
            crash_code=(m.CRASH_EXIT_BEFORE
                        if scenario==m.FAIL_BEFORE else m.CRASH_EXIT_AFTER)
            assert first_backend.wait(timeout=12)==crash_code
            assert first_gate.wait(timeout=12)!=0
            bind_result=("COMMITTED" if scenario==m.FAIL_BEFORE
                         else "ACK_UNKNOWN_RECONCILED_EFFECT")
        first_backend.stdout.close();first_backend.stderr.close()
        first_gate.stdout.close();first_gate.stderr.close()
        first_backend=None;first_gate=None
        # Crash leaves an inode at the socket address. Only a trusted CI
        # supervisor removes stale socket files before a new owner binds.
        cleanup_socket(backend_socket)
        cleanup_socket(gateway_socket)

        backend=start(names["backend"],
            "scripts.final128_408_task1_durable_mock_backend_crash_recovery_v1",
            "--durable-backend",backend_socket,uids["gateway"],dbfile,m.NO_FAIL)
        wait_socket(backend,backend_socket)
        gateway=start(names["gateway"],
            "scripts.final128_407_task1_synthetic_backend_singleuse_bind_v1",
            "--gateway",gateway_socket,backend_socket,uids["agent"],uids["backend"])
        wait_socket(gateway,gateway_socket)
        recovered=ask(names["gateway"],backend_socket,{"v":1,"op":"status"})
        assert recovered["durable_mock_sqlite"] is True
        assert recovered["backend_uid"]==uids["backend"]
        expected=(0 if scenario==m.FAIL_BEFORE else m.UNITS)
        assert recovered["counter"]==expected
        assert recovered["effect_count"]==(0 if scenario==m.FAIL_BEFORE else 1)
        assert recovered["consumed"] is (scenario!=m.FAIL_BEFORE)
        if scenario==m.FAIL_BEFORE:
            # No stale permit was consumed by a precommit crash. A fresh
            # real pinned VERITAS Bind may now COMMIT the one mock effect.
            completion=ask(names["agent"],gateway_socket,token)
            assert completion["ok"] is True
            assert completion["code"]=="407_BIND_COMMITTED_BACKEND_ONCE"
            assert completion["bind_final_outcome"]=="COMMITTED"
        else:
            # After commit or clean restart, gate itself must reject; if
            # its RAM flag was lost, authoritative sink consumption wins.
            repeat=ask(names["agent"],gateway_socket,token)
            assert repeat["ok"] is False
            assert repeat["code"]=="407_BACKEND_ALREADY_CONSUMED"
        done=ask(names["gateway"],backend_socket,{"v":1,"op":"status"})
        assert done["counter"]==m.UNITS
        assert done["effect_count"]==1
        assert done["consumed"] is True
        assert isinstance(done["last_effect_receipt_sha256"],str)
        assert len(done["last_effect_receipt_sha256"])==64

        # Even authenticated GATEWAY cannot replay consumed target grant.
        replay=ask(names["gateway"],backend_socket,{
            "v":1,"op":"apply","target":m.TARGET,"units":m.UNITS,"grant":m.GRANT})
        assert replay["ok"] is False
        assert replay["code"]=="407_BACKEND_UNBOUND_OR_CONSUMED"
        assert replay["state_sha256"]==done["state_sha256"]

        # Restart ONLY the backend again, while gateway remains resident.
        assert ask(names["gateway"],backend_socket,
                   {"v":1,"op":"close"})["ok"] is True
        assert backend.wait(timeout=12)==0,backend.stderr.read()[-1600:]
        backend.stdout.close();backend.stderr.close()
        backend=None
        cleanup_socket(backend_socket)
        third_backend=start(names["backend"],
            "scripts.final128_408_task1_durable_mock_backend_crash_recovery_v1",
            "--durable-backend",backend_socket,uids["gateway"],dbfile,m.NO_FAIL)
        wait_socket(third_backend,backend_socket)
        after_retry=ask(names["gateway"],backend_socket,{"v":1,"op":"status"})
        assert after_retry["state_sha256"]==done["state_sha256"]
        assert after_retry["last_effect_receipt_sha256"]==done["last_effect_receipt_sha256"]
        assert after_retry["counter"]==m.UNITS
        assert after_retry["consumed"] is True
        assert after_retry["effect_count"]==1
        final_attempt=ask(names["agent"],gateway_socket,token)
        assert final_attempt["ok"] is False
        assert final_attempt["backend_effect_count"]==1

        # No agent credential access even to DB metadata (0700 parent).
        attempted_read=subprocess.run([
            "sudo","-n","-u",names["agent"],"head","-c","10",str(dbfile)],
            capture_output=True,text=True)
        assert attempted_read.returncode!=0

        manifest=m.redacted_recovery_manifest(
            scenario=scenario,initial=initial,recovered=recovered,
            after_retry=after_retry,crash_code=crash_code,
            bind_result=bind_result,agent_uid=uids["agent"],
            gateway_uid=uids["gateway"],backend_uid=uids["backend"],
            second_attempt_refused=True)
        assert manifest["effect_count_after_retry"]==1
        assert manifest["global_production_exactly_once_proven"] is False
        assert manifest["paid_provider_calls"]==0
        assert manifest["real_external_bank_effects"]==0
        assert manifest["production_iam_egress_real_credentials_proven"] is False
        assert "forged" not in json.dumps(manifest)
        return manifest
    finally:
        for proc,user,path in [
            (gateway,names["agent"],gateway_socket),
            (third_backend,names["gateway"],backend_socket),
            (backend,names["gateway"],backend_socket),
            (first_gate,names["agent"],gateway_socket),
            (first_backend,names["gateway"],backend_socket),
        ]:
            if proc is None:
                continue
            if proc.poll() is None:
                try:
                    call(user,path,{"v":1,"op":"close"})
                except (OSError,subprocess.TimeoutExpired):
                    pass
            terminate(proc)


@pytest.mark.parametrize("phase",m.FAIL_MODES)
def test_real_crossuid_backend_crash_commit_ack_loss_and_durable_replay(phase):
    outcome=run_scenario(phase)
    assert outcome["scenario"]==phase
    assert outcome["effect_count_after_retry"]==1
    assert outcome["atomic_sqlite_transaction_singleuse_consumption"] is True
    assert outcome["post_restart_replay_refused"] is True
    assert outcome["observed_bind_final_status"]==(
        "ACK_UNKNOWN_RECONCILED_EFFECT" if phase==m.FAIL_AFTER else "COMMITTED")
    if phase==m.FAIL_BEFORE:
        assert outcome["state_initial_sha256"]==outcome["state_recovered_sha256"]
    else:
        assert outcome["state_initial_sha256"]!=outcome["state_recovered_sha256"]
    Path("results").mkdir(exist_ok=True)
    path=Path("results/final128-408-"+phase+"-redacted.json")
    path.write_text(json.dumps(outcome,sort_keys=True,indent=2)+"\n",
                    encoding="utf8")


@pytest.mark.parametrize("mode",["reconnect","retry","unknown",None,True,2,""])
def test_backend_rejects_unrecognized_fault_injection_mode(mode):
    assert mode not in m.FAIL_MODES


@pytest.mark.parametrize("fake",[
    None,True,False,{},{"bank_operation":True},
    {"prior_spend_permission":"$5"},{"signed_production_grant":True},
])
def test_synthetic_durable_commit_does_not_authorize_paid_or_real_effect(fake):
    with pytest.raises(m.Refused,match="FRESH_PAID_APPROVAL_AND_REAL_BACKEND"):
        m.reject_paid_or_real_effect(fake)


def test_mock_sqlite_transaction_and_fault_order_are_explicit():
    code=Path(m.__file__).read_text(encoding="utf8")
    for literal in (
        'db.execute("BEGIN IMMEDIATE")',
        'db.commit()',
        'os._exit(CRASH_EXIT_BEFORE)',
        'os._exit(CRASH_EXIT_AFTER)',
        'PRAGMA synchronous=FULL',
        'PRAGMA journal_mode=DELETE',
        'if peer["uid"]!=gateway_uid:',
        'stat.S_IMODE(ds.st_mode)==0o700',
        'stat.S_IMODE(fs.st_mode)==0o600',
    ):
        assert literal in code
    assert code.index('db.execute("BEGIN IMMEDIATE")') < code.index('os._exit(CRASH_EXIT_BEFORE)')
    assert code.index('db.commit()',code.index('db.execute("BEGIN IMMEDIATE")')) < code.index('os._exit(CRASH_EXIT_AFTER)')
    for forbidden in ("client.chat.completions.create(","client.responses.create(",
                      "requests.post(","pickle.loads(","suite._check_task_result("):
        assert forbidden not in code
