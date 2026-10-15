"""#409 actual distinct-UID multi-target source grants and concurrent sink requests."""
from __future__ import annotations
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import time

import pytest
from scripts import final128_409_multigrant_expiry_drift_concurrency_v1 as m

CLIENT_MODULE="scripts.final128_409_multigrant_expiry_drift_concurrency_v1"

def _crossuid_subprocess_env():
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

def command(user,*argv):
    return ["sudo","-n","-u",user,"--","/usr/bin/env"]+[
        f"{name}={value}" for name,value in _crossuid_subprocess_env().items()
    ]+[sys.executable,"-m",CLIENT_MODULE,*[str(x) for x in argv]]

def start(user,*argv):
    return subprocess.Popen(command(user,*argv),stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,text=True)

def run(user,*argv):
    return subprocess.run(command(user,*argv),capture_output=True,
                          text=True,timeout=22,check=False)

def client(user,path,request):
    return run(user,"--client",path,json.dumps(request,sort_keys=True,separators=(",",":")))

def ask(user,path,request):
    result=client(user,path,request)
    assert result.returncode==0,result.stderr[-2500:]
    parsed=json.loads(result.stdout)
    assert parsed["schema"]==m.SCHEMA
    return parsed

def wait_socket(proc,p):
    clock=time.monotonic()
    while (subprocess.run(["sudo","-n","test","-S",str(p)],
                          capture_output=True).returncode!=0
           and proc.poll() is None):
        assert time.monotonic()-clock<25,"409 owner socket startup deadline"
        time.sleep(.1)
    assert proc.poll() is None,proc.stderr.read()[-4000:]

def finish(proc,user,path):
    if proc is None:
        return
    if proc.poll() is None:
        try:
            client(user,path,{"v":1,"op":"close"})
        except (subprocess.TimeoutExpired,OSError):
            pass
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=12)
    proc.stdout.close()
    proc.stderr.close()

def request(grant,target=None,units=m.DELTA,revision=0,operation="execute"):
    return {"v":1,"op":operation,"grant":grant,
            "target":m.FIXTURES[grant][0] if target is None else target,
            "units":units,"expected_revision":revision}

def backend_case(names,uids,backend_socket,dbfile):
    return start(names["backend"],"--backend",backend_socket,uids["gateway"],dbfile)

def run_real_multigrant():
    if os.environ.get("FINAL128_409_LINUX_READY")!="1":
        pytest.skip("Requires dedicated pinned 409 Linux UID CI")
    names={
        "backend":os.environ["FINAL128_407_BACKEND_USER"],
        "gateway":os.environ["FINAL128_407_GATEWAY_USER"],
        "agent":os.environ["FINAL128_407_AGENT_USER"],
        "stranger":os.environ["FINAL128_407_STRANGER_USER"],
    }
    uids={k:pwd.getpwnam(v).pw_uid for k,v in names.items()}
    assert len(set(uids.values())|{os.geteuid()})==5
    root=Path(os.environ["FINAL128_407_SANDBOX_ROOT"])
    backend_socket=root/"backend_ipc"/"409multitarget.sock"
    gateway_socket=root/"gateway_ipc"/"409bindgate.sock"
    dbfile=root/"backend_private"/"409effect-owned.sqlite3"
    assert subprocess.run(["sudo","-n","test","!","-e",str(dbfile)],
                          capture_output=True).returncode==0
    backend=None;gate=None
    try:
        backend=backend_case(names,uids,backend_socket,dbfile)
        wait_socket(backend,backend_socket)
        gate=start(names["gateway"],"--gateway",gateway_socket,
                   backend_socket,uids["agent"],uids["backend"])
        wait_socket(gate,gateway_socket)
        first=ask(names["agent"],gateway_socket,{"v":1,"op":"status"})
        assert first["effect_count"]==0 and first["consumed_grants"]==0
        assert first["targets"]=={
            m.A:{"counter":0,"revision":0},
            m.B:{"counter":0,"revision":0},
            m.E:{"counter":0,"revision":0}}
        assert first["backend_uid"]==uids["backend"]
        assert first["gateway_uid"]==uids["gateway"]
        assert first["native_task1_state_unchanged"] is True
        original=ask(names["agent"],gateway_socket,{"v":1,"op":"native_probe"})
        assert original["ok"] is False
        assert original["code"]=="409_NATIVE_REAL_BIND_REFUSED"
        assert original["native_real_bind_blocks"]>=1

        # A caller who knows every *public test fixture* grant still cannot
        # dispatch to owner; SO_PEERCRED is enforced by the backend.
        forbidden=client(names["agent"],backend_socket,
                         request(m.G_A1,operation="apply"))
        assert forbidden.returncode!=0
        stranger=client(names["stranger"],gateway_socket,request(m.G_A1))
        assert stranger.returncode!=0
        denied_file=subprocess.run(["sudo","-n","-u",names["agent"],
                                    "head","-c","2",str(dbfile)],
                                   capture_output=True)
        assert denied_file.returncode!=0
        assert ask(names["agent"],gateway_socket,{"v":1,"op":"status"})["ledger_sha256"]==first["ledger_sha256"]

        # Assert expiry is evaluated by backend-owned wall clock, rather
        # than a client-supplied expiry field or a caller-controlled clock.
        expired=ask(names["gateway"],backend_socket,
                    request(m.G_EX,operation="apply"))
        assert expired["code"]=="409_GRANT_EXPIRED_AT_SINK" and not expired["ok"]
        substitute=ask(names["gateway"],backend_socket,
                       request(m.G_B1,target=m.A,operation="apply"))
        assert substitute["code"]=="409_TARGET_SUBSTITUTION_DENIED"
        wrong_units=ask(names["gateway"],backend_socket,
                        request(m.G_A1,units=9,operation="apply"))
        assert wrong_units["code"]=="409_ARGUMENT_DRIFT_DENIED"
        forgery=ask(names["gateway"],backend_socket,
                    request(m.G_A1,revision=1,operation="apply"))
        assert forgery["code"]=="409_EXPECTED_REVISION_FORGERY_DENIED"
        bad_extra=request(m.G_A1,operation="apply")
        bad_extra["approved_by_superuser"]=True
        extra=ask(names["gateway"],backend_socket,bad_extra)
        assert extra["code"]=="409_ENVELOPE_NOT_BOUND"
        assert ask(names["agent"],gateway_socket,{"v":1,"op":"status"})["effect_count"]==0

        # Real competing agent processes. Gate serializes requests and the
        # backend commits exactly once inside SQLite BEGIN IMMEDIATE.
        contender=request(m.G_A1)
        jobs=[subprocess.Popen(command(names["agent"],"--client",
                                      gateway_socket,json.dumps(contender)),
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                               text=True)
              for _ in range(8)]
        outcomes=[]
        for proc in jobs:
            out,err=proc.communicate(timeout=28)
            assert proc.returncode==0,err[-2000:]
            response=json.loads(out)
            assert response["schema"]==m.SCHEMA
            outcomes.append(response)
        positives=[r for r in outcomes if r.get("ok") is True]
        assert len(positives)==1
        assert positives[0]["code"]=="409_REAL_BIND_COMMITTED_AND_SINK_ONCE"
        assert positives[0]["bind_receipt_sha256"] and positives[0]["effect_receipt_sha256"]
        assert all(r["code"]=="409_CONSUMED_GRANT_DENIED"
                   for r in outcomes if not r.get("ok"))
        halfway=ask(names["agent"],gateway_socket,{"v":1,"op":"status"})
        assert halfway["effect_count"]==1 and halfway["consumed_grants"]==1
        assert halfway["targets"][m.A]=={"counter":m.DELTA,"revision":1}
        assert halfway["targets"][m.B]=={"counter":0,"revision":0}

        # Second grant was issued for the same immutable expected version 0.
        # Its unspent bit must NOT bypass target version change.
        stale=ask(names["gateway"],backend_socket,
                  request(m.G_A2,operation="apply"))
        assert not stale["ok"] and stale["code"]=="409_LIVE_STATE_REVISION_DRIFT"
        consumed=ask(names["gateway"],backend_socket,
                     request(m.G_A1,operation="apply"))
        assert not consumed["ok"] and consumed["code"]=="409_CONSUMED_GRANT_DENIED"
        gate_stale=ask(names["agent"],gateway_socket,
                       request(m.G_A2))
        assert not gate_stale["ok"]

        # Different target B is not blocked by target-A revision drift.
        bcommitted=ask(names["agent"],gateway_socket,request(m.G_B1))
        assert bcommitted["ok"] is True
        assert bcommitted["code"]=="409_REAL_BIND_COMMITTED_AND_SINK_ONCE"
        assert bcommitted["bind_receipt_sha256"] and bcommitted["effect_receipt_sha256"]
        after=ask(names["agent"],gateway_socket,{"v":1,"op":"status"})
        assert after["effect_count"]==2 and after["consumed_grants"]==2
        assert after["targets"][m.B]=={"counter":m.DELTA,"revision":1}
        assert after["targets"][m.E]=={"counter":0,"revision":0}

        # Persisted grant/version/expiration and effect hashes survive
        # backend restart, with the SAME gateway still running.
        assert ask(names["gateway"],backend_socket,{"v":1,"op":"close"})["ok"]
        assert backend.wait(timeout=12)==0,backend.stderr.read()[-1500:]
        backend.stdout.close();backend.stderr.close()
        backend=None
        subprocess.run(["sudo","-n","rm","-f",str(backend_socket)],check=True)
        backend=backend_case(names,uids,backend_socket,dbfile)
        wait_socket(backend,backend_socket)
        persisted=ask(names["agent"],gateway_socket,{"v":1,"op":"status"})
        assert persisted["ledger_sha256"]==after["ledger_sha256"]
        assert persisted["effect_receipts_sha256"]==after["effect_receipts_sha256"]
        assert persisted["effect_count"]==2
        negatives=[]
        for proposal,expected in [
            (request(m.G_A1,operation="apply"),"409_CONSUMED_GRANT_DENIED"),
            (request(m.G_A2,operation="apply"),"409_LIVE_STATE_REVISION_DRIFT"),
            (request(m.G_EX,operation="apply"),"409_GRANT_EXPIRED_AT_SINK"),
            (request(m.G_B1,target=m.A,operation="apply"),"409_TARGET_SUBSTITUTION_DENIED"),
        ]:
            r=ask(names["gateway"],backend_socket,proposal)
            assert r["ok"] is False and r["code"]==expected
            negatives.append(r)
        final=ask(names["agent"],gateway_socket,{"v":1,"op":"status"})
        assert final["ledger_sha256"]==after["ledger_sha256"]
        assert final["gateway_successful_bind_count"]==2
        manifest=m.redacted_report(
            first=first,last=final,authorized=[positives[0],bcommitted],
            negative=negatives,agent_uid=uids["agent"],
            gate_uid=uids["gateway"],sink_uid=uids["backend"],
            os_denials=2,parallel_responses=outcomes,
            backend_denial_codes=[x["code"] for x in [
                expired,substitute,wrong_units,forgery,extra,stale,consumed,
                *negatives]])
        assert manifest["synthetic_effects_committed"]==2
        assert manifest["real_bind_committed_receipts"]==2
        assert manifest["client_simultaneous_attempts"]==8
        assert manifest["global_nonbypassable_production_execution_proven"] is False
        Path("results").mkdir(exist_ok=True)
        Path("results/final128-409-redacted-concurrency.json").write_text(
            json.dumps(manifest,sort_keys=True,indent=2)+"\n",encoding="utf8")
        return manifest
    finally:
        finish(gate,names["agent"],gateway_socket)
        finish(backend,names["gateway"],backend_socket)


def test_real_cross_uid_multitarget_expiry_drift_parallel_same_grant_and_restart():
    report=run_real_multigrant()
    assert report["one_winner_among_concurrent_clients"] is True
    assert report["backend_rejected_expired_source_owned_grant"] is True
    assert report["backend_rejected_live_revision_drift"] is True
    assert report["backend_rejected_target_substitution"] is True


@pytest.mark.parametrize("grant,target",[
    (m.G_A1,m.A),(m.G_A2,m.A),(m.G_B1,m.B),(m.G_EX,m.E)
])
def test_source_grant_target_binding_is_unique(grant,target):
    assert m.FIXTURES[grant]==(target,0)


@pytest.mark.parametrize("bad",[None,True,False,{},[],
                              {"prior_paid_approval":"$5"},
                              {"real_production_iam":True}])
def test_synthetic_grants_do_not_confer_real_authority(bad):
    assert bad not in tuple(m.FIXTURES)
    assert m.SCHEMA.startswith("veritas.final128.task1-409")
    assert m.DELTA==7


def test_source_enforces_kernel_peercred_and_true_backend_transaction():
    source=Path(m.__file__).read_text(encoding="utf8")
    required=[
        'if peer["uid"]!=gateway_uid:', 'if peer["uid"]!=agent_uid:',
        'db.execute("BEGIN IMMEDIATE")',
        'db.commit()',
        'time.time()>=expiry',
        'if live[0]!=expected:',
        'len({agent_uid,backend_uid,os.geteuid()})==3',
        'execute_bind_adjudication(',
        'source_grant_valid',
        'sink_expiry_and_unspent',
        'PRAGMA synchronous=FULL',
        'durable._strict_db_path(dbfile)',
    ]
    for token in required:
        assert token in source,token
    for forbidden in ("client.responses.create(","client.chat.completions.create(",
                      "requests.post(","pickle.loads(","suite._check_task_result("):
        assert forbidden not in source
    assert 'production_network_IAM_egress_proven":False' in source
