#!/usr/bin/env python3
"""#405: separate-process Native Task1 effect holder, JSON/stdio-gated, offline.

This is a bounded *process-private in-memory state* proof, NOT a privileged
production principal, OS hardening, credential confinement, IAM or egress proof.
A Python agent process has no reference to the authoritative child bank object.
Every write request goes to the worker's real pinned VERITAS Bind guard and is
refused by the Task1 NO_MUTATION policy; direct Python writes by the client
modify only an independent canary clone, not the worker-owned original.

The child is started with python -m scripts.final128_405_... --worker.
The protocol is newline-delimited JSON with strict envelope and size bounds,
not unsafe pickle/multiprocessing deserialization, and never sends raw Native
environment, transactions, credentials or untrusted attack text.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys

from scripts import final128_399_task1_frozen_direct_native_bind_v1 as native
from scripts import final128_402_task1_native_tools_executor_bind_guard_v1 as guarded
from scripts import task1_source_bound_readonly_grounding_v1 as grounding

SCHEMA = "veritas.final128.task1-405-separate-process-executor-local-gate-v1"
VERSION = 1
MAX_FRAME_BYTES = 8192
MAX_REQUESTS = 40
MAX_READ_TOOL = 4
# No runtime mutation of this source-pinned allowlist.
READ_ONLY = frozenset(guarded.READONLY_NATIVE)
DENIAL_PREFIX = "VERITAS_402_DENIED:"
TASK1_PIN = native.NATIVE_PIN
VERITAS_PIN = native.VERITAS_PIN


class Refused(ValueError):
    pass


def need(ok, reason):
    if ok is not True:
        raise Refused("405_" + reason)


def sha(obj):
    return grounding.digest(obj)


def _strict_pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_MEMBER")
        result[key]=value
    return result


def _reject_json_constant(_value):
    raise ValueError("NONFINITE_JSON_CONSTANT")


def decode_frame(raw):
    if type(raw) is not bytes or len(raw)>MAX_FRAME_BYTES:
        raise Refused("405_BAD_FRAME_SIZE")
    if not raw.endswith(b"\n") or b"\x00" in raw:
        raise Refused("405_UNFRAMED_OR_NUL_REQUEST")
    try:
        req=json.loads(raw.decode("utf8"),
                       object_pairs_hook=_strict_pairs,
                       parse_constant=_reject_json_constant)
    except (UnicodeError,ValueError,TypeError) as exc:
        raise Refused("405_MALFORMED_OR_AMBIGUOUS_JSON") from exc
    need(type(req) is dict and req.get("v")==VERSION
         and type(req["v"]) is int
         and type(req.get("op")) is str,
         "STRICT_VERSIONED_JSON_ENVELOPE_REQUIRED")
    op=req["op"]
    if op in ("status","close"):
        need(set(req)=={"v","op"},"STATUS_AND_CLOSE_HAVE_NO_ARGUMENTS")
    elif op=="tool":
        need(set(req)=={"v","op","name","args"}
             and type(req["name"]) is str
             and type(req["args"]) is dict
             and len(req["args"]) <= 8,
             "TOOL_ENVELOPE_NAME_AND_ARGS_REQUIRED")
    else:
        raise Refused("405_UNKNOWN_OPERATION_DENIED")
    return req


def _stable_response(*,ok,code,pid,initial,current,journal,method=None):
    need(type(code) is str and len(code)<128,
         "INVALID_RESPONSE_CODE")
    return {
        "schema":SCHEMA,
        "ok":ok,
        "code":code,
        "worker_pid":pid,
        "method":method,
        "initial_authoritative_state_sha256":sha(initial),
        "current_authoritative_state_sha256":sha(current),
        "guarded_bind_adjudications":journal["bind_adjudications"],
        "guarded_bind_blocked":journal["bind_blocked"],
        "native_readonly_dispatches":journal["native_read_dispatches"],
        "native_protected_dispatches":journal["native_protected_dispatches"],
        "process_private_in_memory_state_only":True,
        "external_bank_effects":0,
        "real_provider_requests":0,
        "official_native_scorer_calls":0,
        "os_identity_isolation_proven":False,
        "production_credential_exclusivity_proven":False,
        "production_iam_network_confinement_proven":False,
        "global_nonbypassable_effect_boundary_proven":False,
    }


def _handle(req,*,env,initial,runtime,journal,pid):
    method=req["op"]
    if method=="tool":
        name=req["name"]
        # Native's full tool dictionary is still available on the worker,
        # but ALL calls enter the pinned #402 guard via one explicit
        # source-owned handler. No arbitrary attribute / eval dispatch.
        if name not in runtime.functions:
            return _stable_response(
                ok=False,code="405_UNKNOWN_TOOL_DENIED",pid=pid,
                initial=initial,current=env.model_dump(mode="json"),
                journal=journal,method=name)
        result,error=runtime.run_function(env,name,deepcopy(req["args"]))
        if error is None:
            need(name in READ_ONLY
                 and journal["native_protected_dispatches"]==0,
                 "UNAUTHORIZED_WORKER_TOOL_EXECUTION_ADMITTED")
            # Avoid ever returning raw Native transactions or attack text.
            del result
            code="405_NATIVE_READ_ONLY_OK"
            ok=True
        else:
            need(name not in READ_ONLY or
                 error.startswith(DENIAL_PREFIX) or
                 ("ValidationError:" in error) or
                 ("ValueError:" in error),
                 "NATIVE_READ_ONLY_UNEXPECTED_TOOL_ERROR")
            # Native tool errors are untrusted; only return a bounded
            # source-owned error classification (no payload passthrough).
            if error.startswith(DENIAL_PREFIX):
                code="405_VERITAS_PREEXECUTION_REFUSAL"
            else:
                code="405_NATIVE_READ_VALIDATION_REFUSAL"
            ok=False
        return _stable_response(
            ok=ok,code=code,pid=pid,
            initial=initial,current=env.model_dump(mode="json"),
            journal=journal,method=name)
    if method=="status":
        return _stable_response(
            ok=True,code="405_PRIVATE_EXECUTOR_ALIVE",
            pid=pid,initial=initial,
            current=env.model_dump(mode="json"),
            journal=journal)
    if method=="close":
        return _stable_response(
            ok=True,code="405_PRIVATE_EXECUTOR_CLOSED",
            pid=pid,initial=initial,
            current=env.model_dump(mode="json"),
            journal=journal)
    raise Refused("405_UNKNOWN_REQUEST_REACHED_DISPATCH")


def build_worker_source():
    from agentdojo.task_suite.load_suites import get_suite
    path=os.environ.get("FINAL128_405_AGENTDOJO_ROOT")
    need(type(path) is str and path
         and subprocess.check_output(
             ["git","-C",path,"rev-parse","HEAD"],
             text=True).strip()==TASK1_PIN,
         "PINNED_NATIVE_CHILD_ISOLATION_ENV_REQUIRED")
    veritas=os.environ.get("FINAL128_399_VERITAS_ROOT")
    need(type(veritas) is str and veritas
         and subprocess.check_output(
             ["git","-C",veritas,"rev-parse","HEAD"],
             text=True).strip()==VERITAS_PIN,
         "PINNED_VERITAS_CHILD_REQUIRED")
    freeze=json.loads(native.ROSTER_FILE.read_text(encoding="utf8"))
    suite=get_suite("v1.2.2","banking")
    src=native.native_task1_source(suite=suite,enrollment=freeze)
    initial=deepcopy(src["initial"])
    need(src["B"].model_dump(mode="json")==initial
         and src["A"] is not src["B"]
         and src["observed_map"]=={native.SLOT:src["payload"]},
         "FROZEN_NATIVE_DIRECT_TASK1_SOURCE_REQUIRED")
    runtime,journal=guarded.guard_native_task1_runtime(
        native_environment=src["B"],suite=suite,
        pinned_catalog_sha256=src["catalog_sha256"],
        expected_full_native_tool_count=src["tool_count"])
    return src["B"],initial,runtime,journal


def serve_child(stdin=None,stdout=None):
    """Only this child owns its authoritative Native BankAccount object."""
    if stdin is None:
        stdin=sys.stdin.buffer
    if stdout is None:
        stdout=sys.stdout.buffer
    env,initial,runtime,journal=build_worker_source()
    pid=os.getpid()
    need(pid!=os.getppid(),"NOT_AN_INDEPENDENT_WORKER_PROCESS")
    count=0
    while count<MAX_REQUESTS:
        raw=stdin.readline(MAX_FRAME_BYTES+1)
        if raw==b"":
            break
        count+=1
        try:
            req=decode_frame(raw)
            response=_handle(
                req,env=env,initial=initial,runtime=runtime,
                journal=journal,pid=pid)
        except Refused as exc:
            # Never propagate exception details or user-controlled bytes.
            response=_stable_response(
                ok=False,code="405_MALFORMED_OR_FORBIDDEN_REQUEST",
                pid=pid,initial=initial,current=env.model_dump(mode="json"),
                journal=journal)
            del exc
            req=None
        need(env.model_dump(mode="json")==initial
             and journal["native_protected_dispatches"]==0
             and journal["bind_adjudications"]==journal["bind_blocked"],
             "AUTHORITATIVE_CHILD_NATIVE_BANK_MUTATED_OR_UNRESOLVED_BIND")
        out=json.dumps(response,sort_keys=True,separators=(",",":"),
                       ensure_ascii=False,allow_nan=False).encode("utf8")+b"\n"
        stdout.write(out)
        stdout.flush()
        if req is not None and req["op"]=="close":
            break
    return count


def invoke_private_worker(child, request):
    """Agent-facing JSON-only protocol. No Python object/state references."""
    need(type(request) is dict,"JSON_CLIENT_REQUEST_REQUIRED")
    raw=json.dumps(request,sort_keys=True,separators=(",",":"),
                   ensure_ascii=False,allow_nan=False).encode("utf8")+b"\n"
    need(len(raw)<=MAX_FRAME_BYTES,"BOUNDED_JSON_CLIENT_REQUEST_ONLY")
    child.stdin.write(raw)
    child.stdin.flush()
    line=child.stdout.readline(MAX_FRAME_BYTES+1)
    need(line.endswith(b"\n") and len(line)<=MAX_FRAME_BYTES,
         "CHILD_DID_NOT_RETURN_BOUNDED_JSON_RESPONSE")
    reply=json.loads(line)
    need(type(reply) is dict and reply.get("schema")==SCHEMA,
         "CHILD_RESPONSE_SCHEMA_REQUIRED")
    return reply


def launch_private_worker():
    """No provider keys, new child address space, exact pin in child."""
    safe_env=dict(os.environ)
    for key in ("OPENAI_API_KEY","TASK4_OPENAI_API_KEY","ANTHROPIC_API_KEY",
                "OPENAI_BASE_URL","VERITAS_DATABASE_URL","GH_TOKEN",
                "GITHUB_TOKEN"):
        safe_env.pop(key,None)
    return subprocess.Popen(
        [sys.executable,"-m",
         "scripts.final128_405_task1_separate_executor_json_gate_v1",
         "--worker"],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,bufsize=0,env=safe_env)


def report_local_process_boundary(*,worker_pid,parent_pid,pre,post,journal):
    need(type(worker_pid) is int and worker_pid!=parent_pid
         and pre==post
         and journal["guarded_bind_adjudications"]>=1
         and journal["guarded_bind_adjudications"]==
             journal["guarded_bind_blocked"]
         and journal["native_protected_dispatches"]==0,
         "NOT_A_CONFIRMED_SEPARATE_PROCESS_BLOCKED_EFFECT")
    return {
        "schema":SCHEMA,
        "status":"CHILD_PROCESS_PRIVATE_BANK_GUARDED_NO_EFFECT_LOCAL_ONLY",
        "case_id":native.CASE,
        "agentdojo_pin":TASK1_PIN,"veritas_pin":VERITAS_PIN,
        "worker_distinct_from_parent":True,
        "worker_private_original_sha256":pre,
        "worker_private_final_sha256":post,
        "real_veritas_bind_adjudications":journal["guarded_bind_adjudications"],
        "real_veritas_bind_blocked":journal["guarded_bind_blocked"],
        "native_protected_dispatches":0,
        "child_private_state_changed":False,
        "json_protocol_no_pickle":True,
        "local_stdio_boundary_only":True,
        "external_credential_isolation_proven":False,
        "production_process_principal_isolation_proven":False,
        "production_iam_or_network_egress_confinement_proven":False,
        "globally_nonbypassable_execution_proven":False,
        "real_paid_provider_requests":0,
        "official_native_scorer_calls":0,
        "external_bank_effects":0,
        "native_official_utility_A":None,
        "native_official_utility_B":None,
        "real_independent_model_histories_proven":False,
        "single_use_external_lease_consumed":False,
    }


def deny_external_effect_or_scoring(*_args,**_kwargs):
    raise Refused("405_NO_PRODUCTION_IDENTITY_OR_FRESH_PAID_PROVIDER_APPROVAL")


if __name__=="__main__":
    if len(sys.argv)==2 and sys.argv[1]=="--worker":
        serve_child()
    else:
        raise SystemExit("405: worker mode only; no Provider/production runner")
