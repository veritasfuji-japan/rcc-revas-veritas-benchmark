#!/usr/bin/env python3
"""Host-side Docker isolation audit for Task15 worker, NEVER a Provider sender.

Inspects immutable container configuration BEFORE launching the negative probe.
Synthetic host-only credential does not become a container environment variable.
No Docker socket is passed to the worker. Fail closed if Docker is unavailable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "scripts" / "task15_isolated_worker_probe_v1.py"
CONTRACT = ROOT / "contracts" / "TASK15_WORKER_CREDENTIAL_EGRESS_ISOLATION_V1.json"
RULE = "TASK15_WORKER_CREDENTIAL_EGRESS_ISOLATION_V1"
IMAGE = "python:3.11.16-slim"
EXPECTED_TESTS = 14

class IsolationDenied(RuntimeError):
    pass

def require(ok, reason):
    if not ok:
        raise IsolationDenied(reason)

def command(argv, *, env=None, timeout=180, check=True):
    p = subprocess.run(argv, text=True, capture_output=True, env=env, timeout=timeout)
    if check and p.returncode:
        raise IsolationDenied("COMMAND_FAILED:" + " ".join(argv[:3]) + ":" +
                              (p.stderr + p.stdout)[-1200:])
    return p

def validate_inspect(info, probe, fingerprint):
    """Reject a misconfigured Docker worker BEFORE executing adversarial code."""
    c = info["Config"]
    h = info["HostConfig"]
    require(h["NetworkMode"] == "none", "WORKER_NETWORK_MUST_BE_NONE")
    require(h["ReadonlyRootfs"] is True, "ROOTFS_MUST_BE_READ_ONLY")
    require(h["Privileged"] is False, "PRIVILEGED_CONTAINER_FORBIDDEN")
    require("ALL" in [v.upper() for v in (h.get("CapDrop") or [])],
            "ALL_CAPABILITIES_MUST_BE_DROPPED")
    require(not h.get("CapAdd"), "CAPABILITY_ADDITION_FORBIDDEN")
    require(any("no-new-privileges" in v for v in (h.get("SecurityOpt") or [])),
            "NO_NEW_PRIVILEGES_REQUIRED")
    require(c["User"] == "65534:65534", "NON_ROOT_USER_REQUIRED")
    require(c.get("Cmd") == ["python", "-B", "/probe.py"],
            "ONLY_OFFLINE_WORKER_PROBE_ALLOWED")
    require(not c.get("Entrypoint"), "CUSTOM_ENTRYPOINT_FORBIDDEN")
    require(not h.get("Devices"), "HOST_DEVICE_MOUNT_FORBIDDEN")
    require(not h.get("Binds"), "UNREVIEWED_BIND_MOUNT_FORBIDDEN")
    require(not h.get("PortBindings") and not h.get("PublishAllPorts"),
            "PUBLISHED_PORT_FORBIDDEN")
    require(not h.get("PidMode") and h.get("IpcMode") in ("", "private", None),
            "HOST_PID_OR_IPC_NAMESPACE_FORBIDDEN")
    require(h.get("PidsLimit") is not None and 0 < h["PidsLimit"] <= 64,
            "PROCESS_LIMIT_REQUIRED")
    require(h.get("Memory") is not None and 0 < h["Memory"] <= 268435456,
            "MEMORY_LIMIT_REQUIRED")
    mounts = info.get("Mounts") or []
    require(len(mounts) == 1, "ONLY_EXACT_READONLY_PROBE_MOUNT_ALLOWED")
    m = mounts[0]
    require(m["Type"] == "bind" and m["Destination"] == "/probe.py"
            and Path(m["Source"]).resolve() == Path(probe).resolve()
            and m["RW"] is False,
            "UNREVIEWED_OR_WRITABLE_HOST_MOUNT_FORBIDDEN")
    env = c.get("Env") or []
    require(any(v == "EXPECTED_HOST_SECRET_SHA256=" + fingerprint for v in env),
            "HOST_ONLY_SENTINEL_FINGERPRINT_MISSING")
    require(not any(v.startswith(("OPENAI_API_KEY=", "OPENAI_BASE_URL=",
              "ANTHROPIC_API_KEY=", "AWS_SECRET_ACCESS_KEY=", "GITHUB_TOKEN=",
              "GH_TOKEN=")) for v in env), "SENSITIVE_VARIABLE_PASSED_TO_WORKER")
    require(not any("sk-synthetic-host-only-" in v for v in env),
            "SYNTHETIC_SECRET_PASSED_TO_WORKER")
    return True

def junit(report, path):
    cases = report["cases"]
    root = ET.Element("testsuite", {"name": RULE, "tests": str(len(cases)),
                      "failures": str(sum(c["result"] != "PASS" for c in cases)),
                      "errors": "0"})
    for row in cases:
        case = ET.SubElement(root, "testcase", {"classname": RULE,
                                               "name": row["name"]})
        if row["result"] != "PASS":
            ET.SubElement(case, "failure", {"message": row.get("reason", "UNKNOWN")})
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    a = parser.parse_args()
    out = a.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    contract = json.loads(CONTRACT.read_text())
    require(contract["rule_of_one"] == RULE
            and contract["predecessor_merged_main_sha"] ==
                "c388a4decbfb054bff72af104dadf7a395809bd2"
            and contract["expected_worker_tests"] == EXPECTED_TESTS
            and contract["real_provider_calls_authorized"] is False,
            "WRONG_OR_LIVE_CONTRACT")
    require(PROBE.is_file(), "MISSING_WORKER_PROBE")
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("OPENAI_BASE_URL")
            and not os.environ.get("ANTHROPIC_API_KEY"),
            "REAL_PROVIDER_CREDS_OR_BASE_URL_NOT_ALLOWED_IN_JOB")
    probe_sha = hashlib.sha256(PROBE.read_bytes()).hexdigest()
    image_pull = command(["docker", "pull", IMAGE], timeout=240)
    (out / "docker-pull.log").write_text(image_pull.stdout + image_pull.stderr)
    img = json.loads(command(["docker", "image", "inspect", IMAGE]).stdout)[0]
    image_id = img["Id"]
    image_digests = img.get("RepoDigests") or []
    require(image_id.startswith("sha256:") and len(image_digests) >= 1,
            "EXACT_IMAGE_ID_AND_UPSTREAM_DIGEST_REQUIRED")
    host_secret = "sk-synthetic-host-only-" + secrets.token_hex(32)
    fingerprint = hashlib.sha256(host_secret.encode()).hexdigest()
    host_env = dict(os.environ, OPENAI_API_KEY=host_secret)
    ident = None
    try:
        spec = [
            "docker", "create", "--network=none", "--read-only",
            "--user=65534:65534", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--pids-limit=64",
            "--memory=256m", "--cpus=1",
            "--mount", "type=bind,source=" + str(PROBE.resolve()) +
                       ",target=/probe.py,readonly",
            "--env", "EXPECTED_HOST_SECRET_SHA256=" + fingerprint,
            IMAGE, "python", "-B", "/probe.py"
        ]
        ident = command(spec, env=host_env).stdout.strip()
        require(len(ident) == 64 and all(c in "0123456789abcdef" for c in ident),
                "NO_EXACT_CONTAINER_ID")
        info = json.loads(command(["docker", "inspect", ident]).stdout)[0]
        validate_inspect(info, PROBE, fingerprint)
        # Save raw OS-container metadata for independent inspection.
        (out / "docker-container-inspect.json").write_text(
            json.dumps(info, indent=2, sort_keys=True) + "\n")
        run = command(["docker", "start", "--attach", ident],
                      env=host_env, timeout=45, check=False)
        (out / "docker-worker-stdout.log").write_text(run.stdout + run.stderr)
        rows = [r for r in run.stdout.splitlines() if r.strip()]
        require(len(rows) == 1, "EXACT_ONE_WORKER_OBSERVATION_REQUIRED")
        report = json.loads(rows[0])
        state = json.loads(command(["docker", "inspect", ident]).stdout)[0]["State"]
        require(state["ExitCode"] == 0, "ISOLATED_WORKER_NONZERO_EXIT")
        names = [c["name"] for c in report["cases"]]
        require(report["rule_of_one"] == RULE and
                report["kind"] == "UNTRUSTED_WORKER_OBSERVATION"
                and report["real_provider_calls"] == 0
                and report["real_provider_spend_usd"] == 0
                and len(names) == EXPECTED_TESTS and len(set(names)) == EXPECTED_TESTS,
                "INVALID_WORKER_OBSERVATION")
        result = {"rule_of_one": RULE,
                  "determination": "OS_ISOLATED_WORKER_NEGATIVE_PROBES_PASSED_NOT_PRODUCTION_PROVEN",
                  "predecessor_merged_main_sha": contract["predecessor_merged_main_sha"],
                  "worker_probe_sha256": probe_sha, "image_id": image_id,
                  "image_digests": image_digests, "container_id": ident,
                  "network_mode": info["HostConfig"]["NetworkMode"],
                  "readonly_rootfs": info["HostConfig"]["ReadonlyRootfs"],
                  "privileged": info["HostConfig"]["Privileged"],
                  "cap_drop": info["HostConfig"]["CapDrop"],
                  "user": info["Config"]["User"],
                  "host_synthetic_secret_sha256": fingerprint,
                  "docker_state_exit_code": state["ExitCode"],
                  "cases": report["cases"],
                  "actual_provider_requests": 0, "actual_provider_spend_usd": 0,
                  "actual_bank_effects": 0,
                  "independent_auditor_determination": "PENDING"}
        (out / "task15-worker-isolation-evidence.json").write_text(
            json.dumps(result, sort_keys=True, indent=2) + "\n")
        junit(result, out / "task15-worker-isolation-junit.xml")
        require(all(c["result"] == "PASS" for c in report["cases"]),
                "WORKER_NEGATIVE_TEST_FAILED")
        print("BOUNDED_WORKER_ISOLATION_PASS: " + str(len(names)) + "/" + str(len(names)))
        print("Docker image digest: " + str(image_digests))
        print("No actual Provider requests authorized or made by this proof.")
    finally:
        if ident:
            command(["docker", "rm", "-f", ident], check=False)

if __name__ == "__main__":
    try:
        main()
    except (IsolationDenied, subprocess.SubprocessError, ValueError, KeyError,
            OSError, json.JSONDecodeError) as exc:
        print("TASK15_WORKER_ISOLATION_FAIL_CLOSED:" + str(exc), file=sys.stderr)
        sys.exit(1)
