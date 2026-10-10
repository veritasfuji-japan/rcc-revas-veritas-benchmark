"""Host-inspection adversarial regression tests; no Docker or Provider needed."""
from __future__ import annotations
import copy
from pathlib import Path
import unittest
from scripts.task15_worker_credential_egress_isolation_audit_v1 import (
    IsolationDenied, validate_inspect
)

FINGERPRINT = "f" * 64
PROBE = Path("/tmp/offline-task15-probe.py")

def good():
    return {
        "Config": {"User": "65534:65534", "Cmd": ["python", "-B", "/probe.py"],
                   "Entrypoint": None,
                   "Env": ["PATH=/usr/local/bin",
                           "EXPECTED_HOST_SECRET_SHA256=" + FINGERPRINT]},
        "HostConfig": {
            "NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
            "CapDrop": ["ALL"], "CapAdd": None,
            "SecurityOpt": ["no-new-privileges:true"],
            "Devices": [], "Binds": None, "PortBindings": {},
            "PublishAllPorts": False, "PidMode": "", "IpcMode": "",
            "PidsLimit": 64, "Memory": 268435456,
        },
        "Mounts": [{"Type": "bind", "Destination": "/probe.py",
                    "Source": str(PROBE), "RW": False}]
    }

class InspectAdversarialTests(unittest.TestCase):
    def test_proper_container_allowed(self):
        self.assertTrue(validate_inspect(good(), PROBE, FINGERPRINT))

    def test_host_network_denied(self):
        x = good(); x["HostConfig"]["NetworkMode"] = "host"
        with self.assertRaises(IsolationDenied): validate_inspect(x, PROBE, FINGERPRINT)

    def test_bridge_network_denied(self):
        x = good(); x["HostConfig"]["NetworkMode"] = "bridge"
        with self.assertRaises(IsolationDenied): validate_inspect(x, PROBE, FINGERPRINT)

    def test_privileged_denied(self):
        x = good(); x["HostConfig"]["Privileged"] = True
        with self.assertRaises(IsolationDenied): validate_inspect(x, PROBE, FINGERPRINT)

    def test_added_cap_denied(self):
        x = good(); x["HostConfig"]["CapAdd"] = ["NET_ADMIN"]
        with self.assertRaises(IsolationDenied): validate_inspect(x, PROBE, FINGERPRINT)

    def test_writable_fs_denied(self):
        x = good(); x["HostConfig"]["ReadonlyRootfs"] = False
        with self.assertRaises(IsolationDenied): validate_inspect(x, PROBE, FINGERPRINT)

    def test_docker_socket_bind_denied(self):
        x = good(); x["Mounts"].append({"Type": "bind",
              "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock",
              "RW": False})
        with self.assertRaises(IsolationDenied): validate_inspect(x, PROBE, FINGERPRINT)

    def test_probe_mount_writable_denied(self):
        x = good(); x["Mounts"][0]["RW"] = True
        with self.assertRaises(IsolationDenied): validate_inspect(x, PROBE, FINGERPRINT)

    def test_api_key_env_denied(self):
        x = good(); x["Config"]["Env"].append("OPENAI_API_KEY=sk-fake")
        with self.assertRaises(IsolationDenied): validate_inspect(x, PROBE, FINGERPRINT)

    def test_host_sentinel_env_denied(self):
        x = good(); x["Config"]["Env"].append("LEAK=sk-synthetic-host-only-abc")
        with self.assertRaises(IsolationDenied): validate_inspect(x, PROBE, FINGERPRINT)

    def test_root_user_denied(self):
        x = good(); x["Config"]["User"] = "0:0"
        with self.assertRaises(IsolationDenied): validate_inspect(x, PROBE, FINGERPRINT)

    def test_missing_nnp_denied(self):
        x = good(); x["HostConfig"]["SecurityOpt"] = []
        with self.assertRaises(IsolationDenied): validate_inspect(x, PROBE, FINGERPRINT)

    def test_host_pid_denied(self):
        x = good(); x["HostConfig"]["PidMode"] = "host"
        with self.assertRaises(IsolationDenied): validate_inspect(x, PROBE, FINGERPRINT)

    def test_arbitrary_command_denied(self):
        x = good(); x["Config"]["Cmd"] = ["bash"]
        with self.assertRaises(IsolationDenied): validate_inspect(x, PROBE, FINGERPRINT)

if __name__ == "__main__":
    unittest.main()
