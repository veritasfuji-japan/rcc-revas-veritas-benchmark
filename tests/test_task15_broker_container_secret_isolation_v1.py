"""Adversarial broker-container configuration validation. Offline only.

Skipped by the repository's generic fast CI (which does not install crypto).
Dedicated #281 proof installs pinned cryptography and executes all cases.
"""
from __future__ import annotations
import copy
import os
from pathlib import Path
import unittest

if os.environ.get("TASK15_BROKER_CONTAINER_PROOF") != "1":
    raise unittest.SkipTest("Dedicated offline #281 OS broker isolation proof only")

from scripts.task15_broker_container_secret_isolation_audit_v1 import validate_broker

UID=1001
GID=1001
IMAGE="sha256:"+"a"*64
PRIVATE=Path("/tmp/task15-test-private")
SHARED=Path("/tmp/task15-test-public")

def valid():
    return {
       "Image":IMAGE,
       "Config":{
         "User":str(UID)+":"+str(GID),
         "Entrypoint":None,
         "Cmd":["python","-B",
                "/app/scripts/task15_unix_ipc_mock_broker_server_v1.py",
                "--socket","/ipc/broker.sock",
                "--ledger","/private/ledger.sqlite3",
                "--secret-file","/private/only-synthetic-credential"],
         "Env":["PATH=/usr/local/bin"]
       },
       "HostConfig":{
         "NetworkMode":"none","ReadonlyRootfs":True,
         "Privileged":False,"CapDrop":["ALL"],"CapAdd":None,
         "SecurityOpt":["no-new-privileges:true"],
         "PidMode":"","IpcMode":"private","PortBindings":None,
         "PublishAllPorts":False,"Devices":None,"Binds":None,
         "PidsLimit":64,"Memory":268435456
       },
       "Mounts":[
         {"Destination":"/private","Source":str(PRIVATE),"RW":True},
         {"Destination":"/ipc","Source":str(SHARED),"RW":True}
       ]
    }

class BrokerInspectAdversarialTests(unittest.TestCase):
    def check(self,data):
        return validate_broker(data,PRIVATE,SHARED,IMAGE,UID,GID)

    def denied(self,fn):
        bad=copy.deepcopy(valid())
        fn(bad)
        with self.assertRaises((AssertionError, ValueError)):
            self.check(bad)

    def test_01_valid_spec(self):
        self.assertTrue(self.check(valid()))
    def test_02_host_network(self):
        self.denied(lambda x:x["HostConfig"].update(NetworkMode="host"))
    def test_03_bridge_network(self):
        self.denied(lambda x:x["HostConfig"].update(NetworkMode="bridge"))
    def test_04_root_user(self):
        self.denied(lambda x:x["Config"].update(User="0:0"))
    def test_05_privileged(self):
        self.denied(lambda x:x["HostConfig"].update(Privileged=True))
    def test_06_capability_added(self):
        self.denied(lambda x:x["HostConfig"].update(CapAdd=["NET_ADMIN"]))
    def test_07_missing_drop(self):
        self.denied(lambda x:x["HostConfig"].update(CapDrop=[]))
    def test_08_writable_root(self):
        self.denied(lambda x:x["HostConfig"].update(ReadonlyRootfs=False))
    def test_09_missing_nnp(self):
        self.denied(lambda x:x["HostConfig"].update(SecurityOpt=[]))
    def test_10_wrong_private_mount(self):
        self.denied(lambda x:x["Mounts"][0].update(Source="/var/run/docker.sock"))
    def test_11_extra_mount(self):
        self.denied(lambda x:x["Mounts"].append(
            {"Destination":"/host","Source":"/","RW":True}))
    def test_12_secret_in_environment(self):
        self.denied(lambda x:x["Config"]["Env"].append(
            "OPENAI_API_KEY=sk-fake-not-real"))
    def test_13_unpinned_image(self):
        self.denied(lambda x:x.update(Image="sha256:"+"b"*64))
    def test_14_host_pid_namespace(self):
        self.denied(lambda x:x["HostConfig"].update(PidMode="host"))
    def test_15_port_exposure(self):
        self.denied(lambda x:x["HostConfig"].update(
            PortBindings={"443/tcp":[{"HostPort":"443"}]}))
    def test_16_wrong_broker_command(self):
        self.denied(lambda x:x["Config"].update(Cmd=["python","-B","/unreviewed.py"]))
    def test_17_worker_uid_substitution(self):
        self.denied(lambda x:x["Config"].update(User="65534:65534"))

if __name__ == "__main__":
    unittest.main()
