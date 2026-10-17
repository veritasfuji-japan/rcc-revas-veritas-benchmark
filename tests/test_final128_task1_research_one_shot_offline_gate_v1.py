"""A/B one-shot gate V1: offline mock-only, no network or Provider."""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import socket

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest

from scripts import final128_task1_research_one_shot_offline_gate_v1 as gate
from scripts import final128_task1_research_capture_first_offline_v1 as capture

RUN = "39029868682"
MAIN = "ba15301717e48d8296f161be7ee9bd1e220ffd41"
FIRST_SHA = hashlib.sha256(b"native-identical-initial-packets-offline").hexdigest()
KEY = bytes(range(32))
MOCK_A = b'{"synthetic_arm":"A","native_first_reply":"READ_ONLY_TOOL_PROPOSAL"}'
MOCK_B = b'{"synthetic_arm":"B","native_first_reply":"READ_ONLY_TOOL_PROPOSAL"}'


@pytest.fixture(autouse=True)
def refuse_all_network_and_external_secrets(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("TASK1_MOCK_GATE_EXTERNAL_NETWORK_FORBIDDEN")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    for k in ("OPENAI_API_KEY", "TASK1_OPENAI_API_KEY", "TASK1_CAPTURE_AES256_KEY",
              "GITHUB_TOKEN", "GH_TOKEN", "VERITAS_RULESET_OWNER_TOKEN"):
        monkeypatch.delenv(k, raising=False)


@pytest.fixture
def folder(tmp_path):
    p = tmp_path / "mock-state"
    p.mkdir(mode=0o700)
    p.chmod(0o700)
    return p


def plan(main=MAIN, a=FIRST_SHA, b=FIRST_SHA, run=RUN):
    return gate.MockPlan(
        run_id=run, main_sha=main,
        native_first_a_sha256=a, native_first_b_sha256=b,
    )


def instance(folder, chosen_plan=None):
    return gate.OfflineMockGate(folder, chosen_plan or plan())


def ciphertext(folder, arm):
    envelope = json.loads(
        (folder / f"task1-research-{arm}-{RUN}-mock.enc.json").read_bytes()
    )
    aad = capture._aad(
        arm=arm, run_id=RUN, main_sha=MAIN, request_sha256=FIRST_SHA,
    )
    assert hashlib.sha256(aad).hexdigest() == envelope["aad_sha256"]
    return AESGCM(KEY).decrypt(
        base64.b64decode(envelope["nonce_base64"]),
        base64.b64decode(envelope["ciphertext_base64"]), aad,
    )


def seal(g, arm, raw, validator=json.loads):
    return g.seal_mock_then_validate(
        arm=arm, raw=raw, fake_test_key=KEY, validator=validator,
    )


def test_full_two_arm_offline_mock_sequence_is_not_authority(folder):
    g = instance(folder)
    assert g.state() == "UNCLAIMED"
    assert g.live_dispatch_allowed is False
    assert g.plan.claims()["provider_calls_performed"] == 0
    g.claim()
    assert g.state() == "CLAIMED"
    g.begin_arm("A")
    assert g.state() == "A_INTENT_UNKNOWN_STOP"
    assert seal(g, "A", MOCK_A) == {
        "state": "A_MOCK_CAPTURED", "provider_calls": 0, "tag_writes": 0,
        "authorized_for_live_provider": False, "eligible_for_official_scoring": False,
    }
    assert ciphertext(folder, "A") == MOCK_A
    g.begin_arm("B")
    assert g.state() == "B_INTENT_UNKNOWN_STOP"
    receipt = seal(g, "B", MOCK_B)
    assert receipt["state"] == "MOCK_PAIR_COMPLETE_NO_REAL_AUTHORITY"
    assert receipt["provider_calls"] == receipt["tag_writes"] == 0
    assert receipt["authorized_for_live_provider"] is False
    assert ciphertext(folder, "B") == MOCK_B
    assert instance(folder).state() == "MOCK_PAIR_COMPLETE_NO_REAL_AUTHORITY"
    for arm, raw in (("A", MOCK_A), ("B", MOCK_B)):
        blob = (folder / f"task1-research-{arm}-{RUN}-mock.enc.json").read_bytes()
        assert raw not in blob
        assert b"READ_ONLY_TOOL_PROPOSAL" not in blob
    assert all(".tmp" not in p.name for p in folder.iterdir())


def test_b_cannot_start_before_a_result(folder):
    g = instance(folder)
    with pytest.raises(gate.Refused):
        g.begin_arm("A")
    g.claim()
    with pytest.raises(gate.Refused):
        g.begin_arm("B")
    g.begin_arm("A")
    with pytest.raises(gate.Refused):
        g.begin_arm("B")
    assert g.state() == "A_INTENT_UNKNOWN_STOP"


def test_crash_after_a_intent_is_irreversibly_unknown(folder):
    g = instance(folder)
    g.claim()
    g.begin_arm("A")
    restarted = instance(folder)
    assert restarted.state() == "A_INTENT_UNKNOWN_STOP"
    with pytest.raises(gate.Refused, match="STAGE_NOT_ELIGIBLE"):
        restarted.begin_arm("A")
    with pytest.raises(gate.Refused, match="STAGE_NOT_ELIGIBLE"):
        restarted.begin_arm("B")
    with pytest.raises(gate.Refused, match="SAME_INSTANCE_INTENT"):
        seal(restarted, "A", MOCK_A)
    assert not list(folder.glob("*.enc.json"))


def test_crash_after_b_intent_cannot_resume_or_redispatch(folder):
    g = instance(folder)
    g.claim()
    g.begin_arm("A")
    seal(g, "A", MOCK_A)
    g.begin_arm("B")
    recovered = instance(folder)
    assert recovered.state() == "B_INTENT_UNKNOWN_STOP"
    with pytest.raises(gate.Refused):
        recovered.begin_arm("B")
    with pytest.raises(gate.Refused):
        seal(recovered, "B", MOCK_B)
    assert ciphertext(folder, "A") == MOCK_A


def test_parser_rejection_preserves_a_encrypted_and_blocks_b(folder):
    g = instance(folder)
    g.claim()
    g.begin_arm("A")
    receipt = seal(g, "A", b"SIMULATED_BAD_BODY_NOT_JSON")
    assert receipt["state"] == "A_VALIDATION_REFUSED_STOP"
    assert ciphertext(folder, "A") == b"SIMULATED_BAD_BODY_NOT_JSON"
    with pytest.raises(gate.Refused):
        g.begin_arm("B")
    with pytest.raises(gate.Refused):
        g.begin_arm("A")


def test_parser_rejection_preserves_b_encrypted_and_stops(folder):
    g = instance(folder)
    g.claim()
    g.begin_arm("A")
    seal(g, "A", MOCK_A)
    g.begin_arm("B")
    receipt = seal(g, "B", b"{BROKEN")
    assert receipt["state"] == "B_VALIDATION_REFUSED_STOP"
    assert ciphertext(folder, "A") == MOCK_A
    assert ciphertext(folder, "B") == b"{BROKEN"
    with pytest.raises(gate.Refused):
        g.begin_arm("B")
    assert "03-mock-pair-complete.json" not in {p.name for p in folder.iterdir()}


def test_once_claim_two_instances_compete_no_overwrite(folder):
    two = [instance(folder), instance(folder)]
    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(g.claim) for g in two]
    successes = 0
    failures = 0
    for f in futures:
        try:
            f.result()
            successes += 1
        except (gate.Refused, FileExistsError):
            failures += 1
    assert (successes, failures) == (1, 1)
    assert instance(folder).state() == "CLAIMED"
    assert len(list(folder.iterdir())) == 1


def test_same_instance_cannot_repeat_capture_or_arm(folder):
    g = instance(folder)
    g.claim()
    g.begin_arm("A")
    seal(g, "A", MOCK_A)
    with pytest.raises(gate.Refused):
        seal(g, "A", MOCK_A)
    with pytest.raises(gate.Refused):
        g.begin_arm("A")
    g.begin_arm("B")
    seal(g, "B", MOCK_B)
    with pytest.raises(gate.Refused):
        g.begin_arm("B")


def test_capture_exception_consumes_intent_even_before_evidence(folder, monkeypatch):
    g = instance(folder)
    g.claim()
    g.begin_arm("A")
    def explode(**_kw):
        raise OSError("FAKE_STORAGE_ERROR")
    monkeypatch.setattr(gate.capture, "rehearse_mock_then_validate", explode)
    with pytest.raises(OSError):
        seal(g, "A", MOCK_A)
    with pytest.raises(gate.Refused, match="SAME_INSTANCE_INTENT"):
        seal(g, "A", MOCK_A)
    assert instance(folder).state() == "A_INTENT_UNKNOWN_STOP"
    assert not list(folder.glob("*.enc.json"))


def test_encrypted_file_without_final_result_fails_closed(folder, monkeypatch):
    g = instance(folder)
    g.claim()
    g.begin_arm("A")
    original = g._create
    def failure_after_capture(name, data):
        if name == "02-A-result.json":
            raise OSError("LOCAL_JOURNAL_FAKE_FAILURE")
        return original(name, data)
    monkeypatch.setattr(g, "_create", failure_after_capture)
    with pytest.raises(OSError):
        seal(g, "A", MOCK_A)
    assert ciphertext(folder, "A") == MOCK_A
    with pytest.raises(gate.Refused, match="A_UNCERTAIN_SEQUENCE_STOP"):
        instance(folder).state()
    with pytest.raises(gate.Refused):
        g.begin_arm("B")


def test_same_run_new_main_or_new_packet_cannot_reuse_claim(folder):
    g = instance(folder)
    g.claim()
    for different in (
        plan(main="f" * 40),
        plan(a="0" * 64, b="0" * 64),
        plan(run="12345678"),
    ):
        next_gate = instance(folder, different)
        with pytest.raises(gate.Refused):
            next_gate.claim()
        with pytest.raises(gate.Refused):
            next_gate.state()


@pytest.mark.parametrize("kwargs", [
    {"run": "../run"},
    {"run": "0000000000"},
    {"main": "invalid"},
    {"a": "f" * 64, "b": FIRST_SHA},
    {"a": "INVALID", "b": "INVALID"},
])
def test_invalid_mock_plan_refused_before_journal(folder, kwargs):
    with pytest.raises(gate.Refused):
        instance(folder, plan(**kwargs))
    assert list(folder.iterdir()) == []


def test_unprivileged_or_symlink_state_root_denied(tmp_path):
    insecure = tmp_path / "insecure"
    insecure.mkdir(mode=0o755)
    insecure.chmod(0o755)
    with pytest.raises(gate.Refused):
        instance(insecure)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    link = tmp_path / "link"
    link.symlink_to(private, target_is_directory=True)
    with pytest.raises(OSError):
        instance(link)


def test_unknown_file_or_corrupted_journal_refuses_not_repairs(folder):
    g = instance(folder)
    g.claim()
    (folder / "arbitrary.temp").write_text("not a trusted event")
    with pytest.raises(gate.Refused, match="UNEXPECTED_OR_PARTIAL_FILE"):
        g.state()
    (folder / "arbitrary.temp").unlink()
    (folder / "00-claim.json").write_text("{INVALID")
    with pytest.raises(gate.Refused, match="CORRUPTED_JOURNAL"):
        g.state()


def test_claim_file_missing_but_a_intent_exists_is_denied(folder):
    (folder / "01-A-intent.json").write_text("{}")
    with pytest.raises(gate.Refused, match="NO_PRIOR_CLAIM"):
        instance(folder).state()


def test_offline_module_has_no_dispatch_or_token_or_provider_client():
    src = Path(gate.__file__).read_text(encoding="utf-8")
    for forbidden in ("api.openai.com", "urllib.request",
                      "http.client", "requests.post",
                      "workflow_dispatch", "secrets.", "os.environ",
                      "git/refs", "subprocess", "github.token"):
        assert forbidden not in src
    assert not hasattr(gate.OfflineMockGate, "dispatch")
    assert not hasattr(gate.OfflineMockGate, "issue")
    assert gate.MODE == "OFFLINE_SIMULATION_NO_LIVE_AUTHORITY"
