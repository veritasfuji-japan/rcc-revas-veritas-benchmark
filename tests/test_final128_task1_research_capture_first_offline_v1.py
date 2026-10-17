"""Task1 limited B-pilot capture-first NO-EFFECT tests, no API network."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import socket

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest

from scripts import final128_task1_research_capture_first_offline_v1 as unit

RUN = "39027404922"
MAIN = "1e977dc88050663eac8d51bc9f64751efe4a3f67"
REQUEST = hashlib.sha256(b"same-owned-initial-native-A-and-B").hexdigest()
KEY = bytes(range(32))
RAW_A = b'{"message":"OFFLINE_FAKE_ARM_A","choices":[1]}'
RAW_B = b'{"message":"OFFLINE_FAKE_ARM_B","choices":[2]}'


@pytest.fixture(autouse=True)
def no_network_or_provider_environment(monkeypatch):
    def blocked(*_args, **_kwargs):
        pytest.fail("RESEARCH_CAPTURE_FIRST_MUST_NEVER_CONNECT")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    for name in ("OPENAI_API_KEY", "TASK1_OPENAI_API_KEY",
                 "TASK1_CAPTURE_AES256_KEY", "GH_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def private_directory(tmp_path: Path) -> Path:
    folder = tmp_path / "encrypted"
    folder.mkdir(mode=0o700)
    folder.chmod(0o700)
    return folder


def mock_args(folder, arm="A", raw=RAW_A):
    return dict(
        raw=raw, aes256_key=KEY, output_dir=folder, arm=arm,
        run_id=RUN, main_sha=MAIN, request_sha256=REQUEST,
    )


def _read_envelope(folder, arm):
    return json.loads(
        (folder / f"task1-research-{arm}-{RUN}-mock.enc.json").read_text()
    )


def _decrypted(envelope, *, arm, main_sha=MAIN, request_sha256=REQUEST,
               aes_key=KEY):
    aad = unit._aad(arm=arm, run_id=RUN, main_sha=main_sha,
                    request_sha256=request_sha256)
    assert hashlib.sha256(aad).hexdigest() == envelope["aad_sha256"]
    return AESGCM(aes_key).decrypt(
        base64.b64decode(envelope["nonce_base64"]),
        base64.b64decode(envelope["ciphertext_base64"]),
        aad,
    )


def test_mock_a_b_capture_are_distinct_encrypted_no_plaintext(private_directory):
    a = unit.rehearse_mock_then_validate(
        **mock_args(private_directory, arm="A", raw=RAW_A),
        validator=json.loads,
    )
    b = unit.rehearse_mock_then_validate(
        **mock_args(private_directory, arm="B", raw=RAW_B),
        validator=json.loads,
    )
    assert a["status"] == b["status"] == "MOCK_VALIDATED_RAW_REMAINS_SEALED"
    assert a["provider_requests"] == b["provider_requests"] == 0
    assert a["production_tag_writes"] == b["production_tag_writes"] == 0
    assert a["request_sha256"] == b["request_sha256"] == REQUEST
    assert not a["real_origin_authenticated"]
    assert not a["eligible_for_official_scoring"]
    assert set(x.name for x in private_directory.iterdir()) == {a["file"], b["file"]}
    for arm, raw in (("A", RAW_A), ("B", RAW_B)):
        data = (private_directory / f"task1-research-{arm}-{RUN}-mock.enc.json").read_bytes()
        assert raw not in data
        assert b"OFFLINE_FAKE_ARM" not in data
        envelope = _read_envelope(private_directory, arm)
        assert envelope["format"] == "AES256_GCM"
        assert envelope["status"] == "UNTRUSTED_MOCK_RESPONSE_SEALED_PREVALIDATION"
        assert envelope["origin_authenticated"] is False
        assert envelope["eligible_for_paid_dispatch"] is False
        assert envelope["production_tag_consumed"] is False
        assert envelope["raw_sha256"] == hashlib.sha256(raw).hexdigest()
        assert _decrypted(envelope, arm=arm) == raw


def test_bad_parser_cannot_erase_already_encrypted_mock_capture(private_directory):
    broken = b"NOT_JSON__SENSITIVE_FAKE_CONTENT__"
    result = unit.rehearse_mock_then_validate(
        **mock_args(private_directory, raw=broken), validator=json.loads
    )
    assert result["status"] == "MOCK_VALIDATION_REFUSED_RAW_REMAINS_SEALED"
    assert result["validated_mock"] is False
    filename = private_directory / result["file"]
    assert filename.exists()
    assert broken not in filename.read_bytes()
    assert _decrypted(_read_envelope(private_directory, "A"), arm="A") == broken


def test_opaque_validator_error_never_exposes_raw_or_exception(private_directory):
    def rejects(_raw):
        raise RuntimeError("PRIVATE_MARKER_FAKE_NEVER_LOG_ME")
    result = unit.rehearse_mock_then_validate(
        **mock_args(private_directory), validator=rejects
    )
    assert result["status"] == "MOCK_VALIDATION_REFUSED_RAW_REMAINS_SEALED"
    assert "PRIVATE_MARKER" not in json.dumps(result)
    for file in private_directory.iterdir():
        assert b"PRIVATE_MARKER" not in file.read_bytes()


def test_mock_response_is_bound_to_arm_main_and_request_digest(private_directory):
    unit.seal_mock_before_parse(**mock_args(private_directory))
    envelope = _read_envelope(private_directory, "A")
    assert _decrypted(envelope, arm="A") == RAW_A
    for arm, sha, request, key in (
        ("B", MAIN, REQUEST, KEY),
        ("A", "f" * 40, REQUEST, KEY),
        ("A", MAIN, "0" * 64, KEY),
        ("A", MAIN, REQUEST, bytes(reversed(KEY))),
    ):
        aad = unit._aad(arm=arm, run_id=RUN, main_sha=sha,
                        request_sha256=request)
        with pytest.raises(Exception):
            AESGCM(key).decrypt(
                base64.b64decode(envelope["nonce_base64"]),
                base64.b64decode(envelope["ciphertext_base64"]),
                aad,
            )


def test_exclusive_capture_refuses_overwrite_and_preserves_first(private_directory):
    unit.seal_mock_before_parse(**mock_args(private_directory, raw=RAW_A))
    with pytest.raises(FileExistsError):
        unit.seal_mock_before_parse(**mock_args(private_directory, raw=RAW_B))
    assert _decrypted(_read_envelope(private_directory, "A"), arm="A") == RAW_A
    assert len(list(private_directory.iterdir())) == 1


@pytest.mark.parametrize("change", [
    {"raw": b""},
    {"raw": b"x" * (unit.MAX_MOCK_BYTES + 1)},
    {"raw": "not-bytes"},
    {"aes256_key": b"x" * 16},
    {"arm": "C"},
    {"run_id": "../unsafe"},
    {"run_id": "0000"},
    {"main_sha": "not_sha"},
    {"request_sha256": "not_sha256"},
])
def test_bad_inputs_fail_before_any_encrypted_output(private_directory, change):
    args = mock_args(private_directory)
    args.update(change)
    with pytest.raises(unit.Refused):
        unit.seal_mock_before_parse(**args)
    assert list(private_directory.iterdir()) == []


def test_output_directory_must_be_private(tmp_path):
    folder = tmp_path / "public"
    folder.mkdir()
    folder.chmod(0o755)
    with pytest.raises(unit.Refused, match="PRIVATE_OUTPUT_DIRECTORY"):
        unit.seal_mock_before_parse(**mock_args(folder))
    assert list(folder.iterdir()) == []


def test_output_directory_symlink_refused(tmp_path):
    real = tmp_path / "private"
    real.mkdir(mode=0o700)
    real.chmod(0o700)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(OSError):
        unit.seal_mock_before_parse(**mock_args(link))
    assert list(real.iterdir()) == []


def test_validator_is_required_and_never_runs_before_seal(private_directory):
    with pytest.raises(unit.Refused, match="VALIDATOR_REQUIRED"):
        unit.rehearse_mock_then_validate(
            **mock_args(private_directory), validator=None
        )
    assert not list(private_directory.iterdir())
    def validator(raw):
        assert (private_directory / f"task1-research-A-{RUN}-mock.enc.json").exists()
        assert raw == RAW_A
        return {"ignored": "never an actual provider score"}
    receipt = unit.rehearse_mock_then_validate(
        **mock_args(private_directory), validator=validator
    )
    assert receipt["validated_mock"] is True
    assert "score" not in receipt


def test_no_network_or_secret_loader_primitive_is_exposed():
    source = Path(unit.__file__).read_text(encoding="utf-8")
    for forbidden in ("api.openai.com", "https://", "urllib.request",
                      "requests.post", "http.client", "os.environ",
                      "gh api", "git/refs", "workflow_dispatch"):
        assert forbidden not in source
    assert not hasattr(unit, "send")
    assert not hasattr(unit, "issue_singleton")
    assert unit.REPO == "veritasfuji-japan/rcc-revas-veritas-benchmark"
