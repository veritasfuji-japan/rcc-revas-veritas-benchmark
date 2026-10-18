"""Task4 #457 cryptographic local evidence safety and full pinned Native proof."""
from __future__ import annotations
from pathlib import Path
import json
import os
import socket
from types import SimpleNamespace as NS

import pytest

from scripts import task4_457_local_response_aead_v1 as m

WF = Path(".github/workflows/task4-457-local-raw-aead-no-provider.yml")


@pytest.fixture
def private_dir(tmp_path):
    p = tmp_path / "private"
    p.mkdir(mode=0o700)
    return p


@pytest.fixture
def pair():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    return X25519PrivateKey.generate()


def request(response=b"SENSITIVE_LOCAL_TEST_ONLY"):
    return NS(content=b'{"local":"request"}'), NS(
        content=response, status_code=502)


def test_original_raw_response_only_ciphertext_on_disk_before_any_parse(
        private_dir, pair):
    vault = m.SealedLocalVault(private_dir, pair.public_key())
    req, resp = request(b'PRIVATE_SENTINEL_NOT_IN_CIPHERTEXT_457')
    rec = vault.commit_before_parser(
        arm="A", ordinal=0, request=req, response=resp)
    raw = (private_dir / rec["envelope_filename"]).read_bytes()
    assert b'PRIVATE_SENTINEL' not in raw
    assert b'{"local":"request"}' not in raw
    assert rec["local_fsync_completed"]
    assert rec["response_sha256"] == m.digest(resp.content)
    assert json.loads(raw)["header"]["http_status_observed_untrusted"] == 502
    assert len(vault.receipts) == 1
    assert vault.failed is False


def test_eight_ciphertexts_recover_exact_same_bytes_without_export(
        private_dir, pair):
    vault = m.SealedLocalVault(private_dir, pair.public_key())
    for arm in "AB":
        for i in range(4):
            req, response = request(f"PRIVATE_{arm}{i}".encode())
            vault.commit_before_parser(
                arm=arm, ordinal=i, request=req, response=response)
    assert len(vault.receipts) == 8
    assert vault.verify_local_recovery(pair) is True
    assert vault.closed
    assert vault.receipts[0]["independent_durable_custody"] is False
    assert all((private_dir / x["envelope_filename"]).stat().st_mode & 0o777
               == 0o600 for x in vault.receipts)


def test_wrong_recipient_cannot_recover(private_dir, pair):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    vault = m.SealedLocalVault(private_dir, pair.public_key())
    for arm in "AB":
        for i in range(4):
            req, resp = request(f"{arm}-{i}".encode())
            vault.commit_before_parser(arm=arm, ordinal=i, request=req,
                                       response=resp)
    other = X25519PrivateKey.generate()
    with pytest.raises(m.Refused, match="RECIPIENT_MUST_MATCH"):
        vault.verify_local_recovery(other)


def test_ciphertext_tampering_causes_hard_failure(private_dir, pair):
    vault = m.SealedLocalVault(private_dir, pair.public_key())
    for arm in "AB":
        for i in range(4):
            req, resp = request(f"{arm}-{i}".encode())
            vault.commit_before_parser(arm=arm, ordinal=i, request=req,
                                       response=resp)
    p = private_dir / vault.receipts[2]["envelope_filename"]
    p.write_bytes(p.read_bytes().replace(b"ciphertext_b64", b"altered_hex___"))
    with pytest.raises(m.Refused, match="CIPHERTEXT_ARCHIVE_MUTATED"):
        vault.verify_local_recovery(pair)


def test_duplicate_or_existing_file_does_not_overwrite(private_dir, pair):
    vault = m.SealedLocalVault(private_dir, pair.public_key())
    req, resp = request()
    vault.commit_before_parser(arm="A", ordinal=0, request=req, response=resp)
    before = (private_dir / "task4-457-A-0.enc.json").read_bytes()
    with pytest.raises(m.Refused, match="ONLY_EIGHT_FRESH"):
        vault.commit_before_parser(arm="A", ordinal=0, request=req, response=resp)
    assert vault.failed
    assert (private_dir / "task4-457-A-0.enc.json").read_bytes() == before
    with pytest.raises(m.Refused, match="CLOSED_OR_UNKNOWN"):
        vault.commit_before_parser(arm="B", ordinal=0, request=req, response=resp)


def test_existing_collision_freezes_even_new_instance(private_dir, pair):
    req, resp = request()
    first = m.SealedLocalVault(private_dir, pair.public_key())
    first.commit_before_parser(arm="B", ordinal=0, request=req, response=resp)
    new = m.SealedLocalVault(private_dir, pair.public_key())
    with pytest.raises(FileExistsError):
        new.commit_before_parser(arm="B", ordinal=0, request=req, response=resp)
    assert new.failed
    assert len(list(private_dir.iterdir())) == 1


def test_reject_nonprivate_output_directory(tmp_path, pair):
    target = tmp_path / "wide"
    target.mkdir(mode=0o755)
    target.chmod(0o755)
    with pytest.raises(m.Refused, match="PRIVATE_DIR_0700"):
        m.SealedLocalVault(target, pair.public_key())


@pytest.mark.parametrize("key", m.SENSITIVE)
def test_no_secrets_or_live_environment(monkeypatch, key):
    for x in m.SENSITIVE:
        monkeypatch.delenv(x, raising=False)
    monkeypatch.setenv(key, "fake")
    with pytest.raises(m.Refused, match="NO_REAL_PROVIDER"):
        m.deny_live()


def test_workflow_never_has_an_egress_or_credential_entrypoint():
    s = WF.read_text()
    assert "\n  pull_request:" in s
    assert "\n  workflow_dispatch:" not in s
    assert "\n  push:" not in s
    assert "pull_request_target" not in s
    assert "environment:" not in s
    assert "secrets." not in s
    assert "contents: read" in s and "contents: write" not in s
    assert "persist-credentials: false" in s
    assert "--mode offline-encrypt-local-responses" in s
    assert "results/*" in s
    assert "cryptography==50.0.0" in s
    for k in ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY",
              "ANTHROPIC_API_KEY", "OPENAI_BASE_URL"):
        assert k + ': ""' in s


def test_source_has_no_live_dispatch_and_no_plaintext_export():
    s = Path(m.__file__).read_text()
    assert "api_key=os.environ" not in s
    assert "httpx.HTTPTransport" not in s
    assert "HTTPSConnection(" not in s
    assert "requests.post(" not in s
    assert "provider_authenticated" not in s or "False" in s
    assert 'original(server, request)' in s
    assert 'os.O_EXCL' in s and 'os.fsync(dfd)' in s


@pytest.fixture
def no_external_network(monkeypatch):
    def blocked(*a, **k):
        pytest.fail("457_NO_NETWORK_IN_NATIVE_INTEGRATION")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)


@pytest.mark.skipif(os.environ.get("TASK4_457_NATIVE_PROOF") != "1",
                    reason="PINNED_NATIVE_TEST_ONLY")
def test_real_native_local_sdk_response_encrypt_before_native_and_scorer(
        no_external_network, monkeypatch):
    for x in m.SENSITIVE:
        monkeypatch.delenv(x, raising=False)
    report = m.run_local_native_encrypted_capture()
    assert report["ciphertext_locally_fsynced_and_recovered"] == 8
    assert report["same_source_native_terminal_and_scorer"] == 2
    assert report["real_provider_posts"] == 0
    assert report["genuine_model_responses"] == 0
    assert report["new_genuine_utility_recoveries"] == 0
    assert report["external_custody_or_cross_runner_retention_proven"] is False
    assert report["real_recipient_key_management_proven"] is False
    assert report["ciphertext_persisted_after_test"] is False
    assert report["live_provider_dispatch"] == "DENY"
    assert [r["arm"] for r in report["encrypted_local_receipts"]] == ["A"]*4+["B"]*4


@pytest.mark.skipif(os.environ.get("TASK4_457_NATIVE_PROOF") != "1",
                    reason="PINNED_NATIVE_TEST_ONLY")
def test_no_native_execution_with_provider_secret(
        no_external_network, monkeypatch):
    monkeypatch.setenv("TASK4_OPENAI_API_KEY", "FAKE")
    with pytest.raises(m.Refused, match="NO_REAL_PROVIDER"):
        m.run_local_native_encrypted_capture()
