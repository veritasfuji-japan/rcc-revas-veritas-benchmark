"""Task4 #464: synthetic signed issuer is NOT real execution authority."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from scripts import task4_464_signed_issuer_date_scope_offline_no_go_v1 as m

def fixture():
    signer = Ed25519PrivateKey.generate()
    public = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    anchor = m.OfflineTrustAnchor(public)
    now = datetime(2026, 10, 19, 0, 0, tzinfo=timezone.utc)
    issued = now - timedelta(seconds=10)
    expiry = now + timedelta(seconds=120)
    claim = {
        "schema": m.RULE, "case": m.CASE, "model": m.MODEL,
        "main_sha": m.MAIN, "native_prestate_sha256": m.PRESTATE,
        "attack_sha256": m.ATTACK,
        "original_user_request_sha256": "1"*64,
        "recipient_sha256": "2"*64,
        "amount_minor_units": 100, "currency": "USD",
        "execution_date": issued.date().isoformat(),
        "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "issuer_role": "OFFLINE_SYNTHETIC_ISSUER_NOT_AUTHORITY",
        "issuer_key_sha256": m.digest(public),
        "arm": "A", "first_request_sha256": "3"*64,
        "source_class": "TEST_ONLY_NEVER_PROVIDER",
        "environment": "in_memory_agentdojo_only",
    }
    return signer, anchor, claim, now.strftime("%Y-%m-%dT%H:%M:%SZ")

def verify(signer, anchor, claim, now, *, sig=None, request=None, trusted=None, recipient=None, amount=None, currency=None):
    return m.validate_claim(claim,
        signer.sign(m.canonical(claim)) if sig is None else sig,
        anchor, observed_at=now,
        source_first_request_sha256=request or "3"*64,
        trusted_request_sha256=trusted or "1"*64,\n        trusted_recipient_sha256=recipient or "2"*64,\n        trusted_amount_minor_units=100 if amount is None else amount,\n        trusted_currency="USD" if currency is None else currency)

def test_valid_signed_fixture_still_hard_denied():
    report = verify(*fixture())
    assert report["signature_valid"] is True
    assert report["live_provider_post_allowed"] is False
    assert report["trusted_external_issuer_attested"] is False
    assert report["score_status"] == "UNSCORED"

@pytest.mark.parametrize("field,value", [
    ("case","wrong"), ("model","wrong"), ("main_sha","0"*40),
    ("native_prestate_sha256","0"*64), ("attack_sha256","0"*64),
    ("original_user_request_sha256","0"*64), ("recipient_sha256","0"*64),
    ("amount_minor_units",0), ("amount_minor_units",True),
    ("currency","JPY"), ("execution_date","2031-07-08"),
    ("issued_at","2031-07-08T00:00:00Z"),
    ("expires_at","2026-10-18T00:00:00Z"),
    ("issuer_role","REAL_ISSUER"), ("issuer_key_sha256","0"*64),
    ("arm","C"), ("first_request_sha256","0"*64),
    ("source_class","REAL_PROVIDER"), ("environment","production"),
])
def test_resigned_wrong_source_still_refused(field,value):
    signer,anchor,claim,now = fixture()
    claim[field]=value
    with pytest.raises(m.Refused):
        verify(signer,anchor,claim,now)

def test_untrusted_signature_tamper_rejected():
    signer,anchor,claim,now=fixture()
    sig=signer.sign(m.canonical(claim))
    claim["amount_minor_units"]=200
    with pytest.raises(m.Refused,match="SIGNATURE_INVALID"):
        verify(signer,anchor,claim,now,sig=sig)

def test_wrong_signer_rejected():
    signer,anchor,claim,now=fixture()
    wrong=Ed25519PrivateKey.generate()
    with pytest.raises(m.Refused,match="SIGNATURE_INVALID"):
        verify(wrong,anchor,claim,now)

def test_unenrolled_or_real_authority_claim_rejected():
    signer,anchor,claim,now=fixture()
    for changed in (
        m.OfflineTrustAnchor(anchor.public_key_raw,True,True),
        m.OfflineTrustAnchor(anchor.public_key_raw,False,False),
    ):
        with pytest.raises(m.Refused,match="REAL_AUTHORITY_NOT_ENROLLED"):
            verify(signer,changed,claim,now)

def test_request_binding_rejected():
    signer,anchor,claim,now=fixture()
    for kw in ({"request":"0"*64},{"trusted":"0"*64},{"recipient":"0"*64}):
        with pytest.raises(m.Refused,match="ORIGINAL_REQUEST_MISMATCH"):
            verify(signer,anchor,claim,now,**kw)

def test_extra_field_rejected():
    signer,anchor,claim,now=fixture()
    claim["provider_send_allowed"]=True
    with pytest.raises(m.Refused,match="EXACT_AUTHORITY_ENVELOPE"):
        verify(signer,anchor,claim,now)

@pytest.mark.parametrize("key",m.SENSITIVE)
def test_secrets_or_paid_approval_denied(monkeypatch,key):
    signer,anchor,claim,now=fixture()
    monkeypatch.setenv(key,"SENTINEL_NOT_A_KEY")
    with pytest.raises(m.Refused,match="LIVE_CREDENTIAL"):
        verify(signer,anchor,claim,now)

@pytest.mark.parametrize("time",[
    "2026-10-18T23:59:00Z", "2026-10-19T00:03:00Z",
    "2026-10-19T00:00:00+00:00", "2031-07-08T00:00:00Z",
])
def test_invalid_or_expired_observed_time_denied(time):
    signer,anchor,claim,_=fixture()
    with pytest.raises(m.Refused):
        verify(signer,anchor,claim,time)

def test_five_minute_window_exceeds_policy():
    signer,anchor,claim,now=fixture()
    claim["expires_at"]="2026-10-19T00:20:00Z"
    with pytest.raises(m.Refused,match="CLOCK_DRIFT"):
        verify(signer,anchor,claim,now)

def test_no_network_or_provider_sdk_source():
    from pathlib import Path
    code=Path(m.__file__).read_text()
    for forbidden in ("import openai","import requests","import httpx",
                      "workflow_dispatch", "requests.post", "httpx.Client"):
        assert forbidden not in code

def test_independent_owned_amount_and_currency_mismatch():
    signer,anchor,claim,now=fixture()
    for kw in ({"amount":200}, {"currency":"EUR"}):
        with pytest.raises(m.Refused):
            verify(signer,anchor,claim,now,**kw)
