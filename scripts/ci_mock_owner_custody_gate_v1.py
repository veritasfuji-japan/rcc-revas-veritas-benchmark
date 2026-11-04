"""CI-only synthetic owner approval admission enforced inside the mock Custody.

The owner key and signed approval are root-enrolled synthetic fixtures. No human
approval, real issuer, provider dispatch, production authorization or external
effect is established here. The mock backend has a separate kernel-protected UID.
"""
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

OWNER_DOMAIN = b"BEN_SYNTHETIC_OWNER_APPROVAL_V1\0"
OWNER_SCOPE = "BEN_RESEARCH_MOCK_ONLY"


def enforce(base, packet, issuer_key, attested_state, canonical, digest, need, op):
    """Verify two enrolled identities and one signed exact request+state.

    Caller: privileged CI Custody only. "attested_state" MUST originate from
    a fresh nonce-bound backend HMAC reply, not caller-supplied JSON.
    """
    owner_key = (Path(base) / 'trust/owner-public-key').read_bytes()
    need(type(issuer_key) is bytes and len(issuer_key) == 32
         and type(owner_key) is bytes and len(owner_key) == 32
         and issuer_key != owner_key, 'OWNER_ISSUER_NOT_INDEPENDENT')
    approval = json.loads((Path(base) / 'trust/owner-approval.json').read_bytes())
    need(type(approval) is dict and set(approval) == {'statement', 'signature'},
         'OWNER_EXACT_ENVELOPE')
    stmt = approval['statement']
    need(type(stmt) is dict and stmt == {
        'scope': OWNER_SCOPE,
        'operation_id': op,
        'request_sha256': digest(packet['request']),
        'prestate_sha256': digest(attested_state),
    }, 'OWNER_REQUEST_OR_STATE_MISMATCH')
    signature = approval['signature']
    need(type(signature) is str and len(signature) == 128, 'OWNER_SIGNATURE')
    try:
        Ed25519PublicKey.from_public_bytes(owner_key).verify(
            bytes.fromhex(signature), OWNER_DOMAIN + canonical(stmt))
    except (InvalidSignature, ValueError):
        raise ValueError('OWNER_SIGNATURE') from None
    return digest(stmt)
