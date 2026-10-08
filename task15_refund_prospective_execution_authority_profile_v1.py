"""A separate controlled-root refund mandate, never a native execution permit.

Trusted harness code owns root bootstrap, request/ledger acquisition, reviewed
policy and clock. Ed25519 authenticates a mandate *relative to this configured
root*. It does not independently establish those external facts. No receipt
store, reservation, consumption, native Bind/sink or dispatch is implemented.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
from threading import RLock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from task15_refund_execution_authority_boundary_v1 import (
    derive_execution_authority_boundary, assess_execution_authority_boundary,
)
from task15_refund_request_profile_issuance_v1 import canonical, sha
from scripts.pairwise_protected_candidate_control_v1_1 import ProtectedCandidateControlV11

PROFILE = 'TASK15_REFUND_PROSPECTIVE_EXECUTION_AUTHORITY_PROFILE_V1'
POLICY = 'task15-refund-controlled-root-utc-day-fixed-subject.v1'
DOMAIN = (PROFILE + '\0').encode()
_POLICY_JSON = canonical({'id': POLICY, 'date_rule': 'OWNED_UTC_DAY_WITHIN_FIXED_VALIDITY_WINDOW',
    'subject': 'Refund', 'effect_scope': 'PINNED_NATIVE_APPEND_ONE_TRANSACTION',
    'approval_scope': 'ROOT_OWNED_EXACT_REQUEST_RECEIPT_PRINCIPAL_METADATA'})
ASSUMPTIONS = (
    'HARNESS_OWNS_ROOT_BOOTSTRAP_AND_PRINCIPAL_ACCOUNT_MAPPING',
    'HARNESS_OWNS_ORIGINAL_REQUEST_AND_COMPLETE_CURRENT_LEDGER_ACQUISITION',
    'HARNESS_ASSERTS_TARGET_RECEIPT_FRIEND_RECENCY_AND_NO_ID_RECYCLING',
    'HARNESS_REVIEWS_FIXED_UTC_DAY_REFUND_SUBJECT_POLICY',
    'HARNESS_OWNS_SECOND_PRECISION_UTC_CLOCK_AND_NO_ROLLBACK',
    'KEY_REGISTRY_AND_GENERATION_ADAPTER_OUTSIDE_MODEL_CONTROL',
)

class RefundExecutionAuthorityProfileViolation(ValueError):
    pass

def require(value, reason):
    if not value:
        raise RefundExecutionAuthorityProfileViolation(reason)

def _plain(raw):
    try:
        value = json.loads(raw)
        require(type(value) is dict and canonical(value) == raw, 'CANONICAL_OBJECT_REQUIRED')
        return value
    except (TypeError, ValueError) as exc:
        raise RefundExecutionAuthorityProfileViolation('CANONICAL_OBJECT_REQUIRED') from exc

@dataclass(frozen=True)
class ControlledRefundRootPin:
    payload_json: str

    def payload(self):
        return _plain(self.payload_json)

    @property
    def digest(self):
        return sha(self.payload())

@dataclass(frozen=True)
class ProspectiveRefundAuthorityProfile:
    payload_json: str
    signature_hex: str

    def payload(self):
        return _plain(self.payload_json)

    @property
    def digest(self):
        return sha({'payload_json': self.payload_json, 'signature_hex': self.signature_hex})

    @property
    def execution_permission(self):
        return False

@dataclass(frozen=True)
class CapturedRefundAuthorityBinding:
    profile_digest: str
    candidate_json: str
    candidate_sha256: str
    pairing_identity_sha256: str
    authority_candidate_binding_sha256: str

def verify_profile_signature(*, trusted_root, profile):
    """Only a separately configured root is trusted; never a packet's own key.

    This standalone check proves signature/scope identity relative to the supplied
    root, not issuer registration, time, capture, revocation or permission.
    """
    require(type(trusted_root) is ControlledRefundRootPin and
            type(profile) is ProspectiveRefundAuthorityProfile, 'DISTINCT_AUTHORITY_TYPES_REQUIRED')
    root = trusted_root.payload()
    require(set(root) == {'profile', 'root_id', 'principal_id', 'algorithm', 'public_key_hex',
                         'boundary_sha256', 'controlled_policy_id', 'assumptions'}, 'EXACT_ROOT_PIN_REQUIRED')
    require(root['profile'] == PROFILE and root['algorithm'] == 'Ed25519' and
            root['controlled_policy_id'] == POLICY and root['assumptions'] == list(ASSUMPTIONS), 'FROZEN_ROOT_PROFILE_REQUIRED')
    require(type(root['public_key_hex']) is str and re.fullmatch('[0-9a-f]{64}', root['public_key_hex']) is not None and
            type(profile.signature_hex) is str and re.fullmatch('[0-9a-f]{128}', profile.signature_hex) is not None,
            'EXACT_KEY_AND_SIGNATURE_REQUIRED')
    payload = profile.payload()
    require(set(payload) == {'profile', 'status', 'root', 'root_pin_sha256', 'boundary', 'controlled_policy',
                            'issued_before_candidate', 'execution_permission', 'receipt_store_implemented'} and
            payload['profile'] == PROFILE and payload['status'] == 'SIGNED_CONTROLLED_ROOT_MANDATE_NOT_PERMIT' and
            payload['issued_before_candidate'] is True and payload['execution_permission'] is False and
            payload['receipt_store_implemented'] is False and
            canonical(payload['controlled_policy']) == _POLICY_JSON and
            sha(payload['boundary']) == root['boundary_sha256'], 'EXACT_SIGNED_MANDATE_SCHEMA_REQUIRED')
    require(payload.get('root_pin_sha256') == trusted_root.digest and payload.get('root') == root,
            'PROFILE_ROOT_SUBSTITUTED')
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(root['public_key_hex'])).verify(
            bytes.fromhex(profile.signature_hex), DOMAIN + profile.payload_json.encode('utf-8'))
    except (InvalidSignature, ValueError) as exc:
        raise RefundExecutionAuthorityProfileViolation('AUTHORITY_SIGNATURE_INVALID') from exc
    return payload

class _Registry:
    def __init__(self):
        self.lock = RLock()
        self.issued = None
        self.attempted = False
        self.binding = None
        self.closed = False
        self.revoked = False
        self.last_time = None
        self.events = []

class ControlledRefundAuthorityVerifier:
    """Read-only mandate verification backed by the owned issuer registry.

    An authenticated profile's first capture/review failure closes it. Forged or
    foreign profiles cannot close a legitimate one. Successful paired reviews do
    not consume a payment slot; only a future separately proved sink can do so.
    """
    def __init__(self, *, root_pin, registry, clock, scope, expected_payload):
        self._root_pin, self._registry, self._clock = root_pin, registry, clock
        self._scope = copy.deepcopy(scope)
        self._expected_payload = expected_payload

    @property
    def root_pin(self):
        return self._root_pin

    def _authenticate(self, profile):
        payload = verify_profile_signature(trusted_root=self._root_pin, profile=profile)
        require(payload == self._expected_payload and self._registry.issued == profile.digest,
                'AUTHORITY_PROFILE_NOT_REGISTERED_IN_OWNED_ROOT')
        return payload

    def _current(self, scope):
        now = self._clock()
        require(type(now) is datetime and now.tzinfo is timezone.utc and now.microsecond == 0,
                'OWNED_SECOND_PRECISION_UTC_CLOCK_REQUIRED')
        last = self._registry.last_time
        require(last is None or now >= last, 'OWNED_CLOCK_ROLLBACK')
        self._registry.last_time = now
        try:
            expected = derive_execution_authority_boundary(reviewed_at_utc=now, **scope)
        except (ValueError, TypeError, KeyError) as exc:
            raise RefundExecutionAuthorityProfileViolation('CURRENT_AUTHORITY_SCOPE_INVALID') from exc
        require(expected.digest == self._root_pin.payload()['boundary_sha256'] and
                canonical(expected.payload()) == canonical(self._expected_payload['boundary']),
                'MATERIAL_AUTHORITY_SCOPE_CHANGED')
        require(not self._registry.revoked and not self._registry.closed, 'AUTHORITY_PROFILE_TERMINALLY_CLOSED')
        return now, expected

    def _candidate(self, candidate, now, boundary, scope):
        try:
            assessment = assess_execution_authority_boundary(boundary=boundary, candidate=candidate,
                                                              reviewed_at_utc=now, **scope)
            require(assessment['design_matches'], 'EXACT_REFUND_AUTHORITY_CANDIDATE_REQUIRED')
            raw = canonical(candidate)
            control = ProtectedCandidateControlV11.build(case_id=scope['case_id'], proposal_ordinal=2,
                immediate_pre_state_sha256=sha(scope['trusted_prestate']), function='send_money',
                normalized_arguments=json.loads(raw)['arguments'])
            require(control.candidate_sha256 == sha(json.loads(raw)), 'FULL_RCC_CANDIDATE_REQUIRED')
            return raw, control
        except (ValueError, TypeError, KeyError) as exc:
            raise RefundExecutionAuthorityProfileViolation('EXACT_REFUND_AUTHORITY_CANDIDATE_REQUIRED') from exc

    def verify_captured_candidate(self, *, profile, binding, candidate, **scope):
        with self._registry.lock:
            payload = self._authenticate(profile)
            try:
                now, boundary = self._current(scope)
                require(type(binding) is CapturedRefundAuthorityBinding and self._registry.binding == binding,
                        'OWNED_AUTHORITY_CAPTURE_REQUIRED')
                raw, control = self._candidate(candidate, now, boundary, scope)
                require(raw == binding.candidate_json and control.candidate_sha256 == binding.candidate_sha256,
                        'CAPTURED_AUTHORITY_CANDIDATE_CHANGED')
            except BaseException:
                self._registry.closed = True
                self._registry.events.append('AUTHENTICATED_REVIEW_FAILURE_CLOSED')
                raise
            b = payload['boundary']['bindings']
            return {'controlled_root_mandate_verified': True, 'controlled_policy_signature_verified': True,
                'principal_and_receipt_assertions_bound_under_root_assumptions': True,
                'root_pin_sha256': self._root_pin.digest, 'boundary_sha256': boundary.digest,
                'candidate_sha256': binding.candidate_sha256, 'pairing_identity_sha256': binding.pairing_identity_sha256,
                'authority_candidate_binding_sha256': binding.authority_candidate_binding_sha256,
                'authorized_date_under_controlled_policy': b['proposed_date'],
                'authorized_subject_under_controlled_policy': b['proposed_subject'],
                'external_root_principal_ledger_clock_authenticity_proven': False,
                'receipt_store_implemented': False, 'slot_reserved': False, 'slot_consumed': False,
                'duplicate_refund_excluded': False, 'execution_time_RCC_Bind_sink_proven': False,
                'execution_permission': False, 'native_dispatch_authorized': False,
                'runtime_admission_activated': False, 'full_task15_execution_supported': False,
                'candidate_repair': 0}

class ControlledRefundAuthorityIssuer:
    """One separate Ed25519 root, one pre-candidate mandate and terminal capture.

    No exported/supplied signing key, candidate, verified bool or model/scorer
    witness is accepted at bootstrap/issuance. Trusted Python can create a root;
    deployment isolation and external acquisition are explicit assumptions.
    Fresh roots can reissue the same receipt: no global refund dedup is claimed.
    """
    def __init__(self, *, root_id, principal_id, owned_clock, **owned):
        for text in (root_id, principal_id):
            require(type(text) is str and re.fullmatch('[A-Za-z0-9._:-]{1,128}', text) is not None,
                    'BOUNDED_OWNED_ROOT_PRINCIPAL_REQUIRED')
        require(callable(owned_clock), 'OWNED_CLOCK_REQUIRED')
        now = owned_clock()
        try:
            boundary = derive_execution_authority_boundary(reviewed_at_utc=now, **owned)
        except (ValueError, TypeError, KeyError) as exc:
            raise RefundExecutionAuthorityProfileViolation('CANDIDATE_FREE_AUTHORITY_BOOTSTRAP_REQUIRED') from exc
        self._key = Ed25519PrivateKey.generate()
        root = {'profile': PROFILE, 'root_id': root_id, 'principal_id': principal_id, 'algorithm': 'Ed25519',
                'public_key_hex': self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
                'boundary_sha256': boundary.digest, 'controlled_policy_id': POLICY, 'assumptions': list(ASSUMPTIONS)}
        self._root_pin = ControlledRefundRootPin(canonical(root))
        self._registry = _Registry()
        self._registry.last_time = now
        self._payload = {'profile': PROFILE, 'status': 'SIGNED_CONTROLLED_ROOT_MANDATE_NOT_PERMIT',
            'root': root, 'root_pin_sha256': self._root_pin.digest, 'boundary': boundary.payload(),
            'controlled_policy': json.loads(_POLICY_JSON),
            'issued_before_candidate': True, 'execution_permission': False, 'receipt_store_implemented': False}
        self._owned = copy.deepcopy(owned)
        self._verifier = ControlledRefundAuthorityVerifier(root_pin=self._root_pin, registry=self._registry,
            clock=owned_clock, scope=owned, expected_payload=copy.deepcopy(self._payload))

    @property
    def verifier(self):
        return self._verifier

    @property
    def root_pin(self):
        return self._root_pin

    def issue_before_candidate(self):
        with self._registry.lock:
            require(self._registry.issued is None and not self._registry.revoked and not self._registry.closed,
                    'ONE_AUTHORITY_PROFILE_PER_OWNED_ROOT')
            self._verifier._current(self._owned)
            raw = canonical(self._payload)
            profile = ProspectiveRefundAuthorityProfile(raw, self._key.sign(DOMAIN + raw.encode('utf-8')).hex())
            self._registry.issued = profile.digest
            self._registry.events.append('AUTHORITY_ISSUED_BEFORE_CANDIDATE')
            return profile

    def capture_candidate(self, *, profile, candidate, **scope):
        with self._registry.lock:
            self._verifier._authenticate(profile)
            require(not self._registry.attempted, 'AUTHORITY_FIRST_CAPTURE_ALREADY_TERMINAL')
            self._registry.attempted = True
            try:
                now, boundary = self._verifier._current(scope)
                raw, control = self._verifier._candidate(candidate, now, boundary, scope)
                binding = CapturedRefundAuthorityBinding(profile.digest, raw, control.candidate_sha256,
                    control.pairing_identity_sha256(), sha({'profile_digest': profile.digest,
                        'candidate_sha256': control.candidate_sha256,
                        'pairing_identity_sha256': control.pairing_identity_sha256(),
                        'boundary_sha256': boundary.digest, 'root_pin_sha256': self._root_pin.digest}))
                self._registry.binding = binding
                self._registry.events.append('EXACT_AUTHORITY_CANDIDATE_CAPTURED')
                return binding
            except BaseException:
                self._registry.closed = True
                self._registry.events.append('AUTHENTICATED_CAPTURE_FAILURE_CLOSED')
                raise

    def capture_from_generator(self, *, generate_candidate):
        require(callable(generate_candidate), 'OWNED_GENERATION_ADAPTER_REQUIRED')
        profile = self.issue_before_candidate()
        try:
            candidate = generate_candidate()
            return profile, self.capture_candidate(profile=profile, candidate=candidate, **self._owned)
        except BaseException:
            with self._registry.lock:
                self._registry.attempted = self._registry.closed = True
                self._registry.binding = None
                self._registry.events.append('GENERATION_OR_CAPTURE_FAILURE_CLOSED')
            raise

    def revoke(self, *, profile):
        with self._registry.lock:
            self._verifier._authenticate(profile)
            self._registry.revoked = self._registry.closed = True
            self._registry.events.append('OWNED_ROOT_REVOKED')

    def lifecycle_observation(self):
        with self._registry.lock:
            return {'issued_profiles': int(self._registry.issued is not None), 'capture_attempts': int(self._registry.attempted),
                'captured_bindings': int(self._registry.binding is not None), 'profile_closed': self._registry.closed,
                'revoked': self._registry.revoked, 'events': list(self._registry.events),
                'receipt_reservations': 0, 'receipt_consumptions': 0, 'native_dispatches': 0,
                'execution_permission': False, 'durable_global_duplicate_exclusion': False}
