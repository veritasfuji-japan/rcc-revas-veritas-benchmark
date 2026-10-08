"""Atomic single-store receipt exclusion; consumed/UNKNOWN slots never reopen.

Trusted harness owns this shared in-memory store and its configured verifier
objects. No durable database, native effect, execution capability or Bind/sink
integration is present. Fresh stores/restarts do not preserve this exclusion.
"""
from __future__ import annotations
from dataclasses import dataclass
import copy
import json
import re
import secrets
from threading import RLock
from task15_refund_prospective_execution_authority_profile_v1 import (
    ControlledRefundAuthorityVerifier, ProspectiveRefundAuthorityProfile,
)
from task15_refund_receipt_correlation_and_duplicate_authority_design_v1 import NAMESPACE, receipt_correlation_key
from task15_refund_request_profile_issuance_v1 import canonical, sha

RULE = 'TASK15_REFUND_RECEIPT_RESERVATION_CONSUMPTION_V1'

class RefundReceiptStoreViolation(ValueError):
    pass

def require(value, reason):
    if not value:
        raise RefundReceiptStoreViolation(reason)

@dataclass(frozen=True)
class RefundReceiptReservation:
    payload_json: str
    nonce: str

    def payload(self):
        try:
            p = json.loads(self.payload_json)
            require(type(p) is dict and canonical(p) == self.payload_json, 'CANONICAL_RESERVATION_REQUIRED')
            return p
        except (ValueError, TypeError) as exc:
            raise RefundReceiptStoreViolation('CANONICAL_RESERVATION_REQUIRED') from exc

    @property
    def digest(self):
        return sha({'payload_json': self.payload_json, 'nonce': self.nonce})

    @property
    def execution_permission(self):
        return False

class OwnedRefundReceiptStore:
    """Configured authority roots share one atomic namespace/account/typed-ID key.

    Store constructor/verifier selection and Python object ownership are trusted
    harness operations outside model control. A bearer reservation is checked
    against this store's exact registration and authority capture on consumption.
    A consumption receipt is audit data, never an execution permit. A new store
    starts empty: persistence, cross-process uniqueness and rollback recovery are
    not established by this bounded component.
    """
    def __init__(self, *, owned_verifiers):
        require(type(owned_verifiers) in (list, tuple) and 1 <= len(owned_verifiers) <= 64,
                'BOUNDED_OWNED_VERIFIER_CONFIGURATION_REQUIRED')
        roots = {}
        for verifier in owned_verifiers:
            require(type(verifier) is ControlledRefundAuthorityVerifier, 'CONFIGURED_AUTHORITY_VERIFIER_REQUIRED')
            digest = verifier.root_pin.digest
            require(digest not in roots, 'DUPLICATE_CONFIGURED_ROOT')
            roots[digest] = verifier
        self._verifiers = roots
        self._entries = {}
        self._lock = RLock()

    def _verify(self, *, profile, binding, candidate, scope):
        require(type(profile) is ProspectiveRefundAuthorityProfile, 'DISTINCT_AUTHORITY_PROFILE_REQUIRED')
        try:
            p = profile.payload()
            verifier = self._verifiers.get(p.get('root_pin_sha256'))
            require(verifier is not None, 'AUTHORITY_ROOT_NOT_CONFIGURED_IN_STORE')
            assessment = verifier.verify_captured_candidate(profile=profile, binding=binding, candidate=candidate, **scope)
            require(assessment['controlled_root_mandate_verified'] is True and
                    assessment['execution_permission'] is False, 'EXACT_NON_PERMIT_MANDATE_REVIEW_REQUIRED')
            b = p['boundary']['bindings']
            require(b['ledger_namespace'] == NAMESPACE and type(b['receipt_id']) is int and
                    b['correlation_key'] == receipt_correlation_key(account_id=b['account_id'], receipt_id=b['receipt_id']),
                    'STABLE_TYPED_RECEIPT_KEY_REQUIRED')
            return b, assessment
        except (ValueError, TypeError, KeyError) as exc:
            raise RefundReceiptStoreViolation('CONFIGURED_CURRENT_CAPTURED_AUTHORITY_REQUIRED') from exc

    def reserve(self, *, profile, binding, candidate, **scope):
        with self._lock:
            b, assessment = self._verify(profile=profile, binding=binding, candidate=candidate, scope=scope)
            key = b['correlation_key']
            require(key not in self._entries, 'RECEIPT_ALREADY_RESERVED_OR_TERMINALLY_CLOSED')
            payload = {'rule_of_one': RULE, 'ledger_namespace': b['ledger_namespace'], 'account_id': b['account_id'],
                'receipt_id': b['receipt_id'], 'correlation_key': key, 'receipt_sha256': b['receipt_sha256'],
                'root_pin_sha256': assessment['root_pin_sha256'], 'profile_digest': profile.digest,
                'candidate_sha256': assessment['candidate_sha256'], 'pairing_identity_sha256': assessment['pairing_identity_sha256'],
                'boundary_sha256': assessment['boundary_sha256'],
                'authority_candidate_binding_sha256': assessment['authority_candidate_binding_sha256']}
            reservation = RefundReceiptReservation(canonical(payload), secrets.token_hex(32))
            self._entries[key] = {'reservation': reservation, 'assessment': copy.deepcopy(assessment), 'state': 'RESERVED',
                'reservations': 1, 'consumptions': 0, 'events': ['RESERVED'], 'reconciliation_notes': []}
            return reservation

    def _registered(self, reservation):
        require(type(reservation) is RefundReceiptReservation and type(reservation.nonce) is str and
                re.fullmatch('[0-9a-f]{64}', reservation.nonce) is not None, 'REGISTERED_RESERVATION_REQUIRED')
        p = reservation.payload()
        key = p.get('correlation_key')
        require(type(key) is str, 'REGISTERED_RECEIPT_KEY_REQUIRED')
        entry = self._entries.get(key)
        require(entry is not None and entry['reservation'] == reservation, 'RESERVATION_NOT_OWNED_BY_THIS_STORE')
        return p, entry

    def consume_before_dispatch(self, *, reservation, profile, binding, candidate, **scope):
        with self._lock:
            p, entry = self._registered(reservation)
            require(entry['state'] == 'RESERVED', 'RESERVATION_ALREADY_CLOSED_OR_CONSUMED')
            # Foreign/bad bearer identities cannot close someone else's reservation.
            require(type(profile) is ProspectiveRefundAuthorityProfile and profile.digest == p['profile_digest'],
                    'ORIGINAL_RESERVATION_AUTHORITY_PROFILE_REQUIRED')
            try:
                b, assessment = self._verify(profile=profile, binding=binding, candidate=candidate, scope=scope)
                require(b['correlation_key'] == p['correlation_key'] and assessment == entry['assessment'],
                        'RESERVED_AUTHORITY_CANDIDATE_SCOPE_CHANGED')
            except BaseException:
                entry['state'] = 'CLOSED_BEFORE_CONSUMPTION'
                entry['events'].append('AUTHENTICATED_RECHECK_FAILURE_CLOSED')
                raise
            entry['state'] = 'CONSUMED'
            entry['consumptions'] = 1
            entry['events'].append('CONSUMED_BEFORE_ANY_DISPATCH')
            return self._observation(p, entry)

    def close_before_consumption(self, *, reservation):
        with self._lock:
            p, entry = self._registered(reservation)
            require(entry['state'] == 'RESERVED', 'ONLY_UNCONSUMED_RESERVATION_CAN_CLOSE')
            entry['state'] = 'CLOSED_BEFORE_CONSUMPTION'
            entry['events'].append('CLOSED_BEFORE_CONSUMPTION')
            return self._observation(p, entry)

    def mark_unknown(self, *, reservation):
        """Conservative local terminal state; no actual effect/NO_EFFECT assertion."""
        with self._lock:
            p, entry = self._registered(reservation)
            require(entry['state'] == 'CONSUMED', 'UNKNOWN_REQUIRES_ONE_PRIOR_CONSUMPTION')
            entry['state'] = 'UNKNOWN'
            entry['events'].append('CONSUMPTION_OUTCOME_UNKNOWN')
            return self._observation(p, entry)

    def record_reconciliation_note(self, *, reservation, note_sha256):
        """A hash-only note never authenticates effects or resets a spent slot."""
        with self._lock:
            p, entry = self._registered(reservation)
            require(entry['state'] == 'UNKNOWN', 'RECONCILIATION_NOTE_REQUIRES_UNKNOWN')
            require(type(note_sha256) is str and re.fullmatch('[0-9a-f]{64}', note_sha256) is not None,
                    'HASH_ONLY_RECONCILIATION_NOTE_REQUIRED')
            require(len(entry['reconciliation_notes']) < 16 and note_sha256 not in entry['reconciliation_notes'],
                    'BOUNDED_DISTINCT_RECONCILIATION_NOTES_REQUIRED')
            entry['reconciliation_notes'].append(note_sha256)
            entry['events'].append('NOTE_RECORDED_WITHOUT_STATE_OR_PERMISSION_CHANGE')
            return self._observation(p, entry)

    @staticmethod
    def _observation(p, entry):
        return {'correlation_key': p['correlation_key'], 'receipt_id': p['receipt_id'],
            'state': entry['state'], 'reservations': entry['reservations'], 'consumptions': entry['consumptions'],
            'events': list(entry['events']), 'reconciliation_notes': list(entry['reconciliation_notes']),
            'local_store_slot_reserved': True, 'local_store_slot_consumed': bool(entry['consumptions']),
            'local_shared_store_duplicate_exclusion': True, 'slot_retry_allowed': False,
            'execution_permission': False, 'native_dispatch_authorized': False, 'native_dispatches': 0,
            'runtime_admission_activated': False, 'effect_authenticated': False, 'no_effect_authenticated': False,
            'durable_global_duplicate_exclusion': False, 'restart_persistence_proven': False,
            'RCC_Bind_final_sink_integration_proven': False}

    def observe(self, *, reservation):
        with self._lock:
            p, entry = self._registered(reservation)
            return self._observation(p, entry)
