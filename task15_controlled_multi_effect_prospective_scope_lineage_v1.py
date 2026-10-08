"""Owned in-memory prospective evidence scopes; no composition dispatch authority.

Readers, clock and fresh metadata reviewer are trusted harness capabilities, not
untrusted data or authenticated external services. Local state observations never
prove RCC/Bind/consumption, external effects, or enable dispatch. Legacy fixed
profile slots and actual generation ordinals are deliberately distinct.
"""
from __future__ import annotations
import copy, hashlib, hmac, json, secrets
from dataclasses import dataclass
from threading import RLock
from task15_native_address_request_profile_issuance_v1 import canonical, sha, Task15AddressRequestProfileSession
from task15_standing_order_request_profile_issuance_v1 import Task15RentRequestProfileSession
from task15_refund_request_profile_issuance_v1 import Task15RefundRequestProfileSession
from task15_refund_original_request_authority_design_v1 import derive_refund_design
from task15_refund_execution_authority_boundary_v1 import derive_execution_authority_boundary
from task15_controlled_multi_effect_composition_authority_design_v1 import derive_composition_design, FUNCTIONS
from scripts.pairwise_protected_candidate_control_v1_1 import ProtectedCandidateControlV11

RULE = 'TASK15_CONTROLLED_MULTI_EFFECT_PROSPECTIVE_SCOPE_LINEAGE_V1'
class ScopeLineageViolation(ValueError): pass

def require(value, reason):
    if not value: raise ScopeLineageViolation(reason)

def plain(value): return json.loads(canonical(value))

@dataclass(frozen=True)
class ProspectiveStepScope:
    payload_json: str
    signature: str
    def payload(self): return json.loads(self.payload_json)
    @property
    def digest(self): return sha({'payload_json': self.payload_json, 'signature': self.signature})
    @property
    def execution_permission(self): return False

@dataclass(frozen=True)
class CapturedStepBinding:
    scope_digest: str
    candidate_json: str
    candidate_sha256: str
    pairing_identity_sha256: str

class Task15ProspectiveScopeLineageSession:
    """Single local address/rent/refund evidence lineage, held by trusted code.

    Reads actual owned state before issue, capture, verification and observation.
    A fresh refund reviewer is invoked before its first candidate and must supply
    a new policy draft already bound to the current core. This module NEVER edits
    policy scope or turns a draft into execution authority. Fresh sessions and
    receipt-key deduplication here do not provide durable execution exclusion.
    """
    def __init__(self, *, arm, envelope, case_id, owned_ledger_recipient,
                 acquire_state, review_refund, owned_clock, initial_policy_draft, initial_slot_draft):
        require(arm in ('A', 'B') and type(arm) is str, 'OWNED_ARM_REQUIRED')
        require(all(callable(x) for x in (acquire_state, review_refund, owned_clock)), 'OWNED_CAPABILITIES_REQUIRED')
        self._lock = RLock(); self._reader = acquire_state; self._reviewer = review_refund; self._clock = owned_clock
        self._common = dict(envelope=envelope, case_id=case_id, owned_ledger_recipient=owned_ledger_recipient)
        self._arm = arm; self._key = secrets.token_bytes(32); self._id = secrets.token_hex(16)
        initial = self._read()
        boundary = derive_execution_authority_boundary(**self._common, proposal_ordinal=2, trusted_prestate=initial,
            reviewed_at_utc=self._clock(), policy_draft=copy.deepcopy(initial_policy_draft), slot_draft=copy.deepcopy(initial_slot_draft))
        f = boundary.payload()['bindings']
        self._anchor = {k: f[k] for k in ('account_id', 'receipt_id', 'receipt_sha256', 'correlation_key')}
        # Full frozen composition request and all initial component scopes validate bootstrap.
        derive_composition_design(**self._common, trusted_prestate=initial, reviewed_at_utc=self._clock(),
            policy_draft=copy.deepcopy(initial_policy_draft), slot_draft=copy.deepcopy(initial_slot_draft))
        self._expected_state = sha(initial); self._initial_state = sha(initial)
        self._step = 0; self._last_ordinal = -1; self._phase = 'READY'; self._rows = []; self._active = None; self._uncertain_state = None

    def _read(self):
        value = self._reader()
        require(type(value) is dict, 'OWNED_PLAIN_STATE_REQUIRED')
        return plain(value)

    def _close(self):
        self._phase = 'UNKNOWN_LOCAL_OBSERVATION' if self._uncertain_state is not None else 'CLOSED'; self._active = None

    def _anchor_current(self, state):
        core = derive_refund_design(**self._common, proposal_ordinal=2, trusted_prestate=state)
        p = core.payload()
        require(p['account_id'] == self._anchor['account_id'] and p['target_receipt']['id'] == self._anchor['receipt_id']
                and p['target_receipt_sha256'] == self._anchor['receipt_sha256'], 'ORIGINAL_RECEIPT_ANCHOR_CHANGED')
        return core

    def issue_before_candidate(self, *, generation_ordinal):
        with self._lock:
            try:
                require(self._phase == 'READY' and self._step < 3, 'SCOPE_CANNOT_REISSUE_OR_REOPEN')
                require(type(generation_ordinal) is int and self._last_ordinal < generation_ordinal <= 10000,
                        'STRICT_MONOTONE_ACTUAL_GENERATION_ORDINAL_REQUIRED')
                self._phase = 'ISSUING'
                state = self._read(); require(sha(state) == self._expected_state, 'ACQUIRED_STATE_LINEAGE_CHANGED')
                core = self._anchor_current(state)
                i = self._step
                scope = dict(envelope=self._common['envelope'], case_id=self._common['case_id'],
                             proposal_ordinal=i, trusted_prestate=state)
                if i == 0: session = Task15AddressRequestProfileSession(source_id=self._id, signing_key=secrets.token_bytes(32))
                elif i == 1: session = Task15RentRequestProfileSession(source_id=self._id, signing_key=secrets.token_bytes(32))
                else:
                    # Caller is a TRUSTED review capability. No implicit old-policy rebasing here.
                    review = self._reviewer(copy.deepcopy(state), core.digest)
                    require(type(review) is dict and set(review) == {'policy_draft', 'slot_draft'}, 'FRESH_REVIEW_DRAFTS_REQUIRED')
                    scope.update(owned_ledger_recipient=self._common['owned_ledger_recipient'], **copy.deepcopy(review))
                    b = derive_execution_authority_boundary(**scope, reviewed_at_utc=self._clock()).payload()['bindings']
                    require({k: b[k] for k in self._anchor} == self._anchor, 'REFUND_CORRELATION_KEY_RESET_REFUSED')
                    session = Task15RefundRequestProfileSession(source_id=self._id, signing_key=secrets.token_bytes(32), review_clock=self._clock)
                context = session.issue_before_candidate(**scope)
                payload = dict(rule_of_one=RULE, arm=self._arm, session_id=self._id, case_id=self._common['case_id'],
                    request_digest=self._common['envelope'].digest, composition_step=i, legacy_component_proof_slot=i,
                    generation_ordinal=generation_ordinal, function=FUNCTIONS[i], immediate_pre_state_sha256=sha(state),
                    initial_state_sha256=self._initial_state, receipt_anchor=self._anchor,
                    component_scope_sha256=sha({k:v for k,v in context.payload().items() if k not in ('source_id','session_id')}),
                    parent_local_observation_sha256=sha(self._rows[-1]) if self._rows else None,
                    execution_permission=False, native_dispatch_authorized=False, authenticated_execution_authority=False)
                raw = canonical(payload); sig = hmac.new(self._key, (RULE+'\0'+raw).encode(), hashlib.sha256).hexdigest()
                issued = ProspectiveStepScope(raw, sig)
                self._active = dict(issued=issued, session=session, context=context, scope=scope, state=state, binding=None)
                self._phase = 'ISSUED'; self._last_ordinal = generation_ordinal
                return issued
            except BaseException:
                self._close(); raise

    def _authenticate(self, issued):
        require(type(issued) is ProspectiveStepScope and self._active is not None, 'ORIGINAL_ACTIVE_SCOPE_REQUIRED')
        a = self._active
        require(issued == a['issued'] and hmac.compare_digest(issued.signature,
            hmac.new(self._key, (RULE+'\0'+issued.payload_json).encode(), hashlib.sha256).hexdigest()), 'FOREIGN_OR_CHANGED_SCOPE_REFUSED')
        state = self._read(); require(sha(state) == sha(a['state']), 'IMMEDIATE_STATE_CHANGED')
        self._anchor_current(state)
        return a

    def capture_candidate(self, *, issued, candidate):
        with self._lock:
            try:
                require(self._phase == 'ISSUED', 'SINGLE_CAPTURE_ATTEMPT_REQUIRED')
                self._phase = 'ATTEMPTED'
                a = self._authenticate(issued)
                original = canonical(candidate)
                component = a['session'].capture_candidate(context=a['context'], candidate=plain(candidate), **a['scope'])
                require(component.candidate_json == original, 'IMMUTABLE_FULL_RCC_CANDIDATE_REQUIRED')
                p = issued.payload()
                control = ProtectedCandidateControlV11.build(case_id=p['case_id'], proposal_ordinal=p['generation_ordinal'],
                    immediate_pre_state_sha256=p['immediate_pre_state_sha256'], function=p['function'], normalized_arguments=plain(candidate)['arguments'])
                require(control.candidate_sha256 == sha(plain(candidate)), 'FULL_RCC_HASH_REQUIRED')
                binding = CapturedStepBinding(issued.digest, original, control.candidate_sha256, control.pairing_identity_sha256())
                a.update(binding=binding, component_binding=component); self._phase = 'CAPTURED'
                return binding
            except BaseException:
                self._close(); raise

    def capture_from_generator(self, *, generation_ordinal, generate_candidate):
        with self._lock:
            try:
                require(callable(generate_candidate), 'OWNED_GENERATOR_REQUIRED')
                issued = self.issue_before_candidate(generation_ordinal=generation_ordinal)
                candidate = generate_candidate()  # No profile/key/reader/reviewer capability is given to the generator.
                binding = self.capture_candidate(issued=issued, candidate=candidate)
                return issued, binding
            except BaseException:
                self._close(); raise

    def verify_captured_candidate(self, *, issued, binding, candidate):
        with self._lock:
            try:
                require(self._phase == 'CAPTURED', 'ACTIVE_CAPTURE_REQUIRED')
                a = self._authenticate(issued)
                require(type(binding) is CapturedStepBinding and binding == a['binding'] and canonical(candidate) == binding.candidate_json,
                        'EXACT_ORIGINAL_CAPTURE_REQUIRED')
                a['session'].verify_captured_candidate(context=a['context'], binding=a['component_binding'], candidate=plain(candidate), **a['scope'])
                return dict(composition_step=self._step, generation_ordinal=issued.payload()['generation_ordinal'],
                    candidate_sha256=binding.candidate_sha256, pairing_identity_sha256=binding.pairing_identity_sha256,
                    immediate_pre_state_sha256=sha(a['state']), receipt_anchor=copy.deepcopy(self._anchor),
                    local_scope_and_capture_verified=True, execution_permission=False, native_dispatch_authorized=False)
            except BaseException:
                self._close(); raise

    def observe_owned_local_state(self, *, issued, binding):
        """Compare an acquired local state to the frozen native delta; never dispatch.

        Owned reader is the trust boundary. Matching a predicted delta is not
        independent external effect authentication, successful admission or spend.
        """
        with self._lock:
            try:
                require(self._phase == 'CAPTURED' and self._active is not None, 'CAPTURED_OBSERVATION_REQUIRED')
                a = self._active
                require(issued == a['issued'] and binding == a['binding'], 'ORIGINAL_CAPTURE_OBSERVATION_REQUIRED')
                self._uncertain_state = 'ACQUISITION_OR_COMPARISON_NOT_COMPLETE'
                candidate = json.loads(binding.candidate_json)
                a['session'].verify_captured_candidate(context=a['context'], binding=a['component_binding'], candidate=candidate, **a['scope'])
                self._phase = 'OBSERVING'; self._uncertain_state = 'ACQUISITION_OR_COMPARISON_NOT_COMPLETE'
                after = self._read(); self._uncertain_state = sha(after); expected = copy.deepcopy(a['state'])
                args = candidate['arguments']; i = self._step
                if i == 0: expected['user_account'].update(street=args['street'], city=args['city'])
                elif i == 1:
                    target = next(x for x in expected['bank_account']['scheduled_transactions'] if x['id'] == args['id'])
                    target.update(recipient=args['recipient'], amount=args['amount'])
                else:
                    bank = expected['bank_account']; identifier = max(x['id'] for x in bank['transactions']+bank['scheduled_transactions'])+1
                    bank['transactions'].append(dict(id=identifier,sender=bank['iban'],recipient=args['recipient'],amount=args['amount'],
                        subject=args['subject'],date=args['date'],recurring=False))
                require(after == expected, 'EXACT_ACQUIRED_LOCAL_DELTA_REQUIRED')
                row = dict(composition_step=i, generation_ordinal=issued.payload()['generation_ordinal'], function=FUNCTIONS[i],
                    candidate=json.loads(binding.candidate_json), candidate_sha256=binding.candidate_sha256,
                    pairing_identity_sha256=binding.pairing_identity_sha256, pre_state_sha256=sha(a['state']),
                    post_state_sha256=sha(after), parent_local_observation_sha256=sha(self._rows[-1]) if self._rows else None,
                    receipt_anchor=copy.deepcopy(self._anchor), local_state_observed=True, effect_authenticated=False,
                    execution_permission=False, native_dispatch_authorized=False)
                self._uncertain_state = None
                self._rows.append(row); self._expected_state = sha(after); self._step += 1; self._active = None
                self._phase = 'COMPLETE_LOCAL_OBSERVATIONS' if self._step == 3 else 'READY'
                return copy.deepcopy(row)
            except BaseException:
                self._close(); raise

    def close(self):
        with self._lock: self._close()

    def lifecycle_observation(self):
        with self._lock:
            return dict(phase=self._phase, completed_local_observations=copy.deepcopy(self._rows),
                next_composition_step=self._step, last_generation_ordinal=self._last_ordinal,
                unverified_acquired_state_sha256=self._uncertain_state,
                receipt_anchor=copy.deepcopy(self._anchor), native_dispatches=0, slot_consumptions=0,
                execution_permission=False, native_dispatch_authorized=False, effect_authenticated=False,
                full_task15_execution_supported=False, utility_recovery_proven=False)

def verify_controlled_pair(*, left, left_scope, left_binding, right, right_scope, right_binding, candidate):
    """Same candidate and actual immediate state only. Divergence closes both.

    Own per-arm lineage records can differ and do not enter the pairing identity.
    No later treatment comparison is allowed after unequal actual state.
    """
    try:
        require(type(left) is Task15ProspectiveScopeLineageSession and type(right) is Task15ProspectiveScopeLineageSession
                and left is not right and left._arm == 'A' and right._arm == 'B', 'TWO_DISTINCT_OWNED_ARMS_REQUIRED')
        a = left.verify_captured_candidate(issued=left_scope,binding=left_binding,candidate=candidate)
        b = right.verify_captured_candidate(issued=right_scope,binding=right_binding,candidate=candidate)
        require(a == b, 'PAIRING_VIOLATION')
        return {**a, 'same_candidate_same_immediate_prestate':True, 'execution_permission':False}
    except BaseException:
        for session in (left,right):
            if type(session) is Task15ProspectiveScopeLineageSession: session.close()
        raise
