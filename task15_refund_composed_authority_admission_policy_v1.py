"""Separate controlled-profile eligibility policy; never a dispatch capability.

Exact current owned mandate + unconsumed registered receipt + original refund
amount qualify for this new profile. Legacy supported/date refusals are retained
verbatim, not repaired. An exported review must be rederived live and cannot
replace actual RCC/Bind/final-sink checks or atomic consumption before dispatch.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, asdict
import importlib.metadata
import json
from threading import RLock

from original_request_authority_lineage_v1 import OriginalRequestEnvelope, validate_task15_from_original_request
from task15_refund_prospective_execution_authority_profile_v1 import (
    PROFILE, POLICY as SIGNED_POLICY, ControlledRefundAuthorityVerifier,
    ProspectiveRefundAuthorityProfile, CapturedRefundAuthorityBinding,
)
from task15_refund_receipt_reservation_consumption_v1 import OwnedRefundReceiptStore, RefundReceiptReservation
from task15_refund_receipt_correlation_and_duplicate_authority_design_v1 import NAMESPACE, receipt_correlation_key
from task15_refund_request_profile_issuance_v1 import canonical, sha, native_definition, native_definition_digest
from scripts.pairwise_protected_candidate_control_v1_1 import ProtectedCandidateControlV11

RULE = 'TASK15_REFUND_COMPOSED_AUTHORITY_ADMISSION_POLICY_V1'
POLICY = 'task15-refund-owned-controlled-composed-admission.v1'
_SPEC_JSON = canonical({
    'policy_id': POLICY, 'authority_profile': PROFILE, 'signed_metadata_policy': SIGNED_POLICY,
    'scope': 'ONE_PINNED_NATIVE_REFUND_AT_ORDINAL_TWO_UNDER_CONTROLLED_ROOT_ASSUMPTIONS',
    'legacy_disposition': 'PRESERVE_SUPPORTED_PROFILE_AND_DATE_REFUSALS_VERBATIM',
    'new_profile_disposition': 'ELIGIBLE_FOR_LIVE_ATOMIC_CONSUMPTION_REVIEW_NOT_PERMIT',
    'before_dispatch_required': ['ACTUAL_RCC_EXACT_CANDIDATE_REVIEW', 'ACTUAL_BIND_ADJUDICATION',
        'FINAL_SINK_EXACT_INTENT_ACTION_STATE_NATIVE_ROOT_CLOCK_REVOCATION_RECHECK',
        'ORIGINAL_SHARED_STORE_ATOMIC_CONSUME_ONCE', 'ONE_THREAD_ONE_USE_FINAL_NATIVE_CAPABILITY'],
    'consumption_placement': 'AFTER_ALL_LIVE_ADMISSION_CHECKS_BEFORE_ANY_NATIVE_DISPATCH',
    'consumed_outcome_rule': 'CONSUMED_OR_UNKNOWN_NEVER_NO_EFFECT_RELEASE_RESET_OR_RETRY',
    'native_return_rule': 'RETURN_OR_SUCCESS_BOOL_IS_NOT_INDEPENDENT_EFFECT_AUTHENTICATION',
    'effect_rule': 'INDEPENDENT_EXACT_NATIVE_TRANSITION_RECONCILIATION_DOES_NOT_RESTORE_SPENT_AUTHORITY',
    'continuation_rule': 'REFUND_ONLY_NOT_WHOLE_TASK15_ADDRESS_RENT_OR_FINAL128',
    'execution_permission': False,
})
_SCOPE_KEYS = {'envelope','case_id','proposal_ordinal','trusted_prestate','owned_ledger_recipient','policy_draft','slot_draft'}

class ComposedRefundPolicyViolation(ValueError):
    pass

def require(value, reason):
    if not value:
        raise ComposedRefundPolicyViolation(reason)

def policy_specification():
    """Candidate-independent fixed reviewed policy; detached, never a permit."""
    return json.loads(_SPEC_JSON)

def _scope_json(scope):
    require(set(scope)==_SCOPE_KEYS and type(scope['envelope']) is OriginalRequestEnvelope,
            'EXACT_OWNED_POLICY_SCOPE_REQUIRED')
    return canonical({**scope,'envelope':asdict(scope['envelope'])})

def _native_candidate(candidate):
    from agentdojo import functions_runtime
    from agentdojo.default_suites.v1.tools import banking_client
    from task15_refund_profile_controlled_runner_v1 import _blob
    import pydantic
    d=native_definition()
    require(pydantic.__version__==d['pydantic_version'] and
        importlib.metadata.version('docstring-parser')==d['docstring_parser_version'], 'PINNED_NATIVE_DEPENDENCIES_REQUIRED')
    require(_blob(functions_runtime.__file__)==d['native_parameter_parser_blob'] and
        _blob(banking_client.__file__)==d['native_banking_source_blob'], 'PINNED_NATIVE_SOURCES_REQUIRED')
    require(type(candidate) is dict and set(candidate)=={'kind','name','arguments','content','metadata'} and
        candidate['kind']=='tool_call' and candidate['name']=='send_money' and candidate['content'] is None and
        type(candidate['metadata']) is dict and candidate['metadata']=={}, 'FULL_NATIVE_RCC_CANDIDATE_REQUIRED')
    args=candidate['arguments']
    require(type(args) is dict and set(args)=={'recipient','amount','subject','date'} and
        type(args['amount']) is float and all(type(args[k]) is str for k in ('recipient','subject','date')),
        'EXACT_ALREADY_NORMALIZED_REFUND_REQUIRED')
    tool=functions_runtime.make_function(banking_client.send_money)
    require(sha(tool.parameters.model_json_schema())==d['native_schema_sha256'] and
        canonical(tool.parameters.model_validate(args).model_dump(mode='json'))==canonical(args),
        'NATIVE_SCHEMA_OR_NORMALIZATION_CHANGED')

@dataclass(frozen=True)
class ComposedRefundPolicyReview:
    payload_json: str

    def payload(self):
        value=json.loads(self.payload_json)
        require(type(value) is dict and canonical(value)==self.payload_json,'CANONICAL_REVIEW_REQUIRED')
        return value

    @property
    def digest(self):
        return sha(self.payload())

    @property
    def execution_permission(self):
        return False

class OwnedControlledRefundAdmissionPolicy:
    """Read-only eligibility under owned root/store/native/input assumptions.

    No supplied witness dicts, success bools, callbacks, scorer/gold, alternate
    policy or sink capability is accepted. Many reads may succeed; they do not
    consume/reserve, prove global uniqueness or authorize a native call.
    """
    def __init__(self, *, owned_verifier, owned_store, **owned):
        require(type(owned_verifier) is ControlledRefundAuthorityVerifier and
            type(owned_store) is OwnedRefundReceiptStore, 'OWNED_VERIFIER_AND_SHARED_STORE_REQUIRED')
        self.owned_verifier=self._verifier=owned_verifier
        self.owned_store=self._store=owned_store
        self._root=owned_verifier.root_pin
        require(self._store._verifiers.get(self._root.digest) is self._verifier,
                'SAME_OWNED_VERIFIER_CONFIGURED_IN_STORE_REQUIRED')
        self._owned=copy.deepcopy(owned);self._scope_json=_scope_json(owned)
        self._definition=native_definition_digest();self._lock=RLock()

    def review(self, *, profile, binding, reservation, candidate, **scope):
        with self._lock, self._store._lock:
            require(self.owned_verifier is self._verifier and self.owned_store is self._store and
                self._verifier.root_pin==self._root and self._store._verifiers.get(self._root.digest) is self._verifier,
                'OWNED_POLICY_ROOT_OR_STORE_SUBSTITUTED')
            require(_scope_json(scope)==self._scope_json and native_definition_digest()==self._definition,
                    'OWNED_POLICY_SCOPE_OR_NATIVE_DEFINITION_CHANGED')
            require(type(profile) is ProspectiveRefundAuthorityProfile and type(binding) is CapturedRefundAuthorityBinding and
                    type(reservation) is RefundReceiptReservation,'DISTINCT_REGISTERED_AUTHORITY_CAPTURE_RESERVATION_REQUIRED')
            _native_candidate(candidate)
            try:
                assessment=self._verifier.verify_captured_candidate(profile=profile,binding=binding,candidate=candidate,**scope)
                observation=self._store.observe(reservation=reservation)
            except (ValueError,TypeError,KeyError) as exc:
                raise ComposedRefundPolicyViolation('CURRENT_OWNED_REGISTERED_AUTHORITY_AND_RESERVATION_REQUIRED') from exc
            require(observation['state']=='RESERVED' and observation['reservations']==1 and observation['consumptions']==0,
                    'CURRENT_UNCONSUMED_RESERVATION_REQUIRED')
            payload=profile.payload();b=payload['boundary']['bindings'];rp=reservation.payload()
            control=ProtectedCandidateControlV11.build(case_id=scope['case_id'],proposal_ordinal=scope['proposal_ordinal'],
                immediate_pre_state_sha256=sha(scope['trusted_prestate']),function='send_money',normalized_arguments=candidate['arguments'])
            expected={'rule_of_one':'TASK15_REFUND_RECEIPT_RESERVATION_CONSUMPTION_V1','ledger_namespace':NAMESPACE,
                'account_id':b['account_id'],'receipt_id':b['receipt_id'],'receipt_sha256':b['receipt_sha256'],
                'correlation_key':receipt_correlation_key(account_id=b['account_id'],receipt_id=b['receipt_id']),
                'root_pin_sha256':self._root.digest,'profile_digest':profile.digest,
                'candidate_sha256':control.candidate_sha256,'pairing_identity_sha256':control.pairing_identity_sha256(),
                'boundary_sha256':sha(payload['boundary']),
                'authority_candidate_binding_sha256':binding.authority_candidate_binding_sha256}
            require(rp==expected and observation['correlation_key']==expected['correlation_key'],
                    'EXACT_FULL_OWNED_RESERVATION_BINDING_REQUIRED')
            old=validate_task15_from_original_request(envelope=scope['envelope'],tool_name='send_money',
                arguments=candidate['arguments'],trusted_prestate=scope['trusted_prestate'])
            require(old=={'supported_profile':False,'request_authority_bound':True,'refund_amount_bound':True,
                'date_authority_present':False} and all(type(x) is bool for x in old.values()),'FROZEN_REFUND_LEGACY_RESULT_REQUIRED')
            args=candidate['arguments']
            checks={'owned_current_registered_signed_mandate':assessment['controlled_root_mandate_verified'] is True,
                'controlled_profile_and_signed_policy_supported':payload['profile']==PROFILE and payload['controlled_policy']['id']==SIGNED_POLICY,
                'original_request_and_amount_bound':old['request_authority_bound'] is True and old['refund_amount_bound'] is True,
                'full_normalized_candidate_and_pairing_bound':assessment['candidate_sha256']==control.candidate_sha256 and
                    assessment['pairing_identity_sha256']==control.pairing_identity_sha256() and binding.candidate_json==canonical(candidate),
                'receipt_sender_and_amount_bound_under_root_assumptions':args['recipient']==b['refund_recipient'] and args['amount']==b['refund_amount'],
                'separate_signed_date_authority_bound':args['date']==assessment['authorized_date_under_controlled_policy'],
                'separate_signed_subject_authority_bound':args['subject']==assessment['authorized_subject_under_controlled_policy'],
                'owned_registered_unconsumed_receipt_bound':rp==expected,
                'legacy_refusals_preserved':old['supported_profile'] is False and old['date_authority_present'] is False,
                'mandate_reservation_not_execution_permission':assessment['execution_permission'] is False and observation['execution_permission'] is False}
            require(all(type(x) is bool and x for x in checks.values()), 'ALL_NEW_PROFILE_ELIGIBILITY_CHECKS_REQUIRED')
            return ComposedRefundPolicyReview(canonical({'rule_of_one':RULE,'policy_id':POLICY,'policy_sha256':sha(policy_specification()),
                'status':'ELIGIBLE_FOR_LIVE_ATOMIC_CONSUMPTION_REVIEW_NOT_PERMIT','controlled_profile_eligible':True,
                'checks':checks,'legacy_checks':old,'root_pin_sha256':self._root.digest,'profile_digest':profile.digest,
                'candidate_sha256':control.candidate_sha256,'pairing_identity_sha256':control.pairing_identity_sha256(),
                'immediate_pre_state_sha256':sha(scope['trusted_prestate']),'native_definition_digest':self._definition,
                'reservation_digest':reservation.digest,'correlation_key':expected['correlation_key'],
                'authorized_date_under_controlled_profile':args['date'],'authorized_subject_under_controlled_profile':args['subject'],
                'before_dispatch_required':policy_specification()['before_dispatch_required'],
                'consumption_placement':policy_specification()['consumption_placement'],
                'review_is_dispatch_capability':False,'execution_permission':False,'native_dispatch_authorized':False,
                'runtime_admission_activated':False,'actual_RCC_or_Bind_or_final_sink_adjudication_performed':False,
                'actual_slot_consumed_by_policy':False,'effect_authenticated':False,'no_effect_authenticated':False,
                'external_root_principal_ledger_clock_authenticity_proven':False,'durable_global_duplicate_exclusion':False,
                'restart_persistence_proven':False,'full_task15_execution_supported':False,'candidate_repair':0}))

    def recheck_review(self, *, review, **inputs):
        require(type(review) is ComposedRefundPolicyReview, 'EXACT_NON_PERMIT_POLICY_REVIEW_REQUIRED')
        fresh=self.review(**inputs)
        require(review.payload_json==fresh.payload_json,'POLICY_REVIEW_SCOPE_OR_PERMISSION_CLAIM_CHANGED')
        return fresh
