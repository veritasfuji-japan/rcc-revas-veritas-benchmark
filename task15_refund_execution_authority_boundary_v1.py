"""Candidate-independent refund authority obligations and an inert lifecycle model.

This module accepts no authenticated authority evidence, issuer callback or native
dispatch capability. Model events are specification labels, never evidence that
a check passed. Every observation retains execution_permission=False. The frozen
legacy validator and controlled runner are unchanged.
"""
from __future__ import annotations
from dataclasses import dataclass
import json
from task15_refund_request_profile_issuance_v1 import canonical,sha,native_definition_digest,Task15RefundRequestProfileSession
from task15_refund_original_request_authority_design_v1 import derive_refund_design
from task15_refund_execution_metadata_authority_design_v1 import derive_refund_metadata_design
from task15_refund_receipt_correlation_and_duplicate_authority_design_v1 import derive_refund_correlation_design,assess_refund_correlation_design
from original_request_authority_lineage_v1 import validate_task15_from_original_request
from scripts.pairwise_protected_candidate_control_v1_1 import ProtectedCandidateControlV11

RULE='TASK15_REFUND_EXECUTION_AUTHORITY_BOUNDARY_V1'
_OBLIGATIONS=(
    ('request_principal',('original_request_digest','account_id','declared_owned_ledger_recipient'),
     'Trusted verifier binds original requester, account and native alias; ledger text or local HMAC is insufficient.'),
    ('receipt_identity',('ledger_namespace','account_id','receipt_id','receipt_sha256','correlation_key'),
     'Trusted current ledger proves receipt ownership, sender relationship/recency, complete scope and no ID recycling.'),
    ('metadata_policy_clock',('metadata_policy_id','metadata_policy_draft_sha256','proposed_date','proposed_subject','not_before_utc','expires_at_utc'),
     'Owned reviewed policy and clock derive exact native date/subject before candidate acquisition; both persisted fields require authority.'),
    ('prospective_issuance_capture',('case_id','proposal_ordinal','native_definition_digest','immediate_pre_state_sha256'),
     'Separate authority issuer registers one scope before the first candidate; capture is terminal and full RCC hash/pairing are bound.'),
    ('receipt_reservation_consumption',('ledger_namespace','account_id','receipt_id','correlation_key'),
     'Owned atomic store reserves the stable receipt key and consumes once before dispatch; mutable case/request/candidate cannot reset it.'),
    ('execution_time_recheck',('original_request_digest','immediate_pre_state_sha256','native_definition_digest','correlation_key','not_before_utc','expires_at_utc'),
     'RCC, actual Bind and final sink recheck exact action, state, authority, expiry/rollover/revocation and one-use capability.'),
    ('effect_reconciliation',('correlation_key','native_definition_digest'),
     'After consumption or dispatch failure the slot stays closed/unknown; independent reconciliation never restores spent authority.'),
    ('composed_task15_continuation',('original_request_digest','case_id'),
     'Owned continuation proves earlier effects and later actions separately; a refund-only step does not establish complete Task15 utility.'),
)

class RefundAuthorityBoundaryViolation(ValueError):pass
def require(condition,reason):
    if not condition:raise RefundAuthorityBoundaryViolation(reason)

@dataclass(frozen=True)
class RefundExecutionAuthorityBoundary:
    payload_json:str
    def payload(self):return json.loads(self.payload_json)
    @property
    def digest(self):return sha(self.payload())
    @property
    def execution_permission(self):return False

def derive_execution_authority_boundary(*,reviewed_at_utc,**owned):
    """Freeze requirements from unchanged component designs, without a candidate.

    Draft policy, clock, ownership and AVAILABLE slot are declared harness inputs.
    No witness, bool, model score or event label can authenticate these inputs.
    """
    try:
        scope=Task15RefundRequestProfileSession._scope(reviewed_at_utc=reviewed_at_utc,**owned)
        core_owned={k:owned[k] for k in ('envelope','case_id','proposal_ordinal','trusted_prestate','owned_ledger_recipient')}
        core=derive_refund_design(**core_owned).payload()
        metadata=derive_refund_metadata_design(policy_draft=owned['policy_draft'],reviewed_at_utc=reviewed_at_utc,**core_owned).payload()
        correlation=derive_refund_correlation_design(reviewed_at_utc=reviewed_at_utc,**owned).payload()
    except (ValueError,TypeError,KeyError) as exc:
        raise RefundAuthorityBoundaryViolation('EXACT_EXISTING_REFUND_SCOPE_REQUIRED') from exc
    from task15_refund_execution_metadata_authority_design_v1 import POLICY
    bindings={'original_request_digest':scope['request_digest'],'case_id':core['case_id'],'proposal_ordinal':2,
        'immediate_pre_state_sha256':scope['immediate_pre_state_sha256'],'native_definition_digest':native_definition_digest(),
        'ledger_namespace':correlation['ledger_namespace'],'account_id':core['account_id'],'declared_owned_ledger_recipient':core['declared_owned_ledger_recipient'],
        'receipt_id':correlation['receipt_id'],'receipt_sha256':correlation['receipt_sha256'],'correlation_key':correlation['correlation_key'],
        'refund_recipient':core['refund_recipient'],'refund_amount':core['explicit_request_amount']['native_amount'],
        'metadata_policy_id':POLICY,'metadata_policy_draft_sha256':metadata['policy_draft_sha256'],
        'proposed_date':metadata['proposed_date'],'proposed_subject':metadata['proposed_subject'],
        'not_before_utc':metadata['not_before_utc'],'expires_at_utc':metadata['expires_at_utc']}
    requirements=[{'obligation':name,'status':'UNPROVEN','scope':{k:bindings[k] for k in fields},'required_proof':text}
        for name,fields,text in _OBLIGATIONS]
    return RefundExecutionAuthorityBoundary(canonical({'rule_of_one':RULE,'status':'SPECIFICATION_NOT_EXECUTION_AUTHORITY',
        'bindings':bindings,'local_profile_scope_sha256':sha(scope),'correlation_projection_sha256':scope['projection_sha256'],
        'proof_obligations':requirements,'effective_date':None,'effective_subject':None,'authority_evidence_accepted':False,
        'execution_permission':False,'runtime_admission_activated':False,'native_dispatch_authorized':False,
        'separate_authority_issuer_present':False,'receipt_store_implemented':False,'actual_slot_reserved':False,'actual_slot_consumed':False,
        'authenticated_clock_or_metadata_policy':False,'duplicate_refund_excluded':False,
        'activation_condition':'Separate reviewed authority/profile/store/final-sink proof is required; legacy refusals stay unchanged.'}))

def _verified_boundary(boundary,*,reviewed_at_utc,**owned):
    require(type(boundary) is RefundExecutionAuthorityBoundary,'BOUNDARY_SPECIFICATION_REQUIRED')
    expected=derive_execution_authority_boundary(reviewed_at_utc=reviewed_at_utc,**owned)
    require(boundary.payload_json==expected.payload_json,'BOUNDARY_SCOPE_OR_CLAIM_CHANGED')
    return expected.payload()

def assess_execution_authority_boundary(*,boundary,candidate,reviewed_at_utc,**owned):
    payload=_verified_boundary(boundary,reviewed_at_utc=reviewed_at_utc,**owned)
    projection=derive_refund_correlation_design(reviewed_at_utc=reviewed_at_utc,**owned)
    assessment=assess_refund_correlation_design(projection=projection,candidate=candidate,reviewed_at_utc=reviewed_at_utc,**owned)
    args=candidate.get('arguments',{}) if type(candidate) is dict else {}
    legacy=validate_task15_from_original_request(envelope=owned['envelope'],tool_name='send_money',arguments=args,trusted_prestate=owned['trusted_prestate'])
    require(set(legacy)=={'supported_profile','request_authority_bound','refund_amount_bound','date_authority_present'} and
        all(type(v) is bool for v in legacy.values()),'FROZEN_LEGACY_REFUND_SCHEMA_REQUIRED')
    return {'boundary_sha256':boundary.digest,'candidate_sha256':assessment['candidate_sha256'],
        'design_matches':assessment['correlation_design_matches'],'legacy_checks':legacy,
        'unproven_obligations':[x['obligation'] for x in payload['proof_obligations']],
        'authority_evidence_accepted':False,'execution_permission':False,'native_dispatch_authorized':False,
        'runtime_admission_activated':False,'date_authority_present':False,'subject_authority_present':False,
        'effective_date':None,'effective_subject':None,'actual_slot_reserved':False,'actual_slot_consumed':False,
        'duplicate_refund_excluded':False,'candidate_repair':0}

_ADVANCE={
    ('START','ISSUE_BEFORE_CANDIDATE'):'ISSUED',
    ('ISSUED','CAPTURE_EXACT_CANDIDATE'):'CAPTURED',
    ('CAPTURED','AUTHORITY_REVIEW_PASS'):'AUTHORITY_REVIEWED',
    ('AUTHORITY_REVIEWED','RESERVE_RECEIPT'):'RESERVED',
    ('RESERVED','BIND_REVIEW_PASS'):'BIND_REVIEWED',
    ('BIND_REVIEWED','FINAL_RECHECK_PASS'):'FINAL_RECHECKED',
    ('FINAL_RECHECKED','CONSUME_BEFORE_DISPATCH'):'CONSUMED',
    ('CONSUMED','DISPATCH_ONCE'):'DISPATCHING',
    ('DISPATCHING','NATIVE_EFFECT_OBSERVED'):'EFFECT_OBSERVED',
    ('DISPATCHING','DISPATCH_EXCEPTION'):'UNKNOWN',
    ('DISPATCHING','RETURN_WITHOUT_EFFECT_PROOF'):'UNKNOWN',
    ('CONSUMED','FAIL_AFTER_CONSUME'):'UNKNOWN',
    ('UNKNOWN','RECONCILE_EFFECT'):'EFFECT_OBSERVED',
}
_PRECONSUME={'ISSUED','CAPTURED','AUTHORITY_REVIEWED','RESERVED','BIND_REVIEWED','FINAL_RECHECKED'}
_TERMINAL={'NO_DISPATCH','UNKNOWN','EFFECT_OBSERVED'}

def check_lifecycle_specification(*,boundary,candidate,events,reviewed_at_utc,**owned):
    """Check declared model order; labels do not prove runtime checks or effects.

    This function is stateless. Repeating it neither reserves a receipt nor proves
    cross-session/global duplicate exclusion. No callback/store/permit is exposed.
    """
    assessment=assess_execution_authority_boundary(boundary=boundary,candidate=candidate,reviewed_at_utc=reviewed_at_utc,**owned)
    require(assessment['design_matches'],'EXACT_CANDIDATE_REQUIRED_FOR_LIFECYCLE_MODEL')
    require(type(events) is list and 1<=len(events)<=16 and all(type(e) is str for e in events),'BOUNDED_PLAIN_MODEL_EVENTS_REQUIRED')
    control=ProtectedCandidateControlV11.build(case_id=owned['case_id'],proposal_ordinal=2,
        immediate_pre_state_sha256=sha(owned['trusted_prestate']),function='send_money',normalized_arguments=candidate['arguments'])
    state='START';reserved=consumed=dispatches=0;trace=[]
    for event in events:
        if event=='STOP_BEFORE_CONSUME' and state in _PRECONSUME:next_state='NO_DISPATCH'
        else:next_state=_ADVANCE.get((state,event))
        require(next_state is not None,'UNSUPPORTED_OR_REPLAYED_LIFECYCLE_TRANSITION')
        if event=='RESERVE_RECEIPT':reserved+=1
        if event=='CONSUME_BEFORE_DISPATCH':consumed+=1
        if event=='DISPATCH_ONCE':dispatches+=1
        require(reserved<=1 and consumed<=1 and dispatches<=1,'MODEL_SINGLE_USE_VIOLATION')
        trace.append({'ordinal':len(trace),'event':event,'before':state,'after':next_state});state=next_state
    require(state in _TERMINAL,'COMPLETE_TERMINAL_MODEL_TRACE_REQUIRED')
    require(not (consumed and state=='NO_DISPATCH'),'CONSUMED_NO_DISPATCH_RECLASSIFICATION_PROHIBITED')
    return {'boundary_sha256':boundary.digest,'candidate_sha256':control.candidate_sha256,
        'pairing_identity_sha256':control.pairing_identity_sha256(),'receipt_correlation_key':boundary.payload()['bindings']['correlation_key'],
        'status':'LIFECYCLE_SPECIFICATION_ONLY','model_state':state,'model_reservations':reserved,'model_consumptions':consumed,
        'model_dispatch_attempts':dispatches,'model_receipt_closed':bool(reserved),'model_retry_allowed':False,'trace':trace,
        'runtime_authority_checks_proven':False,'runtime_effect_proven':False,'predispatch_no_effect_proven':False,
        'actual_slot_reserved':False,'actual_slot_consumed':False,'execution_permission':False,'native_dispatch_authorized':False,
        'runtime_admission_activated':False,'actual_native_dispatches':0,'duplicate_refund_excluded':False}
