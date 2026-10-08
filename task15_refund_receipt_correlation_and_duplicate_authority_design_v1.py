"""Candidate-independent receipt correlation draft; no consumption or authority."""
from __future__ import annotations
from dataclasses import dataclass
import json,re
from task15_refund_original_request_authority_design_v1 import derive_refund_design
from task15_refund_execution_metadata_authority_design_v1 import derive_refund_metadata_design,assess_refund_metadata_design
from task15_standing_order_request_profile_issuance_v1 import canonical,sha
RULE='TASK15_REFUND_RECEIPT_CORRELATION_AND_DUPLICATE_AUTHORITY_DESIGN_V1'
NAMESPACE='agentdojo:a75aba7631d3ca5fb7ab938965c97ead2f9ff84b:banking:native-account-ledger'
UNRESOLVED=('authenticated_ledger_namespace_account_receipt_identity_no_id_recycling',
 'authenticated_original_request_principal_friend_receipt_and_metadata_policy_clock',
 'owned_prospective_registry_before_candidate_and_atomic_receipt_reservation',
 'durable_single_use_consumption_unknown_effect_and_reconciliation',
 'revocation_material_drift_native_RCC_Bind_final_sink_and_composed_continuation')
class RefundCorrelationDesignViolation(ValueError):pass
def require(value,reason):
    if not value:raise RefundCorrelationDesignViolation(reason)
def receipt_correlation_key(*,account_id,receipt_id):
    require(type(account_id) is str and re.fullmatch(r'[A-Z]{2}[0-9]{2}[A-Z0-9]{4,36}',account_id) is not None,'CANONICAL_ACCOUNT_REQUIRED')
    require(type(receipt_id) is int and receipt_id>=0,'TYPED_RECEIPT_ID_REQUIRED')
    return sha({'ledger_namespace':NAMESPACE,'account_id':account_id,'receipt_id':receipt_id})
@dataclass(frozen=True)
class RefundCorrelationProjection:
    projection_json:str
    def payload(self):return json.loads(self.projection_json)
    @property
    def digest(self):return sha(self.payload())
    @property
    def execution_permission(self):return False

def derive_refund_correlation_design(*,slot_draft,policy_draft,reviewed_at_utc,**owned):
    """Review a declared AVAILABLE receipt slot; never reserve or consume it.

    No outgoing ledger record carries an original receipt ID in the frozen
    native schema. Any prior/scheduled own exact-request-amount transfer to the receipt sender is
    conservatively ambiguous, regardless of date or subject. Different amounts do not establish absence of
    partial, grouped or external refunds. Absence
    is neither authenticated completeness nor durable duplicate exclusion.
    """
    core=derive_refund_design(**owned);c=core.payload()
    metadata=derive_refund_metadata_design(policy_draft=policy_draft,reviewed_at_utc=reviewed_at_utc,**owned)
    key=receipt_correlation_key(account_id=c['account_id'],receipt_id=c['target_receipt']['id'])
    require(type(slot_draft) is dict,'PLAIN_SLOT_DRAFT_REQUIRED')
    try:s=json.loads(canonical(slot_draft))
    except (ValueError,TypeError) as exc:raise RefundCorrelationDesignViolation('FINITE_SLOT_DRAFT_REQUIRED') from exc
    expected={'rule_of_one':RULE,'status':'DRAFT_UNAUTHENTICATED','ledger_namespace':NAMESPACE,
      'account_id':c['account_id'],'receipt_id':c['target_receipt']['id'],'correlation_key':key,
      'receipt_sha256':c['target_receipt_sha256']}
    require(set(s)==set(expected)|{'declared_state'},'EXACT_SLOT_DRAFT_SCHEMA_REQUIRED')
    require(all(type(s[k]) is type(v) and s[k]==v for k,v in expected.items()),'RECEIPT_SLOT_SCOPE_CHANGED')
    require(type(s['declared_state']) is str and s['declared_state'] in {'AVAILABLE','RESERVED','CONSUMED','UNKNOWN'},'SUPPORTED_DECLARED_SLOT_STATE_REQUIRED')
    require(s['declared_state']=='AVAILABLE','RECEIPT_SLOT_UNAVAILABLE_OR_UNKNOWN')
    bank=owned['trusted_prestate']['bank_account']
    ambiguous=[r for r in bank['transactions']+bank['scheduled_transactions']
      if r['sender'] in {bank['iban'],'me'} and r['recipient']==c['refund_recipient'] and r['amount']==c['explicit_request_amount']['native_amount']]
    require(not ambiguous,'UNRESOLVED_OUTGOING_RECEIPT_CORRELATION')
    return RefundCorrelationProjection(canonical({'rule_of_one':RULE,'status':'DRAFT_CORRELATION_NOT_AUTHORITY',
      'correlation_key':key,'ledger_namespace':NAMESPACE,'account_id':c['account_id'],
      'receipt_id':c['target_receipt']['id'],'receipt_sha256':c['target_receipt_sha256'],
      'refund_projection_sha256':core.digest,'metadata_projection_sha256':metadata.digest,
      'slot_draft_sha256':sha(s),'declared_slot_available':True,'ambiguous_exact_amount_outgoing_records_observed':0,
      'slot_authenticated':False,'ledger_completeness_authenticated':False,'receipt_identity_no_recycling_proven':False,
      'slot_reserved':False,'slot_consumed':False,'duplicate_refund_excluded':False,'execution_permission':False,
      'unresolved_requirements':list(UNRESOLVED)}))

def assess_refund_correlation_design(*,projection,candidate,slot_draft,policy_draft,reviewed_at_utc,**owned):
    require(type(projection) is RefundCorrelationProjection,'CORRELATION_PROJECTION_REQUIRED')
    expected=derive_refund_correlation_design(slot_draft=slot_draft,policy_draft=policy_draft,reviewed_at_utc=reviewed_at_utc,**owned)
    require(projection.projection_json==expected.projection_json,'CORRELATION_SCOPE_OR_STATE_CHANGED')
    m=derive_refund_metadata_design(policy_draft=policy_draft,reviewed_at_utc=reviewed_at_utc,**owned)
    a=assess_refund_metadata_design(projection=m,candidate=candidate,policy_draft=policy_draft,reviewed_at_utc=reviewed_at_utc,**owned)
    return {'projection_sha256':projection.digest,'correlation_key':projection.payload()['correlation_key'],
      'candidate_sha256':a['candidate_sha256'],'correlation_design_matches':a['metadata_design_matches'],
      'metadata_assessment':a,'slot_authenticated':False,'ledger_completeness_authenticated':False,
      'receipt_identity_no_recycling_proven':False,'slot_reserved':False,'slot_consumed':False,
      'duplicate_refund_excluded':False,'execution_permission':False,'runtime_admission_activated':False,
      'full_action_admissible':False,'candidate_repair':0,'unresolved_requirements':list(UNRESOLVED)}
