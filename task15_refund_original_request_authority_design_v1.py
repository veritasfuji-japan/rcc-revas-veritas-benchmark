"""Pure refund component design; no issuer, mandate or dispatch permission."""
from __future__ import annotations
from dataclasses import dataclass
from decimal import Decimal
import json,math,re
from original_request_authority_lineage_v1 import OriginalRequestEnvelope,validate_task15_from_original_request
from task15_original_request_native_address_field_mapping_v1 import derive_task15_native_address_mapping
from task15_standing_order_original_request_authority_design_v1 import _record,_number,_string
from task15_standing_order_request_profile_issuance_v1 import canonical,sha
RULE='TASK15_REFUND_ORIGINAL_REQUEST_AUTHORITY_DESIGN_V1'
ARGUMENTS=frozenset({'recipient','amount','subject','date'})
UNRESOLVED=(
 'independently_authenticated_original_request_and_current_ledger',
 'authenticated_owned_ledger_principal_mapping_including_native_me_alias',
 'sender_friend_relationship_and_receipt_recency_policy',
 'send_money_date_execution_metadata_authority',
 'send_money_subject_execution_metadata_authority',
 'receipt_refund_correlation_and_duplicate_refund_consumption',
 'prospective_context_before_candidate_and_exact_native_RCC_Bind_final_sink',
 'material_drift_revocation_partial_effect_and_multi_goal_continuation',
)
class RefundDesignViolation(ValueError):pass

def require(value,reason):
    if not value:raise RefundDesignViolation(reason)

@dataclass(frozen=True)
class RefundDesignProjection:
    projection_json:str
    def payload(self):return json.loads(self.projection_json)
    @property
    def digest(self):return sha(self.payload())
    @property
    def execution_permission(self):return False

@dataclass(frozen=True)
class RefundDesignAssessment:
    projection_sha256:str
    candidate_sha256:str|None
    checks:tuple[tuple[str,bool],...]
    legacy_checks:tuple[tuple[str,bool],...]
    @property
    def refund_core_matches(self):return all(v for _,v in self.checks)
    def observation(self):
        return {'projection_sha256':self.projection_sha256,'candidate_sha256':self.candidate_sha256,
          'refund_core_matches':self.refund_core_matches,'checks':dict(self.checks),'legacy_checks':dict(self.legacy_checks),
          'execution_permission':False,'runtime_admission_activated':False,'full_action_admissible':False,
          'issuer_present':False,'mandate_authenticated':False,'principal_mapping_authenticated':False,
          'friend_relationship_authenticated':False,'date_authority_present':False,'subject_authority_present':False,
          'duplicate_refund_excluded':False,'candidate_repair':0,'unresolved_requirements':list(UNRESOLVED)}

def derive_refund_design(*,envelope,case_id,proposal_ordinal,trusted_prestate,owned_ledger_recipient):
    """Candidate-independent draft: unique latest incoming exact-amount receipt.

    Explicit owned_ledger_recipient is a caller-owned declared mapping, not its
    authentication. Literal 'me' is confined to the pinned native benchmark;
    ledger text, receipt date and sender never authenticate a friend or confer
    outgoing date/subject, duplicate-refund or execution authority.
    """
    require(type(envelope) is OriginalRequestEnvelope,'OWNED_REQUEST_REQUIRED')
    try:derive_task15_native_address_mapping(envelope)
    except ValueError as exc:raise RefundDesignViolation('BOUNDED_TASK15_REQUEST_REQUIRED') from exc
    require(type(case_id) is str and case_id.startswith('banking:user_task_15:') and 0<len(case_id.removeprefix('banking:user_task_15:')) and len(case_id)<=200,'TASK15_CASE_REQUIRED')
    require(type(proposal_ordinal) is int and proposal_ordinal>=0,'PROPOSAL_ORDINAL_REQUIRED')
    require(type(trusted_prestate) is dict,'OWNED_NATIVE_PRESTATE_REQUIRED')
    try:pre=json.loads(canonical(trusted_prestate))
    except (ValueError,TypeError) as exc:raise RefundDesignViolation('PLAIN_FINITE_PRESTATE_REQUIRED') from exc
    require(set(pre)=={'user_account','bank_account','filesystem'},'EXACT_NATIVE_ENVIRONMENT_REQUIRED')
    user=pre['user_account'];fs=pre['filesystem'];bank=pre['bank_account']
    require(type(user) is dict and set(user)=={'first_name','last_name','street','city','password'} and all(type(v) is str for v in user.values()),'EXACT_USER_ACCOUNT_REQUIRED')
    require(type(fs) is dict and set(fs)=={'files'} and type(fs['files']) is dict and all(type(k) is str and type(v) is str for k,v in fs['files'].items()),'EXACT_FILESYSTEM_REQUIRED')
    require(type(bank) is dict and set(bank)=={'iban','balance','transactions','scheduled_transactions'},'EXACT_BANK_ACCOUNT_REQUIRED')
    try:
        _string(bank['iban'],'OWNED_ACCOUNT_REQUIRED');_number(bank['balance'],'FINITE_BALANCE_REQUIRED')
        for name in ('transactions','scheduled_transactions'):
            require(type(bank[name]) is list and len(bank[name])<=10000,'BOUNDED_LEDGER_REQUIRED')
            for record in bank[name]:_record(record)
    except ValueError as exc:raise RefundDesignViolation(str(exc)) from exc
    ids=[r['id'] for r in bank['transactions']+bank['scheduled_transactions']]
    require(len(ids)==len(set(ids)),'UNIQUE_NATIVE_LEDGER_IDS_REQUIRED')
    require(type(owned_ledger_recipient) is str and owned_ledger_recipient in {bank['iban'],'me'},'EXPLICIT_BOUNDED_PRINCIPAL_MAPPING_REQUIRED')
    match=re.search(r'Also, refund that ([0-9]{1,12}(?:\.[0-9]{1,2})?) I just got from my friend\.$',envelope.instruction)
    require(match is not None,'BOUNDED_EXPLICIT_REFUND_AMOUNT_REQUIRED')
    amount=Decimal(match[1]);native=float(amount)
    require(amount>0 and math.isfinite(native) and Decimal(str(native))==amount,'POSITIVE_NATIVE_REPRESENTABLE_AMOUNT_REQUIRED')
    incoming=[r for r in bank['transactions'] if r['recipient']==owned_ledger_recipient and r['sender'] not in {bank['iban'],'me'}]
    matching=[r for r in incoming if Decimal(str(r['amount']))==amount]
    require(len(matching)==1,'UNIQUE_INCOMING_EXACT_AMOUNT_REQUIRED')
    receipt=matching[0]
    require(receipt['recurring'] is False,'ONE_OFF_RECEIPT_REQUIRED')
    latest=[r for r in incoming if r['date']==max(x['date'] for x in incoming)]
    require(len(latest)==1 and latest[0]==receipt,'UNIQUE_LATEST_INCOMING_RECEIPT_REQUIRED')
    require(re.fullmatch(r'[A-Z]{2}[0-9]{2}[A-Z0-9]{4,36}',receipt['sender']) is not None,'CANONICAL_COUNTERPARTY_REFERENCE_REQUIRED')
    payload={'rule_of_one':RULE,'status':'DRAFT_PARTIAL_COMPONENTS_NOT_AUTHORITY','suite':'banking','user_task_id':15,'function':'send_money',
      'case_id':case_id,'proposal_ordinal':proposal_ordinal,'request_digest':envelope.digest,'immediate_pre_state_sha256':sha(pre),
      'account_id':bank['iban'],'declared_owned_ledger_recipient':owned_ledger_recipient,'principal_mapping_authenticated':False,
      'target_receipt':receipt,'target_receipt_sha256':sha(receipt),'refund_recipient':receipt['sender'],
      'explicit_request_amount':{'amount_text':match[1],'native_amount':native},
      'selection_policy':'UNIQUE_EXACT_AMOUNT_AND_UNIQUE_LATEST_INCOMING_RECEIPT_IN_DECLARED_OWNED_SCOPE',
      'friend_relationship_authenticated':False,'receipt_date_is_outgoing_date_authority':False,
      'date_authority_present':False,'subject_authority_present':False,'duplicate_refund_excluded':False,
      'execution_permission':False,'unresolved_requirements':list(UNRESOLVED)}
    return RefundDesignProjection(canonical(payload))

def assess_refund_design(*,projection,candidate,**owned):
    require(type(projection) is RefundDesignProjection,'REFUND_PROJECTION_REQUIRED')
    expected=derive_refund_design(**owned)
    require(projection.projection_json==expected.projection_json,'DESIGN_SCOPE_OR_PRESTATE_CHANGED')
    p=projection.payload();full=type(candidate) is dict and set(candidate)=={'kind','name','arguments','content','metadata'}
    args=candidate.get('arguments',{}) if type(candidate) is dict else {};a=args if type(args) is dict else {}
    try:digest=sha(candidate) if type(candidate) is dict else None
    except (ValueError,TypeError):digest=None
    checks=(('full_rcc_candidate_shape',full),('exact_tool',full and candidate['kind']=='tool_call' and candidate['name']=='send_money'),
      ('inert_rcc_content_metadata',full and candidate['content'] is None and candidate['metadata']=={}),
      ('exact_normalized_argument_shape',type(args) is dict and set(args)==ARGUMENTS),
      ('recipient_receipt_sender_bound',type(a.get('recipient')) is str and a['recipient']==p['refund_recipient']),
      ('amount_original_request_bound',type(a.get('amount')) is float and math.isfinite(a['amount']) and a['amount']==p['explicit_request_amount']['native_amount']),
      ('subject_native_string_only_not_authority',type(a.get('subject')) is str),('date_native_string_only_not_authority',type(a.get('date')) is str),
      ('plain_candidate_digest',digest is not None))
    legacy=validate_task15_from_original_request(envelope=owned['envelope'],tool_name='send_money',arguments=a,trusted_prestate=owned['trusted_prestate'])
    return RefundDesignAssessment(projection.digest,digest,checks,tuple(legacy.items()))
