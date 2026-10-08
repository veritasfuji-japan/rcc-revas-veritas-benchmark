"""Review candidate-independent refund metadata drafts; never issue authority."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import json,re
from task15_refund_original_request_authority_design_v1 import derive_refund_design,assess_refund_design
from task15_standing_order_request_profile_issuance_v1 import canonical,sha

RULE='TASK15_REFUND_EXECUTION_METADATA_AUTHORITY_DESIGN_V1'
POLICY='task15-refund-utc-day-fixed-subject.draft.v1'
SUBJECT='Refund'
MAX_AGE=300
UNRESOLVED=(
 'independently_authenticated_original_request_current_ledger_and_principal',
 'authenticated_friend_receipt_correlation_and_freshness',
 'reviewed_metadata_policy_issuer_and_authenticated_clock',
 'prospective_registered_context_before_candidate_and_final_sink_recheck',
 'duplicate_refund_single_use_revocation_and_material_drift',
 'native_RCC_Bind_and_composed_partial_effect_continuation',
)
class RefundMetadataDesignViolation(ValueError):pass
def require(value,reason):
    if not value:raise RefundMetadataDesignViolation(reason)
def instant(value):
    require(type(value) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',value) is not None,'EXACT_UTC_INSTANT_REQUIRED')
    try:return datetime.strptime(value,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError as exc:raise RefundMetadataDesignViolation('VALID_UTC_INSTANT_REQUIRED') from exc

@dataclass(frozen=True)
class RefundMetadataProjection:
    projection_json:str
    def payload(self):return json.loads(self.projection_json)
    @property
    def digest(self):return sha(self.payload())
    @property
    def execution_permission(self):return False

def derive_refund_metadata_design(*,policy_draft,reviewed_at_utc,**owned):
    """Lint a caller-owned policy/time fixture before candidate acquisition.

    UTC day and fixed subject are proposed policy values, not native-inert
    arguments or authenticated authority. No clock, issuer, scorer or candidate
    is consulted. Repeating this pure review neither consumes nor authorizes.
    """
    core=derive_refund_design(**owned)
    require(type(policy_draft) is dict,'PLAIN_POLICY_DRAFT_REQUIRED')
    try:d=json.loads(canonical(policy_draft))
    except (ValueError,TypeError) as exc:raise RefundMetadataDesignViolation('FINITE_POLICY_DRAFT_REQUIRED') from exc
    constants={'rule_of_one':RULE,'status':'DRAFT_NOT_AUTHORITY','policy_id':POLICY,
      'date_rule':'UTC_DAY_OF_REVIEW_FIXTURE','subject_rule':'FIXED_TASK_ROLE_LITERAL',
      'subject':SUBJECT,'timezone':'UTC','calendar':'GREGORIAN','max_context_age_seconds':MAX_AGE,
      'rollover':'REJECT_AND_REQUIRE_NEW_CONTEXT','effect_scope':'PINNED_NATIVE_APPEND_ONE_TRANSACTION'}
    require(set(d)==set(constants)|{'scope_sha256','review_reference','not_before_utc','expires_at_utc'},'EXACT_POLICY_DRAFT_SCHEMA_REQUIRED')
    require(all(type(d[k]) is type(v) and d[k]==v for k,v in constants.items()),'UNSUPPORTED_METADATA_POLICY')
    require(d['scope_sha256']==core.digest and type(d['scope_sha256']) is str,'REFUND_SCOPE_SUBSTITUTED')
    require(type(d['review_reference']) is str and re.fullmatch(r'[A-Za-z0-9._:-]{1,128}',d['review_reference']) is not None,'BOUNDED_UNVERIFIED_REVIEW_REFERENCE_REQUIRED')
    start,end=instant(d['not_before_utc']),instant(d['expires_at_utc'])
    require(type(reviewed_at_utc) is datetime and reviewed_at_utc.tzinfo is timezone.utc and reviewed_at_utc.microsecond==0,'SECOND_PRECISION_UTC_REVIEW_FIXTURE_REQUIRED')
    require(timedelta(0)<end-start<=timedelta(seconds=MAX_AGE),'BOUNDED_VALIDITY_WINDOW_REQUIRED')
    require(start<=reviewed_at_utc<end,'REVIEW_OUTSIDE_VALIDITY_WINDOW')
    require(start.date()==end.date()==reviewed_at_utc.date(),'UTC_DAY_ROLLOVER_REJECTED')
    require(core.payload()['target_receipt']['date']<=reviewed_at_utc.date().isoformat(),'RECEIPT_AFTER_REVIEW_DAY')
    return RefundMetadataProjection(canonical({'rule_of_one':RULE,'status':'DRAFT_METADATA_COMPONENTS_NOT_AUTHORITY',
      'refund_projection_sha256':core.digest,'policy_draft_sha256':sha(d),
      'proposed_date':start.date().isoformat(),'proposed_subject':SUBJECT,
      'date_source':'CALLER_OWNED_UNAUTHENTICATED_UTC_REVIEW_FIXTURE',
      'subject_source':'FIXED_REVIEW_POLICY_LITERAL_NOT_RECEIPT_OR_CANDIDATE',
      'not_before_utc':d['not_before_utc'],'expires_at_utc':d['expires_at_utc'],
      'effective_date':None,'effective_subject':None,'clock_authenticated':False,
      'policy_authenticated':False,'date_authority_present':False,'subject_authority_present':False,
      'execution_permission':False,'unresolved_requirements':list(UNRESOLVED)}))

def assess_refund_metadata_design(*,projection,candidate,policy_draft,reviewed_at_utc,**owned):
    require(type(projection) is RefundMetadataProjection,'METADATA_PROJECTION_REQUIRED')
    expected=derive_refund_metadata_design(policy_draft=policy_draft,reviewed_at_utc=reviewed_at_utc,**owned)
    require(projection.projection_json==expected.projection_json,'METADATA_SCOPE_OR_POLICY_CHANGED')
    core=assess_refund_design(projection=derive_refund_design(**owned),candidate=candidate,**owned).observation()
    args=candidate.get('arguments',{}) if type(candidate) is dict else {}
    a=args if type(args) is dict else {};p=projection.payload()
    checks={'refund_core_matches':core['refund_core_matches'],
      'exact_proposed_date':type(a.get('date')) is str and a['date']==p['proposed_date'],
      'exact_proposed_subject':type(a.get('subject')) is str and a['subject']==p['proposed_subject']}
    return {'projection_sha256':projection.digest,'candidate_sha256':core['candidate_sha256'],
      'metadata_design_matches':all(checks.values()),'checks':checks,'legacy_checks':core['legacy_checks'],
      'date_authority_present':False,'subject_authority_present':False,'effective_date':None,'effective_subject':None,
      'clock_authenticated':False,'policy_authenticated':False,'principal_mapping_authenticated':False,
      'friend_relationship_authenticated':False,'duplicate_refund_excluded':False,
      'issuer_present':False,'mandate_authenticated':False,'runtime_admission_activated':False,
      'full_action_admissible':False,'execution_permission':False,'candidate_repair':0,
      'unresolved_requirements':list(UNRESOLVED)}
