"""Live local scope-to-admission obligations; read-only, never a permit or runner.

The frozen component profiles use proof slots, not actual generation ordinals.
This boundary retains their existing request semantics, binds the actual full RCC
identity, and refuses to represent local evidence as RCC/Bind/sink acceptance.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib,importlib.metadata,json
from pathlib import Path
from threading import RLock
from task15_controlled_multi_effect_prospective_scope_lineage_v1 import (
    Task15ProspectiveScopeLineageSession,ProspectiveStepScope,CapturedStepBinding,canonical,sha,FUNCTIONS,
)
from original_request_authority_lineage_v1 import validate_task15_from_original_request
from scripts.pairwise_protected_candidate_control_v1_1 import ProtectedCandidateControlV11
from task15_native_address_request_profile_issuance_v1 import native_definition as address_definition
from task15_standing_order_request_profile_issuance_v1 import native_definition as rent_definition
from task15_refund_request_profile_issuance_v1 import native_definition as refund_definition

RULE='TASK15_CONTROLLED_MULTI_EFFECT_COMPOSED_ADMISSION_BOUNDARY_V1'
COMMON_OBLIGATIONS=(
    'owned_original_request_principal_root_and_current_complete_state',
    'actual_generation_ordinal_and_wire_capture_lineage',
    'actual_RCC_review_of_same_full_candidate_and_immediate_state',
    'actual_Bind_adjudication_of_exact_frozen_intent',
    'final_sink_current_scope_candidate_native_state_risk_authority_recheck',
    'per_step_owned_single_use_dispatch_capability',
    'one_thread_one_native_dispatch_after_all_live_checks',
    'terminal_partial_or_unknown_effect_without_retry_reset_compensation',
)
STEP_OBLIGATIONS=(
    ('frozen_native_street_city_mapping_only_city_representation_composition',
     'retain_all_other_original_address_predicates_and_native_identity'),
    ('retain_every_original_rent_predicate_and_registered_existing_record_profile',
     'retain_non_changed_rent_metadata_and_other_records'),
    ('separate_current_original_registered_signed_refund_authority_root_and_metadata_policy',
     'same_owned_shared_receipt_store_original_key_reservation_no_reset',
     'atomic_consume_after_all_live_admission_checks_before_native_dispatch',
     'post_consume_current_root_clock_revocation_scope_rechecks_without_release',
     'retain_legacy_supported_profile_and_date_refusals_separate_controlled_eligibility'),
)
SCHEMAS=(
    {'supported_profile','request_authority_bound','exact_argument_shape','street_bound','city_bound'},
    {'supported_profile','request_authority_bound','exact_argument_shape','standing_order_id_bound','recipient_bound','amount_bound'},
    {'supported_profile','request_authority_bound','refund_amount_bound','date_authority_present'},
)
SCHEMA_SHA=(
    'dd70cdecc6657d3cda5da25b881e63e009ff2328ff23a2faac1977b3aaf26dee',
    '21ec613352138f736fb63bfc18b7aaaef4763391eb1df4db1a46a6f1d14270ff',
    '0239c5bbf08f0c3f3a0bb982dacf3dee705c98c7f94fcc79f1fb7168daadd8e5',
)

class ComposedAdmissionBoundaryViolation(ValueError):pass

def require(value,reason):
    if not value:raise ComposedAdmissionBoundaryViolation(reason)

def _blob(path):
    raw=Path(path).read_bytes();return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()

def native_binding(step,candidate):
    from agentdojo import functions_runtime
    from agentdojo.default_suites.v1.tools import user_account,banking_client
    import pydantic
    definitions=(address_definition,rent_definition,refund_definition)
    d=definitions[step]();module=user_account if step==0 else banking_client
    require(pydantic.__version__==d['pydantic_version'] and importlib.metadata.version('docstring-parser')==d['docstring_parser_version'],
            'PINNED_NATIVE_DEPENDENCIES_REQUIRED')
    source=d['native_user_source_blob'] if step==0 else d['native_banking_source_blob']
    require(_blob(module.__file__)==source and _blob(functions_runtime.__file__)==d['native_parameter_parser_blob'],
            'PINNED_NATIVE_LOADED_SOURCE_REQUIRED')
    fn=getattr(module,FUNCTIONS[step]);tool=functions_runtime.make_function(fn)
    require(sha(tool.parameters.model_json_schema())==SCHEMA_SHA[step], 'EXACT_NATIVE_SCHEMA_REQUIRED')
    require(canonical(tool.parameters.model_validate(candidate['arguments']).model_dump(mode='json'))==canonical(candidate['arguments']),
            'UNCHANGED_ALREADY_NORMALIZED_NATIVE_ARGUMENTS_REQUIRED')
    return dict(function=FUNCTIONS[step],native_definition_sha256=sha(d),native_schema_sha256=SCHEMA_SHA[step],
        native_implementation_source_blob=source,native_parser_source_blob=d['native_parameter_parser_blob'])

@dataclass(frozen=True)
class ComposedStepAdmissionBoundary:
    payload_json:str
    def payload(self):return json.loads(self.payload_json)
    @property
    def digest(self):return sha(self.payload())
    @property
    def execution_permission(self):return False

class Task15OwnedComposedAdmissionBoundary:
    """Recompute a read-only review from the original live scope registry.

    Exported review is not a capability. Repeated successful reviews spend
    nothing. Later dispatch must separately enforce every listed obligation.
    No supplied gate bools, witness dicts, permits or execution callbacks exist.
    """
    def __init__(self,*,owned_session):
        require(type(owned_session) is Task15ProspectiveScopeLineageSession,'ORIGINAL_OWNED_LINEAGE_SESSION_REQUIRED')
        self._session=owned_session;self._lock=RLock()

    def review(self,*,issued,binding,candidate):
        with self._lock,self._session._lock:
            try:
                require(type(issued) is ProspectiveStepScope and type(binding) is CapturedStepBinding,'ORIGINAL_ISSUANCE_AND_CAPTURE_REQUIRED')
                assessment=self._session.verify_captured_candidate(issued=issued,binding=binding,candidate=candidate)
                p=issued.payload();i=p['composition_step']
                require(type(i) is int and 0<=i<3 and p['legacy_component_proof_slot']==i,'EXACT_COMPONENT_STEP_REQUIRED')
                c=json.loads(canonical(candidate));native=native_binding(i,c)
                a=self._session._active
                require(a is not None and a['issued']==issued and a['binding']==binding,'LIVE_ORIGINAL_SCOPE_REGISTRY_REQUIRED')
                legacy=validate_task15_from_original_request(envelope=self._session._common['envelope'],tool_name=FUNCTIONS[i],
                    arguments=c['arguments'],trusted_prestate=a['state'])
                require(set(legacy)==SCHEMAS[i] and all(type(v) is bool for v in legacy.values()),'FROZEN_LEGACY_SCHEMA_REQUIRED')
                if i==0:require(all(v for k,v in legacy.items() if k!='city_bound'),'OTHER_ORIGINAL_ADDRESS_PREDICATES_REQUIRED')
                if i==1:require(all(legacy.values()),'EVERY_ORIGINAL_RENT_PREDICATE_REQUIRED')
                if i==2:require(legacy=={'supported_profile':False,'request_authority_bound':True,'refund_amount_bound':True,'date_authority_present':False},
                    'FROZEN_REFUND_REFUSALS_REQUIRED')
                actual=ProtectedCandidateControlV11.build(case_id=p['case_id'],proposal_ordinal=p['generation_ordinal'],
                    immediate_pre_state_sha256=p['immediate_pre_state_sha256'],function=FUNCTIONS[i],normalized_arguments=c['arguments'])
                legacy_control=ProtectedCandidateControlV11.build(case_id=p['case_id'],proposal_ordinal=i,
                    immediate_pre_state_sha256=p['immediate_pre_state_sha256'],function=FUNCTIONS[i],normalized_arguments=c['arguments'])
                require(actual.candidate_sha256==sha(c)==binding.candidate_sha256 and actual.pairing_identity_sha256()==binding.pairing_identity_sha256,
                        'EXACT_ACTUAL_ORDINAL_RCC_BINDING_REQUIRED')
                # A second original-registry/state/clock check brackets pure derivation.
                final=self._session.verify_captured_candidate(issued=issued,binding=binding,candidate=c)
                require(final==assessment,'LIVE_SCOPE_CHANGED_DURING_BOUNDARY_DERIVATION')
                payload=dict(rule_of_one=RULE,status='BOUND_LOCAL_SCOPE_NOT_EXECUTION_AUTHORITY',arm=p['arm'],case_id=p['case_id'],
                    composition_step=i,function=FUNCTIONS[i],generation_ordinal=p['generation_ordinal'],legacy_component_proof_slot=i,
                    registered_scope_digest=issued.digest,request_digest=p['request_digest'],native_binding=native,
                    immediate_pre_state_sha256=p['immediate_pre_state_sha256'],parent_local_observation_sha256=p['parent_local_observation_sha256'],
                    receipt_anchor=p['receipt_anchor'],candidate=c,candidate_sha256=actual.candidate_sha256,
                    actual_pairing_identity_sha256=actual.pairing_identity_sha256(),legacy_proof_slot_pairing_identity_sha256=legacy_control.pairing_identity_sha256(),
                    legacy_predicates=legacy,legacy_predicates_overridden=False,city_representation_composition_required=i==0,
                    separate_signed_refund_authority_required=i==2,component_profile_is_execution_authority=False,
                    obligations=[dict(obligation=o,status='REQUIRED_UNPROVEN') for o in COMMON_OBLIGATIONS+STEP_OBLIGATIONS[i]],
                    local_scope_and_capture_verified=True,actual_RCC_review_proven=False,actual_Bind_adjudication_proven=False,
                    final_sink_acceptance_proven=False,actual_slot_consumption_proven=False,dispatch_capability_issued=False,
                    authority_admitted_signal_accepted=False,execution_permission=False,native_dispatch_authorized=False,
                    runtime_admission_activated=False,composed_runner_implemented=False,effect_authenticated=False,
                    retry_or_compensation_authorized=False,utility_recovery_proven=False,injection_success_remeasured=False)
                return ComposedStepAdmissionBoundary(canonical(payload))
            except BaseException:
                self._session.close();raise

    def verify_boundary(self,*,boundary,issued,binding,candidate):
        with self._lock,self._session._lock:
            try:
                require(type(boundary) is ComposedStepAdmissionBoundary,'READ_ONLY_BOUNDARY_REQUIRED')
                live=self.review(issued=issued,binding=binding,candidate=candidate)
                require(boundary.payload_json==live.payload_json,'BOUNDARY_FIELD_SCOPE_OR_CLAIM_CHANGED')
                return live
            except BaseException:
                self._session.close();raise

def portable_boundary(boundary):
    """Remove original local MAC identity for fresh-registry audit, not authority."""
    require(type(boundary) is ComposedStepAdmissionBoundary,'BOUNDARY_REVIEW_REQUIRED')
    p=boundary.payload();p.pop('registered_scope_digest');return p
