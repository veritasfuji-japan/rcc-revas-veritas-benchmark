"""Inert Task15 composition specification; no issuer, runner, store or scorer.

Predicted states are review material derived from owned inputs and frozen native
semantics. They never replace acquired immediate state or authorize rebasing an
existing profile. Lifecycle labels model ordering, not successful runtime checks.
"""
from __future__ import annotations
from dataclasses import dataclass
import copy
import json
from task15_native_address_request_profile_issuance_v1 import canonical, sha
from task15_original_request_native_address_field_mapping_v1 import (
    derive_task15_native_address_mapping, assess_task15_native_address_fields,
)
from task15_standing_order_original_request_authority_design_v1 import (
    derive_rent_update_design, assess_rent_update_design,
)
from task15_refund_execution_authority_boundary_v1 import (
    derive_execution_authority_boundary, assess_execution_authority_boundary,
)
from scripts.pairwise_protected_candidate_control_v1_1 import ProtectedCandidateControlV11

RULE = 'TASK15_CONTROLLED_MULTI_EFFECT_COMPOSITION_AUTHORITY_DESIGN_V1'
FUNCTIONS = ('update_user_info', 'update_scheduled_transaction', 'send_money')
OBLIGATIONS = (
    'owned_original_request_principal_and_initial_state_before_generation',
    'fresh_per_arm_per_step_profile_before_candidate_from_acquired_immediate_state',
    'fresh_reviewed_refund_policy_scope_after_address_and_rent_changes',
    'one_full_RCC_candidate_and_identical_immediate_prestate_per_controlled_pair',
    'RCC_Bind_final_sink_recheck_and_per_step_single_use',
    'owned_append_only_effect_lineage_without_authority_inheritance',
    'terminal_partial_failure_without_retry_reset_or_automatic_compensation',
    'completed_own_history_only_native_scoring_without_authority_feedback',
)

class CompositionDesignViolation(ValueError):
    pass

def require(value, reason):
    if not value:
        raise CompositionDesignViolation(reason)

@dataclass(frozen=True)
class Task15CompositionDesign:
    payload_json: str
    def payload(self):
        return json.loads(self.payload_json)
    @property
    def digest(self):
        return sha(self.payload())
    @property
    def execution_permission(self):
        return False

def _scopes(owned):
    common = {k: owned[k] for k in ('envelope', 'case_id', 'trusted_prestate')}
    rent = {**common, 'proposal_ordinal': 1}
    refund = {**common, 'proposal_ordinal': 2,
        **{k: owned[k] for k in ('owned_ledger_recipient', 'policy_draft', 'slot_draft', 'reviewed_at_utc')}}
    return rent, refund

def derive_composition_design(*, envelope, case_id, trusted_prestate,
                              owned_ledger_recipient, policy_draft, slot_draft, reviewed_at_utc):
    """Project three distinct effect scopes before any proposal is supplied.

    All component checks here refer to the INITIAL owned snapshot. Later-state
    projections do not reissue or rewrite the initial refund metadata draft.
    Actual per-step issuance and acquisition remain a separate proof obligation.
    The fixed order is conservative runner policy, not inferred user authority.
    """
    owned = dict(envelope=envelope, case_id=case_id, trusted_prestate=trusted_prestate,
        owned_ledger_recipient=owned_ledger_recipient, policy_draft=policy_draft,
        slot_draft=slot_draft, reviewed_at_utc=reviewed_at_utc)
    try:
        address = derive_task15_native_address_mapping(envelope)
        rent_scope, refund_scope = _scopes(owned)
        rent = derive_rent_update_design(**rent_scope)
        refund = derive_execution_authority_boundary(**refund_scope)
        initial = json.loads(canonical(trusted_prestate))
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError) as exc:
        raise CompositionDesignViolation('EXACT_EXISTING_COMPONENT_DESIGNS_REQUIRED') from exc
    r, f = rent.payload(), refund.payload()['bindings']
    address_fields = address.native_fields()
    rent_fields = {'id': r['target_record']['id'], **r['explicit_request_fields']}
    refund_fields = {k: f[k] for k in ('receipt_id', 'receipt_sha256', 'correlation_key',
        'refund_recipient', 'refund_amount', 'proposed_date', 'proposed_subject')}
    states = [initial]
    after = copy.deepcopy(initial); after['user_account'].update(address_fields); states.append(after)
    after = copy.deepcopy(after)
    target = next(x for x in after['bank_account']['scheduled_transactions'] if x['id'] == rent_fields['id'])
    target.update(recipient=rent_fields['recipient'], amount=rent_fields['native_amount']); states.append(after)
    after = copy.deepcopy(after); bank = after['bank_account']
    next_id = max(x['id'] for x in bank['transactions'] + bank['scheduled_transactions']) + 1
    bank['transactions'].append({'id': next_id, 'sender': bank['iban'], 'recipient': f['refund_recipient'],
        'amount': f['refund_amount'], 'subject': f['proposed_subject'], 'date': f['proposed_date'], 'recurring': False})
    states.append(after)
    steps = []
    for i, (function, fields, component_digest) in enumerate(zip(FUNCTIONS,
        (address_fields, rent_fields, refund_fields), (address.mapping_digest, rent.digest, refund.digest))):
        steps.append({'step': i, 'function': function, 'request_digest': envelope.digest,
            'initial_component_projection_sha256': component_digest, 'effect_fields': fields,
            'draft_pre_state_sha256': sha(states[i]), 'draft_post_state_sha256': sha(states[i+1]),
            'fresh_scope_required_before_first_candidate': True, 'earlier_effect_is_authority': False})
    return Task15CompositionDesign(canonical({'rule_of_one': RULE, 'status': 'SPECIFICATION_NOT_AUTHORITY',
        'request_digest': envelope.digest, 'case_id': case_id, 'initial_state_sha256': sha(initial),
        'controlled_order': list(FUNCTIONS), 'steps': steps, 'draft_states': states,
        'initial_refund_policy_scope_sha256': policy_draft['scope_sha256'],
        'later_refund_policy_reuse_allowed': False, 'projection_states_are_acquired_evidence': False,
        'step_numbers_are_generation_ordinals': False, 'initial_component_checks_cover_later_state': False,
        'receipt_correlation_key': f['correlation_key'],
        'proof_obligations': [{'obligation': k, 'status': 'REQUIRED_SEPARATE_COMPOSITION_PROOF'} for k in OBLIGATIONS],
        'execution_permission': False, 'runtime_admission_activated': False, 'issuer_present': False,
        'effect_authenticated': False, 'native_dispatch_authorized': False,
        'global_duplicate_exclusion': False, 'full_task15_execution_supported': False,
        'utility_recovery_proven': False, 'injection_success_remeasured': False}))

def _verified(design, owned):
    require(type(design) is Task15CompositionDesign, 'COMPOSITION_SPECIFICATION_REQUIRED')
    expected = derive_composition_design(**owned)
    require(design.payload_json == expected.payload_json, 'COMPOSITION_SCOPE_OR_CLAIM_CHANGED')
    return expected.payload()

def assess_composition_candidates(*, design, candidates, **owned):
    """Assess immutable normalized proposals against INITIAL component scopes.

    Matching all scopes is not future-stage admissibility, capture, pairing or
    permission. Draft pairing hashes identify review objects only.
    """
    p = _verified(design, owned)
    require(type(candidates) is list and len(candidates) == 3, 'THREE_PLAIN_CANDIDATE_REVIEW_OBJECTS_REQUIRED')
    rent_scope, refund_scope = _scopes(owned)
    rent = derive_rent_update_design(**rent_scope); refund = derive_execution_authority_boundary(**refund_scope)
    c = candidates[0]
    full = type(c) is dict and set(c) == {'kind', 'name', 'arguments', 'content', 'metadata'}
    args = c.get('arguments', {}) if type(c) is dict else {}
    address = assess_task15_native_address_fields(envelope=owned['envelope'], tool_name=c.get('name') if type(c) is dict else None, arguments=args)
    matches = [full and c['kind'] == 'tool_call' and c['content'] is None and c['metadata'] == {} and
        type(args) is dict and set(args) == {'first_name','last_name','street','city'} and address.field_mapping_matches,
        assess_rent_update_design(projection=rent, candidate=candidates[1], **rent_scope).design_matches,
        assess_execution_authority_boundary(boundary=refund, candidate=candidates[2], **refund_scope)['design_matches']]
    identities = []
    if all(matches):
        for i, candidate in enumerate(candidates):
            control = ProtectedCandidateControlV11.build(case_id=p['case_id'], proposal_ordinal=i,
                immediate_pre_state_sha256=p['steps'][i]['draft_pre_state_sha256'],
                function=FUNCTIONS[i], normalized_arguments=candidate['arguments'])
            require(control.candidate_sha256 == sha(candidate), 'FULL_RCC_REVIEW_HASH_REQUIRED')
            identities.append({'candidate_sha256': control.candidate_sha256,
                'draft_pairing_identity_sha256': control.pairing_identity_sha256()})
    return {'design_sha256': design.digest, 'initial_component_matches': matches,
        'effect_scope_candidates_match': all(matches), 'draft_review_identities': identities,
        'actual_candidates_captured': False, 'actual_controlled_pairing_proven': False,
        'later_state_admission_proven': False, 'execution_permission': False, 'candidate_repair': 0,
        'runtime_admission_activated': False, 'native_dispatch_authorized': False}

_ADVANCE = {'ISSUE_FRESH_SCOPE': ('START','ISSUED'), 'CAPTURE_SAME_CANDIDATE_AND_PRESTATE': ('ISSUED','CAPTURED'),
    'RCC_BIND_FINAL_SINK_RECHECK': ('CAPTURED','CHECKED'), 'CONSUME_ONCE': ('CHECKED','CONSUMED'),
    'DISPATCH_ONCE': ('CONSUMED','DISPATCHING'), 'LOCAL_STEP_OBSERVED': ('DISPATCHING','OBSERVED')}

def check_composition_specification(*, design, events, **owned):
    """Stateless sequence model; labels cannot prove checks, effects or pairing."""
    _verified(design, owned)
    require(type(events) is list and 1 <= len(events) <= 18 and all(type(e) is str for e in events), 'BOUNDED_PLAIN_EVENTS_REQUIRED')
    step = 0; phase = 'START'; consumed = []; dispatched = []; observed = []; trace = []
    terminal = None
    for event in events:
        require(terminal is None, 'TERMINAL_COMPOSITION_CANNOT_REOPEN')
        before = phase
        if event in ('STOP_BEFORE_CONSUME','PAIRING_DIVERGED') and phase in ('START','ISSUED','CAPTURED','CHECKED'):
            terminal = 'PAIRING_STOPPED' if event == 'PAIRING_DIVERGED' else 'STOPPED'; phase = 'CLOSED'
        elif event == 'FAIL_AFTER_CONSUME' and phase == 'CONSUMED':
            terminal = 'UNKNOWN'; phase = 'UNKNOWN'
        elif event in ('FAIL_DISPATCH','RETURN_WITHOUT_OBSERVATION') and phase == 'DISPATCHING':
            terminal = 'UNKNOWN'; phase = 'UNKNOWN'
        else:
            transition = _ADVANCE.get(event)
            require(transition is not None and transition[0] == phase, 'UNSUPPORTED_OR_REPLAYED_COMPOSITION_EVENT')
            phase = transition[1]
            if event == 'CONSUME_ONCE': consumed.append(step)
            if event == 'DISPATCH_ONCE': dispatched.append(step)
            if event == 'LOCAL_STEP_OBSERVED': observed.append(step)
        trace.append({'step': step, 'function': FUNCTIONS[step], 'event': event, 'before': before, 'after': phase})
        if phase == 'OBSERVED':
            if step == 2: terminal = 'COMPLETE_SPECIFICATION'
            else: step += 1; phase = 'START'
    require(terminal is not None, 'COMPLETE_TERMINAL_SPECIFICATION_REQUIRED')
    return {'design_sha256': design.digest, 'model_terminal': terminal, 'model_observed_steps': observed,
        'model_consumed_steps': consumed, 'model_dispatch_steps': dispatched, 'trace': trace,
        'model_partial_effects_preserved': bool(observed) and terminal != 'COMPLETE_SPECIFICATION',
        'model_spent_steps_reusable': False, 'model_retry_allowed': False, 'automatic_compensation_allowed': False,
        'later_pairing_claim_allowed_after_divergence': False, 'events_are_authority_evidence': False,
        'actual_slot_consumptions': 0, 'actual_native_dispatches': 0, 'candidate_repair': 0,
        'execution_permission': False, 'runtime_effects_proven': False, 'no_effect_authenticated': False,
        'full_task15_execution_supported': False, 'utility_recovery_proven': False}
