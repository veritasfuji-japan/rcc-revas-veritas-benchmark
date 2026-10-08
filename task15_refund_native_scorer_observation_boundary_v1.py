"""Read-only native rubric observation after completed controlled refund pairs.

Caller owns evidence acquisition; hashes/journal labels are not authentication.
There is no complete pipeline conversation here: output and trace inputs are
explicitly empty. This is a state-rubric development diagnostic only.
"""
from __future__ import annotations
import copy,math
from task15_refund_request_profile_issuance_v1 import sha,canonical
from task15_refund_controlled_composed_admission_runner_v1 import RULE as EXECUTION_RULE
from original_request_authority_lineage_v1 import OriginalRequestEnvelope
from scripts.agentdojo_final_runner_integration_v0_1 import ExecutionBarrier,score_after_execution
RULE='TASK15_REFUND_NATIVE_SCORER_OBSERVATION_BOUNDARY_V1'
class RefundObservationViolation(RuntimeError):pass

def require(v,reason):
    if not v:raise RefundObservationViolation(reason)

def _validate(execution):
    require(type(execution) is dict and execution.get('execution_rule_of_one')==EXECUTION_RULE and
        execution.get('completion_status')=='PAIRED_PROTECTED_CALLS_TERMINAL','COMPLETED_REFUND_PAIR_REQUIRED')
    sc=execution['owned_input'];pre=sc['trusted_prestate'];env=sc['envelope']
    require(set(env)=={'suite','user_task_id','instruction'} and env['suite']=='banking' and
        type(env['user_task_id']) is int and env['user_task_id']==15 and type(env['instruction']) is str and
        sc['case_id'].startswith('banking:user_task_15:') and type(sc['proposal_ordinal']) is int and
        sc['proposal_ordinal']>=0,'OWNED_TASK15_SCOPE_REQUIRED')
    envelope=OriginalRequestEnvelope(**env);candidate=execution['candidate'];args=candidate['arguments']
    require(set(candidate)=={'kind','name','arguments','content','metadata'} and candidate['kind']=='tool_call' and
        candidate['name']=='send_money' and candidate['content'] is None and candidate['metadata']=={} and
        set(args)=={'recipient','amount','subject','date'} and type(args['amount']) is float and
        math.isfinite(args['amount']) and all(type(args[k]) is str for k in ('recipient','subject','date')),'FULL_NATIVE_REFUND_CANDIDATE_REQUIRED')
    from task15_refund_prospective_execution_authority_profile_v1 import (ControlledRefundRootPin,
        ProspectiveRefundAuthorityProfile,verify_profile_signature)
    root=ControlledRefundRootPin(**execution['root_pin']);profile=ProspectiveRefundAuthorityProfile(**execution['profile'])
    signed=verify_profile_signature(trusted_root=root,profile=profile);scope=signed['boundary']['bindings']
    require(scope['original_request_digest']==envelope.digest and scope['immediate_pre_state_sha256']==sha(pre) and
        scope['case_id']==sc['case_id'] and scope['proposal_ordinal']==sc['proposal_ordinal'] and
        scope['account_id']==pre['bank_account']['iban'],'EXPORTED_SIGNED_SCOPE_LINKAGE_REQUIRED')
    arms=execution['arms'];require(type(arms) is list and len(arms)==2 and [a['arm'] for a in arms]==['A','B'],'PAIRED_ARMS_REQUIRED')
    for k in ('candidate_sha256','pre_state_sha256','control_identity_sha256','refund_pairing_identity_sha256'):
        require(type(arms[0][k]) is str and len(arms[0][k])==64 and arms[0][k]==arms[1][k],'PAIRING_VIOLATION:'+k)
    require(sha(candidate)==arms[0]['candidate_sha256'] and sha(pre)==arms[0]['pre_state_sha256'],'CANDIDATE_OR_PRESTATE_HASH_MISMATCH')
    from scripts.pairwise_protected_candidate_control_v1_1 import ProtectedCandidateControlV11
    control=ProtectedCandidateControlV11.build(case_id=sc['case_id'],proposal_ordinal=sc['proposal_ordinal'],
        immediate_pre_state_sha256=sha(pre),function='send_money',normalized_arguments=args)
    require(control.candidate_sha256==arms[0]['candidate_sha256'] and
        control.pairing_identity_sha256()==arms[0]['control_identity_sha256'],'FULL_PAIRING_IDENTITY_REQUIRED')
    require(execution['generation_events']==['SIGNED_AUTHORITY_ISSUED_BEFORE_GENERATOR','REFUND_CONTEXT_ISSUED_BEFORE_GENERATOR',
        'CANDIDATE_GENERATOR_INVOKED_ONCE','NORMALIZED_CANDIDATE_CAPTURED','EXECUTION_BOUNDARY_CAPTURED'],'PROSPECTIVE_CAPTURE_ORDER_REQUIRED')
    for a in arms:
        require(a['disposition'] in {'COMMITTED','REFUND_PROFILE_REJECTED','BLOCKED'} and type(a['native_dispatch_count']) is int and
            a['native_dispatch_count']==int(a['disposition']=='COMMITTED'),'COMPLETE_DISPATCH_OUTCOME_REQUIRED')
        count=a['native_dispatch_count'];post=a['post_environment'];require(sha(post)==a['post_state_sha256'],'POSTSTATE_HASH_MISMATCH')
        expected=copy.deepcopy(pre)
        if count:
            account=expected['bank_account'];ids=[t['id'] for t in account['transactions']+account['scheduled_transactions']]
            account['transactions'].append({'id':max(ids,default=0)+1,'sender':account['iban'],**args,'recurring':False})
        require(canonical(post)==canonical(expected),'EXACT_REFUND_ONLY_NATIVE_TRANSITION_REQUIRED')
        expected_return=[{'message':f"Transaction to {args['recipient']} for {args['amount']} sent."},None]
        require(a['native_return']==(expected_return if count else None),'ACTUAL_NATIVE_RETURN_REQUIRED')
        rows=a['journal'];require(type(rows) is list and rows and [j['sequence'] for j in rows]==list(range(len(rows))),
            'ORDERED_EXECUTION_JOURNAL_REQUIRED')
        events=[j['event'] for j in rows]
        require(events[0]=='RCC_REVIEW' and events[-1]=='TERMINAL_OWNED_RECEIPT_OBSERVATION' and
            events.count('NATIVE_REFUND_DISPATCH_ATTEMPT')==count and
            rows[-1]['payload']['observation']==a['owned_store_observation'],'TERMINAL_OBSERVATION_LINKAGE_REQUIRED')
        dispatch=[j['payload'] for j in rows if j['event']=='NATIVE_REFUND_DISPATCH_ATTEMPT']
        require(all(d['arm']==a['arm'] and d['candidate_sha256']==a['candidate_sha256'] for d in dispatch),
            'EXACT_NATIVE_DISPATCH_JOURNAL_REQUIRED')
        o=a['owned_store_observation']
        if o is not None:
            for k in ('effect_authenticated','no_effect_authenticated','slot_retry_allowed','execution_permission',
                'native_dispatch_authorized','runtime_admission_activated','durable_global_duplicate_exclusion','restart_persistence_proven'):
                require(o[k] is False,'STORE_OBSERVATION_BECAME_EFFECT_AUTHORITY_OR_RETRY:'+k)
            require(o['correlation_key']==scope['correlation_key'] and type(o['consumptions']) is int and o['reservations']==1 and o['native_dispatches']==0,'STORE_COUNTER_REQUIRED')
            require(o['state']==('RESERVED' if a['arm']=='A' else 'UNKNOWN' if count else 'CLOSED_BEFORE_CONSUMPTION') and
                o['consumptions']==int(a['arm']=='B' and count),'TERMINAL_STORE_LIFECYCLE_REQUIRED')
        if a['arm']=='A':require(a['disposition']=='COMMITTED','BASELINE_NATIVE_CALL_REQUIRED')
        if a['arm']=='B':
            receipts=[j['payload']['receipt'] for j in rows if j['event']=='VERITAS_BIND_RECEIPT']
            if count:
                require(o is not None and len(receipts)==1 and receipts[0]['final_outcome']=='COMMITTED' and
                    receipts[0]['constraint_check_result']['status']=='pass','ACTUAL_LOCAL_BIND_COMMIT_REQUIRED')
                require(events.count('OWNED_RECEIPT_CONSUMED_BEFORE_NATIVE_DISPATCH')==1 and
                    events.index('OWNED_RECEIPT_CONSUMED_BEFORE_NATIVE_DISPATCH')<events.index('NATIVE_REFUND_DISPATCH_ATTEMPT')<
                    events.index('VERITAS_BIND_RECEIPT'),'CONSUME_BEFORE_NATIVE_DISPATCH_ORDER_REQUIRED')
                consumption=next(j['payload'] for j in rows if j['event']=='OWNED_RECEIPT_CONSUMED_BEFORE_NATIVE_DISPATCH')
                require(consumption['candidate_sha256']==a['candidate_sha256'] and
                    consumption['observation']['state']=='CONSUMED' and consumption['observation']['consumptions']==1 and
                    consumption['observation']['correlation_key']==o['correlation_key'],'CONSUMPTION_JOURNAL_LINKAGE_REQUIRED')
            else:
                require('OWNED_RECEIPT_CONSUMED_BEFORE_NATIVE_DISPATCH' not in events,'REFUSAL_CONSUMED_SLOT')
                require(not receipts or (len(receipts)==1 and receipts[0]['final_outcome'] in {'BLOCKED','ESCALATED','PRECONDITION_FAILED','APPLY_FAILED'}),
                    'REFUSAL_BECAME_COMMIT')
    return pre,envelope,arms

def observe_completed_task15_refund(*,execution,scorer=None):
    """No issuer, store, executor, generator or native dispatch interface is passed.

    The native scorer is trusted code, not a Python sandbox. An optional scorer
    is a fault-test seam; confinement of arbitrary closure code is not claimed.
    """
    frozen=copy.deepcopy(execution)
    try:
        identity=sha(frozen);pre,envelope,arms=_validate(frozen)
    except (KeyError,TypeError,ValueError,AttributeError) as exc:
        raise RefundObservationViolation('MALFORMED_COMPLETED_REFUND_EVIDENCE') from exc
    # First rubric lookup is strictly downstream of validation of both arms.
    from agentdojo.task_suite.load_suites import get_suite
    from scripts.agentdojo_native_scorer_invocation_v0_1 import NativeScorerInput,invoke_native_agentdojo_scorer
    suite=get_suite('v1.2.2','banking');user=suite.get_user_task_by_id('user_task_15');injection=suite.get_injection_task_by_id('injection_task_0')
    match=envelope.instruction==user.PROMPT;invoke=scorer if scorer is not None else invoke_native_agentdojo_scorer;scores=[]
    for a in arms:
        evidence=NativeScorerInput(case_id=frozen['owned_input']['case_id'],arm=a['arm'],model_output=[],
            pre_environment=suite.environment_type.model_validate(copy.deepcopy(pre)),
            post_environment=suite.environment_type.model_validate(copy.deepcopy(a['post_environment'])),functions_stack_trace=[])
        def digest():return sha({'pre':evidence.pre_environment.model_dump(mode='json'),'post':evidence.post_environment.model_dump(mode='json'),
            'output':evidence.model_output,'trace':[x.model_dump(mode='json') for x in evidence.functions_stack_trace]})
        before=digest();barrier=ExecutionBarrier(evidence.case_id,a['arm'],a['pre_state_sha256'],a['post_state_sha256'])
        value=score_after_execution(barrier=barrier,scorer=lambda:invoke(suite=suite,user_task=user,injection_task=injection,evidence=evidence))
        require(digest()==before,'SCORER_MUTATED_DETACHED_EVIDENCE')
        require(type(value) is dict and set(value)=={'utility','security'} and all(type(v) is bool for v in value.values()),'STRICT_NATIVE_SCORE_SHAPE_REQUIRED')
        scores.append({'arm':a['arm'],'score_status':'SCORED','native_rubric_utility':value['utility'],
            'injection_task_0_goal_success':value['security'],'native_dispatch_count':a['native_dispatch_count'],
            'candidate_sha256':a['candidate_sha256'],'post_state_sha256':a['post_state_sha256']})
    require(sha(execution)==identity,'CALLER_EVIDENCE_CHANGED_DURING_OBSERVATION')
    return {'rule_of_one':RULE,'case_id':frozen['owned_input']['case_id'],'completed_execution_sha256':identity,
        'timing':'POST_COMPLETED_PAIRED_PROTECTED_CALLS_ONLY','native_task_prompt_match':match,
        'rubric_scope':'NATIVE_TASK15_PROMPT_STATE_DIAGNOSTIC' if match else 'MISMATCHED_REQUEST_DIAGNOSTIC_ONLY',
        'model_output_source':'EMPTY_NO_COMPLETED_CONVERSATION_AVAILABLE','functions_stack_trace_source':'EMPTY_NO_PIPELINE_TRACE_AVAILABLE',
        'scores':scores,'scorer_calls':2,'authority_feedback':0,'candidate_repair':0,'dispatch_from_observer':0,
        'effect_authenticated':False,'no_effect_authenticated':False,'receipt_retry_authorized':False,'full_task15_execution_supported':False,
        'whole_trajectory_scored':False,'injection_success_remeasured':False,
        'scope':'OFFLINE_REFUND_ONLY_STATE_RUBRIC_DIAGNOSTIC_NOT_FINAL128_OR_ATTACK_EVALUATION'}
