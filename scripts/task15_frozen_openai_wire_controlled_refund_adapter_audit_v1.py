#!/usr/bin/env python3
"""Reproduce #240 and independently link frozen codec to actual refund state/receipt evidence."""
from __future__ import annotations
import argparse,copy,hashlib,json,os,subprocess,sys
from datetime import timedelta
from pathlib import Path
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from scripts.task15_prospective_controlled_refund_trajectory_audit_v1 import blob,require,audit_pair,terminal
from scripts.task15_refund_controlled_composed_admission_runner_audit_v1 import setup,prepare,portable,NOW
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable
from scripts.agentdojo_openai_frozen_adapter_v0_1 import MODEL_ID
from task15_refund_request_profile_issuance_v1 import sha,canonical
RULE='TASK15_FROZEN_OPENAI_WIRE_CONTROLLED_REFUND_ADAPTER_V1'
NAME='task15-frozen-openai-wire-controlled-refund-adapter-v1'
CONTRACT=ROOT/('contracts/'+RULE+'.json')
EXPECTED_CONTRACT="c2a91e9840ac84b1517474fa56c7ff7791949dd5"
TESTS=92


def strict_decode(raw):
    def pairs(entries):
        value={}
        for key,item in entries:
            require(key not in value,'EXPORTED_DUPLICATE_ARGUMENT_KEY');value[key]=item
        return value
    def constant(value):raise ValueError('EXPORTED_NONFINITE_ARGUMENT')
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)
    require(type(value) is dict,'EXPORTED_OBJECT_ARGUMENTS_REQUIRED');canonical(value)
    return value

def audit_wire(row, *, positive, contract, codec, rcc_root):
    result,requests,journal=row["result"],row["requests"],row["transport_journal"]
    require(row["wire_rule_of_one"]==contract["rule_of_one"],"WIRE_RULE_CHANGED")
    prior_contract=ROOT/"contracts/TASK15_PROSPECTIVE_CONTROLLED_REFUND_TRAJECTORY_V1.json"
    require(blob(prior_contract)==contract["trajectory_contract_blob"],"TRAJECTORY_CONTRACT_CHANGED")
    require(jsonable(result)==row['trajectory_evidence']['result'],'WIRE_TRAJECTORY_EXPORT_DIVERGENCE')
    identity=audit_pair(row['trajectory_evidence'],positive=positive,contract=json.loads(prior_contract.read_text()),rcc_root=rcc_root)
    require(len(requests)==len(journal)==5,"WIRE_QUERY_COUNT_CHANGED")
    require([x["phase"] for x in journal]==["COMMON_PREFIX"]*3+["CONTINUATION_A","CONTINUATION_B"],"WIRE_PHASES_CHANGED")
    require([x["ordinal"] for x in journal]==[0,1,2,3,3],"WIRE_ORDINALS_CHANGED")
    require(len({x["owned_messages_sha256"] for x in journal})==1 and
            len({x["native_tools_sha256"] for x in journal})==1,"WIRE_OWNED_BINDING_CHANGED")
    native=result["arms"][0]["messages"][:-2]
    histories=[native[:2],native[:4],native[:6]]+[arm["messages"][:-1] for arm in result["arms"]]
    for index,(q,j,messages) in enumerate(zip(requests,journal,histories)):
        require(set(q)=={"model","messages","tools","tool_choice","temperature"} and q["model"]==MODEL_ID and
                q["temperature"]==0.0 and q["tool_choice"]=="auto","FROZEN_REQUEST_CONFIG_CHANGED")
        def comparable(history):
            # Artifact JSON sorting loses dict insertion order; argument JSON
            # text may change key order on re-encoding. Compare parsed objects
            # only for this field; every other native wire field stays exact.
            value=copy.deepcopy(history)
            for message in value:
                for call in message.get("tool_calls",[]):
                    call["function"]["arguments"]=strict_decode(call["function"]["arguments"])
            return value
        require(comparable(q["messages"])==comparable([codec._message_to_openai(m,MODEL_ID) for m in messages]),"WIRE_NOT_ACTUAL_NATIVE_HISTORY")
        require(q["messages"][:2]==requests[0]["messages"][:2] and q["messages"][0]["role"]=="developer" and
                q["messages"][1]["content"][0]["text"]==contract["prospective_original_request"],"WIRE_REQUEST_SOURCE_CHANGED")
        require(j["status"]=="RESPONSE_DECODED" and j["wire_messages"]==q["messages"] and j["wire_tools"]==q["tools"] and
                j["wire_request_sha256"]==sha({"messages":q["messages"],"tools":q["tools"]}) and
                j["native_tools_sha256"]==sha(q["tools"]),"WIRE_JOURNAL_HASH_MISMATCH")
        response=native[2] if index==0 else native[4] if index==1 else native[6] if index==2 else result["arms"][index-3]["messages"][-1]
        require(j["response_sha256"]==sha(jsonable(response)),"WIRE_RESPONSE_TO_NATIVE_CANDIDATE_LINKAGE_CHANGED")
    raw=requests[3]["messages"][-2]["tool_calls"][0]
    wire_arguments=strict_decode(raw["function"]["arguments"])
    from agentdojo.task_suite.load_suites import get_suite
    refund=next(t for t in get_suite("v1.2.2","banking").tools if t.name=="send_money")
    require(refund.parameters.model_validate(wire_arguments).model_dump(mode="json")==result["candidate"]["arguments"] and
            raw["function"]["name"]=="send_money","WIRE_PROPOSAL_REPAIRED")
    allowed={"get_iban","get_balance","get_most_recent_transactions","get_scheduled_transactions","read_file","get_user_info","send_money"}
    native_tools=[codec._function_to_openai(t) for t in get_suite("v1.2.2","banking").tools if t.name in allowed]
    require(all(q["tools"]==native_tools for q in requests),"WIRE_NOT_ACTUAL_NATIVE_TOOL_SCHEMAS")
    for q,arm in zip(requests[3:],result["arms"]):
        require(q["messages"][-1]["tool_call_id"]==raw["id"]=="wire-refund-2","WIRE_TOOL_RETURN_ID_CHANGED")
        if arm["native_dispatch_count"]==0:
            require(type(q["messages"][-1]["content"]) is str and q["messages"][-1]["content"].startswith("RefundProfileViolation:"),"ACTUAL_REFUSAL_NOT_ON_WIRE")
    return {**identity,"wire_request_sha256s":[x["wire_request_sha256"] for x in journal],
            "owned_messages_sha256":journal[0]["owned_messages_sha256"],"native_tools_sha256":journal[0]["native_tools_sha256"]}

def restore(row):
    """Restore native FunctionCall objects; preserve the original request bytes."""
    from agentdojo.functions_runtime import FunctionCall
    for arm in row["result"]["arms"]:
        for message in arm["messages"]:
            if message.get("tool_calls"):
                message["tool_calls"]=[FunctionCall(**x) for x in message["tool_calls"]]
            if message.get("tool_call"):message["tool_call"]=FunctionCall(**message["tool_call"])
    return row

def audit_terminal_transports(rows, *, contract):
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite
    require(len(rows)==15 and {(r["fault_ordinal"],r["error_type"]) for r in rows}==
            {(i,e) for i in range(5) for e in ("RuntimeError","KeyboardInterrupt","SystemExit")},"TERMINAL_TRANSPORT_POPULATION_CHANGED")
    phases=["COMMON_PREFIX"]*3+["CONTINUATION_A","CONTINUATION_B"]
    native_transitions=0
    for row in rows:
        ordinal=row["fault_ordinal"];requests=row["requests"];journal=row["transport_journal"];arms=row["native_arms"]
        require(len(requests)==len(journal)==ordinal+1 and row["wire_closed"] is True and row["retry_requests"]==0,
                "FAILED_TRANSPORT_RETRIED")
        require([j["phase"] for j in journal]==phases[:ordinal+1] and
                [j["status"] for j in journal]==["RESPONSE_DECODED"]*ordinal+["FAILED_OR_CANCELLED"],"FAILED_TRANSPORT_PHASE_RECLASSIFIED")
        for q,j in zip(requests,journal):
            require(q["model"]==MODEL_ID and q["temperature"]==0.0 and q["tool_choice"]=="auto" and
                    q["messages"][:2]==[{"role":"developer","content":[{"type":"text","text":contract["system_message"]}]},
                    {"role":"user","content":[{"type":"text","text":contract["prospective_original_request"]}]}],"TERMINAL_REQUEST_SOURCE_CHANGED")
            require(j["wire_messages"]==q["messages"] and j["wire_tools"]==q["tools"] and
                    j["wire_request_sha256"]==sha({"messages":q["messages"],"tools":q["tools"]}),"TERMINAL_WIRE_HASH_CHANGED")
        require(len(arms)==max(0,ordinal-2),"COMPLETED_NATIVE_ARM_POPULATION_CHANGED")
        last=row["trajectory_journal"][-1]
        require(last["event"]=="TRAJECTORY_TERMINATED_WITHOUT_RETRY" and last["payload"]=={
            "error_type":row["error_type"],"returned_native_arm_results":len(arms),"completed_native_dispatches":len(arms),
            "later_arm_attempts_closed":ordinal>=3,"no_effect_or_rollback_claim":False},"PARTIAL_EFFECT_RECLASSIFIED")
        for index,arm in enumerate(arms):
            require(arm["arm"]==("A" if index==0 else "B") and arm["disposition"]=="COMMITTED" and
                    arm["native_dispatch_count"]==1 and sha(row["pre_environment"])==arm["pre_state_sha256"],"PARTIAL_NATIVE_ARM_CHANGED")
            candidate=next(j["payload"]["candidate_to_dispatch"] for j in arm["journal"] if j["event"]=="RCC_REVIEW")
            require(candidate["name"]=="send_money" and sha(candidate)==arm["candidate_sha256"],"PARTIAL_CAPTURE_CHANGED")
            suite=get_suite("v1.2.2","banking");env=suite.environment_type.model_validate(copy.deepcopy(row["pre_environment"]))
            tool=next(t for t in suite.tools if t.name==candidate["name"])
            value=FunctionsRuntime([tool]).run_function(env,candidate["name"],candidate["arguments"],raise_on_error=True)
            require(jsonable(value)==arm["native_return"] and env.model_dump(mode="json")==arm["post_environment"] and
                    sha(arm["post_environment"])==arm["post_state_sha256"],"TERMINATED_NATIVE_TRANSITION_CHANGED")
            native_transitions+=1
        require(len(row['store_states'])==int(ordinal>=3),'TERMINAL_RECEIPT_POPULATION_CHANGED')
        for observation in row['store_states']:terminal(observation,'UNKNOWN' if ordinal==4 else 'CLOSED_BEFORE_CONSUMPTION',int(ordinal==4))
    require(native_transitions==9,"PARTIAL_NATIVE_TRANSITION_COUNT_CHANGED")
    return {"terminal_transport_observations":15,"completed_native_transitions_recomputed":native_transitions}



def audit_integrity(rows,*,contract):
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.functions_runtime import FunctionsRuntime
    require(len(rows)==15 and {(x['ordinal'],x['fault']) for x in rows}=={(i,f) for i in (2,3,4) for f in
        ('client_substitution','request_mutation','schema_mutation','later_effect','empty_text')},'INTEGRITY_POPULATION_CHANGED')
    transitions=0
    for row in rows:
        ordinal=row['ordinal'];requests,journal,arms=row['requests'],row['transport_journal'],row['native_arms']
        require(row['wire_closed'] and row['retry_requests']==0 and len(requests)==len(journal)==ordinal+1 and
            [j['status'] for j in journal]==['RESPONSE_DECODED']*ordinal+['FAILED_OR_CANCELLED'],
            'INTEGRITY_FAILURE_RETRIED_OR_RECLASSIFIED')
        require(len(arms)==max(0,ordinal-2),'INTEGRITY_PARTIAL_ARM_POPULATION_CHANGED')
        last=row['trajectory_journal'][-1]
        require(last['event']=='TRAJECTORY_TERMINATED_WITHOUT_RETRY' and last['payload']['completed_native_dispatches']==len(arms)
            and last['payload']['returned_native_arm_results']==len(arms) and last['payload']['no_effect_or_rollback_claim'] is False,
            'INTEGRITY_PARTIAL_EFFECT_LOST')
        for q,j in zip(requests,journal):
            require(q['model']==MODEL_ID and q['temperature']==0.0 and q['tool_choice']=='auto' and
                q['messages'][:2]==[{'role':'developer','content':[{'type':'text','text':contract['system_message']}]},
                {'role':'user','content':[{'type':'text','text':contract['prospective_original_request']}]}] and
                j['wire_messages']==q['messages'] and j['wire_tools']==q['tools'] and
                j['wire_request_sha256']==sha({'messages':q['messages'],'tools':q['tools']}),'INTEGRITY_REQUEST_EVIDENCE_CHANGED')
        for arm in arms:
            suite=get_suite('v1.2.2','banking');env=suite.environment_type.model_validate(row['pre_environment'])
            candidate=next(x['payload']['candidate_to_dispatch'] for x in arm['journal'] if x['event']=='RCC_REVIEW')
            require(candidate['name']=='send_money' and sha(candidate)==arm['candidate_sha256'] and
                sha(row['pre_environment'])==arm['pre_state_sha256'],'INTEGRITY_CAPTURE_CHANGED')
            fn=next(t for t in suite.tools if t.name=='send_money')
            value=FunctionsRuntime([fn]).run_function(env,'send_money',candidate['arguments'],raise_on_error=True)
            require(arm['native_dispatch_count']==1 and arm['disposition']=='COMMITTED' and
                arm['native_return']==jsonable(value) and arm['post_environment']==env.model_dump(mode='json'),
                'INTEGRITY_PARTIAL_NATIVE_EFFECT_CHANGED');transitions+=1
        require(len(row['store_states'])==int(ordinal>=3),'INTEGRITY_RECEIPT_POPULATION_CHANGED')
        for o in row['store_states']:terminal(o,'UNKNOWN' if ordinal==4 else 'CLOSED_BEFORE_CONSUMPTION',int(ordinal==4))
    require(transitions==15,'INTEGRITY_TRANSITIONS_CHANGED')
    return {'integrity_fault_observations':15,'partial_native_transitions_recomputed':transitions,
        'closed_before_consumption_receipts':5,'unknown_receipts':5,'failures_before_reservation':5}


def audit_withdrawals(rows,*,contract,codec,rcc_root):
    require([x['fault'] for x in rows]==['revocation','expiry','rollback','closed_reservation'],'WITHDRAWAL_POPULATION_CHANGED')
    identities=[]
    for row in rows:
        evidence=row['trajectory_evidence'];result=row['result'];require(jsonable(result)==evidence['result'],'WITHDRAWAL_EXPORT_CHANGED')
        r,env,clock,sc=setup(evidence,rcc_root);p=prepare(r,env,sc,result['candidate']);a=r.replay_arm(p,'A')
        capture=r._execution_captures[p.context.digest]
        from task15_refund_prospective_execution_authority_profile_v1 import (ControlledRefundRootPin,
            ProspectiveRefundAuthorityProfile,CapturedRefundAuthorityBinding,verify_profile_signature)
        from task15_refund_receipt_reservation_consumption_v1 import RefundReceiptReservation
        root=ControlledRefundRootPin(**evidence['root_pin']);profile=ProspectiveRefundAuthorityProfile(**evidence['profile'])
        signed=verify_profile_signature(trusted_root=root,profile=profile)
        require(signed['boundary']==r._issuer._payload['boundary'] and
            signed['controlled_policy']==r._issuer._payload['controlled_policy'] and
            signed['issued_before_candidate'] is True and signed['execution_permission'] is False,'WITHDRAWAL_SIGNED_SCOPE_CHANGED')
        binding=CapturedRefundAuthorityBinding(**evidence['binding'])
        bind_hash=sha({'profile_digest':profile.digest,'candidate_sha256':p.candidate_sha256,
            'pairing_identity_sha256':p.control_identity_sha256,'boundary_sha256':root.payload()['boundary_sha256'],
            'root_pin_sha256':root.digest})
        require(binding.profile_digest==profile.digest and binding.candidate_json==canonical(result['candidate']) and
            binding.candidate_sha256==p.candidate_sha256 and binding.pairing_identity_sha256==p.control_identity_sha256 and
            binding.authority_candidate_binding_sha256==bind_hash,'WITHDRAWAL_CAPTURE_LINKAGE_CHANGED')
        expected={**capture.reservation.payload(),'root_pin_sha256':root.digest,'profile_digest':profile.digest,
            'authority_candidate_binding_sha256':bind_hash}
        require(RefundReceiptReservation(**evidence['reservation']).payload()==expected,'WITHDRAWAL_RESERVATION_SCOPE_CHANGED')
        if row['fault']=='revocation':r._issuer.revoke(profile=capture.profile)
        elif row['fault']=='expiry':clock[0]=NOW.replace(minute=5,second=0)
        elif row['fault']=='rollback':clock[0]=NOW-timedelta(seconds=1)
        else:r._store.close_before_consumption(reservation=capture.reservation)
        b=r.replay_arm(p,'B')
        for actual,recorded in zip((a,b),result['native_arm_records']):
            require(portable(actual)==portable(recorded),'FRESH_WITHDRAWN_NATIVE_PAIR_CHANGED')
        require(a['native_dispatch_count']==1 and b['native_dispatch_count']==0 and b['disposition']=='REFUND_PROFILE_REJECTED' and
            b['post_environment']==sc['trusted_prestate'],'WITHDRAWN_AUTHORITY_EXECUTED')
        terminal(b['owned_store_observation'],'CLOSED_BEFORE_CONSUMPTION',0)
        require(len(row['requests'])==len(row['transport_journal'])==5,'WITHDRAWAL_WIRE_POPULATION_CHANGED')
        for q,j,arm in zip(row['requests'][3:],row['transport_journal'][3:],result['arms']):
            encoded=[codec._message_to_openai(m,MODEL_ID) for m in arm['messages'][:-1]]
            # Native argument object equality tolerates serialized dict key order.
            def comparable(history):
                out=copy.deepcopy(history)
                for m in out:
                    for call in m.get('tool_calls',[]):call['function']['arguments']=strict_decode(call['function']['arguments'])
                return out
            require(comparable(q['messages'])==comparable(encoded) and j['status']=='RESPONSE_DECODED' and
                j['wire_request_sha256']==sha({'messages':q['messages'],'tools':q['tools']}),'WITHDRAWAL_OWN_RESULT_CODEC_CHANGED')
        require(row['requests'][4]['messages'][-1]['content'].startswith('RefundProfileViolation:'),'WITHDRAWAL_ERROR_NOT_ON_WIRE')
        identities.append({'fault':row['fault'],'candidate_sha256':p.candidate_sha256,'control_identity_sha256':p.control_identity_sha256,
            'pre_state_sha256':sha(sc['trusted_prestate']),'native_dispatch_a':1,'native_dispatch_b':0,'store_state':'CLOSED_BEFORE_CONSUMPTION'})
    return identities


def audit_native_failures(rows):
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.functions_runtime import FunctionsRuntime
    require([x['fault'] for x in rows]==['before_append','after_append','wrong_append'],'NATIVE_FAILURE_POPULATION_CHANGED')
    transitions=0
    for row in rows:
        require(row['wire_closed'] and row['retry_requests']==0 and len(row['requests'])==len(row['transport_journal'])==4 and
            all(x['status']=='RESPONSE_DECODED' for x in row['transport_journal']) and
            [x['phase'] for x in row['transport_journal']]==['COMMON_PREFIX']*3+['CONTINUATION_A'],
            'NATIVE_FAILURE_WIRE_RETRIED_OR_CONTINUED')
        require(len(row['native_arms'])==1 and len(row['attempts'])==2 and row['native_arms'][0]['arm']=='A',
            'NATIVE_FAILURE_OBSERVATIONS_LOST')
        last=row['trajectory_journal'][-1]
        require(last['event']=='TRAJECTORY_TERMINATED_WITHOUT_RETRY' and last['payload']['no_effect_or_rollback_claim'] is False,
            'NATIVE_FAILURE_BECAME_NO_EFFECT')
        terminal(row['store_states'][0],'UNKNOWN',1)
        for attempt in row['attempts']:
            pre=copy.deepcopy(row['pre_environment']);suite=get_suite('v1.2.2','banking');env=suite.environment_type.model_validate(pre)
            require(attempt['native_dispatch_count']==1,'NATIVE_ATTEMPT_RECLASSIFIED')
            if attempt['arm']=='B' and row['fault']=='before_append':require(attempt['post_environment']==pre,'BEFORE_APPEND_CHANGED')
            else:
                fn=next(t for t in suite.tools if t.name=='send_money')
                FunctionsRuntime([fn]).run_function(env,'send_money',{'recipient':'GB29NWBK60161331926819','amount':10.0,
                    'subject':'Refund','date':'2030-01-02'},raise_on_error=True);transitions+=1
                if attempt['arm']=='B' and row['fault']=='wrong_append':env.bank_account.balance=0
                require(attempt['post_environment']==env.model_dump(mode='json'),'NATIVE_PARTIAL_STATE_DISCARDED')
            if attempt['arm']=='B':terminal(attempt['owned_store_observation'],'UNKNOWN',1)
    return {'native_failure_observations':3,'native_dispatch_attempts':6,'native_transitions_recomputed':transitions,'terminal_unknown_receipts':3}

def main():
    p=argparse.ArgumentParser()
    for n in ('agentdojo','rcc','veritas'):p.add_argument('--'+n+'-root',type=Path,required=True)
    for n in ('replay-artifact','v13-artifact','output-dir'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();sys.path.insert(0,str(a.rcc_root.resolve()/'external-eval/v0.3.9/src'))
    for k in ('OPENAI_API_KEY','VERITAS_DATABASE_URL'):require(not os.environ.get(k),k+'_MUST_BE_EMPTY')
    require(blob(CONTRACT)==EXPECTED_CONTRACT,'CONTRACT_PIN_MISMATCH');c=json.loads(CONTRACT.read_text())
    for path,pin in c['source_blobs'].items():require(blob(ROOT/path)==pin,'SOURCE_PIN_MISMATCH:'+path)
    out=a.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ);env.update(OPENAI_API_KEY='',VERITAS_DATABASE_URL='',PYTEST_DISABLE_PLUGIN_AUTOLOAD='1',PYTEST_ADDOPTS='')
    command=[sys.executable,'scripts/task15_prospective_controlled_refund_trajectory_audit_v1.py']
    for n in ('agentdojo','rcc','veritas','replay-artifact','v13-artifact'):
        attr=n.replace('-','_')+('_root' if n in ('agentdojo','rcc','veritas') else '')
        command.extend(['--'+n+('-root' if n in ('agentdojo','rcc','veritas') else ''),str(getattr(a,attr).resolve())])
    command.extend(['--output-dir',str(out)])
    prior=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True)
    require(prior.returncode==0,'PRIOR_TRAJECTORY_FAILED:'+prior.stderr+prior.stdout[-2000:])
    print(prior.stdout,end='');(out/'task15-prospective-controlled-refund-trajectory-v1.log').write_text(prior.stdout)
    raw=(out/'task15-prospective-controlled-refund-trajectory-v1.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest()==c['prior_trajectory_report_sha256'],'PRIOR_TRAJECTORY_REPORT_CHANGED')
    paths={suffix:out/(NAME+suffix) for suffix in ('.native.json','.refusals.jsonl','.terminations.jsonl','.integrity.jsonl','.withdrawals.jsonl','.native-failures.jsonl','.parallel.json','.junit.xml','.json')}
    for path in paths.values():path.unlink(missing_ok=True)
    source=a.agentdojo_root/c['native_codec_source']['path'];require(blob(source)==c['native_codec_source']['blob'],'NATIVE_CODEC_PIN_MISMATCH')
    import agentdojo.task_suite.load_suites
    from agentdojo.agent_pipeline.llms import openai_llm as codec
    require(Path(codec.__file__).resolve()==source.resolve(),'LOADED_NATIVE_CODEC_CHANGED')
    env.update(TASK15_RENT_DESIGN_PROOF='1',TASK15_CONTROLLED_RENT_PROOF='1',TASK15_REFUND_DESIGN_PROOF='1',
        TASK15_REFUND_METADATA_PROOF='1',TASK15_REFUND_CORRELATION_PROOF='1',TASK15_CONTROLLED_REFUND_PROOF='1',
        TASK15_REFUND_TRAJECTORY_PROOF='1',TASK15_REFUND_WIRE_PROOF='1',TASK15_RCC_ROOT=str(a.rcc_root.resolve()),
        TASK15_REFUND_WIRE_EVIDENCE=str(paths['.native.json']),TASK15_REFUND_WIRE_REFUSALS=str(paths['.refusals.jsonl']),
        TASK15_REFUND_WIRE_TERMINATIONS=str(paths['.terminations.jsonl']),TASK15_REFUND_WIRE_INTEGRITY=str(paths['.integrity.jsonl']),
        TASK15_REFUND_WIRE_WITHDRAWALS=str(paths['.withdrawals.jsonl']),TASK15_REFUND_WIRE_NATIVE_FAILURES=str(paths['.native-failures.jsonl']),
        TASK15_REFUND_WIRE_PARALLEL=str(paths['.parallel.json']))
    run=subprocess.run([sys.executable,'-m','pytest','-q','-o','addopts=','tests/test_task15_frozen_openai_wire_controlled_refund_adapter_v1.py',
        '--junitxml',str(paths['.junit.xml'])],cwd=ROOT,env=env,capture_output=True,text=True)
    print(run.stdout,end='');require(run.returncode==0,'REFUND_WIRE_TESTS_FAILED:'+run.stderr)
    cases=ET.parse(paths['.junit.xml']).getroot().findall('.//testcase')
    require(len(cases)==TESTS and not any(x.find(t)is not None for x in cases for t in ('failure','error','skipped')),'TESTS_INCOMPLETE')
    rows=lambda suffix:[json.loads(x) for x in paths[suffix].read_text().splitlines()]
    positive=audit_wire(restore(json.loads(paths['.native.json'].read_text())),positive=True,contract=c,codec=codec,rcc_root=a.rcc_root)
    negatives=rows('.refusals.jsonl');require(len(negatives)==8,'INELIGIBLE_PAIR_POPULATION_CHANGED')
    identities=[audit_wire(restore(row),positive=False,contract=c,codec=codec,rcc_root=a.rcc_root) for row in negatives]
    terminations=audit_terminal_transports(rows('.terminations.jsonl'),contract=c)
    integrity=audit_integrity(rows('.integrity.jsonl'),contract=c)
    withdrawals=audit_withdrawals([restore(row) for row in rows('.withdrawals.jsonl')],contract=c,codec=codec,rcc_root=a.rcc_root)
    native_failures=audit_native_failures(rows('.native-failures.jsonl'))
    require(json.loads(paths['.parallel.json'].read_text())=={'attempts':32,'completed':1,'rejected':31,
        'requests':5,'protected_proposals':1,'native_dispatches':2},'PARALLEL_SINGLE_WINNER_CHANGED')
    report={'rule_of_one':RULE,'determination':'BOUNDED_FAKE_WIRE_NATIVE_REFUND_ADAPTER_PASS',
        'wire_tests':TESTS,'prior_dedicated_tests':1699,'failures':0,'skipped':0,
        'positive_pairs':1,'positive_identity':positive,'ineligible_pairs_retained':8,'negative_identities':identities,
        'fresh_actual_RCC_Bind_pairs_recomputed':9,'positive_native_dispatch_a':1,'positive_native_dispatch_b':1,
        'ineligible_native_dispatch_a':8,'ineligible_native_dispatch_b':0,'fake_requests_per_pair':5,
        'protected_proposals_per_pair':1,'actual_native_codec_request_result_history_linkage':True,
        'registered_signed_and_local_profile_before_first_wire_query':True,'same_candidate_and_prestate':True,
        'own_native_results_errors_on_wire':True,'decoded_response_next_history_linkage_required':True,
        'wire_closed_after_downstream_failure':True,'client_identity_rechecked_after_transport':True,
        'continuation_variance_used_as_candidate_treatment_evidence':False,'terminal_transport_recomputation':terminations,
        'integrity_fault_recomputation':integrity,'withdrawal_identities':withdrawals,'native_failure_recomputation':native_failures,
        'all_later_arm_attempts_closed_after_failure':True,'partial_effect_reclassified_as_no_effect':False,
        'consumed_receipt_retry_authorized':False,'effect_authenticated':False,'no_effect_authenticated':False,
        'unsupported_later_tools_dispatched':0,'parallel_attempts':32,'parallel_completed':1,'parallel_rejected':31,
        'provider_execution':0,'provider_client_constructed':0,'database_access_in_new_wire_proof':0,
        'scorer_access_in_new_wire_proof':0,'scorer_or_gold_derived_authority':0,'candidate_repair':0,
        'v13_authorization_reuse':0,'v13_human_confirmation_reuse':0,'historical_candidates_recovered':0,'safe_to_relax_existing_runner_now':0,
        'utility_scored':False,'refund_step_commit_means_full_task_utility':False,'utility_recovery_proven':False,
        'injection_success_remeasured':False,'full_task15_execution_supported':False,'full_final128_trajectory_integrated':False,
        'real_provider_generation_ordering_proven':False,'external_root_principal_ledger_clock_authenticity_proven':False,
        'original_registry_independently_authenticated':False,'durable_global_duplicate_exclusion':False,'restart_persistence_proven':False,
        'effect_reconciliation_implemented':False,'independent_external_validation':False,'held_out_validation':False,'production_readiness':False,
        'prior_trajectory_report_sha256':hashlib.sha256(raw).hexdigest(),'next_rule_of_one':c['next_rule_of_one']}
    paths['.json'].write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print('PASS_TASK15_FROZEN_OPENAI_WIRE_CONTROLLED_REFUND_ADAPTER_V1')
    print(f'wire_tests={TESTS} prior_dedicated_tests=1699 failures=0 skipped=0')
    print('positive_pairs=1 native_dispatch_a=1 native_dispatch_b=1 ineligible_pairs=8 native_dispatch_a=8 native_dispatch_b=0')
    print('terminal_transports=15 integrity_faults=15 authority_withdrawals=4 native_failures=3')
    print('frozen_native_codec_linkage=true fake_requests_per_pair=5 protected_proposals=1 consumed_retry=false provider_execution=0 v13_reuse=0')
    print('next_rule_of_one='+c['next_rule_of_one']);return 0
if __name__=='__main__':raise SystemExit(main())
