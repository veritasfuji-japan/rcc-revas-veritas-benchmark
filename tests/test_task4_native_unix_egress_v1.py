"""Portable strict-policy checks; full Native/kernel proof runs separately in CI."""
import copy
from pathlib import Path

import pytest
from scripts import task4_native_unix_egress_v1 as u


def policy():
    rows=[dict(table=dict(family='inet',name=u.TABLE,handle=1,comment='native-unix-egress:'+'a'*32)),
          dict(chain=dict(family='inet',table=u.TABLE,name='output',handle=2,type='filter',hook='output',prio=0,policy='accept'))]
    for i,(role,uid) in enumerate(u.TARGETS.items()):
        rows.append(dict(rule=dict(family='inet',table=u.TABLE,chain='output',handle=i+3,comment=role,
            expr=[{'match':{'op':'==','left':{'meta':{'key':'skuid'}},'right':uid}},
                  {'counter':{'packets':4,'bytes':100}}, {'reject':{'type':'icmpx','expr':3}}])))
    return dict(nftables=rows)


def test_all_actors_include_the_prior_five_plus_agent_executor_stranger():
    assert set(u.e.DENIED.values()) < set(u.TARGETS.values())
    assert set(u.TARGETS.values())==set(range(61101,61109))
    assert 0 not in u.TARGETS.values() and 109 not in u.TARGETS.values() and 61109 not in u.TARGETS.values()
    assert u.n.NATIVE==61101 and u.n.CUSTODY==61106 and u.n.BACKEND==61103
    assert u.sources()['native_os_custody']==u.N_PIN
    assert u.validate_policy(policy()) is True


@pytest.mark.parametrize('change',['uid','missing_rule','extra_rule','accept','wrong_chain','wrong_family','comment','negative_counter','handle_bool'])
def test_policy_changes_cannot_pass_as_full_eight_uid_rejection(change):
    doc=policy();r=doc['nftables'][2]['rule']
    if change=='uid':r['expr'][0]['match']['right']=0
    elif change=='missing_rule':doc['nftables'].pop()
    elif change=='extra_rule':doc['nftables'].append(copy.deepcopy(doc['nftables'][-1]))
    elif change=='accept':r['expr'][2]={'accept':None}
    elif change=='wrong_chain':r['chain']='input'
    elif change=='wrong_family':r['family']='ip'
    elif change=='comment':doc['nftables'][0]['table']['comment']='foreign'
    elif change=='negative_counter':r['expr'][1]['counter']['packets']=-1
    else:r['handle']=True
    with pytest.raises((ValueError,KeyError)):u.validate_policy(doc)


@pytest.mark.parametrize('token',['bad; delete table','a'*31,'a'*33,False])
def test_arbitrary_marker_cannot_enter_nft_batch(token):
    with pytest.raises(ValueError):u.rules(token)


def test_rehearsal_requires_ack_before_root_or_paths(monkeypatch):
    monkeypatch.setattr(u.e,'require_root',lambda:pytest.fail('root before ack'))
    with pytest.raises(ValueError):u.run(Path('/tmp/not-used'))


def flow(denied=True):
    row=dict(role='agent',uid=61101,gid=61101,version=4,protocol='tcp',
             effective_capabilities=0,no_new_privs=True,result='SOCKET_ERROR',errno=113,
             kernel_packets_before=2,kernel_packets_after=3)
    if not denied:
        row.update(result='SUCCESS',errno=None);del row['kernel_packets_before'];del row['kernel_packets_after']
    return row


@pytest.mark.parametrize('fault',['no_counter','wrong_uid','duplicates','success_as_denial'])
def test_errno_without_complete_uid_flow_and_kernel_counter_join_is_not_proof(fault):
    rows=[]
    for version,protocol in u.e.FLOWS:
        r=flow();r.update(version=version,protocol=protocol,errno=113 if version==4 else 13);rows.append(r)
    if fault=='no_counter':rows[0]['kernel_packets_after']=rows[0]['kernel_packets_before']
    elif fault=='wrong_uid':rows[0]['uid']=0
    elif fault=='duplicates':rows[-1]=rows[0]
    else:rows[0].update(result='SUCCESS',errno=None)
    with pytest.raises(ValueError):u.validate_flows(rows,dict(agent=61101),True)


def test_four_exact_counter_joined_flows_are_required():
    rows=[]
    for version,protocol in u.e.FLOWS:
        r=flow();r.update(version=version,protocol=protocol,errno=113 if version==4 else 13);rows.append(r)
    u.validate_flows(rows,dict(agent=61101),True)


def test_unix_adapter_rejects_arbitrary_method_before_opening_socket(monkeypatch):
    monkeypatch.setattr(u.n.kernel,'role_identity',lambda uid:None)
    monkeypatch.setattr(u.socket,'socket',lambda *a,**kw:pytest.fail('socket before method/path validation'))
    with pytest.raises(ValueError):u.unix_call(Path('/run/unused'),'DELETE','/anything',None,b'fixture')


def test_limits_do_not_claim_vm_provider_retained_ledger_or_bounded_history():
    limits=u.limitations()
    assert limits['real_provider_posts']==limits['external_bank_effects']==0
    assert limits['provider_dispatch']=='DENY' and limits['utility']=='UNSCORED'
    assert all(value is False for key,value in limits.items() if key not in
        ('real_provider_posts','external_bank_effects','provider_dispatch','utility'))
