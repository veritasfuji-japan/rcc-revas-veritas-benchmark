"""Portable transport/admission negatives; actual root proof is mandatory in CI."""
from pathlib import Path
import socket
import ssl

import pytest
from scripts import task4_native_bounded_unix_egress_v1 as m


def test_frozen_authority_and_existing_profiles_are_unchanged():
    pins=m.sources()['frozen']
    assert len(pins)==15 and pins==m.FROZEN
    assert pins['task4_native_os_custody_v1']==m.u.N_PIN
    assert m.b.RUNTIME==61108 and m.n.NATIVE==61101 and m.signed.LEDGER==61109


def test_ack_is_required_before_root_or_output(monkeypatch):
    monkeypatch.setattr(m.e,'require_root',lambda:pytest.fail('before ack'))
    with pytest.raises(ValueError):m.run(Path('/tmp/unused'))


@pytest.mark.parametrize('component',['signed','retained'])
def test_existing_deployment_refuses_before_output_or_tools(monkeypatch,component):
    monkeypatch.setattr(m.e,'require_root',lambda:None)
    monkeypatch.setattr(getattr(m,component),'required',lambda:True)
    monkeypatch.setattr(m.e,'tools',lambda:pytest.fail('tools before collision refusal'))
    with pytest.raises(ValueError):m.run(Path('/tmp/unused'),acknowledge=True)


@pytest.mark.parametrize('method,path,body',[('POST','/effect',None),('DELETE','/status/A0',None),('GET','/unrelated',None),('GET','/status/A0',{})])
def test_status_transport_only_permits_read_only_shape(monkeypatch,method,path,body):
    monkeypatch.setattr(m,'connection',lambda _:pytest.fail('socket before shape'))
    with pytest.raises(ValueError):m.status_call(Path('/unused'),method,path,body,b'test')


class Raw:
    def __init__(self):self.closed=False;self.address=None
    def settimeout(self,value):assert value==5
    def connect(self,path):self.address=path
    def close(self):self.closed=True


class Channel(Raw):
    def getpeercert(self,binary_form):assert binary_form;return b'leaf'


class Context:
    verify_mode=ssl.CERT_REQUIRED
    check_hostname=True
    def __init__(self):self.wraps=[];self.channel=Channel()
    def wrap_socket(self,raw,server_hostname):
        assert server_hostname==m.tls.NAME
        self.wraps.append(raw);return self.channel


@pytest.mark.parametrize('fault',['none','wrong_uid','wrong_pin','connect_error','bad_ca','no_hostname'])
def test_unix_transport_no_ip_fallback_and_pins_before_use(monkeypatch,fault):
    raw=Raw();context=Context();families=[]
    monkeypatch.setattr(m,'fixture',lambda _:None)
    monkeypatch.setattr(m.n.kernel,'role_identity',lambda uid:None)
    monkeypatch.setattr(m.ssl,'create_default_context',lambda **_:context)
    monkeypatch.setattr(m.u,'peer_uid',lambda _:61104 if fault=='wrong_uid' else m.n.BACKEND)
    monkeypatch.setattr(m.ingress,'plan',lambda _:dict(leaf_sha256=m.e.sha(b'wrong' if fault=='wrong_pin' else b'leaf')))
    def create(family,kind):
        families.append(family);assert family==socket.AF_UNIX and kind==socket.SOCK_STREAM;return raw
    monkeypatch.setattr(m.socket,'socket',create)
    monkeypatch.setattr(m.socket,'getaddrinfo',lambda *a,**k:pytest.fail('DNS attempted'))
    if fault=='connect_error':
        def fail(_):raise ConnectionRefusedError()
        raw.connect=fail
    if fault=='bad_ca':
        def fail(*a,**k):raise ssl.SSLCertVerificationError()
        context.wrap_socket=fail
    if fault=='no_hostname':context.check_hostname=False
    if fault=='none':
        conn=m.connection(Path('/unused'));conn.connect()
        assert conn.sock is context.channel and raw.address.endswith('/backend-ipc/service.sock')
        assert conn.default_port==443 and context.minimum_version==ssl.TLSVersion.TLSv1_2
        assert families==[socket.AF_UNIX]
    else:
        with pytest.raises((ValueError,OSError)):m.connection(Path('/unused')).connect()
        assert families==([] if fault=='no_hostname' else [socket.AF_UNIX])
        if fault!='no_hostname':assert raw.closed
        if fault=='wrong_uid':assert context.wraps==[]
        if fault=='wrong_pin':assert context.channel.closed


def test_transport_installation_does_not_replace_authority_or_bind(monkeypatch):
    original=(m.n.verify,m.b.verify_packet,m.b.consume_packet,m.n.bind_post,m.b.native,m.signed.gate)
    monkeypatch.setattr(m,'fixture',lambda _:None)
    with monkeypatch.context() as patch:
        patch.setattr(m.tls,'call',m.tls.call);patch.setattr(m.tls,'server_class',m.tls.server_class)
        patch.setattr(m.ingress,'dispatch',m.ingress.dispatch)
        m.install_transport(Path('/unused'))
        assert m.tls.call is m.status_call and m.tls.server_class is m.server_class and m.ingress.dispatch is m.dispatch
        assert original==(m.n.verify,m.b.verify_packet,m.b.consume_packet,m.n.bind_post,m.b.native,m.signed.gate)


def test_limitations_exclude_live_operator_remote_provider_and_host_claims():
    limits=m.limitations()
    assert limits['provider_dispatch']=='DENY' and limits['utility']=='UNSCORED'
    assert limits['real_provider_posts']==limits['external_bank_effects']==0
    assert all(value is False for key,value in limits.items() if key not in
               ('provider_dispatch','utility','real_provider_posts','external_bank_effects'))
