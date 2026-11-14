import hashlib
import json
import secrets
import time
from dataclasses import replace
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi.testclient import TestClient
from app.server import create_app
from recurrence.auth import LocalAuth,COOKIE,password_hash
from recurrence.config import Settings
from recurrence.agent import RecurrenceAgent
from recurrence.history import HistoryStore
from recurrence.memory import FakeMemory,MemoryHit
from recurrence.llm import OfflineLLM
from recurrence.validation import validate_hits
from tests.test_incidentiq import ReasoningLLM


def operator(path=None):
    salt=secrets.token_hex(16)
    return LocalAuth(True,'qa-operator',salt,password_hash('test-only-long-password',salt),secrets.token_hex(32),path)


def client(tmp_path,auth=None):
    return TestClient(create_app(settings=Settings.from_env(offline=True),auth=auth or operator(),history=HistoryStore(tmp_path/'history.json')))


def login(c):return c.post('/api/auth/login',json={'username':'qa-operator','password':'test-only-long-password'})


def test_login_logout_protection_and_cookie(tmp_path):
    c=client(tmp_path)
    assert c.get('/api/investigations').status_code==401
    assert c.get('/',follow_redirects=False).status_code==303
    assert c.post('/api/auth/login',json={'username':'qa-operator','password':'wrong'}).status_code==401
    r=login(c);assert r.status_code==200
    cookie=r.headers['set-cookie'].lower()
    assert 'httponly' in cookie and 'samesite=strict' in cookie and 'max-age=28800' in cookie
    token=c.cookies.get(COOKIE)
    assert c.get('/api/auth/session').json()['authenticated']
    assert c.get('/api/dashboard').status_code==200
    assert c.get('/').status_code==200  # Refresh retains the cookie.
    assert c.post('/api/auth/logout').status_code==200
    assert c.get('/api/investigations').status_code==401
    c.cookies.set(COOKIE,token)
    assert c.get('/api/investigations').status_code==401


def test_missing_auth_setup_expiry_tamper_and_rate_limit(tmp_path,monkeypatch):
    c=client(tmp_path,LocalAuth(True))
    assert c.get('/api/auth/session').json()['setup_required']
    assert login(c).status_code==503
    a=operator();token=a.issue();assert a.verify(token)
    assert not a.verify(token+'tamper')
    current=time.time();monkeypatch.setattr('recurrence.auth.time.time',lambda:current+28801)
    assert not a.verify(token)
    c=client(tmp_path/'rate');
    for _ in range(5):assert c.post('/api/auth/login',json={'username':'x','password':'x'}).status_code==401
    assert login(c).status_code==429


def test_revocation_and_session_survive_new_auth_instance(tmp_path):
    path=tmp_path/'revoked.json';a=operator(path);token=a.issue()
    fresh=LocalAuth(True,a.username,a.salt,a.digest,a.secret,path)
    assert fresh.verify(token)
    a.revoke(token)
    assert not fresh.verify(token)
    assert (path.stat().st_mode & 0o777)==0o600


def test_cross_origin_post_rejected(tmp_path):
    c=client(tmp_path);login(c)
    assert c.post('/api/providers/check',json={},headers={'Origin':'https://evil.example'}).status_code==403


def test_atomic_history_search_resolution_and_restart(tmp_path):
    c=client(tmp_path);login(c)
    assert c.get('/api/dashboard').json()['metrics']['total']==0
    r=c.post('/api/ask',json={'service':'orders','engineer':'e','alert':'pool exhausted password=do-not-save','environment':'production','severity':'SEV2'});assert r.status_code==200
    ident=r.json()['conversation_id']
    assert c.get('/api/dashboard').json()['metrics']['total']==1
    assert c.get('/api/investigations',params={'q':'orders','status':'open','severity':'SEV2'}).json()[0]['id']==ident
    assert c.get('/api/investigations',params={'q':'no-match'}).json()==[]
    r=c.post('/api/resolve',json={'conversation_id':ident,'service':'orders','environment':'production','engineer':'e','summary':'pool','root_cause':'leak','fix':'cleanup','outcome':'recovered','verified':True})
    assert r.status_code==200
    assert c.get('/api/dashboard').json()['metrics']['resolved']==1
    fresh=HistoryStore(tmp_path/'history.json');saved=fresh.get(ident)
    assert saved['status']=='resolved' and len(saved['events'])==2
    assert 'do-not-save' not in (tmp_path/'history.json').read_text()
    assert 'report' in saved['result']


def test_history_atomic_concurrent_updates_and_corruption(tmp_path):
    h=HistoryStore(tmp_path/'h.json');r={'understanding':{'incident_summary':'pool','error_signatures':['idle=0']},'memories':[]}
    with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(lambda i:h.save_investigation(str(i),{'service':'s'},r),range(12)))
    assert h.metrics()['total']==12
    h.path.write_text('{invalid')
    with pytest.raises(json.JSONDecodeError):h.save_investigation('bad',{'service':'s'},r)
    assert h.path.read_text()=='{invalid'


def test_unverified_classes_excluded_and_cross_service_verified_analogy():
    hits=[MemoryHit(text='pool',id=k,metadata={'kind':k,'service':'orders','environment':'production','status':'unverified'}) for k in ['incident_intake','investigation_advice']]
    rows=validate_hits(hits,'orders','production',allow_cross_service=True)
    assert all(not r['validation']['eligible_for_reasoning'] for r in rows)
    hit=MemoryHit(text='pool fixed',id='fact',metadata={'kind':'incident','service':'other','environment':'production','status':'verified'})
    r=validate_hits([hit],'orders','production',allow_cross_service=True)[0]
    assert r['validation']['eligible_for_reasoning'] and r['validation']['service_relevance']=='different'


def test_intake_and_advice_retained_only_after_recall_and_report():
    events=[]
    class CloudStandin(FakeMemory):
        name='hindsight'
        def recall(self,*a,**k):events.append('recall');return super().recall(*a,**k)
        def retain_many(self,items):events.append('retain');super().retain_many(items)
    m=CloudStandin();llm=ReasoningLLM(events);a=RecurrenceAgent(m,llm)
    a.resolve('orders','e','pool idle=0','leak','cleanup',incident_id='INC-QA',environment='production',outcome='recovered');events.clear()
    result=a.answer('pool idle=0','e','orders',environment='production',conversation_id='IQ-test')
    assert result['report']
    assert events.index('understand')<events.index('recall')<events.index('reason')<events.index('retain')
    assert {x['metadata']['kind'] for x in m.items[-2:]}=={'incident_intake','investigation_advice'}
    assert all(x['metadata']['status']=='unverified' for x in m.items[-2:])
    assert result['retention']=={'intake':'retained','advice':'retained'}


def test_cache_ttl_force_refresh_and_scope(monkeypatch):
    from tests.test_incidentiq import REPORT
    class NoCitations(ReasoningLLM):
        def run(self,*args):
            r=json.loads(json.dumps(REPORT));r['ai_reasoning'][0]['historical_source_ids']=[]
            return json.dumps(r),[]
    m=FakeMemory();a=RecurrenceAgent(m,NoCitations([]))
    a.answer('pool','e','orders',force_refresh=False)
    before=len([x for x in m.calls if x[0]=='recall' and 'preferences' not in x[1]['query']])
    result=a.answer('pool','e','orders',force_refresh=False)
    assert all(x['cached'] for x in result['retrieval_events'])
    result=a.answer('pool','e','orders',force_refresh=True)
    assert all(not x['cached'] for x in result['retrieval_events'])
    for key,(t,hits) in list(a._cache.items()):a._cache[key]=(t-61,hits)
    result=a.answer('pool','e','orders',force_refresh=False)
    assert all(not x['cached'] for x in result['retrieval_events'])
    result=a.answer('pool','e','orders',environment='staging',force_refresh=False)
    assert all(not x['cached'] for x in result['retrieval_events'])


def test_provider_unknown_is_not_fabricated(tmp_path):
    c=client(tmp_path);login(c);p=c.get('/api/providers').json()
    assert p['hindsight']['status']=='unknown' and p['groq']['status']=='unknown'
    assert p['hindsight']['last_duration_ms'] is None


def test_merge_deduplicates_ids_and_documents_preserving_source_ids():
    from recurrence.validation import merge_hits
    a=MemoryHit(text='pool exhausted',id='fact-a',document_id='INC-1',metadata={'kind':'incident'})
    b=MemoryHit(text='cleanup fixed it',id='fact-b',document_id='INC-1',metadata={'kind':'incident'})
    rows=merge_hits([a,a,b])
    assert len(rows)==1 and rows[0].source_ids==['fact-a','fact-b']
    assert 'pool exhausted' in rows[0].text and 'cleanup fixed it' in rows[0].text
    assert a.text=='pool exhausted'  # Backend/cache records remain immutable.


def test_live_request_retained_even_when_historical_recall_disabled():
    from tests.test_incidentiq import REPORT
    class CloudStandin(FakeMemory):name='hindsight'
    class LLM(ReasoningLLM):
        def run(self,*args):
            r=json.loads(json.dumps(REPORT));r['ai_reasoning'][0]['historical_source_ids']=[]
            return json.dumps(r),[]
    mem=CloudStandin();result=RecurrenceAgent(mem,LLM([])).answer('pool timeout','e','orders',memory_on=False)
    assert not any(call[0]=='recall' for call in mem.calls)
    assert result['retention']=={'intake':'retained','advice':'retained'}
    assert {x['metadata']['kind'] for x in mem.items}=={'incident_intake','investigation_advice'}


def test_workspace_memory_search_cache_and_force_refresh(tmp_path):
    c=client(tmp_path);login(c)
    first=c.post('/api/memory/search',json={'question':'database pool'}).json()
    second=c.post('/api/memory/search',json={'question':'database pool'}).json()
    fresh=c.post('/api/memory/search',json={'question':'database pool','force_refresh':True}).json()
    assert first['cached'] is False and second['cached'] is True and fresh['cached'] is False
    assert first['memories']==second['memories']
