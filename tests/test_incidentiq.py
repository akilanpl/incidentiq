import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient
from app.server import create_app
from recurrence.agent import RecurrenceAgent
from recurrence.config import Settings, build_llm
from recurrence.llm import GroqLLM, LLMUnavailable, MissingLLM, OfflineLLM
from recurrence.memory import FakeMemory, MemoryHit
from recurrence.safety import redact, safe_error
from recurrence.understanding import Understanding
from recurrence.validation import validate_hits

REPORT = {'ai_reasoning': [{'hypothesis': 'Pool saturation', 'confidence': 'medium', 'supporting_evidence': ['idle=0'],
    'historical_source_ids': ['INC-QA'], 'similarities': ['pool exhausted'], 'differences': ['new deployment'],
    'uncertainty': 'Need session metrics', 'basis': 'historical evidence and current evidence'}],
    'recommended_investigation': [{'priority': 1, 'check': 'Inspect active sessions', 'expected_observation': 'Leaked idle sessions',
       'safe_remediation': 'Review connection cleanup patch', 'risk_or_impact': 'Deployment risk', 'verification_required': 'Pool and errors recover'}],
    'failed_approaches': ['restart'], 'missing_evidence': ['session metrics'], 'resolution_verification': ['pool baseline']}


class ReasoningLLM:
    name = 'groq'

    def __init__(self, events):
        self.events = events
        self.messages = None

    def understand(self, system, payload, schema):
        self.events.append('understand')
        assert 'gsk_' not in json.dumps(payload)
        return Understanding(incident_summary='Pool timeout', service='orders', environment='production',
            error_signatures=['idle=0'], known_facts=['Pool has no idle connections'],
            suspected_causes=['session leak'], retrieval_queries=['orders database pool exhaustion; verified fixes and failed attempts']).model_dump()

    def run(self, messages, tools, execute):
        self.events.append('reason')
        self.messages = messages
        return json.dumps(REPORT), []


class OrderedMemory(FakeMemory):
    def __init__(self, events):
        super().__init__()
        self.events = events

    def recall(self, query, **kwargs):
        self.events.append('recall')
        return super().recall(query, **kwargs)


def test_understand_before_targeted_recall_and_grounded_report():
    events = []
    mem = OrderedMemory(events)
    llm = ReasoningLLM(events)
    agent = RecurrenceAgent(mem, llm)
    agent.resolve('orders', 'engineer', 'pool exhausted idle=0', 'session leak', 'finally cleanup', 'restart', 'INC-QA',
                  environment='production', outcome='pool recovered')
    out = agent.answer('idle=0 password=secret gsk_abcdefghijklmnop', 'engineer', 'orders', environment='production')
    assert events[0] == 'understand' and events.index('recall') < events.index('reason')
    query = next(c[1]['query'] for c in mem.calls if c[0] == 'recall')
    assert query != 'idle=0 password=secret gsk_abcdefghijklmnop' and 'verified fixes' in query
    assert out['report']['ai_reasoning'][0]['historical_source_ids'] == ['INC-QA']
    assert out['understanding_source'] == 'groq'
    assert out['memories'][0]['validation']['resolution_status'] == 'verified'
    assert 'gsk_' not in json.dumps(mem.items) + json.dumps(llm.messages) + json.dumps(out)
    assert llm.messages[0]['content'].startswith('You are IncidentIQ')
    assert 'Root cause: session leak' in llm.messages[1]['content']


def test_relevance_validation_dedup_advice_and_staleness():
    now = datetime(2026, 11, 14, tzinfo=timezone.utc)
    good = MemoryHit(text='verified fix', id='actual-id', document_id='INC-QA', metadata={'kind':'incident','status':'verified','service':'orders','environment':'production'}, occurred_at='2026-11-10T00:00:00Z')
    wrong = MemoryHit(text='staging fix', id='staging', metadata={'service':'orders','environment':'staging'})
    advice = MemoryHit(text='restart', id='advice', metadata={'kind':'advice','service':'orders'})
    old = MemoryHit(text='old fix', id='old', occurred_at='2025-01-01T00:00:00Z')
    rows = validate_hits([good,good,wrong,advice,old], 'orders','production',now)
    assert len(rows) == 4 and rows[0]['hit'].id == 'actual-id'
    assert rows[0]['validation']['resolution_status'] == 'verified'
    assert not rows[1]['validation']['eligible_for_reasoning']
    assert not rows[2]['validation']['eligible_for_reasoning']
    assert any('90 days' in x for x in rows[3]['validation']['warnings'])


@pytest.mark.parametrize('secret', ['Authorization: Bearer abcdef123456', 'password=hunter2', 'postgresql://user:secret@db/app',
    'api_key="sensitive"', 'gsk_abcdefghijklmnopqrstuv', 'AKIA1234567890ABCDEF'])
def test_redaction(secret):
    result=redact({'logs': [secret]})
    assert '[REDACTED_' in result['logs'][0] and result['logs'][0] != secret


def test_missing_live_key_never_uses_offline_template(monkeypatch):
    monkeypatch.delenv('GROQ_API_KEY', raising=False)
    s=Settings.from_env(offline=False)
    assert isinstance(build_llm(s), MissingLLM)
    with pytest.raises(LLMUnavailable): build_llm(s).run([],None,None)


def test_feedback_requires_engineer_verification_and_real_outcome():
    c=TestClient(create_app(settings=Settings.from_env(offline=True)))
    body={'service':'orders','engineer':'oncall','summary':'pool timeout','root_cause':'leak','fix':'cleanup'}
    assert c.post('/api/resolve',json=body).status_code == 422
    assert c.post('/api/resolve',json={**body,'outcome':'recovered'}).status_code == 422
    response=c.post('/api/resolve',json={**body,'outcome':'pool and errors baseline','verified':True})
    assert response.status_code == 200 and response.json()['backend'] == 'fake-offline'


def test_malformed_understanding_retries_json_schema():
    client=MagicMock()
    def response(content): return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content,tool_calls=[]))])
    client.chat.completions.create.side_effect=[response('not json'),response(json.dumps(Understanding(incident_summary='pool',retrieval_queries=['previous pool failures']).model_dump()))]
    llm=GroqLLM('key','url','model',client=client)
    assert llm.understand('extract',{'evidence':'pool'},Understanding.model_json_schema())['incident_summary']=='pool'
    assert client.chat.completions.create.call_count == 2


def test_failed_understanding_skips_raw_incident_retrieval():
    class BadUnderstanding(ReasoningLLM):
        def understand(self,*args): raise ValueError('bad JSON')
    mem=FakeMemory(); llm=BadUnderstanding([])
    out=RecurrenceAgent(mem,llm).answer('pool raw sensitive logs','e','orders')
    assert out['understanding_source']=='unavailable'
    assert not any(c[0]=='recall' and 'pool raw sensitive logs' in c[1]['query'] for c in mem.calls)
    assert out['report'] is None  # Report cites INC-QA without any source: reject.
    assert not mem.items  # No invalid advice learned.


def test_memory_write_redacts_all_feedback_fields():
    mem=FakeMemory();a=RecurrenceAgent(mem,OfflineLLM())
    a.resolve('orders','e','password=oops','api_key=bad','postgres://user:pass@db/a', notes='Bearer abc12345', outcome='Recovered')
    stored=json.dumps(mem.items)
    assert 'oops' not in stored and 'user:pass' not in stored and 'abc12345' not in stored
    assert mem.items[0]['metadata']['status']=='verified'


def test_sdk_error_body_not_exposed():
    error=RuntimeError('401 Bearer super-secret-key request headers')
    assert 'super-secret' not in safe_error(error) and '401' in safe_error(error)


def test_real_memory_ids_and_sync_retention_are_preserved():
    from recurrence.memory import HindsightMemory
    from unittest.mock import create_autospec
    from hindsight_client import Hindsight
    client=create_autospec(Hindsight,instance=True)
    client.recall.return_value=SimpleNamespace(results=[SimpleNamespace(id='cloud-fact-id',text='original fact',type='world',occurred_start=None,mentioned_at=None,tags=['service:orders'],context='source context',document_id='INC-QA',metadata={'status':'verified'})])
    m=HindsightMemory('https://api.hindsight.vectorize.io','incidentiq-sre',client=client)
    m.retain('password=do-not-store')
    assert client.retain.call_args.kwargs['retain_async'] is False
    assert 'do-not-store' not in client.retain.call_args.kwargs['content']
    m.retain_many([{'content':'password=secret'}])
    assert client.retain_batch.call_args.kwargs['retain_async'] is False
    hit=m.recall('pool')[0]
    assert hit.id=='cloud-fact-id' and hit.context=='source context' and hit.document_id=='INC-QA'
    m.ensure_bank()
    assert client.update_bank_config.call_args.kwargs['disposition_skepticism']==4


def test_bank_auth_failure_is_not_swallowed():
    from recurrence.memory import HindsightMemory
    c=MagicMock();c.create_bank.side_effect=RuntimeError('401 secret-header')
    with pytest.raises(RuntimeError,match='401') as error:
        HindsightMemory('url','bank',client=c).ensure_bank()
    assert 'secret-header' not in str(error.value)


def test_live_api_missing_credentials_returns_503_without_substitution(monkeypatch):
    from dataclasses import replace
    s=replace(Settings.from_env(offline=False),hindsight_api_key=None,groq_api_key=None)
    a=RecurrenceAgent(FakeMemory(),MissingLLM())
    from recurrence.auth import LocalAuth
    c=TestClient(create_app(agent=a,settings=s,auth=LocalAuth(enabled=False)))
    assert c.post('/api/ask',json={'service':'orders','engineer':'e','alert':'pool exhausted'}).status_code==503
    assert c.post('/api/patterns',json={'question':'pool exhausted'}).status_code==503
    assert not a.memory.items


def test_sdk_calls_and_cleanup_share_one_thread_under_concurrency():
    from recurrence.memory import HindsightMemory
    from concurrent.futures import ThreadPoolExecutor
    import threading
    class ThreadBoundSDK:
        def __init__(self): self.threads=[]
        def recall(self,**kwargs):
            self.threads.append(threading.get_ident())
            return SimpleNamespace(results=[])
        def close(self): self.threads.append(threading.get_ident())
    client=ThreadBoundSDK();mem=HindsightMemory('url','bank',client=client)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _:mem.recall('pool'),range(8)))
    mem.close()
    assert len(set(client.threads))==1
    with pytest.raises(RuntimeError,match='closed'):mem.recall('pool')


def test_report_with_unknown_citation_is_repaired_once():
    class RepairLLM(ReasoningLLM):
        def __init__(self): super().__init__([]);self.calls=0
        def run(self,messages,tools,execute):
            self.calls+=1
            result=json.loads(json.dumps(REPORT))
            result['ai_reasoning'][0]['historical_source_ids']=['INVENTED'] if self.calls==1 else []
            return json.dumps(result),[]
    llm=RepairLLM();mem=FakeMemory()
    out=RecurrenceAgent(mem,llm).answer('pool timeout idle=0','e','orders')
    assert llm.calls==2 and out['report']
    assert out['report']['ai_reasoning'][0]['historical_source_ids']==[]
    assert out['tool_trace'][0]['event']=='report_repair_attempt'
