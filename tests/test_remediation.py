import json,secrets,io,base64
from pathlib import Path
import httpx,pytest
from fastapi.testclient import TestClient
from PIL import Image
from recurrence.auth import LocalAuth,password_hash,COOKIE
from recurrence.config import Settings
from recurrence.history import HistoryStore
from recurrence.prometheus import TelemetryVerifier
from recurrence.safety import redact,sanitise_text
from recurrence.vision import validate_images
from app.server import create_app

@pytest.mark.parametrize('text,label',[('-----BEGIN PRIVATE KEY-----\nABCDEF\n-----END PRIVATE KEY-----','PRIVATE_KEY'),('eyJabcdefghi.abcdefghijk.abcdefghijk','TOKEN'),('xoxb-123456789012-abcdefghijk','API_KEY'),('github_pat_abcdefghijklmnopqrstuvwxyz1234','API_KEY'),('AWS_SECRET_ACCESS_KEY=reallysecret','API_KEY'),('"password": "supersecret"','PASSWORD'),('email user@example.com','PERSONAL_DATA'),('phone +1 415-555-1234','PERSONAL_DATA'),('Authorization: Bearer abcdef12345','TOKEN'),('postgres://alice:secret@db/app','PASSWORD')])
def test_redaction_categories(text,label):
 clean,findings=sanitise_text(text);assert '[REDACTED_'+label+']' in clean and findings
 assert redact(clean)==clean

def make(tmp_path):
 salt=secrets.token_hex(16);a=LocalAuth(True,'admin',salt,password_hash('admin-test-password',salt),secrets.token_hex(32),users_path=tmp_path/'users.json')
 a.add_user('viewer','viewer-test-password','viewer');a.add_user('responder','responder-test-password','responder')
 app=create_app(settings=Settings.from_env(offline=True),auth=a,history=HistoryStore(tmp_path/'history.json'))
 return TestClient(app),a,app

def login(c,name):
 password={'admin':'admin-test-password','viewer':'viewer-test-password','responder':'responder-test-password'}[name]
 r=c.post('/api/auth/login',json={'username':name,'password':password});assert r.status_code==200

def test_roles_backend_and_no_hash_leak(tmp_path):
 c,a,app=make(tmp_path);login(c,'viewer');assert c.post('/api/ask',json={'service':'s','engineer':'e','alert':'pool'}).status_code==403
 assert c.get('/api/investigations').status_code==200
 login(c,'responder');assert c.get('/api/admin/users').status_code==403
 login(c,'admin');assert c.post('/api/admin/users',json={'username':'new-user','password':'another-long-password','role':'viewer'}).status_code==200
 users=c.get('/api/admin/users').json();assert all(set(u)=={'username','role'} for u in users)
 assert c.post('/api/admin/users/admin/role',json={'role':'viewer'}).status_code==422
 assert 'another-long-password' not in (tmp_path/'users.json').read_text()

def test_review_binding_explicit_confirmation_and_changed_input(tmp_path):
 from recurrence.review import preview,approved
 c,a,app=make(tmp_path);login(c,'admin');body={'service':'orders','engineer':'e','alert':'timeout password=secret'}
 p=c.post('/api/evidence/preview',json={'scope':'/api/ask','payload':body}).json()
 assert 'secret' not in json.dumps(p['sanitised']) and p['redactions']
 assert approved(a,'admin','/api/ask',body,p['review_token'])
 assert not approved(a,'admin','/api/ask',{**body,'alert':'changed'},p['review_token'])
 assert not approved(a,'viewer','/api/ask',body,p['review_token'])
 app.state.require_review=True
 # Offline settings do not have API keys; production enforcement is exercised below with explicit settings.

def telemetry(values,status=200):
 def handler(request):
  assert request.method=='GET' and request.url.path=='/api/v1/query'
  if status!=200:return httpx.Response(status,json={'error':'no'})
  value=values.get(request.url.params['query'])
  return httpx.Response(200,json={'status':'success','data':{'resultType':'vector','result':[] if value is None else [{'value':[1,str(value)]}]}})
 return TelemetryVerifier('https://prom.example','secret',{'service_up':('up','>=',1),'error_rate':('errors','<=',0.01),'db_pool':('pool','<=',0.8)},httpx.Client(transport=httpx.MockTransport(handler)))

@pytest.mark.parametrize('values,status,expected',[({'up':1,'errors':.002,'pool':.5},200,'VERIFIED_BY_TELEMETRY'),({'up':1,'errors':.5,'pool':.5},200,'NOT_VERIFIED'),({'up':1,'errors':.002,'pool':.99},200,'NOT_VERIFIED'),({'up':None,'errors':.002,'pool':.5},200,'NOT_VERIFIED'),({},401,'NOT_VERIFIED')])
def test_readonly_prometheus(values,status,expected):
 v=telemetry(values,status);assert v.snapshot()['verification_status']==expected

def test_prometheus_unconfigured_timeout_malformed():
 assert TelemetryVerifier().snapshot()['verification_status']=='TELEMETRY_NOT_CONFIGURED'
 for handler in (lambda r:(_ for _ in ()).throw(httpx.ReadTimeout('timeout')),lambda r:httpx.Response(200,json={'bad':'data'})):
  v=TelemetryVerifier('https://prom.example',queries={'up':('up','>=',1)},client=httpx.Client(transport=httpx.MockTransport(handler)))
  assert v.snapshot()['verification_status']=='NOT_VERIFIED'

def test_three_images_and_aggregate():
 b=io.BytesIO();Image.new('RGB',(10,10)).save(b,format='PNG');u='data:image/png;base64,'+base64.b64encode(b.getvalue()).decode()
 result=validate_images([u,u,u]);assert len(result['items'])==3
 with pytest.raises(ValueError):validate_images([u]*4)

def test_first_run_admin_setup(tmp_path):
 a=LocalAuth(True,secret=secrets.token_hex(32),users_path=tmp_path/'users.json')
 c=TestClient(create_app(settings=Settings.from_env(offline=True),auth=a,history=HistoryStore(tmp_path/'h.json')))
 assert c.get('/api/auth/session').json()['setup_required']
 assert c.post('/api/auth/setup',json={'username':'first-admin','password':'a-long-new-password'}).status_code==200
 assert c.post('/api/auth/setup',json={'username':'attacker','password':'a-long-new-password'}).status_code==409
 assert c.post('/api/auth/login',json={'username':'first-admin','password':'a-long-new-password'}).status_code==200

@pytest.mark.parametrize('text,secret',[('Authorization: Basic dXNlcjpwYXNz','dXNlcjpwYXNz'),('"password": "my secret phrase"','my secret phrase'),('mobile=+919876543210','9876543210'),('-----BEGIN ENCRYPTED PRIVATE KEY-----\nSECRET\n-----END ENCRYPTED PRIVATE KEY-----','SECRET')])
def test_extended_context_secrets(text,secret):assert secret not in redact(text)

def test_review_http_gate_blocks_changed_evidence(tmp_path):
 from dataclasses import replace
 from recurrence.agent import RecurrenceAgent
 from recurrence.memory import FakeMemory
 from tests.test_incidentiq import ReasoningLLM
 c,a,offlineapp=make(tmp_path)
 class Mem(FakeMemory):name='hindsight'
 class LLM(ReasoningLLM):
  def run(self,*args):
   from tests.test_incidentiq import REPORT
   report=json.loads(json.dumps(REPORT));report['ai_reasoning'][0]['historical_source_ids']=[];return json.dumps(report),[]
 settings=replace(Settings.from_env(offline=False),groq_api_key='test-key',hindsight_api_key='test-key')
 app=create_app(settings=settings,agent=RecurrenceAgent(Mem(),LLM([])),auth=a,history=HistoryStore(tmp_path/'live.json'));c=TestClient(app);login(c,'admin')
 body={'service':'s','engineer':'e','alert':'pool password=private'}
 assert c.post('/api/ask',json=body).status_code==422
 p=c.post('/api/evidence/preview',json={'scope':'/api/ask','payload':body}).json()
 assert c.post('/api/ask',json={**body,'alert':'changed','review_token':p['review_token']}).status_code==422
 assert c.post('/api/ask',json={**body,'review_token':p['review_token']}).status_code==200
 assert 'private' not in (tmp_path/'live.json').read_text()

def test_mixed_sdk_retain_recall_concurrency_and_cleanup():
 import threading
 from concurrent.futures import ThreadPoolExecutor
 from types import SimpleNamespace
 from recurrence.memory import HindsightMemory
 class SDK:
  def __init__(self):self.calls=[]
  def retain(self,**kw):self.calls.append(('retain',threading.get_ident()))
  def recall(self,**kw):self.calls.append(('recall',threading.get_ident()));return SimpleNamespace(results=[])
  def close(self):self.calls.append(('close',threading.get_ident()))
 sdk=SDK();memory=HindsightMemory('https://example.invalid','test-bank',client=sdk)
 with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(lambda n:memory.retain('synthetic') if n%2 else memory.recall('synthetic'),range(20)))
 memory.close()
 assert {kind for kind,_ in sdk.calls}=={'retain','recall','close'} and len({thread for _,thread in sdk.calls})==1
 assert all(not thread.is_alive() for thread in memory._executor._threads)


def test_nested_structured_secret_keys():
 clean=redact({'service':'orders','nested':{'password':'shortsecret','groq_api_key':'opaque','authorization':'opaque'},'facts':[{'access_token':'opaque'}]})
 assert clean['service']=='orders'
 assert 'shortsecret' not in json.dumps(clean) and 'opaque' not in json.dumps(clean)
 assert clean['nested']['password']=='[REDACTED_PASSWORD]'

def test_configured_telemetry_is_unverified_until_queried():
 v=TelemetryVerifier('https://prom.example',queries={'up':('up','>=',1)})
 assert v.last['verification_status']=='NOT_VERIFIED' and v.last['checked_at'] is None

def test_setup_operator_updates_existing_account(tmp_path,monkeypatch):
 from scripts import setup_operator
 a=LocalAuth(secret=secrets.token_hex(32),users_path=tmp_path/'data/users.json')
 a.add_user('operator','original-password','admin');a.add_user('reader','reader-password','viewer')
 answers=iter(['operator']);passwords=iter(['replacement-password','replacement-password'])
 monkeypatch.setattr('builtins.input',lambda _:next(answers));monkeypatch.setattr(setup_operator,'getpass',lambda _:next(passwords))
 setup_operator.main(tmp_path)
 b=LocalAuth(secret=secrets.token_hex(32),users_path=tmp_path/'data/users.json')
 assert b.check_password('operator','replacement-password')
 assert not b.check_password('operator','original-password')
 assert b.check_password('reader','reader-password')


def test_demo_metrics_cannot_verify_production_recovery():
 v=telemetry({'up':1,'errors':.002,'pool':.35});v.demo=True
 result=v.snapshot()
 assert result['demo_checks_passed'] is True
 assert result['verification_status']=='NOT_VERIFIED' and result['demo'] is True


def test_offline_app_does_not_connect_to_configured_demo_telemetry(tmp_path):
 c,a,app=make(tmp_path)
 assert app.state.verifier.url==''
 assert app.state.verifier.snapshot()['verification_status']=='TELEMETRY_NOT_CONFIGURED'
