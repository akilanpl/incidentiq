"""FastAPI app: JSON API + a single-page console at /.

Run:  uvicorn app.server:app --reload --port 8000
Offline (no keys, fake memory, template answers):  RECURRENCE_OFFLINE=1 uvicorn app.server:app
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4
from contextlib import asynccontextmanager
from recurrence.safety import safe_error
from pathlib import Path
import os
from time import perf_counter
from urllib.parse import urlparse
from fastapi.responses import JSONResponse, RedirectResponse
from recurrence.auth import LocalAuth, COOKIE, TTL
from recurrence.history import HistoryStore
from recurrence.prometheus import TelemetryVerifier
from recurrence.review import preview as evidence_preview,approved
from recurrence.vision import validate_images,image_metadata
from recurrence.safety import redact

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from recurrence.agent import RecurrenceAgent
from recurrence.config import Settings, build_llm, build_memory
from recurrence.seed import load_data, seed

STATIC = Path(__file__).parent / "static"


class AskIn(BaseModel):
    alert: str = Field(default="", max_length=60000)
    image_data: str | None = Field(default=None,max_length=7000100)
    image_reviewed: bool = False
    images: list[str] = Field(default_factory=list,max_length=3)
    review_token: str | None = None
    engineer: str = Field(min_length=1, max_length=120)
    service: str = Field(min_length=1, max_length=120)
    environment: str = Field(default="", max_length=120)
    severity: str = Field(default="", max_length=40)
    memory_on: bool = True
    force_refresh: bool = True
    now: str | None = None  # ISO time; lets the demo replay "today" deterministically


class ResolveIn(BaseModel):
    service: str = Field(min_length=1, max_length=120)
    engineer: str = Field(min_length=1, max_length=120)
    summary: str = Field(min_length=1, max_length=10000)
    root_cause: str = Field(min_length=1, max_length=10000)
    fix: str = Field(min_length=1, max_length=10000)
    did_not_work: str = Field(default="", max_length=10000)
    incident_id: str | None = Field(default=None, max_length=120)
    environment: str = Field(default="", max_length=120)
    severity: str = Field(default="", max_length=40)
    outcome: str = Field(min_length=1, max_length=10000)
    notes: str = Field(default="", max_length=10000)
    error_signature: str = Field(default="", max_length=3000)
    verified: bool = False
    conversation_id: str | None = None
    review_token: str | None = None


class PrefIn(BaseModel):
    engineer: str = Field(min_length=1, max_length=120)
    text: str = Field(min_length=3, max_length=3000)


class PatternIn(BaseModel):
    question: str = Field(min_length=3, max_length=3000)
    force_refresh: bool = False


class LoginIn(BaseModel):
    username: str = Field(min_length=1,max_length=120)
    password: str = Field(min_length=1,max_length=1024)


class PreviewIn(BaseModel):
    scope:str
    payload:dict
class UserIn(BaseModel):
    username:str=Field(min_length=1,max_length=120)
    password:str=Field(min_length=12,max_length=1024)
    role:str
class RoleIn(BaseModel):
    role:str

def create_app(agent: RecurrenceAgent | None = None, settings: Settings | None = None, auth=None, history=None) -> FastAPI:
    settings = settings or Settings.from_env()
    auth = auth or LocalAuth.from_env(offline=settings.offline)
    history = history or HistoryStore(Path(os.getenv('INCIDENTIQ_HISTORY_PATH', str(Path(__file__).resolve().parent.parent / 'data' / ('investigations-offline.json' if settings.offline else 'investigations.json')))))
    if agent is None:
        agent = RecurrenceAgent(build_memory(settings), build_llm(settings))
        if settings.offline:
            seed(agent.memory)  # offline fake memory starts empty every run
    @asynccontextmanager
    async def lifespan(app):
        yield
        if hasattr(agent.memory, "aclose"):
            await agent.memory.aclose()
        elif hasattr(agent.memory, "close"):
            agent.memory.close()
        if hasattr(agent.llm, "client"):
            agent.llm.client.close()

    app = FastAPI(title="IncidentIQ", version="1.0.0", lifespan=lifespan)
    @app.exception_handler(RequestValidationError)
    async def safe_validation(request,exc):
        return JSONResponse({'detail':[{'loc':e['loc'],'msg':e['msg'],'type':e['type']} for e in exc.errors()]},status_code=422)

    verifier=TelemetryVerifier.from_env()
    app.state.verifier=verifier
    app.state.require_review=not settings.offline
    app.state.agent = agent
    app.state.auth = auth
    app.state.history = history

    @app.middleware('http')
    async def protect(request,call_next):
        if request.headers.get('content-length','').isdigit() and int(request.headers['content-length'])>15*1024*1024:
            return JSONResponse({'detail':'Request exceeds the upload size limit'},status_code=413)
        public=request.url.path in ('/login','/api/auth/login','/api/auth/session','/api/auth/logout','/api/auth/setup','/health') or (request.url.path.startswith('/static/') and not request.url.path.endswith('.html'))
        operator=auth.verify(request.cookies.get(COOKIE)) if auth.enabled else {'user':'Local offline operator','role':'admin'}
        request.state.operator=operator
        if auth.enabled and not public and not operator:
            if request.url.path.startswith('/api/'):
                return JSONResponse({'detail':'Authentication required'},status_code=401)
            return RedirectResponse('/login',status_code=303)
        if auth.enabled and request.method in ('POST','PUT','DELETE','PATCH'):
            origin=request.headers.get('origin')
            if origin and (urlparse(origin).netloc != request.url.netloc or urlparse(origin).scheme != request.url.scheme):
                return JSONResponse({'detail':'Cross-origin request rejected'},status_code=403)
        path=request.url.path
        if operator and path.startswith('/api/admin') and operator['role']!='admin':
            return JSONResponse({'detail':'Administrator role required'},status_code=403)
        if operator and operator['role']=='viewer' and request.method!='GET' and path not in ('/api/auth/logout','/api/auth/login'):
            return JSONResponse({'detail':'Viewer role is read-only'},status_code=403)
        if app.state.require_review and request.method=='POST' and path in ('/api/ask','/api/resolve','/api/preference','/api/patterns','/api/memory/search') and settings.groq_api_key and settings.hindsight_api_key:
            body=await request.json()
            if not operator or not approved(auth,operator['user'],path,body,body.get('review_token','')):
                return JSONResponse({'detail':'Sanitised evidence review and explicit approval required; preview this exact submission first'},status_code=422)
        response=await call_next(request)
        response.headers['Cache-Control']='no-store'
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['X-Frame-Options']='DENY'
        return response

    @app.get('/login')
    def login_page():
        return FileResponse(STATIC/'login.html')

    @app.get('/api/auth/session')
    def session(request: Request):
        data=auth.verify(request.cookies.get(COOKIE)) if auth.enabled else {'user':'Local offline operator','role':'admin'}
        return {'authenticated':bool(data),'username':data['user'] if data else None,'role':data['role'] if data else None,'mode':'OFFLINE / TEST MODE' if settings.offline else 'LIVE','enabled':auth.enabled,'setup_required':auth.enabled and not auth.configured}

    @app.post('/api/auth/login')
    def login(body:LoginIn,request:Request):
        if auth.rate_limited(request.client.host if request.client else 'local'):
            raise HTTPException(429,'Too many login attempts. Try again in one minute.')
        if not auth.configured:raise HTTPException(503,'Run the local setup_operator helper, then restart the app.')
        if not auth.check_password(body.username,body.password):raise HTTPException(401,'Invalid username or password')
        response=JSONResponse({'authenticated':True,'username':body.username,'role':auth._users()[body.username]['role']})
        response.set_cookie(COOKIE,auth.issue(body.username),httponly=True,samesite='strict',secure=False,max_age=TTL,path='/')
        return response

    @app.post('/api/auth/logout')
    def logout(request:Request):
        auth.revoke(request.cookies.get(COOKIE))
        response=JSONResponse({'authenticated':False});response.delete_cookie(COOKIE,path='/');return response

    @app.post('/api/evidence/preview')
    def preview_evidence(body:PreviewIn,request:Request):
        if body.scope not in ('/api/ask','/api/resolve','/api/preference','/api/patterns','/api/memory/search'):
            raise HTTPException(422,'Unsupported review scope')
        return evidence_preview(auth,request.state.operator['user'],body.scope,body.payload)

    @app.post('/api/auth/setup')
    def setup(body:LoginIn,request:Request):
        if auth.rate_limited(request.client.host):raise HTTPException(429,'Too many setup attempts')
        if auth.configured:raise HTTPException(409,'Administrator already exists')
        try:return auth.setup_admin(body.username,body.password)
        except ValueError as exc:raise HTTPException(422,str(exc))

    @app.get('/api/admin/users')
    def users():return auth.list_users()

    @app.post('/api/admin/users')
    def add_user(body:UserIn):
        try:return auth.add_user(body.username,body.password,body.role)
        except ValueError as exc:raise HTTPException(422,str(exc))

    @app.post('/api/admin/users/{username}/role')
    def role(username:str,body:RoleIn):
        try:return auth.change_role(username,body.role)
        except ValueError as exc:raise HTTPException(422,str(exc))

    @app.get('/api/telemetry')
    def telemetry():return verifier.last

    @app.get('/api/investigations')
    def investigations(q:str='',status:str='',severity:str=''):
        rows=history.list(q,status,severity)
        return [{k:v for k,v in r.items() if k not in ('result','submission','resolution')} for r in rows]

    @app.get('/api/investigations/{ident}')
    def investigation(ident:str):
        record=history.get(ident)
        if not record:raise HTTPException(404,'Investigation not found')
        return record

    @app.get('/api/dashboard')
    def dashboard():
        return {'metrics':history.metrics(),'recent':[{k:v for k,v in r.items() if k not in ('result','submission','resolution')} for r in history.list()[:10]],'providers':provider_status()}

    def provider_status():
        unknown={'status':'unknown','last_operation':None,'last_success_at':None,'last_duration_ms':None,'last_recall_ms':None,'last_retention_at':None,'error':None}
        return {'hindsight':dict(agent.memory.state.snapshot() if hasattr(agent.memory,'state') else unknown,bank_id=settings.bank_id,backend=agent.memory.name),
                'groq':dict(agent.llm.state.snapshot() if hasattr(agent.llm,'state') else unknown,model=settings.model,vision_model='qwen/qwen3.8-27b',fallback_model=settings.fallback_model,backend=agent.llm.name),'prometheus':verifier.last}

    @app.post('/api/memory/search')
    def search_memory(body: PatternIn):
        started=perf_counter();query=redact(body.question)
        key=(settings.bank_id,'Platform Engineering','workspace-search',' '.join(query.casefold().split()))
        try:
            with agent._cache_lock:
                entry=agent._cache.get(key) if not body.force_refresh else None
                if entry and perf_counter()-entry[0]>=60:entry=None
            if entry:
                hits=entry[1];cached=True
            else:
                hits=agent.memory.recall(query,max_tokens=2500);cached=False
                with agent._cache_lock:agent._cache[key]=(perf_counter(),hits)
            return {'memories':redact([h.to_dict() for h in hits]),'cached':cached,'duration_ms':round((perf_counter()-started)*1000,1)}
        except Exception as exc:
            raise HTTPException(502,safe_error(exc))

    @app.get('/api/providers')
    def providers():return provider_status()

    @app.post('/api/providers/check')
    def check_providers():
        if settings.offline:return provider_status()
        try:agent.memory._call('get_bank_config',bank_id=settings.bank_id)
        except Exception:pass
        started=perf_counter()
        try:
            available={m.id for m in agent.llm.client.models.list().data}
            if settings.model not in available:
                raise RuntimeError('Configured Groq model unavailable')
            agent.llm.state.record('models',started)
        except Exception as exc:
            if hasattr(agent.llm,'state'):agent.llm.state.record('models',started,exc)
        return provider_status()
    data = load_data()

    def _now(s: str | None) -> datetime:
        if not s:
            return datetime.now().astimezone()
        try:
            return datetime.fromisoformat(s)
        except ValueError:
            raise HTTPException(422, "now must be ISO 8601")

    @app.get("/health")
    @app.get("/api/health")
    def health():
        return {"ok": True, "memory": agent.memory.name, "llm": agent.llm.name, "bank_id": settings.bank_id,
                "mode": "offline-test-only" if settings.offline else "live",
                "connectivity": "not probed; badges describe configuration only",
                "missing_credentials": [] if settings.offline else [name for name, val in
                    (("HINDSIGHT_API_KEY", settings.hindsight_api_key), ("GROQ_API_KEY", settings.groq_api_key)) if not val]}

    @app.get("/api/demo")
    def demo():
        return {
            "engineers": sorted({p["engineer"] for p in data["preferences"]}),
            "services": [s["service"] for s in data["service_facts"]],
            "alerts": data["demo_alerts"],
        }

    @app.post("/api/ask")
    def ask(body: AskIn):
        if not settings.offline and not settings.hindsight_api_key:
            raise HTTPException(503, "HINDSIGHT_API_KEY missing; add locally to .env and restart the server")
        if not settings.offline and not settings.groq_api_key:
            raise HTTPException(503, "GROQ_API_KEY missing; add locally to .env and restart the server")
        if not settings.offline and (agent.memory.name!='hindsight' or agent.llm.name!='groq'):
            raise HTTPException(503,'Live mode requires real Hindsight and Groq providers; test stand-ins are rejected')
        image=None
        values=body.images or ([body.image_data] if body.image_data else [])
        if values:
            if not body.image_reviewed:raise HTTPException(422,'Review the screenshot for secrets before sending it to the vision provider')
            if settings.offline:raise HTTPException(422,'Screenshot understanding requires a real Groq vision call; offline mode is unsupported')
            try:image=validate_images(values)
            except ValueError as exc:raise HTTPException(422,str(exc))
        elif len(body.alert.strip())<3:
            raise HTTPException(422,'Provide at least 3 characters of evidence or an image')
        ident='IQ-'+uuid4().hex[:12]
        result=agent.answer(body.alert, body.engineer, body.service, body.memory_on, _now(body.now), body.environment, body.severity, conversation_id=ident, force_refresh=True,image=image)  # New conversations always bypass retrieval cache.
        result['conversation_id']=ident
        result['telemetry']=verifier.snapshot()
        result['evidence_reviewed']=bool(body.review_token) or settings.offline
        if result.get('report') or settings.offline:
            submission=body.model_dump(exclude={'image_data','images','image_reviewed','review_token'})
            submission['evidence_reviewed']=True
            submission['attachment']=image_metadata(image)
            history.save_investigation(ident,redact(submission),result)
        return result

    @app.post("/api/resolve")
    def resolve(body: ResolveIn):
        if not body.verified:
            raise HTTPException(422, "Verify the outcome before retaining a confirmed resolution")
        if not settings.offline and not settings.hindsight_api_key:
            raise HTTPException(503, "HINDSIGHT_API_KEY missing")
        if not body.incident_id:
            body.incident_id = "INC-LIVE-" + uuid4().hex[:12]
        params=body.model_dump();conversation=params.pop('conversation_id');params.pop('review_token',None)
        if conversation:
            record=history.get(conversation)
            if not record:raise HTTPException(404,'Investigation not found')
            if record['service']!=body.service or record['environment']!=body.environment:
                raise HTTPException(422,'Feedback scope must match the saved investigation')
        try:
            telemetry=verifier.snapshot()
            n = agent.resolve(**params)
            outcome_status='VERIFIED_BY_TELEMETRY' if telemetry['verification_status']=='VERIFIED_BY_TELEMETRY' else 'ENGINEER_ATTESTED' if telemetry['verification_status']=='TELEMETRY_NOT_CONFIGURED' else 'NOT_VERIFIED'
            params['recovery_verification']=outcome_status;params['telemetry']=telemetry
            if conversation:history.resolve(conversation,params,n)
        except Exception as exc:
            raise HTTPException(502, "memory write failed: " + safe_error(exc))
        return {"retained":n,"incident_id":body.incident_id,"backend":agent.memory.name,"status":"engineer-verified","recovery_verification":outcome_status,"telemetry":telemetry}

    @app.post("/api/preference")
    def preference(body: PrefIn):
        if not settings.offline and not settings.hindsight_api_key:
            raise HTTPException(503, "HINDSIGHT_API_KEY missing")
        try:
            agent.remember_preference(body.engineer, body.text)
        except Exception as exc:
            raise HTTPException(502, "memory write failed: " + safe_error(exc))
        return {"retained": 1}

    @app.post("/api/patterns")
    def patterns(body: PatternIn):
        if not settings.offline and not settings.hindsight_api_key:
            raise HTTPException(503, "HINDSIGHT_API_KEY missing")
        try:
            return {"answer": agent.patterns(body.question)}
        except Exception as exc:
            raise HTTPException(502, "reflect failed: " + safe_error(exc))

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


app = create_app()
