"""Deterministic, best-effort sanitisation; never a guarantee of complete detection."""
import math
import os
import re
from collections import Counter

RULES=[
 ('PRIVATE_KEY',r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----',0),
 ('TOKEN',r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b',0),
 ('API_KEY',r'\b(?:gsk_[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{25,}|xox[baprs]-[A-Za-z0-9-]{10,})\b',0),
 ('TOKEN',r'(?i)\bBasic\s+[A-Za-z0-9+/=]+',0),
 ('TOKEN',r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+',0),
 ('PERSONAL_DATA',r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',0),
 ('PERSONAL_DATA',r'(?<![\w.])(?:\+\d{1,3}[ -]?)?(?:\(\d{3}\)[ -]?|\d{3}[- ])\d{3}[- ]\d{4}(?![\w.])',0),
]
CONTEXT=re.compile(r'''(?ix)(["']?\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|pwd|secret|authorization|aws_secret_access_key|aws_session_token|aws_access_key_id|accountkey|sas_token|client_secret|hindsight_api_key|groq_api_key|slack_token|private_key)["']?\s*[:=]\s*)(["']?)([^\r\n,;\s}"']+)''')
DB=re.compile(r'(?i)(\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://)([^\s/@]+:[^\s/@]+)@')
ENTROPY=re.compile(r'(?i)((?:credential|token|secret|key)\w*["\']?\s*[:=]\s*["\']?)([A-Za-z0-9+/=_-]{24,})')


def sanitise_text(value):
    findings=[]
    def mask(label):
        def replace(match):
            if match.group(0).startswith('[REDACTED_'):return match.group(0)
            findings.append({'category':label,'count':1})
            return '[REDACTED_'+label+']'
        return replace
    for name in ('GROQ_API_KEY','HINDSIGHT_API_KEY','PROMETHEUS_BEARER_TOKEN','INCIDENTIQ_SESSION_SECRET'):
        secret=os.getenv(name)
        if secret and len(secret)>6 and secret in value:
            findings.append({'category':'API_KEY','count':value.count(secret)})
            value=value.replace(secret,'[REDACTED_API_KEY]')
    def db(m):findings.append({'category':'PASSWORD','count':1});return m[1]+'[REDACTED_PASSWORD]@'
    value=DB.sub(db,value)
    for label,pattern,flags in RULES:value=re.sub(pattern,mask(label),value,flags=flags)
    def contextual(m):
        if m[3].startswith('[REDACTED'):return m[0]
        label='PASSWORD' if re.search('pass|pwd',m[1],re.I) else 'TOKEN' if re.search('token|authorization',m[1],re.I) else 'API_KEY'
        findings.append({'category':label,'count':1});return m[1]+m[2]+'[REDACTED_'+label+']'
    quoted=re.compile(r"""(?i)(["']?\b(?:password|passwd|pwd|api[_-]?key|secret|access[_-]?token|authorization)["']?\s*[:=]\s*)(["'])([^\r\n]*?)\2""")
    def quoted_mask(m):
        return m[0] if m[3].startswith('[REDACTED') else contextual(m)+m[2]
    value=quoted.sub(quoted_mask,value)
    value=CONTEXT.sub(contextual,value)
    def phone(m):findings.append({'category':'PERSONAL_DATA','count':1});return m[1]+'[REDACTED_PERSONAL_DATA]'
    value=re.sub(r'(?i)(\b(?:phone|mobile|telephone)["\']?\s*[:=]\s*["\']?)(\+?\d[\d ()-]{7,}\d)',phone,value)
    def entropy(m):
        counts=Counter(m[2]);h=-sum((n/len(m[2]))*math.log2(n/len(m[2])) for n in counts.values())
        if h<3.5:return m[0]
        findings.append({'category':'TOKEN','count':1});return m[1]+'[REDACTED_TOKEN]'
    value=ENTROPY.sub(entropy,value)
    totals=Counter()
    for f in findings:totals[f['category']]+=f['count']
    return value,[{'category':k,'count':v} for k,v in totals.items()]


def redact(value):
    if isinstance(value,dict):
        clean={}
        for k,v in value.items():
            key=str(k)
            if CONTEXT.match(key+'=value') and v not in (None,''):
                label='PASSWORD' if re.search('pass|pwd',key,re.I) else 'TOKEN' if re.search('token|authorization',key,re.I) else 'API_KEY'
                clean[k]='[REDACTED_'+label+']'
            else:clean[k]=redact(v)
        return clean
    if isinstance(value,(list,tuple)):return [redact(v) for v in value]
    return sanitise_text(value)[0] if isinstance(value,str) else value


def safe_error(exc):
    status=getattr(exc,'status_code',None) or getattr(exc,'status',None)
    if not status:
        for code in (401,402,403,404,409,429):
            if str(code) in str(exc):status=code;break
    reason={401:'invalid or missing API key',402:'credits required',403:'access denied or credits unavailable',404:'endpoint, bank or model not found',409:'bank already exists',429:'rate limit or quota exceeded'}.get(status,'connection, SDK or provider failure')
    return f'{type(exc).__name__}: {reason}'+(f' (HTTP {status})' if status else '')
