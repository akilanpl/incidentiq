"""Read-only configured Prometheus instant queries. No arbitrary client-supplied PromQL."""
import os
import math
from datetime import datetime,timezone
import httpx
from .safety import safe_error


class TelemetryVerifier:
    def __init__(self,url='',token='',queries=None,client=None,demo=False):
        self.demo=demo
        self.url=url.rstrip('/');self.token=token;self.queries=queries or {};self.client=client
        self.last={'demo':self.demo,'scope':'synthetic demo; not production recovery' if self.demo else 'configured telemetry','verification_status':'NOT_VERIFIED' if self.url and self.queries else 'TELEMETRY_NOT_CONFIGURED','source':'prometheus','checks':[],'checked_at':None}

    @classmethod
    def from_env(cls):
        from pathlib import Path
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).resolve().parent.parent/'.env.telemetry')
        queries={}
        if os.getenv('PROMETHEUS_SERVICE_UP_QUERY'):queries['service_up']=(os.environ['PROMETHEUS_SERVICE_UP_QUERY'],'>=',1.0)
        for name,query,threshold in [('error_rate','PROMETHEUS_ERROR_RATE_QUERY','PROMETHEUS_ERROR_RATE_MAX'),('db_pool','PROMETHEUS_DB_POOL_QUERY','PROMETHEUS_DB_POOL_MAX')]:
            if os.getenv(query):
                try:maximum=float(os.environ[threshold]);assert math.isfinite(maximum)
                except (KeyError,ValueError,AssertionError):maximum=None
                queries[name]=(os.environ[query],'<=',maximum)
        return cls(os.getenv('PROMETHEUS_URL',''),os.getenv('PROMETHEUS_BEARER_TOKEN',''),queries,demo=os.getenv('PROMETHEUS_DEMO','0')=='1')

    def snapshot(self):
        result={'verification_status':'TELEMETRY_NOT_CONFIGURED','source':'prometheus','checks':[],'checked_at':datetime.now(timezone.utc).isoformat()}
        if not self.url or not self.queries:self.last=result;return result
        result['verification_status']='NOT_VERIFIED'
        client=self.client or httpx.Client(timeout=5,follow_redirects=False)
        try:
            for metric,(query,op,threshold) in self.queries.items():
                check={'metric':metric,'expected':f'{op} {threshold}' if threshold is not None else 'Threshold not configured','passed':False,'values':[]}
                try:
                    response=client.get(self.url+'/api/v1/query',params={'query':query},headers={'Authorization':'Bearer '+self.token} if self.token else {})
                    response.raise_for_status();data=response.json()
                    if data.get('status')!='success':raise ValueError('Prometheus query failed')
                    body=data['data'];kind=body['resultType'];items=body['result']
                    raw=[items[1]] if kind=='scalar' else [item['value'][1] for item in items] if kind=='vector' else []
                    values=[float(x) for x in raw]
                    if not values or not all(math.isfinite(x) for x in values):raise ValueError('No finite numeric metrics')
                    check['values']=values;check['value']=values[0] if len(values)==1 else None
                    check['passed']=threshold is not None and all(v>=threshold if op=='>=' else v<=threshold for v in values)
                except Exception as exc:check['error']=safe_error(exc)
                result['checks'].append(check)
            if result['checks'] and all(c['passed'] for c in result['checks']):result['verification_status']='VERIFIED_BY_TELEMETRY'
        finally:
            if not self.client:client.close()
        if self.demo:
            result['demo']=True;result['scope']='Synthetic demo metrics; not independent production recovery verification'
            result['demo_checks_passed']=result['verification_status']=='VERIFIED_BY_TELEMETRY'
            result['verification_status']='NOT_VERIFIED'
        self.last=result;return result
