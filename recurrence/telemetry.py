"""Actual observed provider operations. Unknown until an operation runs."""
import threading
from time import perf_counter
from datetime import datetime,timezone
from .safety import safe_error


class ProviderState:
    def __init__(self):
        self.lock=threading.Lock();self.data={'status':'unknown','last_operation':None,'last_success_at':None,'last_duration_ms':None,'error':None,'last_recall_ms':None,'last_retention_at':None,'last_inference_status':None,'last_inference_ms':None,'operation_counts':{},'latest_request_usage':None,'app_observed_tokens':0,'rate_limit_headers':{},'usage_scope':'App-observed calls in this process; response rate limits may be shared at project/organisation scope; not account credit balance'}

    def record(self,operation,started,error=None):
        with self.lock:
            self.data['operation_counts'][operation]=self.data['operation_counts'].get(operation,0)+1
            now=datetime.now(timezone.utc).isoformat();duration=round((perf_counter()-started)*1000,1)
            self.data.update(status='disconnected' if error else 'connected',last_operation=operation,last_duration_ms=duration,error=safe_error(error) if error else None,checked_at=now)
            if operation in ('inference','vision_inference'):
                self.data.update(last_inference_status='failed' if error else 'success',last_inference_ms=duration)
            if not error:
                self.data['last_success_at']=now
                if operation=='recall':self.data['last_recall_ms']=duration
                if operation in ('retain','retain_batch'):self.data['last_retention_at']=now

    def usage(self,usage,headers):
        with self.lock:
            self.data['latest_request_usage']=usage if any(v is not None for v in usage.values()) else None
            if isinstance(usage.get('total_tokens'),int):self.data['app_observed_tokens']+=usage['total_tokens']
            self.data['rate_limit_headers']=headers

    def snapshot(self):
        with self.lock:return dict(self.data)
