"""Atomic, redacted local history for the single-process local workspace."""
import json
import os
from pathlib import Path
import tempfile
import threading
from datetime import datetime, timezone
from .safety import redact


def timestamp():return datetime.now(timezone.utc).isoformat()


class HistoryStore:
    def __init__(self,path):
        self.path=Path(path);self.lock=threading.RLock()

    def _read(self):
        if not self.path.exists():return {}
        # Corrupt data is reported, never silently overwritten with an empty store.
        value=json.loads(self.path.read_text())
        if not isinstance(value,dict):raise ValueError('History file must contain an object')
        return value

    def _write(self,records):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        fd,name=tempfile.mkstemp(prefix='.history-',dir=self.path.parent)
        try:
            with os.fdopen(fd,'w') as f:
                json.dump(redact(records),f,indent=2);f.flush();os.fsync(f.fileno())
            os.replace(name,self.path)
        finally:
            if os.path.exists(name):os.unlink(name)

    def save_investigation(self,ident,submission,result):
        with self.lock:
            records=self._read();now=timestamp()
            records[ident]=redact({'id':ident,'created_at':now,'updated_at':now,'service':submission['service'],
                'environment':submission.get('environment',''),'severity':submission.get('severity',''),
                'title':result['understanding']['incident_summary'][:180], 'status':'open',
                'error_signatures':result['understanding']['error_signatures'], 'submission':submission,'result':result,
                'events':[{'type':'investigation','timestamp':now,'summary':'Investigation generated','source_ids':list(dict.fromkeys(h.get('id') or h.get('document_id') for h in result['memories'] if h.get('id') or h.get('document_id')))}],
                'resolution':None})
            self._write(records);return records[ident]

    def resolve(self,ident,feedback,retained):
        with self.lock:
            records=self._read()
            if ident not in records:raise KeyError(ident)
            record=records[ident];now=timestamp();record.update(status='resolved',updated_at=now,resolution=redact(feedback))
            record['events'].append({'type':'verified_resolution','timestamp':now,'summary':'Engineer confirmed recovery; Hindsight retention succeeded','retained':retained})
            self._write(records);return record

    def get(self,ident):
        with self.lock:return self._read().get(ident)

    def list(self,query='',status='',severity=''):
        with self.lock:records=list(self._read().values())
        if query:
            q=query.casefold();records=[r for r in records if q in ' '.join([r['id'],r['service'],r['title'],*r.get('error_signatures',[])]).casefold()]
        if status:records=[r for r in records if r['status']==status]
        if severity:records=[r for r in records if r['severity']==severity]
        return sorted(records,key=lambda r:r['updated_at'],reverse=True)

    def metrics(self):
        records=self.list()
        return {'total':len(records),'resolved':sum(r['status']=='resolved' for r in records),'open':sum(r['status']=='open' for r in records),
                'historical_memories_used':sum(sum(bool(m.get('validation',{}).get('eligible_for_reasoning')) for m in r['result']['memories']) for r in records)}
