"""Actual Cloud retain→recall and Groq inference. No offline fallback.
Run .venv/bin/python -m scripts.live_smoke; optional --learning-loop exercises the agent too.
"""
import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from dotenv import dotenv_values
from recurrence.config import Settings, build_llm, build_memory
from recurrence.safety import safe_error
from recurrence.understanding import understand


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--learning-loop', action='store_true')
    args = parser.parse_args()
    values = dotenv_values('.env')
    missing = [k for k in ('HINDSIGHT_API_KEY', 'GROQ_API_KEY') if not values.get(k)]
    report = {'timestamp': datetime.now(timezone.utc).isoformat(), 'offline': False, 'missing': missing,
              'hindsight': 'not tested', 'groq': 'not tested'}
    mem = None
    llm = None
    try:
        if missing:
            raise RuntimeError('missing local credentials: ' + ', '.join(missing))
        s = Settings.from_env(offline=False)
        if s.hindsight_url != 'https://api.hindsight.vectorize.io':
            raise RuntimeError('Hindsight Cloud API endpoint must be https://api.hindsight.vectorize.io')
        mem = build_memory(s)
        mem.ensure_bank()
        marker = 'INCIDENTIQ-LIVE-SMOKE-' + uuid4().hex[:12]
        content = (f'Synthetic connectivity test {marker}. The smoke-orders production service suffered database '
                   'connection timeouts after a session leak filled its pool. Engineers confirmed unreleased '
                   'sessions as the root cause. Closing sessions in finally blocks fixed the issue; restarting '
                   'workers alone failed. Outcome verified: database pool usage and error rate returned to baseline.')
        mem.retain(content, context='synthetic verified connectivity test; not a real production incident',
                   document_id=marker, tags=['service:smoke-orders', 'kind:incident', 'synthetic:true'],
                   metadata={'incident_id': marker, 'kind': 'incident', 'service': 'smoke-orders', 'status': 'verified', 'environment': 'production'},
                   timestamp=datetime.now(timezone.utc).isoformat())
        hits = []
        for attempt in range(6):
            hits = mem.recall('smoke-orders exhausted database pool caused by unclosed sessions: which fix succeeded and what failed?', max_tokens=3000)
            if any(marker in (h.text + (h.document_id or '') + json.dumps(h.metadata)) for h in hits):
                break
            time.sleep(2 + attempt)
        else:
            raise RuntimeError('Cloud retention completed but unique memory was not recalled within bounded retry')
        report.update(hindsight='PASS real synchronous retain + semantic recall', smoke_document_id=marker,
                      recalled_ids=[h.id for h in hits], recalled_documents=[h.document_id for h in hits])
        llm = build_llm(s)
        models = {m.id for m in llm.client.models.list().data}
        if s.model not in models:
            raise RuntimeError('Preferred Groq model unavailable in account: ' + s.model)
        fallback = next((m for m in ['openai/gpt-oss-20b', 'qwen/qwen3.8-27b', 'llama-3.3-70b-versatile', 'qwen/qwen3-32b', 'llama-3.1-8b-instant'] if m in models and m != s.model), '')
        if s.fallback_model in models and s.fallback_model != s.model:
            fallback = s.fallback_model
        llm.fallback_model = fallback or None
        understanding, source = understand(llm, 'ERROR orders database connection timed out; pool active=40 idle=0 after deploy', 'orders', 'production', 'SEV2')
        assert source == 'groq' and understanding.retrieval_queries
        report.update(groq='PASS real model listing + JSON understanding inference', model=s.model,
                      fallback_model=fallback, vision_candidate_available='qwen/qwen3.8-27b' in models,
                      understanding=understanding.model_dump())
        if args.learning_loop:
            from recurrence.agent import RecurrenceAgent
            agent = RecurrenceAgent(mem, llm)
            inc = 'INCIDENTIQ-LEARNING-' + uuid4().hex[:10]
            service = 'smoke-' + uuid4().hex[:6]
            agent.resolve(service, 'Synthetic smoke engineer', 'Database pool timeout due to leaked sessions',
                          'Confirmed sessions not released in exception handler', 'Added finally block to close sessions',
                          'Restarting workers only temporarily helped', inc, environment='production', severity='SEV2',
                          outcome='Verified recovered: error rate and pool usage baseline', error_signature='Connection timeout; idle=0')
            # New SDK/backend instance proves persistence beyond an in-process dictionary.
            fresh = build_memory(s)
            try:
                out = RecurrenceAgent(fresh, llm).answer('Database connections timing out, active pool full idle=0', 'Synthetic smoke engineer', service, environment='production', severity='SEV2')
                if not any(inc in (h['text'] + (h.get('document_id') or '') + json.dumps(h['metadata'])) for h in out['memories']):
                    raise RuntimeError('Learning-loop incident not found in fresh-client recall')
                report['learning_diagnostics'] = {'tool_trace': out.get('tool_trace', []), 'backend': out.get('backend', {})}
                if not out.get('report') or out['backend']['llm'] != 'groq' or any(t['event'] in ('llm_unavailable', 'invalid_report') for t in out['tool_trace']):
                    raise RuntimeError('Learning-loop final inference failed')
                if not any(x['historical_source_ids'] for x in out['report']['ai_reasoning']):
                    raise RuntimeError('Report did not use actual historical source citations')
                report['learning_loop'] = {'status': 'PASS real resolve → fresh-client recall → Groq recommendation', 'incident_id': inc, 'result': out}
            finally:
                fresh.close()
    except Exception as exc:
        report['error'] = str(exc) if isinstance(exc, (RuntimeError, AssertionError)) else safe_error(exc)
    finally:
        if llm:
            llm.client.close()
        if mem:
            mem.close()
    Path('docs/live_verification.json').write_text(json.dumps(report, indent=2))
    summary = {k: v for k, v in report.items() if k not in ('understanding', 'learning_loop', 'learning_diagnostics', 'recalled_ids', 'recalled_documents')}
    summary['recalled_count'] = len(report.get('recalled_ids', []))
    if report.get('learning_loop'):
        summary['learning_loop'] = report['learning_loop']['status']
    print(json.dumps(summary, indent=2))
    return 1 if 'error' in report else 0


if __name__ == '__main__':
    sys.exit(main())
