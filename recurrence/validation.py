"""Conservative relevance/provenance checks; content never grants instruction authority."""
from datetime import datetime
import copy
from .memory import days_ago


def merge_hits(hits):
    """Merge facts from one source document; preserve every genuine fact ID."""
    out=[];documents={};ids=set()
    for original in hits:
        if original.id and original.id in ids:continue
        if original.id:ids.add(original.id)
        hit=copy.deepcopy(original)
        hit.source_ids=list(dict.fromkeys((hit.source_ids or [])+([hit.id] if hit.id else [])))
        key=(hit.document_id,hit.metadata.get('kind')) if hit.document_id else None
        if key and key in documents:
            first=documents[key]
            if hit.text not in first.text:first.text+='\n'+hit.text
            first.source_ids=list(dict.fromkeys(first.source_ids+hit.source_ids))
        else:
            out.append(hit)
            if key:documents[key]=hit
    return out


def validate_hits(hits, service, environment, now=None, allow_cross_service=False):
    now = now or datetime.now().astimezone()
    rows, seen = [], set()
    for hit in hits:
        key = hit.id or (hit.document_id, hit.text)
        if key in seen:
            continue
        seen.add(key)
        meta = hit.metadata or {}
        scopes = [t.split(':', 1)[1] for t in hit.tags if t.startswith('service:')]
        historical_service = meta.get('service')
        if historical_service:
            scopes.append(historical_service)
        service_match = not scopes or service in scopes
        old_env = meta.get('environment')
        env_match = not environment or not old_env or old_env == environment
        status = meta.get('status', '')
        kind = meta.get('kind', '')
        # Only explicit engineer-confirmed metadata earns verified status. Legacy seed data is labelled synthetic.
        verified = status == 'verified' and kind in ('incident', 'dead-end')
        age = days_ago(hit.occurred_at, now)
        warnings = []
        if not scopes:
            warnings.append('Service relevance requires review: scope absent')
        if not old_env:
            warnings.append('Historical environment unknown')
        if not service_match:
            warnings.append('Different service: potentially related dependency only')
        if not env_match:
            warnings.append('Different environment')
        if not verified:
            warnings.append('Resolution not verified by structured source metadata')
        if kind == 'advice':
            warnings.append('Unverified agent advice; never treat as successful remediation')
        if age is None or age > 90:
            warnings.append('Age unknown or over 90 days: check current versions and runbooks')
        if age is not None and age < 0:
            warnings.append('Future timestamp: verify source chronology')
        rows.append({'hit': hit, 'validation': {
            'service_relevance': 'match' if service_match and scopes else ('unknown' if not scopes else 'different'),
            'environment_relevance': 'unknown' if not old_env else ('match' if env_match else 'different'),
            'resolution_status': 'verified' if verified else ('unverified-advice' if kind == 'advice' else 'unverified'),
            'warnings': warnings,
            'contradictions': 'Not automatically resolved; compare evidence, dates and versions before applying advice',
            'eligible_for_reasoning': (service_match or (allow_cross_service and verified)) and env_match and kind not in ('advice', 'investigation_advice', 'incident_intake'),
        }})
    return rows
