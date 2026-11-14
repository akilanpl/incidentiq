import base64
import io
import json
from pathlib import Path
import pytest
from PIL import Image
from fastapi.testclient import TestClient
from app.server import create_app
from recurrence.vision import validate_image,LIMIT
from recurrence.config import Settings
from recurrence.history import HistoryStore
from recurrence.auth import LocalAuth


def image_url(fmt='PNG',mime='image/png'):
    i=Image.new('RGB',(20,20),'black');b=io.BytesIO();i.save(b,format=fmt)
    return 'data:'+mime+';base64,'+base64.b64encode(b.getvalue()).decode()


@pytest.mark.parametrize('fmt,mime',[('PNG','image/png'),('JPEG','image/jpeg'),('WEBP','image/webp')])
def test_valid_types(fmt,mime):
    r=validate_image(image_url(fmt,mime));assert r['mime']==mime and r['size_bytes']>0


@pytest.mark.parametrize('value',['data:image/svg+xml;base64,AAAA','data:image/png;base64,not!base64','data:image/png;base64,YWJjZA=='])
def test_invalid_images_rejected(value):
    with pytest.raises(ValueError):validate_image(value)


def test_mime_mismatch_and_oversize():
    with pytest.raises(ValueError,match='MIME'):validate_image(image_url('PNG','image/jpeg'))
    value='data:image/png;base64,'+base64.b64encode(b'x'*(LIMIT+1)).decode()
    with pytest.raises(ValueError,match='5 MB'):validate_image(value)


def test_review_required_and_no_validation_input_echo(tmp_path):
    c=TestClient(create_app(settings=Settings.from_env(offline=True),auth=LocalAuth(False),history=HistoryStore(tmp_path/'history.json')))
    r=c.post('/api/ask',json={'service':'s','engineer':'e','image_data':image_url()})
    assert r.status_code==422 and 'Review' in r.json()['detail']
    r=c.post('/api/ask',json={'service':'s','engineer':'e','alert':'password=private','image_data':2})
    assert r.status_code==422 and 'private' not in r.text and 'input' not in r.json()['detail'][0]


def test_image_evidence_enters_same_understanding_before_recall():
    from tests.test_incidentiq import REPORT
    from recurrence.memory import FakeMemory
    from recurrence.agent import RecurrenceAgent
    from recurrence.understanding import Understanding
    events=[]
    class VisionLLM:
        name='groq';last_model='qwen/qwen3.8-27b'
        def understand_image(self,system,payload,schema,image):
            events.append('vision')
            assert payload['evidence']=='accompanying text' and image['mime']=='image/png'
            return Understanding(incident_summary='Visible pool timeout',service='orders',error_signatures=['DB_POOL_TIMEOUT'],retrieval_queries=['DB_POOL_TIMEOUT verified historical fixes']).model_dump()
        def run(self,*args):
            events.append('reason');report=json.loads(json.dumps(REPORT));report['ai_reasoning'][0]['historical_source_ids']=[]
            return json.dumps(report),[]
    class Mem(FakeMemory):
        def recall(self,query,**kwargs):events.append('recall');assert 'DB_POOL_TIMEOUT' in query or 'prefer' in query;return []
    a=RecurrenceAgent(Mem(),VisionLLM());out=a.answer('accompanying text','e','orders',image=validate_image(image_url()))
    assert out['vision_used'] and out['understanding']['error_signatures']==['DB_POOL_TIMEOUT']
    assert events.index('vision')<events.index('recall')<events.index('reason')
    assert 'data_url' not in json.dumps(out)


def test_embedded_metadata_removed_before_provider_processing():
    image=Image.new('RGB',(20,20),'black');exif=Image.Exif();exif[270]='private embedded metadata';buf=io.BytesIO();image.save(buf,format='JPEG',exif=exif)
    result=validate_image('data:image/jpeg;base64,'+base64.b64encode(buf.getvalue()).decode())
    cleaned=base64.b64decode(result['data_url'].split(',',1)[1])
    assert b'private embedded metadata' not in cleaned
    with Image.open(io.BytesIO(cleaned)) as final:assert len(final.getexif())==0
