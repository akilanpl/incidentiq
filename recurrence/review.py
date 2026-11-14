"""Approval bound to sanitised evidence and exact image bytes."""
import hashlib,json,time
from .safety import redact,sanitise_text

def envelope(payload):
 clean=redact({k:v for k,v in payload.items() if k not in ('review_token','image_data','images')})
 images=payload.get('images') or ([payload['image_data']] if payload.get('image_data') else [])
 clean['image_hashes']=[hashlib.sha256(x.encode()).hexdigest() for x in images];return clean

def digest(payload):return hashlib.sha256(json.dumps(envelope(payload),sort_keys=True,separators=(',',':'),default=str).encode()).hexdigest()

def preview(auth,username,scope,payload):
 findings=[]
 for key,value in payload.items():
  if isinstance(value,str) and key not in ('image_data','review_token'):
   _,detected=sanitise_text(value);findings.extend(dict(item,field=key) for item in detected)
 return {'sanitised':envelope(payload),'redactions':findings,'review_token':auth.serializer('review').dumps({'user':username,'scope':scope,'digest':digest(payload),'reviewed_at':int(time.time())}),'image_count':len(envelope(payload)['image_hashes'])}

def approved(auth,username,scope,payload,token):
 try:
  item=auth.serializer('review').loads(token,max_age=600)
  return item['user']==username and item['scope']==scope and item['digest']==digest(payload)
 except Exception:return False
