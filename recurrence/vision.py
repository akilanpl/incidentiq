"""In-memory screenshot validation. Pixels are reviewed by the operator, not auto-redacted."""
import base64
import io
import re
from PIL import Image,UnidentifiedImageError

LIMIT=5*1024*1024
FORMATS={'image/png':'PNG','image/jpeg':'JPEG','image/webp':'WEBP'}


def validate_image(value):
    match=re.fullmatch(r'data:(image/(?:png|jpeg|webp));base64,([A-Za-z0-9+/=\r\n]+)',value or '')
    if not match:raise ValueError('Use a PNG, JPEG or WebP image encoded as a data URL')
    mime,payload=match.groups()
    try:raw=base64.b64decode(payload,validate=True)
    except ValueError:raise ValueError('Invalid image encoding') from None
    if len(raw)>LIMIT:raise ValueError('Screenshot exceeds the 5 MB limit')
    try:
        with Image.open(io.BytesIO(raw)) as image:
            if image.format!=FORMATS[mime]:raise ValueError('Image MIME type does not match its content')
            if image.width*image.height>20_000_000:raise ValueError('Screenshot dimensions exceed the safety limit')
            image.verify()
        with Image.open(io.BytesIO(raw)) as image:
            clean=image.copy();clean.info.clear();out=io.BytesIO();clean.save(out,format=FORMATS[mime])
        clean_bytes=out.getvalue()
        if len(clean_bytes)>LIMIT:raise ValueError('Screenshot exceeds 5 MB after metadata removal')
    except (UnidentifiedImageError,OSError,Image.DecompressionBombError):
        raise ValueError('Invalid or unsafe screenshot') from None
    return {'data_url':f'data:{mime};base64,'+base64.b64encode(clean_bytes).decode(),'mime':mime,'size_bytes':len(raw)}


def validate_images(values):
    if not 1<=len(values)<=3:raise ValueError('Attach between one and three images')
    items=[validate_image(value) for value in values]
    if sum(x['size_bytes'] for x in items)>10*1024*1024:raise ValueError('Aggregate image upload exceeds 10 MB')
    return items[0] if len(items)==1 else {'items':items,'mime':'multiple','size_bytes':sum(x['size_bytes'] for x in items)}


def image_metadata(image):
    if not image:return None
    return {k:v for k,v in image.items() if k not in ('data_url','items')} | ({'images':[{k:v for k,v in item.items() if k!='data_url'} for item in image['items']]} if 'items' in image else {})
