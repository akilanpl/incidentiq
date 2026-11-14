"""Local salted-password accounts and library-signed sessions."""
import hashlib,hmac,json,os,secrets,tempfile,threading,time
from pathlib import Path
from dotenv import load_dotenv,set_key
from itsdangerous import URLSafeTimedSerializer,BadSignature,SignatureExpired
COOKIE='incidentiq_session'
TTL=28800
ROLES=('admin','responder','viewer')
def password_hash(password,salt):return hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=16384,r=8,p=1,dklen=32).hex()
class LocalAuth:
 def __init__(self,enabled=True,username='',salt='',digest='',secret='',revocation_path=None,users_path=None):
  self.enabled=enabled;self.username=username;self.salt=salt;self.digest=digest;self.secret=secret;self.revocation_path=Path(revocation_path) if revocation_path else None;self.users_path=Path(users_path) if users_path else None;self.revoked={};self.attempts={};self.lock=threading.RLock()
  self.accounts={username:{'salt':salt,'hash':digest,'role':'admin'}} if username and len(salt)==32 and len(digest)==64 else {}
  if self.users_path and self.users_path.exists():self.accounts=json.loads(self.users_path.read_text())
  elif self.users_path and self.accounts:self._save_users()
 @classmethod
 def from_env(cls,offline=False):
  if offline:return cls(enabled=False)
  root=Path(__file__).resolve().parent.parent;load_dotenv(root/'.env.auth')
  return cls(os.getenv('INCIDENTIQ_AUTH_ENABLED','1')=='1',os.getenv('INCIDENTIQ_USERNAME',''),os.getenv('INCIDENTIQ_PASSWORD_SALT',''),os.getenv('INCIDENTIQ_PASSWORD_HASH',''),os.getenv('INCIDENTIQ_SESSION_SECRET',''),root/'data/session-revocations.json',root/'data/users.json')
 def _atomic(self,path,data):
  path.parent.mkdir(parents=True,exist_ok=True);fd,name=tempfile.mkstemp(prefix='.users-',dir=path.parent)
  try:
   with os.fdopen(fd,'w') as f:json.dump(data,f);f.flush();os.fsync(f.fileno())
   os.replace(name,path)
  finally:
   if os.path.exists(name):os.unlink(name)
 def _save_users(self):
  if self.users_path:self._atomic(self.users_path,self.accounts)
 def _users(self):
  if self.users_path and self.users_path.exists():self.accounts=json.loads(self.users_path.read_text())
  return self.accounts
 @property
 def configured(self):return len(self.secret)>=32 and any(u['role']=='admin' for u in self._users().values())
 def add_user(self,username,password,role):
  if role not in ROLES or not username or len(username)>120 or not all(c.isalnum() or c in '._-' for c in username):raise ValueError('Invalid username or role')
  if not 12<=len(password)<=1024:raise ValueError('Password must contain 12–1024 characters')
  with self.lock:
   users=self._users()
   if username in users:raise ValueError('Username already exists')
   salt=secrets.token_hex(16);users[username]={'salt':salt,'hash':password_hash(password,salt),'role':role};self._save_users()
  return {'username':username,'role':role}
 def change_role(self,username,role):
  if role not in ROLES:raise ValueError('Invalid role')
  with self.lock:
   users=self._users()
   if username not in users:raise ValueError('Unknown user')
   if users[username]['role']=='admin' and role!='admin' and sum(u['role']=='admin' for u in users.values())<=1:raise ValueError('Cannot remove last administrator')
   users[username]['role']=role;self._save_users()
  return {'username':username,'role':role}
 def list_users(self):return [{'username':k,'role':v['role']} for k,v in self._users().items()]
 def setup_admin(self,username,password):
  with self.lock:
   if self.configured:raise ValueError('Administrator already configured')
   if not self.secret:
    self.secret=secrets.token_hex(32)
    if self.users_path:
     path=self.users_path.parent.parent/'.env.auth';path.touch(mode=0o600,exist_ok=True);set_key(path,'INCIDENTIQ_SESSION_SECRET',self.secret);path.chmod(0o600)
   user=self.add_user(username,password,'admin');self.username=username;return user
 def check_password(self,username,password):
  user=self._users().get(username)
  if not user or not self.configured:return False
  try:return hmac.compare_digest(password_hash(password,user['salt']),user['hash'])
  except (ValueError,TypeError):return False
 def rate_limited(self,ip):
  with self.lock:
   now=time.time();self.attempts={k:[t for t in v if now-t<60] for k,v in self.attempts.items() if any(now-t<60 for t in v)};times=self.attempts.setdefault(ip,[])
   if len(times)>=5:return True
   times.append(now);return False
 def serializer(self,salt='session'):return URLSafeTimedSerializer(self.secret,salt='incidentiq-'+salt)
 def issue(self,username=None):return self.serializer().dumps({'user':username or self.username,'exp':int(time.time())+TTL,'nonce':secrets.token_hex(16)})
 def verify(self,token):
  if not token or not self.configured:return None
  try:
   data=self.serializer().loads(token,max_age=TTL);now=time.time()
   with self.lock:
    if self.revocation_path and self.revocation_path.exists():self.revoked=json.loads(self.revocation_path.read_text())
    self.revoked={k:v for k,v in self.revoked.items() if v>now};revoked=data['nonce'] in self.revoked
   user=self._users().get(data['user'])
   if data['exp']<=now or not user or revoked:return None
   return dict(data,role=user['role'])
  except (BadSignature,SignatureExpired,ValueError,KeyError,TypeError):return None
 def revoke(self,token):
  data=self.verify(token)
  if data:
   with self.lock:
    self.revoked[data['nonce']]=data['exp']
    if self.revocation_path:self._atomic(self.revocation_path,self.revoked)
