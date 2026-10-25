import contextlib
import datetime
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from schema import DEFAULTS, address, decode_env, duration, encode_env, target, validate

class Conflict(ValueError): pass

def run(args, *, env=None, timeout=20, check=True):
 r=subprocess.run(args,env=env,capture_output=True,text=True,timeout=timeout)
 if check and r.returncode: raise ValueError((r.stderr or r.stdout or 'عملیات ناموفق بود')[-2000:])
 return r

def atomic(path, data, mode=0o600, gid=None):
 path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
 fd,tmp=tempfile.mkstemp(prefix='.write-',dir=path.parent)
 try:
  with os.fdopen(fd,'wb') as f:
   f.write(data.encode() if isinstance(data,str) else data);f.flush();os.fsync(f.fileno())
   os.fchmod(f.fileno(),mode)
   if gid is not None: os.fchown(f.fileno(),0,gid)
  os.replace(tmp,path)
  d=os.open(path.parent,os.O_DIRECTORY)
  try: os.fsync(d)
  finally: os.close(d)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)

class SystemService:
 def action(self,action):
  if action not in ('start','stop','restart','enable','disable'):raise ValueError('عملیات سرویس نامعتبر')
  if action in ('start','restart'):run(['/usr/bin/systemctl','reset-failed','edge-gateway.service'],check=False)
  run(['/usr/bin/systemctl',action,'edge-gateway.service'],timeout=340)
 def status(self):
  r=run(['/usr/bin/systemctl','show','edge-gateway.service','--property=ActiveState,SubState,MainPID,UnitFileState,MemoryCurrent,TasksCurrent,ExecMainStatus,ActiveEnterTimestamp'],check=False)
  return dict(x.split('=',1) for x in r.stdout.splitlines() if '=' in x)
 def logs(self):
  return run(['/usr/bin/journalctl','-u','edge-gateway.service','-n','150','--no-pager','--output=short-iso'],check=False).stdout[-60000:]
 def healthy(self,cfg):
  last=None
  for _ in range(12):
   time.sleep(.5)
   st=self.status();pid=st.get('MainPID')
   if st.get('ActiveState')=='active' and pid and pid!='0':
    host,port=address(cfg['EDGE_ADDR']);host=host or '127.0.0.1'
    if host=='0.0.0.0':host='127.0.0.1'
    if host=='::':host='::1'
    try:
     ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
     # Local startup probe only. Outgoing gateway certificate validation is unchanged.
     with socket.create_connection((host,port),timeout=1) as sock:
      with ctx.wrap_socket(sock,server_hostname='localhost'):pass
     if pid==last:return True
     last=pid
    except OSError:last=None
  return False

class DemoService:
 def __init__(self):self.active=False;self.enabled=False
 def action(self,a):
  if a in ('start','restart'):self.active=True
  elif a=='stop':self.active=False
  elif a=='enable':self.enabled=True
  elif a=='disable':self.enabled=False
 def status(self):return dict(ActiveState='active' if self.active else 'inactive',SubState='running' if self.active else 'dead',MainPID='0',UnitFileState='enabled' if self.enabled else 'disabled',MemoryCurrent='0',TasksCurrent='0')
 def logs(self):return 'حالت نمایشی: هیچ سرویس واقعی کنترل نمی‌شود.'
 def healthy(self,cfg):return self.active

class Controller:
 def __init__(self,root='/',demo=False,binary='/opt/edge-gateway/edge-gateway'):
  self.root=Path(root);self.demo=demo;self.binary=binary
  self.state=self.path('/var/lib/edge-panel');self.config=self.path('/etc/edge-gateway/edge-gateway.env');self.certs=self.path('/etc/edge-gateway/certs')
  self.revisions=self.state/'revisions';self.tx=self.state/'transaction.json'
  for p in (self.state,self.revisions,self.certs):p.mkdir(parents=True,exist_ok=True)
  self.lock=threading.RLock();self.service=DemoService() if demo else SystemService()
  self.gid=None if demo else grp.getgrnam('edge-gateway').gr_gid
 def path(self,p):return self.root/str(p).lstrip('/')
 def read(self):return decode_env(self.config.read_text()) if self.config.exists() else dict(DEFAULTS)
 def revision(self):return hashlib.sha256(self.config.read_bytes() if self.config.exists() else b'').hexdigest()
 def audit(self,event,**details):
  row={'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'event':event,**details}
  with open(self.state/'audit.jsonl','a',encoding='utf-8') as f:f.write(json.dumps(row,ensure_ascii=False)+'\n')
  os.chmod(self.state/'audit.jsonl',0o600)
 @contextlib.contextmanager
 def transaction_lock(self):
  with self.lock:
   with open(self.state/'operation.lock','a') as f:
    fcntl.flock(f,fcntl.LOCK_EX)
    try:yield
    finally:fcntl.flock(f,fcntl.LOCK_UN)
 def public(self):
  cfg=self.read();has_secret=bool(cfg['EDGE_HMAC_SECRET']);cfg['EDGE_HMAC_SECRET']=''
  return {'config':cfg,'revision':self.revision(),'has_secret':has_secret,'demo':self.demo}
 def prepare(self,cfg):
  if not isinstance(cfg,dict):raise ValueError('تنظیمات باید object باشند')
  cfg=dict(cfg)
  if not cfg.get('EDGE_HMAC_SECRET'):cfg['EDGE_HMAC_SECRET']=self.read()['EDGE_HMAC_SECRET']
  validate(cfg)
  if duration(cfg['EDGE_SHUTDOWN_TIMEOUT'])>300:raise ValueError('پنل حداکثر مهلت خاموش‌شدن 300s را پشتیبانی می‌کند')
  _,port=address(cfg['EDGE_ADDR'])
  if port==int(os.environ.get('EDGE_PANEL_PORT','9090')):raise ValueError('پورت gateway با پنل تداخل دارد')
  for k in ('EDGE_CERT_FILE','EDGE_KEY_FILE'):
   p=self.path(cfg[k]); resolved=p.resolve()
   if not resolved.is_relative_to(self.certs.resolve()) or not p.is_file():raise ValueError('فایل گواهی یا کلید موجود نیست: '+cfg[k])
  ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  try:ctx.load_cert_chain(self.path(cfg['EDGE_CERT_FILE']),self.path(cfg['EDGE_KEY_FILE']),password=lambda:'')
  except (ssl.SSLError,OSError):raise ValueError('گواهی و کلید معتبر یا همسان نیستند')
  info=run(['openssl','x509','-in',str(self.path(cfg['EDGE_CERT_FILE'])),'-checkend','0','-noout'],check=False)
  if info.returncode:raise ValueError('گواهی منقضی شده یا معتبر نیست')
  # Independent validation by the actual Go executable, before writing anything.
  if not self.demo:
   env={'PATH':'/usr/bin:/bin',**cfg}
   run([self.binary,'--check-config'],env=env)
   # Verify that the unprivileged gateway account can read the configured pair.
   for k in ('EDGE_CERT_FILE','EDGE_KEY_FILE'):
    run(['/usr/sbin/runuser','-u','edge-gateway','--','/usr/bin/test','-r',cfg[k]])
  return cfg
 def write(self,cfg):atomic(self.config,encode_env(cfg),0o640,self.gid)
 def recover(self):
  with self.transaction_lock():
   if self.tx.exists():
    tx=json.loads(self.tx.read_text());self._restore(tx);self.tx.unlink();self.audit('recovery')
 def _restore(self,tx):
  if tx['old'] is None:self.config.unlink(missing_ok=True)
  else:self.write(tx['old'])
  self.service.action('restart' if tx['active'] and tx['old'] else 'stop')
  if tx['active'] and tx['old'] and not self.service.healthy(tx['old']):raise ValueError('تنظیمات قبلی برگشت، اما سرویس قبلی بالا نیامد؛ لاگ و journal را بررسی کنید')
 def apply(self,cfg,revision):
  with self.transaction_lock():
   if self.tx.exists():raise Conflict('بازیابی تراکنش قبلی لازم است؛ پنل را restart کنید')
   if revision!=self.revision():raise Conflict('تنظیمات در تب دیگری عوض شده‌اند؛ ابتدا دوباره بارگذاری کنید')
   cfg=self.prepare(cfg);old=self.read() if self.config.exists() else None
   active=self.service.status().get('ActiveState')=='active'
   tx={'old':old,'active':active}
   atomic(self.tx,json.dumps(tx))
   rid=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+secrets.token_hex(4)
   if old:atomic(self.revisions/(rid+'.json'),json.dumps(old))
   try:
    self.write(cfg);self.service.action('restart')
    if not self.service.healthy(cfg):raise ValueError('سرویس با تنظیمات جدید بالا نیامد')
   except Exception as error:
    try:self._restore(tx)
    except Exception as rollback_error:
     self.audit('rollback_failed');raise ValueError('اعمال ناموفق و بازیابی سرویس ناقص؛ فایل transaction حفظ شد. '+str(rollback_error)) from error
    self.tx.unlink();self.audit('apply_rolled_back');raise ValueError('اعمال ناموفق؛ تنظیمات و وضعیت قبلی بازیابی شد. '+str(error)) from error
   self.tx.unlink();self.audit('apply',revision=self.revision())
   # Retain the most recent 50 revisions. Certificates referenced by old revisions
   # are immutable and deliberately not deleted automatically.
   for p in sorted(self.revisions.glob('*.json'))[:-50]:p.unlink()
   return self.public()
 def history(self):return [{'id':p.stem,'created':p.stem.split('-')[0]} for p in sorted(self.revisions.glob('*.json'),reverse=True)]
 def old_config(self,rid):
  if not re.fullmatch(r'\d{8}T\d{6}-[a-f0-9]{8}',rid):raise ValueError('شناسهٔ نسخه نامعتبر است')
  return json.loads((self.revisions/(rid+'.json')).read_text())
 def upload_cert(self,cert,key):
  if not isinstance(cert,str) or not isinstance(key,str) or max(len(cert),len(key))>131072:raise ValueError('گواهی یا کلید بیش از حد بزرگ است')
  with self.transaction_lock():
   # Validate in a temporary directory first; never replace a live pair in place.
   with tempfile.TemporaryDirectory(dir=self.state) as d:
    cp=Path(d)/'cert.pem';kp=Path(d)/'key.pem';atomic(cp,cert);atomic(kp,key)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:ctx.load_cert_chain(cp,kp,password=lambda:'')
    except (ssl.SSLError,OSError):raise ValueError('گواهی یا کلید نامعتبر، رمزگذاری‌شده یا غیرهمسان است')
    if run(['openssl','x509','-in',str(cp),'-checkend','0','-noout'],check=False).returncode:raise ValueError('گواهی منقضی شده است')
    name=secrets.token_hex(12)
    atomic(self.certs/(name+'.crt'),cert,0o640,self.gid);atomic(self.certs/(name+'.key'),key,0o640,self.gid)
   self.audit('certificate_import',id=name)
   return {'cert':'/etc/edge-gateway/certs/'+name+'.crt','key':'/etc/edge-gateway/certs/'+name+'.key'}
 def certificate_info(self):
  cfg=self.read();p=self.path(cfg['EDGE_CERT_FILE'])
  if not p.is_file():return {'info':'هنوز گواهی وارد نشده است.'}
  return {'info':run(['openssl','x509','-in',str(p),'-noout','-subject','-issuer','-dates','-fingerprint','-sha256','-ext','subjectAltName'],check=False).stdout}
 def backup(self):
  with self.transaction_lock():
   cfg=self.read();return {'format':'edge-panel-backup-v1','config':cfg,'certificate':self.path(cfg['EDGE_CERT_FILE']).read_text(),'private_key':self.path(cfg['EDGE_KEY_FILE']).read_text()}
 def import_backup(self,obj):
  if not isinstance(obj,dict) or obj.get('format')!='edge-panel-backup-v1':raise ValueError('فرمت پشتیبان نامعتبر است')
  cfg=obj.get('config');validate(cfg)
  pair=self.upload_cert(obj.get('certificate'),obj.get('private_key'))
  cfg=dict(cfg);cfg['EDGE_CERT_FILE']=pair['cert'];cfg['EDGE_KEY_FILE']=pair['key'];self.prepare(cfg)
  return cfg
 def diagnostics(self,cfg):
  # No HTTP requests or shell execution: a bounded TCP reachability test only.
  cfg=dict(cfg);cfg['EDGE_HMAC_SECRET']=cfg.get('EDGE_HMAC_SECRET') or self.read()['EDGE_HMAC_SECRET'];validate(cfg)
  rows=[]
  for raw in [cfg['EDGE_DECOY_ORIGIN']]+cfg['EDGE_INTERNAL_BACKENDS'].split(',')[:16]:
   u=target(raw);port=u.port or (443 if u.scheme in ('https','wss') else 80);start=time.monotonic()
   try:
    with socket.create_connection((u.hostname,port),timeout=1):pass
    rows.append({'target':raw,'ok':True,'ms':round((time.monotonic()-start)*1000)})
   except OSError as e:rows.append({'target':raw,'ok':False,'error':str(e)})
  return rows
