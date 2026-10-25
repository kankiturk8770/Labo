#!/usr/bin/env python3
"""Local-first, dependency-free management plane. No code runs from user input."""
import argparse
import getpass
import hashlib
import hmac
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import secrets
import ssl
import threading
import time
from urllib.parse import urlsplit

from control import Controller, Conflict, atomic
from schema import DEFAULTS, SCHEMA

HERE=Path(__file__).resolve().parent

def password_record(password):
 if len(password)<14 or len(password)>256:raise ValueError('گذرواژه باید بین ۱۴ و ۲۵۶ کاراکتر باشد')
 salt=secrets.token_hex(24)
 digest=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),600000).hex()
 return {'salt':salt,'digest':digest,'iterations':600000}

def verify_password(password,record):
 if not isinstance(password,str) or len(password)>256:return False
 digest=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(record['salt']),record['iterations']).hex()
 return hmac.compare_digest(digest,record['digest'])

class App:
 def __init__(self,controller,host,port,tls=False,public_host=''):
  self.control=controller;self.tls=tls;self.sessions={};self.failures={};self.guard=threading.RLock()
  self.allowed_hosts={f'127.0.0.1:{port}',f'localhost:{port}',f'[::1]:{port}'}
  if public_host:self.allowed_hosts.add(public_host)
  self.authfile=controller.state/'auth.json';self.pending_apply=False
 def auth(self):return json.loads(self.authfile.read_text())
 def session(self,token):
  with self.guard:
   now=time.time();self.sessions={k:v for k,v in self.sessions.items() if v['expires']>now}
   return self.sessions.get(token)
 def login(self,password,ip):
  with self.guard:
   now=time.time()
   self.failures={k:[t for t in v if now-t<900] for k,v in self.failures.items() if any(now-t<900 for t in v)}
   # Global and per-peer bounds, including concurrent attempts.
   if len(self.failures.get(ip,[]))>=5 or sum(map(len,self.failures.values()))>=30:raise PermissionError('تلاش زیاد؛ ۱۵ دقیقه بعد دوباره امتحان کنید')
   self.failures.setdefault(ip,[]).append(now)
  ok=verify_password(password,self.auth())
  with self.guard:
   if not ok:self.control.audit('login_failed');raise PermissionError('گذرواژه درست نیست')
   self.failures.pop(ip,None)
   token=secrets.token_urlsafe(32);session={'csrf':secrets.token_urlsafe(32),'expires':time.time()+8*3600}
   self.sessions={k:v for k,v in self.sessions.items() if v['expires']>time.time()}
   if len(self.sessions)>=32:self.sessions.pop(next(iter(self.sessions)))
   self.sessions[token]=session;self.control.audit('login')
   return token,session

class Server(ThreadingHTTPServer):
 daemon_threads=True
 def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.slots=threading.BoundedSemaphore(32)
 def process_request(self,request,client_address):
  if not self.slots.acquire(False):request.close();return
  request.settimeout(15)
  try:super().process_request(request,client_address)
  except Exception:self.slots.release();raise
 def process_request_thread(self,*args):
  try:super().process_request_thread(*args)
  finally:self.slots.release()

class Handler(BaseHTTPRequestHandler):
 server_version='EdgePanel';sys_version=''
 def log_message(self,*args):pass
 @property
 def app(self):return self.server.app
 def headers_out(self,status,mime='application/json; charset=utf-8',extra=None):
  self.send_response(status);self.send_header('Content-Type',mime)
  self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff')
  self.send_header('X-Frame-Options','DENY');self.send_header('Referrer-Policy','no-referrer')
  self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
  for k,v in (extra or {}).items():self.send_header(k,v)
  self.end_headers()
 def output(self,obj,status=200,extra=None):
  body=json.dumps(obj,ensure_ascii=False).encode();self.headers_out(status,extra=extra);self.wfile.write(body)
 def token(self):
  c=cookies.SimpleCookie()
  try:c.load(self.headers.get('Cookie',''));return c['edge_session'].value if 'edge_session' in c else ''
  except cookies.CookieError:return ''
 def request_guard(self):
  host=self.headers.get('Host','')
  if host not in self.app.allowed_hosts:raise PermissionError('Host مجاز نیست')
  origin=self.headers.get('Origin')
  if origin and origin!=('https' if self.app.tls else 'http')+'://'+host:raise PermissionError('Origin مجاز نیست')
 def cookie(self,token,expire=False):return 'edge_session='+token+'; HttpOnly; SameSite=Strict; Path=/; Max-Age='+('0' if expire else '28800')+('; Secure' if self.app.tls else '')
 def do_GET(self):self.dispatch(False)
 def do_POST(self):self.dispatch(True)
 def dispatch(self,post):
  try:
   self.request_guard();path=urlsplit(self.path).path
   if not post and path in ('/','/app.js','/style.css'):
    name={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}[path]
    mime={'/':'text/html; charset=utf-8','/app.js':'text/javascript; charset=utf-8','/style.css':'text/css; charset=utf-8'}[path]
    self.headers_out(200,mime);self.wfile.write((HERE/'static'/name).read_bytes());return
   data={}
   if post:
    if self.headers.get('Content-Type','').split(';')[0]!='application/json':raise ValueError('JSON لازم است')
    if self.headers.get('Transfer-Encoding'):raise ValueError('Transfer-Encoding مجاز نیست')
    size=int(self.headers.get('Content-Length','0'))
    if not 0<size<=524288:raise ValueError('اندازهٔ درخواست نامعتبر است')
    data=json.loads(self.rfile.read(size))
    if not isinstance(data,dict):raise ValueError('JSON object لازم است')
   if path=='/api/login' and post:
    token,session=self.app.login(data.get('password',''),self.client_address[0]);self.output({'csrf':session['csrf']},extra={'Set-Cookie':self.cookie(token)});return
   session=self.app.session(self.token())
   if not session:self.output({'error':'ابتدا وارد شوید'},401);return
   if post and not hmac.compare_digest(self.headers.get('X-CSRF-Token',''),session['csrf']):raise PermissionError('CSRF token نامعتبر است؛ دوباره وارد شوید')
   c=self.app.control
   if not post:
    if path=='/api/state':self.output({**c.public(),'schema':SCHEMA,'csrf':session['csrf'],'status':c.service.status(),'history':c.history(),'certificate':c.certificate_info()});return
    if path=='/api/status':self.output(c.service.status());return
    if path=='/api/logs':
     secret=c.read()['EDGE_HMAC_SECRET'];logs=c.service.logs()
     if secret:logs=logs.replace(secret,'[REDACTED]')
     audit=c.state/'audit.jsonl';self.output({'logs':logs,'audit':audit.read_text()[-30000:] if audit.exists() else ''});return
    if path=='/api/source':
     source=HERE.parent/'main.go';original=HERE.parent/'original/main.go'
     self.output({'source':source.read_text(),'original_sha256':hashlib.sha256(original.read_bytes()).hexdigest(),'current_sha256':hashlib.sha256(source.read_bytes()).hexdigest()});return
   else:
    if path=='/api/logout':
     with self.app.guard:self.app.sessions.pop(self.token(),None)
     self.output({'ok':True},extra={'Set-Cookie':self.cookie('',True)});return
    if path=='/api/password':
     if not verify_password(data.get('old',''),self.app.auth()):raise PermissionError('گذرواژهٔ فعلی درست نیست')
     record=password_record(data.get('new',''));atomic(self.app.authfile,json.dumps(record))
     with self.app.guard:self.app.sessions.clear()
     c.audit('password_changed');self.output({'ok':True},extra={'Set-Cookie':self.cookie('',True)});return
    if path=='/api/validate':c.prepare(data.get('config'));self.output({'ok':True});return
    if path=='/api/apply':self.output(c.apply(data.get('config'),data.get('revision')));return
    if path=='/api/rollback':self.output(c.apply(c.old_config(data.get('id','')),data.get('revision')));return
    if path=='/api/certificates':self.output(c.upload_cert(data.get('certificate'),data.get('private_key')));return
    if path=='/api/generate-secret':self.output({'secret':secrets.token_hex(32)});return
    if path=='/api/backup':c.audit('backup_export');self.output(c.backup(),extra={'Content-Disposition':'attachment; filename="edge-backup.json"'});return
    if path=='/api/import':self.output({'config':c.import_backup(data.get('backup'))});return
    if path=='/api/diagnostics':self.output({'results':c.diagnostics(data.get('config'))});return
    if path=='/api/service':
     a=data.get('action')
     if a not in ('start','stop','restart','enable','disable'):raise ValueError('عملیات سرویس نامعتبر است')
     with c.transaction_lock():
      if c.tx.exists():raise Conflict('تراکنش بازیابی‌نشده وجود دارد')
      if a in ('start','restart'):c.prepare(c.read())
      c.service.action(a)
      if a in ('start','restart') and not c.service.healthy(c.read()):raise ValueError('سرویس آماده نشد؛ لاگ‌ها را بررسی کنید')
      c.audit('service',action=a)
     self.output(c.service.status());return
   self.output({'error':'مسیر یافت نشد'},404)
  except Conflict as e:self.output({'error':str(e)},409)
  except PermissionError as e:self.output({'error':str(e)},403)
  except (ValueError,TypeError,KeyError,FileNotFoundError,ssl.SSLError) as e:self.output({'error':str(e)},400)
  except (BrokenPipeError,ConnectionResetError):pass
  except Exception:
   self.app.control.audit('internal_error');self.output({'error':'خطای داخلی؛ وضعیت سرویس و لاگ پنل را بررسی کنید'},500)

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--host',default='127.0.0.1');parser.add_argument('--port',type=int,default=9090)
 parser.add_argument('--root',default='/');parser.add_argument('--demo',action='store_true');parser.add_argument('--init-password',action='store_true')
 parser.add_argument('--tls-cert');parser.add_argument('--tls-key');parser.add_argument('--public-host',default='')
 a=parser.parse_args();os.umask(0o077);os.environ['EDGE_PANEL_PORT']=str(a.port)
 if a.demo and a.root=='/':parser.error('--demo requires a non-root --root directory')
 c=Controller(a.root,a.demo)
 if a.init_password:
  pw=getpass.getpass('New admin password (14+ characters): ')
  if pw!=getpass.getpass('Repeat password: '):parser.error('Passwords differ')
  atomic(c.state/'auth.json',json.dumps(password_record(pw)));print('Password updated. Restart edge-panel to invalidate sessions.');return
 if not (c.state/'auth.json').exists():parser.error('Initialize credentials with --init-password first')
 try:loopback=ipaddress.ip_address(a.host).is_loopback
 except ValueError:loopback=a.host=='localhost'
 if not loopback and not (a.tls_cert and a.tls_key and a.public_host):parser.error('Public bind requires --tls-cert, --tls-key and --public-host HOST:PORT')
 c.recover()
 server=Server((a.host,a.port),Handler);server.app=App(c,a.host,a.port,bool(a.tls_cert),a.public_host)
 if a.tls_cert:
  ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.load_cert_chain(a.tls_cert,a.tls_key);server.socket=ctx.wrap_socket(server.socket,server_side=True)
 print(f'Edge Panel on {a.host}:{a.port}; demo={a.demo}',flush=True)
 try:server.serve_forever()
 except KeyboardInterrupt:pass
 finally:server.server_close()

if __name__=='__main__':main()
