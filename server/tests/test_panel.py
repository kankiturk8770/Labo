import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'panel'))
from control import Controller,Conflict,atomic,DemoService
from schema import DEFAULTS,SCHEMA,address,decode_env,duration,encode_env,validate
from server import App,Handler,Server,password_record,verify_password

class PanelTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.certs=tempfile.TemporaryDirectory();d=Path(cls.certs.name)
  subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(d/'key'),'-out',str(d/'cert'),'-days','1','-subj','/CN=localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  cls.cert=(d/'cert').read_text();cls.key=(d/'key').read_text()
 @classmethod
 def tearDownClass(cls):cls.certs.cleanup()
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.c=Controller(self.tmp.name,True)
  pair=self.c.upload_cert(self.cert,self.key);self.cfg=dict(DEFAULTS);self.cfg.update(EDGE_HMAC_SECRET='a'*64,EDGE_DECOY_ORIGIN='https://example.com',EDGE_CERT_FILE=pair['cert'],EDGE_KEY_FILE=pair['key'])
  self.c.write(self.cfg)
 def test_schema_coverage(self):
  import re
  source=(ROOT/'main.go').read_text()+(ROOT/'tuning.go').read_text()
  found=set(re.findall(r'"(EDGE_[A-Z_]+)"',source))
  self.assertEqual(found,set(DEFAULTS));self.assertEqual(len(found),18)
 def test_defaults_match_original(self):
  self.assertEqual(DEFAULTS['EDGE_MAX_HEADER_BYTES'],'65536');self.assertEqual(DEFAULTS['EDGE_SIGNATURE_MAX_SKEW'],'5m')
 def test_env_roundtrip(self):
  cfg=dict(self.cfg);cfg['EDGE_HMAC_SECRET']='a'*32+'"\\$` = #ع'
  self.assertEqual(decode_env(encode_env(cfg)),cfg)
 def test_validation(self):
  validate(self.cfg)
  for key,value in [('EDGE_ADDR',':0'),('EDGE_MAX_HEADER_BYTES','1'),('EDGE_TLS_MIN_VERSION','1.0'),('EDGE_HMAC_SECRET','short'),('EDGE_SIGNATURE_MAX_SKEW','-1s'),('EDGE_KEY_FILE','/etc/shadow'),('EDGE_DECOY_ORIGIN','http://example.com'),('EDGE_INTERNAL_BACKENDS','https://u:p@host'),('EDGE_INTERNAL_BACKENDS','https://host/#a'),('EDGE_HMAC_SECRET','a'*32+'\nINJECT=1')]:
   with self.subTest(key=key,value=value),self.assertRaises(ValueError):validate(self.cfg|{key:value})
 def test_duration_ipv6(self):
  self.assertEqual(duration('1m30s'),90);self.assertEqual(duration('500ms'),.5);self.assertEqual(address('[::1]:443'),('::1',443))
 def test_secret_not_exposed(self):
  self.assertEqual(self.c.public()['config']['EDGE_HMAC_SECRET'],'');self.assertTrue(self.c.public()['has_secret'])
 def test_apply_success_and_history(self):
  revision=self.c.revision();self.c.apply(self.cfg|{'EDGE_ADDR':':9443'},revision)
  self.assertEqual(self.c.read()['EDGE_ADDR'],':9443');self.assertTrue(self.c.service.active);self.assertEqual(len(self.c.history()),1);self.assertFalse(self.c.tx.exists())
 def test_blank_secret_preserved(self):
  self.c.apply(self.cfg|{'EDGE_HMAC_SECRET':''},self.c.revision());self.assertEqual(self.c.read()['EDGE_HMAC_SECRET'],self.cfg['EDGE_HMAC_SECRET'])
 def test_conflict_rejects_stale_tab(self):
  with self.assertRaises(Conflict):self.c.apply(self.cfg,'stale')
 def test_apply_failure_restores_inactive(self):
  before=self.c.config.read_bytes()
  with patch.object(self.c.service,'healthy',return_value=False),self.assertRaises(ValueError):self.c.apply(self.cfg|{'EDGE_ADDR':':9443'},self.c.revision())
  self.assertEqual(before,self.c.config.read_bytes());self.assertFalse(self.c.service.active);self.assertFalse(self.c.tx.exists())
 def test_apply_failure_restores_running(self):
  self.c.service.active=True
  with patch.object(self.c.service,'healthy',side_effect=[False,True]),self.assertRaises(ValueError):self.c.apply(self.cfg|{'EDGE_ADDR':':9443'},self.c.revision())
  self.assertTrue(self.c.service.active);self.assertEqual(self.c.read(),self.cfg)
 def test_failed_rollback_retains_journal(self):
  self.c.service.active=True
  with patch.object(self.c.service,'healthy',return_value=False),self.assertRaises(ValueError):self.c.apply(self.cfg|{'EDGE_ADDR':':9443'},self.c.revision())
  self.assertTrue(self.c.tx.exists())
  with self.assertRaises(Conflict):self.c.apply(self.cfg,self.c.revision())
 def test_crash_recovery(self):
  atomic(self.c.tx,json.dumps({'old':self.cfg,'active':False}));self.c.write(self.cfg|{'EDGE_ADDR':':9443'});self.c.recover()
  self.assertEqual(self.c.read(),self.cfg);self.assertFalse(self.c.tx.exists())
 def test_backup_import(self):
  exported=self.c.backup();loaded=self.c.import_backup(exported)
  self.assertEqual(loaded['EDGE_HMAC_SECRET'],self.cfg['EDGE_HMAC_SECRET']);self.assertNotEqual(loaded['EDGE_CERT_FILE'],self.cfg['EDGE_CERT_FILE']);self.c.prepare(loaded)
 def test_bad_certificate(self):
  with self.assertRaises(ValueError):self.c.upload_cert('bad','bad')
 def test_permissions(self):
  self.assertEqual(self.c.config.stat().st_mode&0o777,0o640)
  atomic(self.c.state/'secret','secret');self.assertEqual((self.c.state/'secret').stat().st_mode&0o777,0o600)
 def test_history_traversal(self):
  with self.assertRaises(ValueError):self.c.old_config('../../etc/shadow')
 def test_unknown_key(self):
  with self.assertRaises(ValueError):validate(self.cfg|{'LD_PRELOAD':'anything'})
 def test_concurrent_apply(self):
  revision=self.c.revision();results=[]
  def apply(port):
   try:self.c.apply(self.cfg|{'EDGE_ADDR':port},revision);results.append('ok')
   except Conflict:results.append('conflict')
  threads=[threading.Thread(target=apply,args=(p,)) for p in [':9443',':9444']]
  for t in threads:t.start()
  for t in threads:t.join()
  self.assertCountEqual(results,['ok','conflict'])
 def test_credentials(self):
  r=password_record('test-password-12345');self.assertTrue(verify_password('test-password-12345',r));self.assertFalse(verify_password('incorrect',r))
 def test_http_auth_csrf_and_host(self):
  atomic(self.c.state/'auth.json',json.dumps(password_record('test-password-12345')))
  server=Server(('127.0.0.1',0),Handler);port=server.server_address[1];server.app=App(self.c,'127.0.0.1',port)
  thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
  self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
  def req(method,path,body=None,headers=None):
   conn=http.client.HTTPConnection('127.0.0.1',port,timeout=3);headers=headers or {}
   if body is not None:headers['Content-Type']='application/json'
   conn.request(method,path,json.dumps(body) if body is not None else None,headers);r=conn.getresponse();data=r.read();result=(r.status,dict(r.getheaders()),json.loads(data) if 'application/json' in r.getheader('Content-Type','') else data);conn.close();return result
  self.assertEqual(req('GET','/api/state')[0],401)
  self.assertEqual(req('GET','/',headers={'Host':'evil.example'})[0],403)
  self.assertEqual(req('POST','/api/login',{'password':'test-password-12345'},headers={'Origin':'http://evil.example'})[0],403)
  status,h,r=req('POST','/api/login',{'password':'test-password-12345'});self.assertEqual(status,200);self.assertIn('HttpOnly',h['Set-Cookie']);cookie=h['Set-Cookie'].split(';')[0]
  self.assertEqual(req('GET','/api/state',headers={'Cookie':cookie})[0],200)
  self.assertEqual(req('POST','/api/generate-secret',{},headers={'Cookie':cookie})[0],403)
  st,_,result=req('POST','/api/generate-secret',{},headers={'Cookie':cookie,'X-CSRF-Token':r['csrf']});self.assertEqual(st,200);self.assertEqual(len(result['secret']),64)
  self.assertEqual(req('POST','/api/service',{'action':'anything'},headers={'Cookie':cookie,'X-CSRF-Token':r['csrf']})[0],400)
  req('POST','/api/logout',{},headers={'Cookie':cookie,'X-CSRF-Token':r['csrf']});self.assertEqual(req('GET','/api/state',headers={'Cookie':cookie})[0],401)
 def test_rate_limit(self):
  atomic(self.c.state/'auth.json',json.dumps(password_record('test-password-12345')));app=App(self.c,'127.0.0.1',9090)
  for _ in range(5):
   with self.assertRaises(PermissionError):app.login('wrong','127.0.0.1')
  with self.assertRaisesRegex(PermissionError,'۱۵'):app.login('test-password-12345','127.0.0.1')

if __name__=='__main__':unittest.main()
