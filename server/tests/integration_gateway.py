#!/usr/bin/env python3
"""Compare real TLS traffic against supplied original and extended gateway.
Run after building both with the same Go version:
python3 tests/integration_gateway.py /path/to/original /path/to/current
"""
import hashlib,hmac,http.client,json,os,socket,ssl,subprocess,sys,tempfile,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
secret='integration-key-'+'a'*40
class Backend(BaseHTTPRequestHandler):
 def do_POST(self):
  body=self.rfile.read(int(self.headers.get('Content-Length',0)))
  data=json.dumps({'method':self.command,'uri':self.path,'body':body.hex(),'signature':self.headers.get('X-Signature'),'timestamp':self.headers.get('X-Signature-Timestamp'),'role':self.server.role,'custom':self.headers.get('X-Custom')},sort_keys=True).encode()
  self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
 def log_message(self,*a):pass

def free_port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

def exercise(binary,cert,key,backends,decoy):
 port=free_port();cfg={'EDGE_ADDR':f'127.0.0.1:{port}','EDGE_CERT_FILE':str(cert),'EDGE_KEY_FILE':str(key),'EDGE_HMAC_SECRET':secret,'EDGE_DECOY_ORIGIN':f'http://127.0.0.1:{decoy}','EDGE_ALLOW_INSECURE_DECOY':'true','EDGE_INTERNAL_BACKENDS':','.join(f'http://127.0.0.1:{p}' for p in backends)}
 if binary==sys.argv[2]:
  valid=subprocess.run([binary,'--check-config'],env={'PATH':os.environ['PATH'],**cfg},capture_output=True,timeout=5)
  assert valid.returncode==0,valid.stderr
  bad=subprocess.run([binary,'--check-config'],env={'PATH':os.environ['PATH'],**cfg,'EDGE_MAX_HEADER_BYTES':'0'},capture_output=True,timeout=5)
  assert bad.returncode!=0,'invalid tuning accepted'
 proc=subprocess.Popen([binary],env={'PATH':os.environ['PATH'],**cfg},stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 try:
  for _ in range(100):
   if proc.poll() is not None:raise RuntimeError(proc.stderr.read().decode())
   try:
    with socket.create_connection(('127.0.0.1',port),.1):break
   except OSError:time.sleep(.05)
  ctx=ssl._create_unverified_context();results=[]
  for case in ('valid','valid','invalid','expired','missing','valid'):
   path='/echo%2Ftest?q=%2F&order=1';ts=str(int(time.time())-(900 if case=='expired' else 0))
   sig=hmac.new(secret.encode(),f'{ts}\nPOST\n{path}\n'.encode(),hashlib.sha256).hexdigest()
   headers={'X-Custom':'retained'}
   if case!='missing':headers.update({'X-Signature':sig if case!='invalid' else '00'*32,'X-Signature-Timestamp':ts})
   conn=http.client.HTTPSConnection('127.0.0.1',port,context=ctx,timeout=3);conn.request('POST',path,b'raw\x00\xffbody',headers);r=conn.getresponse();results.append((r.status,json.loads(r.read())));conn.close()
  assert [r[1]['role'] for r in results]==['backend-1','backend-2','decoy','decoy','decoy','backend-1']
  return results
 finally:
  proc.terminate();proc.wait(timeout=5);proc.stderr.close()

def main():
 servers=[]
 try:
  for role in ('backend-1','backend-2','decoy'):
   s=ThreadingHTTPServer(('127.0.0.1',0),Backend);s.role=role;threading.Thread(target=s.serve_forever,daemon=True).start();servers.append(s)
  with tempfile.TemporaryDirectory() as d:
   cert=Path(d)/'cert.pem';key=Path(d)/'key.pem'
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   ports=[s.server_address[1] for s in servers]
   original=exercise(sys.argv[1],cert,key,ports[:2],ports[2]);current=exercise(sys.argv[2],cert,key,ports[:2],ports[2]);assert original==current,(original,current)
   print('PASS: 6 real HTTPS cases; original and current match exactly for status and observed request bytes/headers/routing.')
 finally:
  for s in servers:s.shutdown();s.server_close()
if __name__=='__main__':main()
