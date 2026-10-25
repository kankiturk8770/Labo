#!/usr/bin/env python3
"""Local UI preview. Does not install services or change system settings."""
import json,os,secrets,subprocess,sys,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1];sys.path.insert(0,str(root/'panel'))
from control import Controller,atomic
from schema import DEFAULTS
from server import password_record
base=Path(tempfile.mkdtemp(prefix='edge-demo-'));c=Controller(base,True)
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(base/'key'),'-out',str(base/'cert'),'-days','1','-subj','/CN=localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
pair=c.upload_cert((base/'cert').read_text(),(base/'key').read_text());cfg=dict(DEFAULTS);cfg.update(EDGE_HMAC_SECRET=secrets.token_hex(32),EDGE_DECOY_ORIGIN='https://example.com',EDGE_CERT_FILE=pair['cert'],EDGE_KEY_FILE=pair['key']);c.write(cfg)
pw=os.environ.get('EDGE_DEMO_PASSWORD') or secrets.token_urlsafe(20);atomic(c.state/'auth.json',json.dumps(password_record(pw)))
print('Demo only. URL: http://127.0.0.1:9090\nPassword: '+pw+'\nTemporary data: '+str(base),flush=True)
os.execv(sys.executable,[sys.executable,str(root/'panel/server.py'),'--demo','--root',str(base)])
