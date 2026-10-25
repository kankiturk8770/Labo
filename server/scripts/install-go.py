#!/usr/bin/env python3
"""Fetch an official stable Go release and verify its published SHA256."""
import hashlib,json,os,platform,shutil,tarfile,tempfile,urllib.request
from pathlib import Path
arch={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine())
if not arch:raise SystemExit('Supported architectures: amd64, arm64')
with urllib.request.urlopen('https://go.dev/dl/?mode=json',timeout=30) as r:releases=json.load(r)
release=next(r for r in releases if r.get('stable'))
f=next(f for f in release['files'] if f['os']=='linux' and f['arch']==arch and f['kind']=='archive')
base=Path('/opt/edge-go');base.mkdir(mode=0o755,parents=True,exist_ok=True)
dest=base/release['version']
if not (dest/'go/bin/go').exists():
 with tempfile.TemporaryDirectory(dir=base) as d:
  archive=Path(d)/'go.tar.gz';h=hashlib.sha256()
  with urllib.request.urlopen('https://go.dev/dl/'+f['filename'],timeout=120) as response,archive.open('wb') as out:
   while True:
    b=response.read(1048576)
    if not b:break
    h.update(b);out.write(b)
  if h.hexdigest()!=f['sha256']:raise SystemExit('Go SHA256 mismatch')
  stage=Path(d)/'unpack';stage.mkdir()
  with tarfile.open(archive) as tar:
   for member in tar.getmembers():
    if not (stage/member.name).resolve().is_relative_to(stage.resolve()) or member.issym() or member.islnk():raise SystemExit('Unexpected archive member')
   tar.extractall(stage)
  os.replace(stage,dest)
print(dest/'go/bin/go')
