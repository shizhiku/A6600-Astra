"""Download an isolated host patchelf wheel from PyPI, verify its published SHA256,
extract only the executable. Does not install or modify system packages."""
import urllib.request,json,hashlib,zipfile,io,os
from pathlib import Path
out=Path('/root/astra/97/tools');out.mkdir(parents=True,exist_ok=True)
info=json.load(urllib.request.urlopen('https://pypi.org/pypi/patchelf/json',timeout=30))
xs=[x for x in info['urls'] if x['filename'].endswith('.whl') and 'manylinux' in x['filename'] and 'x86_64' in x['filename']]
if not xs:raise SystemExit('No Linux x86_64 wheel found')
x=sorted(xs,key=lambda x:x['filename'])[0];data=urllib.request.urlopen(x['url'],timeout=60).read();digest=hashlib.sha256(data).hexdigest()
if digest!=x['digests']['sha256']:raise SystemExit('Digest mismatch')
z=zipfile.ZipFile(io.BytesIO(data));names=[n for n in z.namelist() if n.endswith('/patchelf') and ('/bin/' in n or '.data/scripts/' in n)]
if len(names)!=1:raise SystemExit('Ambiguous executable '+str(z.namelist()))
p=out/'patchelf';p.write_bytes(z.read(names[0]));p.chmod(0o755)
(out/'patchelf-receipt.json').write_text(json.dumps({'version':info['info']['version'],'wheel':x['filename'],'url':x['url'],'wheel_sha256':digest,'binary_sha256':hashlib.sha256(p.read_bytes()).hexdigest()},indent=2));print(p)
