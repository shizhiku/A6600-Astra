"""Create a NEW emulator-only image copying an existing variant and replacing
/lib/astra.so with a new bridge. Source image is never modified.
"""
from pathlib import Path
import argparse,shutil,subprocess,hashlib,json
R=Path('<WORKSPACE>')
P=argparse.ArgumentParser();P.add_argument('--image',required=True);P.add_argument('--bridge',required=True);P.add_argument('--output',required=True);A=P.parse_args()
src=Path(A.image);dst=Path(A.output);br=Path(A.bridge)
if dst.exists() or src.resolve()==dst.resolve():raise SystemExit('Output must be new')
D=dst.parent/(dst.stem+'-patch');D.mkdir(exist_ok=False,parents=True)
cmd=D/'commands';cmd.write_text('rm /lib/astra.so\nwrite '+str(br)+' /lib/astra.so\nsif /lib/astra.so mode 0100755\n')
shutil.copy2(src,dst)
x=subprocess.run(['debugfs','-w','-f',str(cmd),str(dst)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT);(D/'debugfs.log').write_bytes(x.stdout)
if x.returncode:raise SystemExit('debugfs failed')
# semantic verify
import importlib.util
s=importlib.util.spec_from_file_location('u',R/'02-脚本/a6600_usr.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.Ext2=__import__('97_ext2').Ext2
f=m.Ext2(str(dst));idx={p:i for p,i,dr in f.walk()if not dr}
payload=f.read_file(idx['/lib/astra.so'])
if hashlib.sha256(payload).hexdigest()!=hashlib.sha256(br.read_bytes()).hexdigest():raise SystemExit('verify failed')
rep={'source':str(src),'source_sha256':hashlib.sha256(src.read_bytes()).hexdigest(),'image':str(dst),'image_sha256':hashlib.sha256(dst.read_bytes()).hexdigest(),'bridge':str(br),'bridge_sha256':hashlib.sha256(br.read_bytes()).hexdigest(),'verified':True}
(D/'manifest.json').write_text(json.dumps(rep,indent=2));arc=R/'03-证据/ASTRA-97'/D.name;arc.mkdir(exist_ok=False,parents=True)
for n in ['manifest.json','debugfs.log']:shutil.copy2(D/n,arc/n)
print(json.dumps(rep,indent=2))
