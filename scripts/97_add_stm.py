"""Add the audited gen5 STM root dependency to NEW experimental ext2 copies.
Never modifies input images or camera media. Preserves payload code except exact
same-length filename renames in private gen5 ELF strings.
"""
from pathlib import Path
import argparse,importlib.util,shutil,hashlib,json,subprocess
R=Path('<WORKSPACE>');a=argparse.ArgumentParser();a.add_argument('--image',required=True);a.add_argument('--output',required=True);x=a.parse_args();src=Path(x.image);dst=Path(x.output)
if dst.exists() or src.resolve()==dst.resolve():raise SystemExit('Output must be new')
s=importlib.util.spec_from_file_location('u',R/'02-脚本/a6600_usr.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.Ext2=__import__('97_ext2').Ext2;fs=m.Ext2(str(src));d=dst.parent/(dst.stem+'-patch');d.mkdir(exist_ok=False,parents=True)
old=b'libSTMcmdexecute.so\0';new=b'a5bSTMcmdexecute.so\0';commands=[];records=[]
for p,i,dr in fs.walk():
 if dr or not p.startswith('/lib/a5'):continue
 mode,n,b=fs.inode(i)
 if mode&0xf000!=0x8000:continue
 data=fs.read_file(i)
 if old not in data:continue
 out=d/Path(p).name;out.write_bytes(data.replace(old,new));commands+=['rm '+p,'write '+str(out)+' '+p,'sif '+p+' mode 0100755'];records.append({'path':p,'occurrences':data.count(old),'source_sha256':hashlib.sha256(data).hexdigest(),'patched_sha256':hashlib.sha256(out.read_bytes()).hexdigest()})
stm=R/'03-证据/静态分析/97_abi/zvroot_libSTMcmdexecute.so';data=stm.read_bytes()
if hashlib.sha256(data).hexdigest()!='aabdecd5a624e8397ef78cd5cb4c0b4d58ad71d72b86b9f307e01488751cfb9a':raise SystemExit('Unexpected STM input')
out=d/'a5bSTMcmdexecute.so';out.write_bytes(data.replace(old,new));commands+=['write '+str(out)+' /lib/a5bSTMcmdexecute.so','sif /lib/a5bSTMcmdexecute.so mode 0100755'];(d/'commands').write_text('\n'.join(commands)+'\n')
shutil.copy2(src,dst)
p=subprocess.run(['debugfs','-w','-f',str(d/'commands'),str(dst)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT);(d/'debugfs.log').write_bytes(p.stdout)
if p.returncode:raise RuntimeError('debugfs failed')
p=subprocess.run(['e2fsck','-fn',str(dst)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT);(d/'fsck.log').write_bytes(p.stdout)
if p.returncode:raise RuntimeError('fsck failed')
fv=m.Ext2(str(dst));index={p:i for p,i,dr in fv.walk() if not dr}
expected={row['path']:row['patched_sha256'] for row in records};expected['/lib/a5bSTMcmdexecute.so']=hashlib.sha256(out.read_bytes()).hexdigest()
for path,digest in expected.items():
 if path not in index or hashlib.sha256(fv.read_file(index[path])).hexdigest()!=digest:raise RuntimeError('Semantic file verification failed '+path)
manifest={'source_image':str(src),'source_sha256':hashlib.sha256(src.read_bytes()).hexdigest(),'image':str(dst),'image_sha256':hashlib.sha256(dst.read_bytes()).hexdigest(),'image_bytes':dst.stat().st_size,'patches':records,'stm_sha256':hashlib.sha256(out.read_bytes()).hexdigest()};(d/'manifest.json').write_text(json.dumps(manifest,indent=2))
arc=R/'03-证据/ASTRA-97'/d.name;arc.mkdir(exist_ok=False,parents=True)
for n in ['manifest.json','debugfs.log','fsck.log']:shutil.copy2(d/n,arc/n)
print(json.dumps(manifest,indent=2))
