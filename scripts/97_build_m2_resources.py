"""Make a NEW 512MiB /usr image from the compact M1, adding all screen-reader
resources. QEMU-only; requires a separately migrated SDM backing disk.
"""
from pathlib import Path
import importlib.util,subprocess,shutil,json,hashlib,os
R=Path('<WORKSPACE>');MIB=int(os.environ.get('ASTRA97_M2_MIB','512'));O=Path('/root/astra/97')/('m2-'+str(MIB));O.mkdir(exist_ok=True,parents=True);IMG=O/('astra-m2-full-'+str(MIB)+'MiB.img');SRC=Path('/root/astra/97/m1-now/astra-m1-now-visual-300MiB.img')
if IMG.exists():raise SystemExit('Refusing overwrite of existing M2 image')
s=importlib.util.spec_from_file_location('u',R/'02-脚本/a6600_usr.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.Ext2=__import__('97_ext2').Ext2;fs=m.Ext2(str(R/'05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15'))
entries=[x for x in fs.walk() if x[0].startswith('/share/screenreader')];stage=O/'audio';stage.mkdir(exist_ok=True)
def run(cmd,log):
 p=subprocess.run([str(x)for x in cmd],stdout=subprocess.PIPE,stderr=subprocess.STDOUT);Path(log).write_bytes(p.stdout)
 if p.returncode:raise RuntimeError(str(cmd[:2])+': '+p.stdout.decode(errors='replace')[-2000:])
commands=[];files=[]
for p,ino,dr in sorted(entries,key=lambda x:(x[0].count('/'),x[0])):
 if dr:commands.append('mkdir '+p);continue
 mode,n,bl=fs.inode(ino)
 if mode&0xf000!=0x8000:raise RuntimeError('Unexpected non-regular audio '+p)
 d=fs.read_file(ino);target=stage/str(ino);target.write_bytes(d)
 if any(c in p for c in '\n\r"'):raise RuntimeError('Unsupported resource path')
 commands += ['write '+str(target)+' "'+p+'"','sif "'+p+'" mode 0100644'];files.append({'path':p,'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()})
shutil.copy2(SRC,IMG)
with IMG.open('r+b') as f:f.truncate(MIB*1024**2)
run(['resize2fs','-f',IMG],O/'resize.log');(O/'debugfs.commands').write_text('\n'.join(commands)+'\n');run(['debugfs','-w','-f',O/'debugfs.commands',IMG],O/'debugfs.log');run(['e2fsck','-fn',IMG],O/'fsck.log')
# Structural fsck alone can pass after debugfs ENOSPC. Verify every written file.
verify=m.Ext2(str(IMG));actual={p:i for p,i,dr in verify.walk() if not dr and p.startswith('/share/screenreader')}
for item in files:
 ino=actual.get(item['path'])
 if ino is None:raise RuntimeError('Missing audio file '+item['path'])
 payload=verify.read_file(ino)
 if len(payload)!=item['bytes'] or hashlib.sha256(payload).hexdigest()!=item['sha256']:raise RuntimeError('Semantic read-back failed '+item['path'])
manifest={'purpose':'emulator-only full-resource M2; no flash authorization','source_m1_sha256':hashlib.sha256(SRC.read_bytes()).hexdigest(),'image':str(IMG),'image_bytes':IMG.stat().st_size,'image_sha256':hashlib.sha256(IMG.read_bytes()).hexdigest(),'screenreader_bytes':sum(f['bytes']for f in files),'screenreader_files':len(files),'files':files};(O/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2))
a=R/'03-证据/ASTRA-97/m2-build';a.mkdir(exist_ok=True,parents=True)
for n in ['manifest.json','resize.log','debugfs.log','fsck.log']:shutil.copy2(O/n,a/n)
print(json.dumps({k:v for k,v in manifest.items()if k!='files'},ensure_ascii=False,indent=2))
