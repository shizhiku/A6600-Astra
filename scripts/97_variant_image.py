"""Create a NEW emulator ext2 variant with explicit hardware ABI boundaries.
No source images, backing disks or real devices are written.
"""
from pathlib import Path
import argparse,importlib.util,subprocess,shutil,hashlib,json,struct
R=Path('<WORKSPACE>');P=argparse.ArgumentParser();P.add_argument('--image',required=True);P.add_argument('--output',required=True);P.add_argument('--lazy',action='store_true');P.add_argument('--share-old-usb',action='store_true');A=P.parse_args();src=Path(A.image);dst=Path(A.output)
if dst.exists() or src.resolve()==dst.resolve():raise SystemExit('Output must be NEW')
s=importlib.util.spec_from_file_location('u',R/'02-脚本/a6600_usr.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.Ext2=__import__('97_ext2').Ext2;fs=m.Ext2(str(src));D=dst.parent/(dst.stem+'-patch');D.mkdir(parents=True,exist_ok=False);tool='/root/astra/97/tools/patchelf'
share={b'a5bUsbControl.so\0':b'libUsbControl.so\0',b'a5bInfraUsbCmn.so\0':b'libInfraUsbCmn.so\0',b'a5bbackup.so\0':b'libbackup.so\0'} if A.share_old_usb else {}
commands=[];expected={};changes=[]
def off_va(d,va):
 ph=struct.unpack_from('<I',d,28)[0];sz=struct.unpack_from('<H',d,42)[0];n=struct.unpack_from('<H',d,44)[0]
 for j in range(n):
  typ,o,v,pa,fsz,msz,fl,al=struct.unpack_from('<IIIIIIII',d,ph+j*sz)
  if typ==1 and v<=va<v+fsz:return o+va-v
 raise RuntimeError('Unmapped code VA')
for p,i,dr in fs.walk():
 if dr or not p.startswith('/lib/a5'):continue
 mode,n,bl=fs.inode(i)
 if mode&0xf000!=0x8000:continue
 data=fs.read_file(i)
 if not data.startswith(b'\x7fELF'):continue
 if Path(p).name in ['a5bUsbControl.so','a5bInfraUsbCmn.so','a5bbackup.so'] and A.share_old_usb:continue
 new=data;ops=[]
 for a,b in share.items():
  if a in new:ops.append({'from':a[:-1].decode(),'to':b[:-1].decode(),'count':new.count(a)});new=new.replace(a,b)
 if Path(p).name=='a5pFwBoot.so' and A.lazy:
  for va in [0x12f8,0x130a]:
   o=off_va(new,va)
   if new[o:o+4]!=bytes.fromhex('40f20a11'):raise RuntimeError('Unexpected NOW boot flags '+hex(va))
   new=new[:o]+bytes.fromhex('40f20911')+new[o+4:];ops.append({'dlopen_flags':'LAZY|GLOBAL|DEEPBIND','va':hex(va)})
 add_edge=A.share_old_usb and Path(p).name in ['a5pFwBoot.so','a5pFw.so']
 if new==data and not add_edge:continue
 f=D/Path(p).name;f.write_bytes(new)
 if add_edge:
  x=subprocess.run([tool,'--add-needed','libInfraPtpControl.so',str(f)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  if x.returncode:raise RuntimeError(x.stdout.decode(errors='replace'))
  ops.append({'needed':'libInfraPtpControl.so'})
 expected[p]=hashlib.sha256(f.read_bytes()).hexdigest();commands+=['rm '+p,'write '+str(f)+' '+p,'sif '+p+' mode 0100755'];changes.append({'path':p,'source_sha256':hashlib.sha256(data).hexdigest(),'patched_sha256':expected[p],'operations':ops})
if A.lazy:
 f=R/'04-产物/libastra_bridge97_lazy.so';commands+=['rm /lib/astra.so','write '+str(f)+' /lib/astra.so','sif /lib/astra.so mode 0100755'];expected['/lib/astra.so']=hashlib.sha256(f.read_bytes()).hexdigest()
(D/'commands').write_text('\n'.join(commands)+'\n');shutil.copy2(src,dst)
x=subprocess.run(['debugfs','-w','-f',str(D/'commands'),str(dst)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT);(D/'debugfs.log').write_bytes(x.stdout)
if x.returncode:raise RuntimeError('debugfs failed')
x=subprocess.run(['e2fsck','-fn',str(dst)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT);(D/'fsck.log').write_bytes(x.stdout)
if x.returncode:raise RuntimeError('fsck failed')
fv=m.Ext2(str(dst));index={p:i for p,i,dr in fv.walk() if not dr}
for p,h in expected.items():
 if p not in index or hashlib.sha256(fv.read_file(index[p])).hexdigest()!=h:raise RuntimeError('Semantic file verification failed '+p)
report={'source':str(src),'source_sha256':hashlib.sha256(src.read_bytes()).hexdigest(),'image':str(dst),'image_sha256':hashlib.sha256(dst.read_bytes()).hexdigest(),'lazy_binding':A.lazy,'share_old_usb_backup':A.share_old_usb,'warning':'DEEPBIND and filename isolation are not proof of complete ABI equivalence','changes':changes,'verified_files':expected};(D/'manifest.json').write_text(json.dumps(report,indent=2));arc=R/'03-证据/ASTRA-97'/D.name;arc.mkdir(exist_ok=False,parents=True)
for n in ['manifest.json','debugfs.log','fsck.log']:shutil.copy2(D/n,arc/n)
print(json.dumps({k:v for k,v in report.items()if k!='changes' and k!='verified_files'},indent=2))
