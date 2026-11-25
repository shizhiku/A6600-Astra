"""Build an emulator-only ASTRA visual-resource image in the EXISTING 300MiB /usr
SDM extent. Keep 4th-gen bootstrap, add renamed 5th-gen libraries with explicit
DT_NEEDED edges and DEEPBIND. No original image or device is modified.
"""
from pathlib import Path
import importlib.util,io,struct,hashlib,json,subprocess,shutil,sys,os
R=Path('<WORKSPACE>');O=Path('/root/astra/97')/os.environ.get('ASTRA97_BUILD_LABEL','m1');O.mkdir(parents=True,exist_ok=True)
S=importlib.util.spec_from_file_location('usr',R/'02-脚本/a6600_usr.py');M=importlib.util.module_from_spec(S);S.loader.exec_module(M);M.Ext2=__import__('97_ext2').Ext2
A6=R/'05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15';ZV=R/'05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15';fs=M.Ext2(str(ZV));old=M.Ext2(str(A6));stage=O/'files';stage.mkdir(exist_ok=True)
PATCHER=Path('/root/astra/97/tools/patchelf');IMAGE=O/('astra-'+O.name+'-visual-300MiB.img')
if IMAGE.exists():raise SystemExit('Refusing to overwrite an existing experimental image')
def run(args,log=None):
 p=subprocess.run([str(a) for a in args],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 if log:Path(log).write_bytes(p.stdout)
 if p.returncode:raise RuntimeError(str(args[:2])+': '+p.stdout.decode(errors='replace')[-1600:])
 return p.stdout

def symlink_target(f,ino):
 mode,n,bl=f.inode(ino)
 if n<=60:
  g,idx=divmod(ino-1,f.ipg);off=f.inode_tables[g]*f.bs+idx*f.inode_size+40;f.f.seek(off);return f.f.read(n).decode()
 return f.read_file(ino).decode()

entries=list(fs.walk());libs=[(p,i)for p,i,d in entries if not d and p.startswith('/lib/') and '.so' in Path(p).name and not Path(p).name.startswith('libosal_')]
name_map={Path(p).name:'a5'+Path(p).name[2:] for p,i in libs}
if len(set(name_map.values()))!=len(name_map):raise RuntimeError('Library rename collision')
# No change to root libc/loader/pthread/libstdc++; only ZV /usr libraries get new names.
manifest={'source_usr':str(A6),'zv_usr':str(ZV),'renames':name_map,'libraries':[],'resources':[],'excluded':['/share/screenreader/**'],'strategy':'existing SDM geometry, ext2 300MiB, preserve old bootstrap + same-length Sony DSO renames + explicit dependency edges'}
commands=[];dirs=set()
# Remove only original /share files and directories; replace with gen5 visual resources.
oldshare=[(p,i,d) for p,i,d in old.walk() if p.startswith('/share/')]
commands += ['rm '+p for p,i,d in oldshare if not d]
commands += ['rmdir '+p for p,i,d in sorted(oldshare,key=lambda x:x[0].count('/'),reverse=True) if d]
# Old dynamic View plugins are not used because the original application entry is replaced.
removed=[]
for p,i,d in old.walk():
 if not d and p.startswith('/lib/viewUnified'):
  commands.append('rm '+p);removed.append(p)
manifest['removed_old_view_plugins']=removed

for p,ino in libs:
 name=Path(p).name;new=name_map[name];mode,n,bl=fs.inode(ino)
 if mode&0xf000==0xa000:
  target=symlink_target(fs,ino);bn=Path(target).name;replacement=name_map.get(bn,bn)
  commands.append('symlink /lib/'+new+' '+replacement);manifest['libraries'].append({'old':name,'new':new,'symlink':replacement});continue
 data=fs.read_file(ino);counts={}
 # Exact NUL-terminated filenames only; equal-length rewrites preserve code/data VAs.
 for a,b in sorted(name_map.items(),key=lambda x:-len(x[0])):
  x=a.encode()+b'\0';y=b.encode()+b'\0';cnt=data.count(x)
  if cnt:data=data.replace(x,y);counts[a]=cnt
 if name=='appFwBoot.so':
  expected=bytes.fromhex('40f20111');replacement=bytes.fromhex('40f20a11')
  # Two verified movw r1,#0x101 (dlopen flags): preserve sequence, add DEEPBIND.
  for va in [0x12f8,0x130a]:
   if data[va:va+4]!=expected:raise RuntimeError(f'Unexpected appFwBoot flags at {va:#x}: {data[va:va+4].hex()}')
   data=data[:va]+replacement+data[va+4:]
 target=stage/new;target.write_bytes(data)
 if name in ['appFwBoot.so','appFw.so']:
  for dependency in ['a5bObj.so','a5bmpr.so','libosal_utm.so','libosal_uipc.so']:
   run([PATCHER,'--add-needed',dependency,target])
 manifest['libraries'].append({'old':name,'new':new,'source_sha256':hashlib.sha256(fs.read_file(ino)).hexdigest(),'staged_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'filename_rewrites':counts})
 commands += ['write '+str(target)+' /lib/'+new,'sif /lib/'+new+' mode 0100755']

for p,ino,isdir in entries:
 if not p.startswith('/share/') or p.startswith('/share/screenreader'):continue
 if isdir:dirs.add(p);continue
 mode,n,bl=fs.inode(ino)
 for par in Path(p).parents:
  if str(par) not in ['.','/','/share']:dirs.add(str(par))
 if mode&0xf000==0xa000:
  commands.append('symlink '+p+' '+symlink_target(fs,ino));continue
 dest=stage/('resource-'+str(ino));dest.write_bytes(fs.read_file(ino));commands += ['write '+str(dest)+' '+p,'sif '+p+' mode 0100644'];manifest['resources'].append({'path':p,'bytes':n,'sha256':hashlib.sha256(dest.read_bytes()).hexdigest()})
# Resource directory creation must precede resource writes but can follow library writes.
ix=next((i for i,c in enumerate(commands) if c.startswith('write ') and '/resource-' in c),len(commands))
commands[ix:ix]=['mkdir '+d for d in sorted(dirs,key=lambda x:(x.count('/'),x))]
patched=R/'03-证据/静态分析/97_abi/97_abi_libIMDB_appboot.so'
bridge=R/'04-产物/libastra_bridge97.so'
if not patched.exists() or not bridge.exists():raise RuntimeError('Missing patched IMDB or compiled bridge')
commands += ['rm /lib/libIMDB.so','write '+str(patched)+' /lib/libIMDB.so','sif /lib/libIMDB.so mode 0100755','write '+str(bridge)+' /lib/astra.so','sif /lib/astra.so mode 0100755']
shutil.copy2(A6,IMAGE)
with IMAGE.open('r+b') as f:f.truncate(300*1024**2)
run(['resize2fs','-f',IMAGE],O/'resize.log')
(O/'debugfs.commands').write_text('\n'.join(commands)+'\n')
run(['debugfs','-w','-f',O/'debugfs.commands',IMAGE],O/'debugfs.log')
p=subprocess.run(['e2fsck','-fn',str(IMAGE)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT);(O/'fsck.log').write_bytes(p.stdout)
if p.returncode:raise RuntimeError('e2fsck did not pass: '+p.stdout.decode(errors='replace')[-2000:])
verify=M.Ext2(str(IMAGE));index={p:i for p,i,dr in verify.walk() if not dr}
for row in manifest['libraries']:
 path='/lib/'+row['new']
 if path not in index:raise RuntimeError('Missing staged library '+path)
 payload=verify.read_file(index[path])
 if 'symlink' in row:
  if payload.decode()!=row['symlink']:raise RuntimeError('Wrong symlink '+path)
 elif hashlib.sha256(payload).hexdigest()!=row['staged_sha256']:raise RuntimeError('Library semantic verification failed '+path)
for row in manifest['resources']:
 if row['path'] not in index or hashlib.sha256(verify.read_file(index[row['path']])).hexdigest()!=row['sha256']:raise RuntimeError('Resource semantic verification failed '+row['path'])
for path,source in [('/lib/libIMDB.so',patched),('/lib/astra.so',bridge)]:
 if hashlib.sha256(verify.read_file(index[path])).hexdigest()!=hashlib.sha256(source.read_bytes()).hexdigest():raise RuntimeError('Bootstrap semantic verification failed '+path)
manifest['semantic_readback_verified']=True
manifest.update({'image':str(IMAGE),'image_bytes':IMAGE.stat().st_size,'image_sha256':hashlib.sha256(IMAGE.read_bytes()).hexdigest(),'resources_total':sum(x['bytes']for x in manifest['resources']),'bridge_sha256':hashlib.sha256(bridge.read_bytes()).hexdigest(),'imdb_sha256':hashlib.sha256(patched.read_bytes()).hexdigest(),'source_usr_sha256':hashlib.sha256(A6.read_bytes()).hexdigest()})
(O/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2));arc=R/'03-证据/ASTRA-97'/(O.name+'-build');arc.mkdir(exist_ok=True,parents=True)
for n in ['manifest.json','resize.log','debugfs.log','debugfs.commands','fsck.log']:shutil.copy2(O/n,arc/n)
print(json.dumps({k:manifest[k]for k in ['image','image_bytes','image_sha256','resources_total']},indent=2))
