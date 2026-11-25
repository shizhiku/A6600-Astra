"""Read-only ELF ABI audit of original images and ASTRA stage. No target execution.
Outputs only under 03-证据/静态分析/97_abi. Run with Windows Python + pyelftools/capstone.
"""
from pathlib import Path, PurePosixPath
import importlib.util, io, json, hashlib, struct, posixpath
from collections import deque
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
BASE=Path(__file__).resolve().parents[1]
OUT=BASE/'03-证据/静态分析/97_abi'
OUT.mkdir(parents=True,exist_ok=True)
spec=importlib.util.spec_from_file_location('ext2reader',BASE/'02-脚本/a6600_usr.py'); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
class Image:
 def __init__(self,path,label):
  self.path=path; self.label=label; self.fs=m.Ext2(str(path)); self.entries={p:i for p,i,d in self.fs.walk() if not d}
 def read(self,path,seen=None):
  seen=set() if seen is None else seen
  if path in seen: raise ValueError('symlink cycle')
  seen.add(path); ino=self.entries[path]; mode,size,blocks=self.fs.inode(ino)
  if mode&0xf000==0xa000:
   b=struct.pack('<15I',*blocks)[:size] if size<=60 else self.fs.read_file(ino)
   t=b.decode(); return self.read(posixpath.normpath(t if t.startswith('/') else posixpath.join(posixpath.dirname(path),t)),seen)
  return self.fs.read_file(ino)
def elf(data,source):
 if not data.startswith(b'\x7fELF'): return None
 e=ELFFile(io.BytesIO(data))
 # Index headers without parsing unrelated malformed ARM attributes sections.
 e._section_name_map={e._get_section_name(e._get_section_header(i)):i for i in range(e.num_sections())}
 ds=e.get_section_by_name('.dynsym'); dyn=e.get_section_by_name('.dynamic'); tags=list(dyn.iter_tags()) if dyn else []
 defs={}; und={}
 if ds:
  for s in ds.iter_symbols():
   if not s.name: continue
   info={'bind':s['st_info']['bind'],'type':s['st_info']['type'],'vis':s['st_other']['visibility'],'value':s['st_value'],'size':s['st_size']}
   if s['st_shndx']=='SHN_UNDEF': und[s.name]=info
   elif info['bind'] in ('STB_GLOBAL','STB_WEAK') and info['vis'] in ('STV_DEFAULT','STV_PROTECTED'): defs[s.name]=info
 return {'source':source,'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'machine':e['e_machine'],'flags':e['e_flags'],'entry':e['e_entry'],'needed':[t.needed for t in tags if t.entry.d_tag=='DT_NEEDED'],'soname':next((t.soname for t in tags if t.entry.d_tag=='DT_SONAME'),None),'rpath':[getattr(t,'rpath',getattr(t,'runpath',None)) for t in tags if t.entry.d_tag in ('DT_RPATH','DT_RUNPATH')],'defs':defs,'und':und,'dynamic':[{t.entry.d_tag:str(t.entry.d_val)} for t in tags if t.entry.d_tag in ('DT_INIT','DT_INIT_ARRAY','DT_INIT_ARRAYSZ','DT_FLAGS','DT_FLAGS_1')]}
def inventory(img):
 out={}
 for p in img.entries:
  if p.startswith('/lib/') or p.startswith('/bin/') or p.startswith('/sbin/'):
   try: x=elf(img.read(p),img.label+':'+p)
   except (KeyError,ValueError,ELFError) as exc:
    print('SKIP',img.label,p,str(exc)); continue
   if x: out[p]=x
 return out
a6=Image(BASE/'05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15','a6usr')
zv=Image(BASE/'05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15','zvusr')
root=Image(BASE/'05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha7','a6root')
inv={i.label:inventory(i) for i in (a6,zv,root)}
stagepath=Path(r'\\wsl.localhost\Ubuntu\root\astra\stage')
stage={}
for p in stagepath.iterdir():
 try: x=elf(p.read_bytes(),'stage:'+p.name)
 except OSError: continue
 if x: stage['/lib/'+p.name]=x
# stage aliases are accounted for explicitly; Windows UNC cannot always open Linux symlinks.
for alias,target in [('libopus.so.0','libopus.so.0.8.0'),('libSoundTouch.so.1','libSoundTouch.so.1.0.0')]:
 if '/lib/'+target in stage: stage['/lib/'+alias]=stage['/lib/'+target]
inv['stage']=stage
for img in (a6,zv):
 for p in ('/bin/im.elf','/lib/libIMDB.so','/lib/appFwBoot.so','/lib/appFw.so'):
  if p in img.entries: (OUT/(img.label+'_'+p.rsplit('/',1)[-1])).write_bytes(img.read(p))

def closure(seeds,usr):
 pool={**inv['a6root'],**usr}; selected={}; queue=deque(seeds); absent=[]
 while queue:
  name=queue.popleft()
  path=name if name.startswith('/') else '/lib/'+name
  x=pool.get(path)
  if x is None:
   absent.append(name); continue
  identity=x['sha256']
  if identity in selected: continue
  selected[identity]=x; queue.extend(x['needed'])
 provided={}
 for x in selected.values():
  for n in x['defs']: provided.setdefault(n,[]).append(x['source'])
 misses={}
 for x in selected.values():
  strong=[s for s,v in x['und'].items() if s not in provided and v['bind']!='STB_WEAK']
  weak=[s for s,v in x['und'].items() if s not in provided and v['bind']=='STB_WEAK']
  misses[x['source']]={'strong':sorted(strong),'weak':sorted(weak)}
 return {'selected':[{'source':x['source'],'sha256':x['sha256'],'needed':x['needed']} for x in selected.values()],'absent_libraries':sorted(set(absent)),'missing':misses}
mixed={**inv['a6usr'],**stage}
scenarios={
 'stock_im':closure(['/bin/im.elf'],inv['a6usr']),
 'mixed_im':closure(['/bin/im.elf'],mixed),
 'mixed_im_plus_imdb':closure(['/bin/im.elf','libIMDB.so'],mixed),
 'mixed_im_plus_appfw':closure(['/bin/im.elf','appFw.so','libObj.so','libmpr.so'],mixed),
 'gen5_appfw_closure':closure(['appFw.so','libObj.so','libmpr.so','libIMDB.so','appFwBoot.so'],inv['zvusr']),
 'mixed_appfw_closure':closure(['appFw.so','libObj.so','libmpr.so','libIMDB.so','appFwBoot.so'],mixed),
}
# An export union baseline replicates earlier methodology but distinguishes weak and strong.
union=set().union(*(set(x['defs']) for group in inv.values() for x in group.values()))
unionmiss={p:{'strong':[n for n,v in x['und'].items() if n not in union and v['bind']!='STB_WEAK'],'weak':[n for n,v in x['und'].items() if n not in union and v['bind']=='STB_WEAK']} for p,x in inv['zvusr'].items() if p in ('/lib/appFw.so','/lib/libObj.so','/lib/libmpr.so','/lib/libIMDB.so')}
collisions=[]
for p,a in inv['a6usr'].items():
 b=inv['zvusr'].get(p)
 if b and a['sha256']!=b['sha256']:
  collisions.append({'path':p,'a6_sha256':a['sha256'],'zv_sha256':b['sha256'],'same_soname':a['soname']==b['soname'],'a6_exports':len(a['defs']),'zv_exports':len(b['defs']),'only_a6':sorted(set(a['defs'])-set(b['defs'])),'only_zv':sorted(set(b['defs'])-set(a['defs']))})
# Full raw metadata makes every count and provider name auditable.
(OUT/'inventory.json').write_text(json.dumps(inv,ensure_ascii=False,indent=2),encoding='utf-8')
(OUT/'closure.json').write_text(json.dumps(scenarios,ensure_ascii=False,indent=2),encoding='utf-8')
(OUT/'collisions.json').write_text(json.dumps(collisions,ensure_ascii=False,indent=2),encoding='utf-8')
(OUT/'union_missing.json').write_text(json.dumps(unionmiss,ensure_ascii=False,indent=2),encoding='utf-8')
manifest={i.label:{'path':str(i.path),'sha256':hashlib.file_digest(open(i.path,'rb'),'sha256').hexdigest()} for i in (a6,zv,root)}
(OUT/'inputs.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
for k,s in scenarios.items():
 print(k,'loaded',len(s['selected']),'absent',s['absent_libraries'],'strong_missing',sum(len(v['strong']) for v in s['missing'].values()))
 for src,v in s['missing'].items():
  if v['strong']: print(' ',src, len(v['strong']))
print('same path different SHA collisions:',len(collisions))
print('union missing:',json.dumps(unionmiss,ensure_ascii=False))
