"""Read-only inventory of gen5 rootfs DSO closure for ASTRA private namespace."""
from pathlib import Path
import io,json,hashlib,importlib.util,posixpath,struct
from collections import deque
from elftools.elf.elffile import ELFFile
B=Path(__file__).resolve().parents[1]; O=B/'03-证据/静态分析/97_abi'
s=importlib.util.spec_from_file_location('ext2',B/'02-脚本/a6600_usr.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
image=B/'05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha7'; fs=m.Ext2(str(image));ent={p:i for p,i,d in fs.walk() if not d}
def data(path,seen=None):
 seen=set() if seen is None else seen
 if path in seen:raise ValueError('symlink cycle')
 seen.add(path);i=ent[path];mode,size,blocks=fs.inode(i)
 if mode&0xf000==0xa000:
  raw=struct.pack('<15I',*blocks)[:size] if size<=60 else fs.read_file(i);t=raw.decode()
  return data(posixpath.normpath(t if t.startswith('/') else posixpath.join(posixpath.dirname(path),t)),seen)
 return fs.read_file(i)
inv={};targets={n for x in json.loads((O/'union_missing.json').read_text(encoding='utf8')).values() for n in x['strong']};witnesses=[]
for p in ent:
 if not p.startswith('/lib/'):continue
 try:raw=data(p)
 except (KeyError,ValueError):continue
 if raw[:4]!=b'\x7fELF':continue
 e=ELFFile(io.BytesIO(raw));e._section_name_map={e._get_section_name(e._get_section_header(i)):i for i in range(e.num_sections())};dy=e.get_section_by_name('.dynamic');tags=list(dy.iter_tags()) if dy else [];vn=e.get_section_by_name('.gnu.version_r'); versions={}
 if vn:
  for v,auxs in vn.iter_versions():versions[v.name]=[aux.name for aux in auxs]
 ds=e.get_section_by_name('.dynsym')
 if ds:
  for sym in ds.iter_symbols():
   if sym.name in targets and sym['st_shndx']!='SHN_UNDEF':witnesses.append({'path':p,'symbol':sym.name,'value':hex(sym['st_value']),'size':sym['st_size'],'bind':sym['st_info']['bind'],'sha256':hashlib.sha256(raw).hexdigest()})
 inv[p]={'source':'zvroot:'+p,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'soname':next((t.soname for t in tags if t.entry.d_tag=='DT_SONAME'),None),'needed':[t.needed for t in tags if t.entry.d_tag=='DT_NEEDED'],'version_requirements':versions,'machine':e['e_machine'],'flags':e['e_flags']}
old=json.loads((O/'inventory.json').read_text(encoding='utf8'));usr=old['zvusr'];a6root=old['a6root'];q=deque(['appFw.so','libObj.so','libmpr.so','appFwBoot.so','AdjChkConfig.so']);selected={};missing=[]
while q:
 name=q.popleft();p='/lib/'+name
 if p in selected:continue
 if p in usr:x=usr[p]
 elif p in a6root:x=a6root[p]
 elif p in inv:x=inv[p]
 else:missing.append(name);continue
 selected[p]=x;q.extend(x['needed'])
needed_root={p:x for p,x in selected.items() if x['source'].startswith('zvroot:')}
for p,x in needed_root.items():(O/('zvroot_'+Path(p).name)).write_bytes(data(p))
result={'image':str(image),'image_sha256':hashlib.file_digest(open(image,'rb'),'sha256').hexdigest(),'selection_policy':'gen5 usr first; reuse original a6600 root standard providers where their exact path exists; then gen5 root. This selects files, not ABI equivalence.','new_root_files':needed_root,'absent_libraries':sorted(set(missing)),'selected':{p:{k:v for k,v in x.items() if k in ('source','sha256','needed')} for p,x in selected.items()}}
(O/'gen5root_inventory.json').write_text(json.dumps(inv,ensure_ascii=False,indent=2),encoding='utf8')
(O/'gen5root_required.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
(O/'gen5root_export_witnesses.json').write_text(json.dumps(witnesses,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps({'image_sha256':result['image_sha256'],'new_root_files':needed_root,'absent':result['absent_libraries'],'previously_missing_export_witnesses':witnesses,'optional_im_only':{p:x for p,x in inv.items() if p in ('/lib/libssl.so.3','/lib/libcrypto.so.3')}},ensure_ascii=False,indent=2))
