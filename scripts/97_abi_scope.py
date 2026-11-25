"""Postprocess deterministic ELF inventories into honest per-namespace symbol bounds."""
from pathlib import Path
import json,io,struct
from elftools.elf.elffile import ELFFile
B=Path(__file__).resolve().parents[1];O=B/'03-证据/静态分析/97_abi'
I=json.loads((O/'inventory.json').read_text(encoding='utf8')); R=json.loads((O/'imdb_entries.json').read_text(encoding='utf8'))
root=I['a6root'];a=I['a6usr'];z=I['zvusr'];mixed={**a,**I['stage']}
def providers(pool):
 out={}
 for p,x in pool.items():
  for name in x['defs']:out.setdefault(name,[]).append(x['source'])
 return out
P={k:providers({**root,**v}) for k,v in [('a6',a),('zv',z),('mixed',mixed)]}
keys=['/lib/appFw.so','/lib/libObj.so','/lib/libmpr.so','/lib/appFwBoot.so','/lib/libIMDB.so']
bounds={}
for label,p in P.items():
 bounds[label]={}
 for k in keys:
  x=z.get(k)
  if not x:continue
  missing=[]
  for n,v in x['und'].items():
   if v['bind']=='STB_WEAK' or n in p:continue
   missing.append({'name':n,'a6_provider':P['a6'].get(n,[]),'zv_provider':P['zv'].get(n,[])})
  bounds[label][k]=missing
# Actual old-IMDB pre-Application requests for bundled libObj exports.
old_obj=a['/lib/libObj.so']['defs'];new_obj=z['/lib/libObj.so']['defs']; rows=[]
for r in R['a6usr']['entries']:
 t=int(r['words'][0],16)
 if t==0x20000004:break
 if t not in (0x20000001,0x20000002,0x20000003) or not r['u16_offset14']:continue
 sym=r['strings'].get('20'); rows.append({'index':r['index'],'type':hex(t),'record_library':r['strings'].get('16'),'effective_dlopen':'/usr/lib/libObj.so','init_symbol':sym,'old_obj_has_init':sym in old_obj if sym else None,'new_obj_has_init':sym in new_obj if sym else None})
# Same-name library substitutions that falsely satisfy a symbol from unshipped gen5.
collisions=[]
for k in keys:
 x=z.get(k)
 if not x:continue
 for n,v in x['und'].items():
  if v['bind']=='STB_WEAK' or n in P['mixed']:continue
  prov=P['zv'].get(n,[])
  if prov:collisions.append({'consumer':k,'name':n,'missing_with_stage_even_all_available_mixed_libs':True,'gen5_provider':prov})
(O/'scope_bounds.json').write_text(json.dumps(bounds,ensure_ascii=False,indent=2),encoding='utf8')
(O/'bootstrap_bundled_records.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf8')
(O/'hidden_by_union.json').write_text(json.dumps(collisions,ensure_ascii=False,indent=2),encoding='utf8')
for label,bs in bounds.items():print(label,{k:len(v) for k,v in bs.items()})
print('old bundled preapp records',len(rows),'newObj missing init',sum(r['new_obj_has_init']==False for r in rows))
print(json.dumps([r for r in rows if r['new_obj_has_init']==False],ensure_ascii=False,indent=2))
print('hidden_by_union',len(collisions))
