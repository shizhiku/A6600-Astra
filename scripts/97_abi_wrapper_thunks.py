"""Locate long-range PIC veneers for ASTRA wrapper imports; read-only evidence."""
from pathlib import Path
import struct,json
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
B=Path(__file__).resolve().parents[1];O=B/'03-证据/静态分析/97_abi';p=B/'05-原始固件/zv1m2_fw/gen5/appFw.so';e=ELFFile(p.open('rb'));t=e.get_section_by_name('.text');blob=t.data();base=t['sh_addr'];targets={0x52932c:'set_user_matrix',0x52a914:'adf_ext_type'}
possible={}
for plt,name in targets.items():
 for delta in range(-16,17,2):possible[(plt+delta)&0xffffffff]=(plt,name,delta)
rows=[]
for i,(v,) in enumerate(struct.iter_unpack('<I',blob)):
 off=i*4;va=base+off;add=(v+va)&0xfffffffe;direct=v&0xfffffffe
 if add not in possible and direct not in targets:continue
 rec={'literal_va':hex(va),'literal_value':hex(v),'candidate_kind':'PIC-add' if add in possible else 'absolute','thumb':[],'arm':[]}
 if add in possible:
  plt,name,delta=possible[add];rec.update({'plt':hex(plt),'name':name,'sum_minus_plt':delta})
 else:rec.update({'plt':hex(direct),'name':targets[direct]})
 for key,mode in [('thumb',CS_MODE_THUMB),('arm',CS_MODE_ARM)]:
  start=max(0,off-16);rec[key]=[f'{x.address:08x}: {x.mnemonic:9} {x.op_str}' for x in Cs(CS_ARCH_ARM,mode).disasm(blob[start:off+12],base+start)]
 rows.append(rec)
(O/'wrapper_thunk_candidates.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf8');print(json.dumps(rows,ensure_ascii=False,indent=2))
