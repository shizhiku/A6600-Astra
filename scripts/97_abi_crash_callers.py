"""Read-only fault caller / ARM exidx analysis of original ASTRA and existing libc evidence."""
from pathlib import Path
import struct,json,bisect,io,hashlib
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_ARM
B=Path(__file__).resolve().parents[1];O=B/'03-证据/静态分析/97_abi';p=B/'05-原始固件/zv1m2_fw/gen5/appFw.so';e=ELFFile(p.open('rb'));text=e.get_section_by_name('.text');tb=text.data();ta=text['sh_addr'];md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True;md.skipdata=True
x=e.get_section_by_name('.ARM.exidx');xd=x.data();funcs=[]
def prel(v):return (v&0x7fffffff)-(0x80000000 if v&0x40000000 else 0)
for off in range(0,len(xd),8):
 a,b=struct.unpack_from('<II',xd,off);funcs.append({'function_va':x['sh_addr']+off+prel(a),'entry_va':x['sh_addr']+off,'unwind_word':hex(b)})
starts=[r['function_va']&~1 for r in funcs];out=[]
# Decode PLT through GOT rather than REL ordinal (interworking veneers make ordinal wrong).
ds=e.get_section_by_name('.dynsym');rel=e.get_section_by_name('.rel.plt');pn=e.get_section_by_name('.plt');pb=pn.data();gn={r['r_offset']:ds.get_symbol(r['r_info_sym']).name for r in rel.iter_relocations()};labels={}
def imm(w):
 v=w&255;n=((w>>8)&15)*2
 return ((v>>n)|(v<<(32-n)))&0xffffffff if n else v
for off in range(20,len(pb)-11,4):
 a,b,c=struct.unpack_from('<III',pb,off)
 if a&0xfffff000!=0xe28fc000 or b&0xfffff000!=0xe28cc000 or c&0xfffff000!=0xe5bcf000:continue
 got=pn['sh_addr']+off+8+imm(a)+imm(b)+(c&4095);name=gn.get(got)
 if name:labels[pn['sh_addr']+off]=name
for i,(v,) in enumerate(struct.iter_unpack('<I',tb)):
 off=i*4
 if off>=8 and tb[off-8:off]==bytes.fromhex('00c09fe50cf08fe0'):
  dest=(v+ta+off+4)&0xffffffff
  if dest in labels:labels[ta+off-8]=labels[dest]+' [PIC veneer]'
for point in (0x02603e5e,0x026e9b9a):
 idx=bisect.bisect_right(starts,point)-1;start=starts[idx];end=starts[idx+1] if idx+1<len(starts) else ta+len(tb);r={'return_va':hex(point|1),'function_start':hex(start),'function_end':hex(end),'unwind':funcs[idx],'instructions':[]}
 lo=start if end-start<=4096 else point-128;hi=min(end,point+192)
 for ins in md.disasm(tb[lo-ta:hi-ta],lo):
  s=f'{ins.address:08x}: {ins.mnemonic:9} {ins.op_str}'
  if ins.mnemonic in ('bl','blx','b.w') and ins.operands and ins.operands[0].type==2:
   target=ins.operands[0].imm
   if target in labels:s+=' ; '+labels[target]
  r['instructions'].append(s)
 out.append(r)
libc=B/'03-证据/静态分析/libc-2.11.2.so';lc={}
if libc.exists():
 data=libc.read_bytes();le=ELFFile(io.BytesIO(data));sy=le.get_section_by_name('.dynsym');lc={'path':str(libc),'sha256':hashlib.sha256(data).hexdigest(),'memcpy_symbols':[{'name':s.name,'value':hex(s['st_value']),'size':s['st_size']} for s in sy.iter_symbols() if s.name=='memcpy']}
 for seg in le.iter_segments():
  if seg['p_type']=='PT_LOAD' and seg['p_vaddr']<=0x60210<seg['p_vaddr']+seg['p_filesz']:
   off=0x60210-seg['p_vaddr'];blob=seg.data();lo=max(0,off-64);lc['fault_context']=[f'{i.address:08x}: {i.mnemonic:9} {i.op_str}' for i in Cs(CS_ARCH_ARM,CS_MODE_ARM).disasm(blob[lo:off+64],seg['p_vaddr']+lo)]
result={'appfw_sha256':hashlib.file_digest(open(p,'rb'),'sha256').hexdigest(),'runtime_bias_from_parent':'0x13c51000','callers':out,'libc_evidence':lc,'limitations':['Existing local libc must be hash-matched to runtime before treating its instruction context as runtime code.','Stack values are candidate return addresses; exidx and BL adjacency validate each independently.','Fault-time r2 may have been changed inside memcpy and is not assumed to equal entry size.']}
(O/'crash_callers.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8');print(json.dumps(result,ensure_ascii=False,indent=2))
