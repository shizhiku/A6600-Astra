"""Export exact unresolved names, demanglings, and static Thumb call sites."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM
import io,json,subprocess
from collections import deque
B=Path(__file__).resolve().parents[1]; O=B/'03-证据/静态分析/97_abi'
U=json.loads((O/'union_missing.json').read_text(encoding='utf8'))
names=[s for x in U.values() for s in x['strong']]
try:
 r=subprocess.run(['wsl','-d','Ubuntu','--','c++filt',*names],capture_output=True,text=True,encoding='utf8',errors='replace',check=True)
 dem=dict(zip(names,r.stdout.splitlines()))
except Exception as exc:dem={};print('demangle unavailable',repr(exc))
results=[];md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
for lib,item in U.items():
 path=B/'05-原始固件/zv1m2_fw/gen5'/Path(lib).name;data=path.read_bytes();e=ELFFile(io.BytesIO(data));ds=e.get_section_by_name('.dynsym');rel=e.get_section_by_name('.rel.plt');plt=e.get_section_by_name('.plt');txt=e.get_section_by_name('.text');syms=list(ds.iter_symbols())
 import struct
 targets={};got_names={r['r_offset']:syms[r['r_info_sym']].name for r in rel.iter_relocations()}
 # REL order is NOT PLT slot order in these binaries. Decode each ARM stub's GOT address.
 def arm_imm(w):
  v=w&255;n=((w>>8)&15)*2
  return ((v>>n)|(v<<(32-n)))&0xffffffff if n else v
 pb=plt.data()
 for po in range(20,len(pb)-11,4):
  w1,w2,w3=struct.unpack_from('<III',pb,po)
  if w1&0xfffff000!=0xe28fc000 or w2&0xfffff000!=0xe28cc000 or w3&0xfffff000!=0xe5bcf000:continue
  got=plt['sh_addr']+po+8+arm_imm(w1)+arm_imm(w2)+(w3&4095)
  name=got_names.get(got)
  if name in item['strong']:
   targets[plt['sh_addr']+po]=name
   if po>=4 and pb[po-4:po]==bytes.fromhex('7847c046'):targets[plt['sh_addr']+po-4]=name
 blob=txt.data();calls=[]
 # ARM PIC long-branch veneers: ldr ip,[pc]; add pc,pc,ip; signed relative literal.
 extra={}
 for vi,(v,) in enumerate(struct.iter_unpack('<I',blob)):
  vo=vi*4
  if vo<8 or blob[vo-8:vo]!=bytes.fromhex('00c09fe50cf08fe0'):continue
  dest=(v+txt['sh_addr']+vo+4)&0xffffffff
  if dest in targets:extra[txt['sh_addr']+vo-8]=targets[dest]
 targets.update(extra)
 for off in range(0,len(blob)-3,2):
  h1,h2=struct.unpack_from('<HH',blob,off)
  if h1&0xf800!=0xf000 or not (h2&0xc000==0xc000 or h2&0xd000==0x9000):continue
  s=(h1>>10)&1;j1=(h2>>13)&1;j2=(h2>>11)&1
  disp=(s<<24)|((1^(j1^s))<<23)|((1^(j2^s))<<22)|((h1&0x3ff)<<12)|((h2&0x7ff)<<1)
  if s:disp-=1<<25
  va=txt['sh_addr']+off
  target=va+4+disp if h2&0x1000 else ((va+4)&~3)+disp
  if target not in targets:continue
  inst=next(md.disasm(blob[off:off+4],va),None)
  if inst is None or inst.mnemonic not in ('bl','blx','b.w') or not inst.operands or inst.operands[0].type!=ARM_OP_IMM or inst.operands[0].imm!=target:continue
  sym=targets[target];start=max(0,off-40)
  context=[f'{x.address:08x}: {x.mnemonic:8} {x.op_str}' for x in md.disasm(blob[start:off+28],txt['sh_addr']+start)]
  rec={'library':str(path),'symbol':sym,'demangled':dem.get(sym,sym),'call_va':hex(va),'branch_target_va':hex(target),'via_pic_veneer':target in extra,'context_note':'Bounded Thumb decode; first instruction may start in prior Thumb32 halfword or literal data. Exact call validated independently.','context':context};calls.append(rec)
 arm=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);arm.detail=True;arm.skipdata=True
 for off in range(0,len(blob)-3,4):
  word=struct.unpack_from('<I',blob,off)[0]
  if word&0x0e000000!=0x0a000000:continue
  disp=(word&0xffffff)<<2
  if disp&(1<<25):disp-=1<<26
  va=txt['sh_addr']+off;target=va+8+disp
  if word&0xfe000000==0xfa000000:target+=((word>>24)&1)<<1
  if target not in targets:continue
  inst=next(arm.disasm(blob[off:off+4],va),None)
  if inst is None or inst.mnemonic not in ('bl','blx','b') or not inst.operands or inst.operands[0].type!=ARM_OP_IMM or inst.operands[0].imm!=target:continue
  sym=targets[target];start=max(0,off-40)
  calls.append({'library':str(path),'symbol':sym,'demangled':dem.get(sym,sym),'call_va':hex(va),'branch_target_va':hex(target),'via_pic_veneer':target in extra,'mode':'ARM','context':[f'{x.address:08x}: {x.mnemonic:8} {x.op_str}' for x in arm.disasm(blob[start:off+28],txt['sh_addr']+start)]})
 results.extend(calls)
for lib,item in U.items():
 for n in item['strong']:print(lib,n,'=>',dem.get(n,n),'call_sites',sum(r['symbol']==n for r in results))
(O/'true_missing_calls.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf8')
(O/'true_missing_demangled.json').write_text(json.dumps({n:dem.get(n,n) for n in names},ensure_ascii=False,indent=2),encoding='utf8')
