"""Resolve ARM PLT stubs statically by decoded literal GOT slots."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
import re,json
BASE=Path(__file__).resolve().parents[1];O=BASE/'03-证据/静态分析/97_flash';P=O/'97_flash_updaterimg_bodylib_libupdaterbody.so'
with P.open('rb') as f:
 e=ELFFile(f);p=e.get_section_by_name('.plt');r=e.get_section_by_name('.rel.plt');t=e.get_section(r['sh_link']);got={x['r_offset']:t.get_symbol(x['r_info_sym']).name for x in r.iter_relocations()};b=p.data();md=Cs(CS_ARCH_ARM,CS_MODE_ARM);maps={}
 for i in range(0,len(b)-11,4):
  ins=list(md.disasm(b[i:i+12],p['sh_addr']+i))
  if len(ins)!=3:continue
  a,c,d=ins
  if a.mnemonic!='add' or not a.op_str.startswith('ip, pc, #') or c.mnemonic!='add' or not c.op_str.startswith('ip, ip, #') or d.mnemonic!='ldr' or not d.op_str.startswith('pc, [ip, #'):continue
  def imm(x):
   nums=[int(v,0) for v in re.findall(r'#(0x[0-9a-f]+|[0-9]+)',x)]
   v=nums[0]
   if len(nums)>1:
    rot=nums[1];v=((v>>rot)|(v<<(32-rot)))&0xffffffff
   return v
  slot=a.address+8+imm(a.op_str)+imm(c.op_str)+imm(d.op_str)
  if slot in got:maps[hex(a.address)]=got[slot]
 out=O/'97_flash_body_plt_v2.json'
 if out.exists():raise FileExistsError(out)
 out.write_text(json.dumps(maps,indent=2))
 print({x:maps.get(x) for x in ['0xd418','0xdddc','0xdfd8','0xd364','0xdd94','0xda24']})
