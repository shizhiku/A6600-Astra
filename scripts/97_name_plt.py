"""Resolve ARM PLT stubs to imported symbol names for ELF32 shared objects."""
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
import io,sys,struct
def rotl(v,r):r&=31;return ((v<<r)|(v>>(32-r)))&0xffffffff if r else v
def plt_names(path):
 d=open(path,'rb').read();e=ELFFile(io.BytesIO(d));dyn=e.get_section_by_name('.dynsym');got={}
 rel=e.get_section_by_name('.rel.plt')
 if rel:
  for r in rel.iter_relocations():got[r['r_offset']]=dyn.get_symbol(r['r_info_sym']).name
 plt=e.get_section_by_name('.plt');out={}
 if not plt:return out
 md=Cs(CS_ARCH_ARM,CS_MODE_ARM);md.detail=True;data=plt.data();base=plt['sh_addr']
 ins=list(md.disasm(data,base))
 for i,x in enumerate(ins):
  if x.mnemonic!='add' or len(x.operands)!=2:continue
  a,b=x.operands
  if x.reg_name(a.reg)!='ip' or b.type!=2 or x.reg_name(b.reg)!='pc':continue
  if i+3>=len(ins):continue
  y=ins[i+1];z=ins[i+2]
  if y.mnemonic!='add' or len(y.operands)!=2 or y.operands[1].type!=2:continue
  if z.mnemonic not in('ldr','ldr.w') or not z.operands or z.operands[0].type!=1 or z.reg_name(z.operands[0].reg)!='pc':continue
  third=z.operands[1]
  g=x.address+8+rotl(b.imm,((b.imm>>8)&15)*2)+y.operands[1].imm+(third.mem.disp if third.type==3 else 0)
  name=got.get(g)
  if name:out[x.address]=name
 return out
if __name__=='__main__':
 for a,n in sorted(plt_names(sys.argv[1]).items()):print(f'{a:#08x} {n}')
