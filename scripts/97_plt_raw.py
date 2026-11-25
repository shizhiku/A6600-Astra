"""Resolve ARM ELF32 PLT entries by decoding the stub instructions directly."""
from elftools.elf.elffile import ELFFile
import io,struct,sys
def ror(v,r):
 r&=31;return ((v>>r)|(v<<(32-r)))&0xffffffff if r else v
def resolve(path):
 d=open(path,'rb').read();e=ELFFile(io.BytesIO(d));plt=e.get_section_by_name('.plt');rel=e.get_section_by_name('.rel.plt');dyn=e.get_section_by_name('.dynsym')
 if not(plt and rel):return {}
 got={r['r_offset']:dyn.get_symbol(r['r_info_sym']).name for r in rel.iter_relocations()}
 out={};base=plt['sh_addr'];data=plt.data()
 for i in range(0,len(data)-11,4):
  a,b,c=struct.unpack_from('<III',data,i);addr=base+i
  if a&0xfffff000!=0xe28fc000 or b&0xfffff000!=0xe28cc000 or c&0xfffff000!=0xe5bcf000:continue
  v0=ror(a&0xff,((a>>8)&15)*2);v1=ror(b&0xff,((b>>8)&15)*2);disp=c&0xfff
  g=addr+8+v0+v1+disp
  if g in got:out[addr]=got[g]
 return out
if __name__=='__main__':
 m=resolve(sys.argv[1])
 for a,n in sorted(m.items()):print(f'{a:#08x} {n}')
