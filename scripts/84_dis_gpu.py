from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import *
import io,struct
ROOT=Path(__file__).resolve().parents[1];out=ROOT/'03-证据/静态分析/probe84';p=out/'grm_gles.ko';d=p.read_bytes();e=ELFFile(io.BytesIO(d));sy=e.get_section_by_name('.symtab');se=list(e.iter_sections());rels={}
for rsec in se:
 if rsec['sh_type']=='SHT_REL':rels[int(rsec['sh_info'])]={r['r_offset']:(sy.get_symbol(r['r_info_sym']),r['r_info_type']) for r in rsec.iter_relocations()}
md=Cs(CS_ARCH_ARM,CS_MODE_ARM);md.detail=True;md.skipdata=True
for s in sy.iter_symbols():
 if s.name not in ['sugilite_register_init','sugilite_interrupt','sugilite_ioctl']:continue
 sec=se[s['st_shndx']];rr=rels.get(s['st_shndx'],{});st=s['st_value'];sz=s['st_size'];b=sec.data();lines=[]
 for x in md.disasm(b[st:st+sz],st):
  note=[]
  if x.address in rr:note.append('reloc '+rr[x.address][0].name)
  if x.mnemonic.startswith('ldr') and len(x.operands)>1 and x.operands[1].type==3 and x.reg_name(x.operands[1].mem.base)=='pc':
   a=x.address+8+x.operands[1].mem.disp
   if 0<=a<len(b)-3:
    v=struct.unpack_from('<I',b,a)[0];note.append(f'lit[{a:#x}]={v:#x}')
    if a in rr:
     y,t=rr[a];idx=y['st_shndx'];note.append('reloc '+y.name)
     if isinstance(idx,int) and se[idx]['sh_type']!='SHT_NOBITS':
      bb=se[idx].data();o=y['st_value']+v
      if 0<=o<len(bb):note.append(repr(bb[o:o+100].split(b'\0')[0]))
  lines.append(f'{x.address:04x} {x.mnemonic:10} {x.op_str:36} '+ '; '.join(note))
 (out/(s.name+'.dis.txt')).write_text('\n'.join(lines),encoding='utf-8')
print('done')
