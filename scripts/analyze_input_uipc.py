"""Offline relocation-aware analysis of a6600 input.ko and libosal_uipc.so."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import *
import io,json
ROOT=Path(__file__).resolve().parents[1]; OUT=ROOT/'03-证据/静态分析/input_uipc'; OUT.mkdir(exist_ok=True)
KO=ROOT/'03-证据/静态分析/input_sen/input.ko'

def load_ko():
 d=KO.read_bytes(); e=ELFFile(io.BytesIO(d)); sym=e.get_section_by_name('.symtab'); sections=list(e.iter_sections())
 rels={}
 for rs in sections:
  if rs['sh_type']=='SHT_REL':
   target=int(rs['sh_info']); rels[target]={r['r_offset']:(sym.get_symbol(r['r_info_sym']).name,r['r_info_type'],r['r_info_sym']) for r in rs.iter_relocations()}
 funcs={}
 for s in sym.iter_symbols():
  idx=s['st_shndx']
  if s['st_info']['type']=='STT_FUNC' and isinstance(idx,int): funcs[s.name]=(idx,int(s['st_value']),int(s['st_size']))
 return d,e,sections,sym,rels,funcs

def dis_func(name):
 d,e,secs,sym,rels,funcs=load_ko(); idx,start,size=funcs[name]; sec=secs[idx]; raw=sec.data()[start:start+size]; rr=rels.get(idx,{})
 cs=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); cs.detail=True; lines=[f'FUNCTION {name} section={sec.name} start={start:#x} size={size:#x}']
 for x in cs.disasm(raw,start):
  note=[]
  for off in range(x.address,x.address+len(x.bytes)):
   if off in rr: note.append('RELOC '+rr[off][0]+' type='+str(rr[off][1]))
  if x.mnemonic.startswith('ldr') and len(x.operands)>1 and x.operands[1].type==3 and x.reg_name(x.operands[1].mem.base)=='pc':
   la=x.address+8+x.operands[1].mem.disp
   if 0<=la<=len(sec.data())-4:
    rawv=int.from_bytes(sec.data()[la:la+4],'little'); desc=f'LIT@{la:#x} raw={rawv:#x}'
    if la in rr:
     rn,rt,si=rr[la]; sy=sym.get_symbol(si); desc+=f' reloc={rn or secs[sy["st_shndx"]].name if isinstance(sy["st_shndx"],int) else rn}+{rawv:#x}'
    note.append(desc)
  if x.mnemonic=='bl' and x.operands and not note: note.append('local '+hex(x.operands[0].imm))
  lines.append(f'{x.address:08x} {x.bytes.hex():10} {x.mnemonic:9} {x.op_str:32}'+(' ; '+'; '.join(note) if note else ''))
 return '\n'.join(lines)

def reloc_summary():
 d,e,secs,sym,rels,funcs=load_ko();out=[]
 for fn,(idx,st,sz) in sorted(funcs.items(),key=lambda z:(z[1][0],z[1][1])):
  used=[(hex(o),n,t) for o,(n,t,si) in rels.get(idx,{}).items() if st<=o<st+sz]
  if used:out.append({'function':fn,'section':secs[idx].name,'start':hex(st),'size':hex(sz),'relocations':used})
 return out

def inspect_lib():
 p=ROOT/'03-证据/静态分析/input_sen/libosal_uipc.so';e=ELFFile(io.BytesIO(p.read_bytes()));dyn=e.get_section_by_name('.dynsym')
 return {s.name:{'value':hex(int(s['st_value'])),'size':hex(int(s['st_size']))} for s in dyn.iter_symbols() if s.name and s['st_info']['type']=='STT_FUNC' and isinstance(s['st_shndx'],int)}
if __name__=='__main__':
 (OUT/'input_relocations.json').write_text(json.dumps(reloc_summary(),indent=2),encoding='utf-8')
 for n in ['kbd_init','kbd_timer_hndlr','getkey_cb','kbd_write_proc','kbd_read_proc','kbd_probe','kbd_close']:
  (OUT/(n+'.dis.txt')).write_text(dis_func(n),encoding='utf-8')
 # The compiler left three local message helpers at .text 0x0/0xbc/0x154 without symbols.
 d,e,secs,sym,rels,funcs=load_ko(); ti=next(i for i,s in enumerate(secs) if s.name=='.text'); cs=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
 chunks=[]
 for st,en in [(0,0xb4),(0xbc,0x14c),(0x154,0x1a4)]:
  chunks.append(f'HELPER {st:#x}')
  chunks.extend(f'{x.address:08x} {x.bytes.hex():10} {x.mnemonic:9} {x.op_str}' for x in cs.disasm(secs[ti].data()[st:en],st))
 (OUT/'local_msg_helpers.dis.txt').write_text('\n'.join(chunks),encoding='utf-8')
 (OUT/'libosal_uipc_exports.json').write_text(json.dumps(inspect_lib(),indent=2),encoding='utf-8');print('wrote',OUT)
