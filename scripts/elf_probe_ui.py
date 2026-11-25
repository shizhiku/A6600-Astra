from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_ARM
import sys,struct,re,json
root=Path(__file__).resolve().parents[1]
if '--out' in sys.argv:
 k=sys.argv.index('--out'); out=sys.argv[k+1]; del sys.argv[k:k+2]; sys.stdout=(root/out).open('w',encoding='utf-8')
p= root/sys.argv[1]
f=p.open('rb'); e=ELFFile(f); data=p.read_bytes()
def raw(va,n):
 for s in e.iter_sections():
  if s['sh_addr']<=va<s['sh_addr']+s['sh_size'] and s['sh_type']!='SHT_NOBITS': return data[s['sh_offset']+va-s['sh_addr']:s['sh_offset']+va-s['sh_addr']+n]
 return b''
symbols=[]
for sn in ('.dynsym','.symtab'):
 sec=e.get_section_by_name(sn)
 if sec:
  for s in sec.iter_symbols(): symbols.append((s['st_value']&~1,s['st_size'],s.name,str(s['st_shndx'])))
if len(sys.argv)==2:
 print('SECTIONS',[(s.name,hex(s['sh_addr']),hex(s['sh_offset']),s['sh_size']) for s in e.iter_sections()])
 print('SYMS',json.dumps([x for x in symbols if re.search('font|TextRM|layout|render|draw|key|input|init',x[2],re.I)],ensure_ascii=False))
else:
 va=int(sys.argv[2],0); n=int(sys.argv[3],0) if len(sys.argv)>3 else 0x100
 md=Cs(CS_ARCH_ARM,CS_MODE_THUMB if not(len(sys.argv)>4 and sys.argv[4]=='arm') else CS_MODE_ARM);md.skipdata=True
 for i in md.disasm(raw(va,n),va):
  note=''
  if i.mnemonic in ('bl','blx','b.w') and i.op_str.startswith('#'):
   target=int(i.op_str[1:],0);note='; '+','.join(s[2] for s in symbols if s[0]==target)
  print(f'{i.address:08x} {i.bytes.hex():10} {i.mnemonic:9} {i.op_str} {note}')
 # plt mapping
 rel=e.get_section_by_name('.rel.plt');plt=e.get_section_by_name('.plt')
 if rel and plt:
  ds=e.get_section(rel['sh_link'])
  print('PLT',json.dumps([(hex(plt['sh_addr']+20+12*j),ds.get_symbol(r['r_info_sym']).name) for j,r in enumerate(rel.iter_relocations())]))
