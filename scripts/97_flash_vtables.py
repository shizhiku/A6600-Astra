"""Read ELF relocation-backed virtual function identities offline."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
import json
B=Path(__file__).resolve().parents[1];O=B/'03-证据/静态分析/97_flash'
with (O/'97_flash_updaterimg_bodylib_libupdaterbody.so').open('rb') as f:
 e=ELFFile(f);sy=[s for t in e.iter_sections() if t['sh_type'] in ['SHT_DYNSYM','SHT_SYMTAB'] for s in t.iter_symbols()];rel={r['r_offset']:e.get_section(t['sh_link']).get_symbol(r['r_info_sym']).name for t in e.iter_sections() if t['sh_type']=='SHT_REL' for r in t.iter_relocations()};out=[]
 for s in sy:
  if s.name in ['_ZTVN7Updater16XmlConfigHandlerE','_ZTVN7Updater20NewFirmwareImageFileE']:
   out.append({'symbol':s.name,'address':s['st_value'],'vptr_offset':8,'slots':[{'offset':i,'relative_vptr_offset':i-8,'symbol':rel.get(s['st_value']+i,'')} for i in range(s['st_size']//4*4) if i%4==0]})
 p=O/'97_flash_updater_vtables.json'
 if p.exists():raise FileExistsError(p)
 p.write_text(json.dumps(out,indent=2));print(json.dumps(out,indent=2))
