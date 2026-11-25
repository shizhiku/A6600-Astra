"""Static annotated original module initialization; no execution."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
import struct,hashlib,json
BASE=Path(__file__).resolve().parents[1];OUT=BASE/'03-证据/静态分析/97_flash'; p=OUT/'97_flash_rootfs_kmod_emmc.ko'; lines=[]
with p.open('rb') as f:
 e=ELFFile(f);sym=e.get_section_by_name('.symtab');sec=e.get_section_by_name('.init.text');rel=e.get_section_by_name('.rel.init.text');buf=sec.data();rmap={}
 for r in rel.iter_relocations():
  s=sym.get_symbol(r['r_info_sym']); val=struct.unpack_from('<I',buf,r['r_offset'])[0];target=s.name or str(s['st_shndx']);snippet=''
  if isinstance(s['st_shndx'],int):
   ts=e.get_section(s['st_shndx']);target=ts.name+':'+s.name
   if 0<=val<ts['sh_size']:
    x=ts.data()[val:val+140].split(b'\0')[0]
    if x and all(32<=c<127 for c in x):snippet=repr(x)
  rmap[r['r_offset']]=f"RELOC {target} type={r['r_info_type']} raw={val:#x} {snippet}"
 md=Cs(CS_ARCH_ARM,CS_MODE_ARM);md.skipdata=True
 for s in sym.iter_symbols():
  if s.name not in ['init_emmc_and_blkdev','emmc_blk_plat_init','init_blk_params.clone.7']:continue
  a=s['st_value'];n=s['st_size'];lines.append(f'\nFUNCTION {s.name} {a:#x} length={n}')
  for x in md.disasm(buf[a:a+n],a):lines.append(f'{x.address:08x} {x.bytes.hex():8} {x.mnemonic:8} {x.op_str} '+rmap.get(x.address,''))
 out=OUT/'97_flash_driver_init.disasm.txt'
 if out.exists():raise FileExistsError(out)
 out.write_text('\n'.join(lines)+'\n',encoding='utf-8')
print(out)
