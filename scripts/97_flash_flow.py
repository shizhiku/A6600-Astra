"""Static selected updater extraction/check flow disassembly, no target execution."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_ARM
import json,re
B=Path(__file__).resolve().parents[1];O=B/'03-证据/静态分析/97_flash';P=O/'97_flash_updaterimg_bodylib_libupdaterbody.so';plt=json.loads((O/'97_flash_body_plt_v2.json').read_text());L=[]
with P.open('rb') as f:
 e=ELFFile(f);done=set();syms=[s for sec in e.iter_sections() if sec['sh_type'] in ('SHT_SYMTAB','SHT_DYNSYM') for s in sec.iter_symbols()];names={s['st_value']&~1:s.name for s in syms if s['st_info']['type']=='STT_FUNC' and s['st_shndx']!='SHN_UNDEF'}
 for s in syms:
  if s['st_info']['type']!='STT_FUNC' or s.name in done or not isinstance(s['st_shndx'],int):continue
  if not any(x in s.name for x in ['BaseNewFirmwareFile7Extract','NewFirmwareImageFile','PartitionImageKeyTag7Extract','XmlConfigHandler7Execute','XmlConfigHandler10Post','XmlConfigHandler8Pre']):continue
  done.add(s.name);sec=e.get_section(s['st_shndx']);a=s['st_value']&~1;n=s['st_size'];d=sec.data()[a-sec['sh_addr']:a-sec['sh_addr']+n];m=Cs(CS_ARCH_ARM,CS_MODE_THUMB if s['st_value']&1 else CS_MODE_ARM);L.append(f'\n{s.name} address={a:#x} size={n}')
  for x in m.disasm(d,a):
   dest=re.fullmatch(r'#(0x[0-9a-f]+)',x.op_str);ann=''
   if x.mnemonic in ('bl','blx','b','b.w') and dest:
    addr=int(dest.group(1),16);ann=plt.get(hex(addr),names.get(addr,''))
   L.append(f'{x.address:08x}: {x.mnemonic:8} {x.op_str:30} {ann}')
p=O/'97_flash_updater_flow.disasm.txt'
if p.exists():raise FileExistsError(p)
p.write_text('\n'.join(L)+'\n',encoding='utf-8');print(p)
