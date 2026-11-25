"""Static ELF / cramfs audit only. Uses already installed capstone/pyelftools."""
from pathlib import Path
import struct,zlib,hashlib,re,json,io
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
BASE=Path(__file__).resolve().parents[1]; OUT=BASE/'03-证据/静态分析/97_flash';L=[]
def say(s):L.append(str(s));print(s)
def save(n,b):
 p=OUT/('97_flash_'+n)
 if p.exists():raise FileExistsError(p)
 p.write_bytes(b)
say('command: python 02-脚本/97_flash_native.py')
b=(BASE/'05-原始固件/a6600_fw/updater.img').read_bytes();say(f'updater.img size={len(b)} sha256={hashlib.sha256(b).hexdigest()} magic={b[:4].hex()}')
def inode(o):
 a,c,d=struct.unpack_from('<III',b,o);return a&65535,c&0xffffff,(d>>6)*4,(d&63)*4
def walk(o,prefix):
 mode,size,off,nl=inode(o)
 if mode&0xf000==0x4000:
  pos=off
  while pos<off+size:
   cm,cs,co,cn=inode(pos);name=b[pos+12:pos+12+cn].rstrip(b'\0').decode('ascii');walk(pos,prefix+'/'+name);pos+=12+cn
 elif mode&0xf000==0x8000:
  n=(size+4095)//4096;table=struct.unpack_from('<'+'I'*n,b,off);start=off+4*n;d=b''
  for end in table:d+=zlib.decompress(b[start:end]);start=end
  d=d[:size];say(f'cramfs {prefix} size={len(d)} sha256={hashlib.sha256(d).hexdigest()}');save('updaterimg'+prefix.replace('/','_'),d)
if b[:4]==bytes.fromhex('453dcd28'):walk(64,'')
paths=[p for p in OUT.glob('97_flash_*') if p.is_file() and p.read_bytes()[:4]==b'\x7fELF']
for path in paths:
 if '_dev_' in path.name:continue
 d=path.read_bytes();elf=ELFFile(io.BytesIO(d));syms=[]
 for sec in elf.iter_sections():
  if sec['sh_type'] in ('SHT_SYMTAB','SHT_DYNSYM'):
   for sym in sec.iter_symbols():
    if re.search(r'(?i)part|sum|crc|sig|rsa|verify|guard|fdat|updat|cryp|check',sym.name):syms.append({'name':sym.name,'value':sym['st_value'],'size':sym['st_size'],'section':sym['st_shndx']})
 save(path.name[len('97_flash_'):]+'.symbols.json',json.dumps(syms,indent=2).encode())
 lines=[]
 for sym in syms:
  if not isinstance(sym['section'],int) or not sym['size']:continue
  if path.name.endswith('emmc.ko') and sym['name'] not in ('emmc_load_partition_tbl','init_fs_part','init_boot_part','init_dfs_part'):continue
  if not path.name.endswith('emmc.ko') and not re.search(r'(?i)crc|sum|sig|rsa|verify|guard|part|cryp',sym['name']):continue
  if sym['size']>8192:continue
  sec=elf.get_section(sym['section']);addr=sym['value']&~1;off=addr-sec['sh_addr'];buf=sec.data()[off:off+sym['size']]
  md=Cs(CS_ARCH_ARM,(CS_MODE_THUMB if sym['value']&1 else CS_MODE_ARM)|CS_MODE_LITTLE_ENDIAN)
  lines.append(f"\n{sym['name']} addr={sym['value']:#x} size={sym['size']} section={sec.name}")
  for ins in md.disasm(buf,addr):lines.append(f'{ins.address:08x}: {ins.bytes.hex():8} {ins.mnemonic} {ins.op_str}')
 save(path.name[len('97_flash_'):]+'.disasm.txt',('\n'.join(lines)+'\n').encode())
 strings=[{'offset':m.start(),'text':m.group().decode('ascii')} for m in re.finditer(rb'[ -~]{5,}',d) if re.search(rb'(?i)crc|sum|sig|rsa|sha|part|nflash|SDM|8246|updat|check|verif|reject|fail',m.group())]
 save(path.name[len('97_flash_'):]+'.selectedstrings.json',json.dumps(strings,indent=2).encode())
save('native.log',('\n'.join(L)+'\n').encode())
