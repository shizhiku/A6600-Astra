"""Map a runtime offset inside a loaded kernel module back to its ELF section."""
from pathlib import Path
import json
from elftools.elf.elffile import ELFFile

root=Path(__file__).resolve().parent
ko=root/'a6600_fw/usr/kmod/liro.ko'
TARGET=0x2474
data=ko.read_bytes()
with open(ko,'rb') as f:
    e=ELFFile(f)
    secs=[]
    cursor=0
    for s in e.iter_sections():
        name=s.name
        if s['sh_type']=='SHT_NOBITS':
            size=s['sh_size'];align=max(1,s['sh_addralign'])
            off=cursor
            cursor=((cursor+align-1)//align)*align+size
            secs.append({'name':name,'kind':'bss','runtime_start':off,'size':size,'runtime_end':off+size})
        elif s['sh_flags']&0x2 or name in ('.text','.rodata','.data','.init.text'):
            size=s['sh_size'];align=max(1,s['sh_addralign'])
            off=cursor
            cursor=((cursor+align-1)//align)*align+size
            secs.append({'name':name,'kind':'alloc','file_offset':s['sh_offset'],'runtime_start':off,'size':size,'runtime_end':off+size})
result={'module':str(ko),'bytes':len(data),'target_offset':hex(TARGET),'sections':secs,'match':None}
for s in secs:
    if s['runtime_start']<=TARGET<s['runtime_end']:
        result['match']={'section':s['name'],'delta_in_section':hex(TARGET-s['runtime_start']),'section_size':s['size']}
(root/'a6600_port/analysis/liro-fault-static/liro-module-offset.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result['match'],indent=2))
for s in secs: print(f"{s['name']:20s} rt {s['runtime_start']:#08x}-{s['runtime_end']:#08x}")
