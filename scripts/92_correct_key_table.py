from pathlib import Path
import struct,json,re,hashlib
ROOT=Path(__file__).resolve().parents[1];p=ROOT/'03-证据/静态分析/libObj.so';d=p.read_bytes();rows=[]
# Independently verified row alignment: {u32 physical_code, u32 name_va}.
for off in range(0x13e8894,len(d)-7,8):
 code,ptr=struct.unpack_from('<II',d,off)
 if not (0xe3f128<=ptr<0x11958ca):break
 name=d[ptr:ptr+160].split(b'\0')[0]
 if not re.fullmatch(rb'[A-Z0-9_]{3,150}',name):break
 rows.append({'file_offset':hex(off),'va':hex(off+0x8000),'physical_code':hex(code),'name':name.decode()})
out={'elf_sha256':hashlib.sha256(d).hexdigest(),'structure':'{physical_code,name_pointer}','entries':rows}
p=ROOT/'03-证据/静态分析/92_menu_map/corrected_physical_key_table.json';p.write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8');print('entries',len(rows));print([r for r in rows if r['name'] in ['KEY_TACT_MENU','KEY_TACT_ENTER','KEY_TACT_UP','KEY_TACT_DOWN','KEY_TACT_LEFT','KEY_TACT_RIGHT','KEY_TACT_PLAY','KEY_TACT_FN']])
