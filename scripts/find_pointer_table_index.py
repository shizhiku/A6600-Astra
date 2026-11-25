"""Find occurrences of the pointer-table index used by the fatal-path predicate."""
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
import json
root=Path(__file__).resolve().parent;d=(root/'qemu_in/av-cam.bin').read_bytes();base=0x635c6000
needle=bytes.fromhex('24380000');hits=[];p=0
while True:
 p=d.find(needle,p)
 if p<0:break
 hits.append(p);p+=1
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.skipdata=True
rows=[]
for off in hits:
 if off<8:continue
 ctx=[]
 for x in md.disasm(d[off-8:off+12],base+off-8):ctx.append(f'{x.address:08x} {x.bytes.hex():10} {x.mnemonic:8} {x.op_str}')
 rows.append({'offset':hex(off),'address':hex(base+off),'context':ctx})
out=root/'a6600_port/analysis/liro-fault-static/table-index-0x3824.json';out.write_text(json.dumps(rows,indent=2),encoding='utf-8')
print('literal hits',len(hits));
for r in rows[:60]:print('\n'.join(r['context'])+'\n')
