"""Find direct Thumb BL callers of the observed 30-iteration timeout routine."""
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
import json,time
root=Path(__file__).resolve().parent; p=root/'qemu_in/av-cam.bin'; d=p.read_bytes();base=0x635c6000;target=0x638529d8
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.skipdata=True;md.detail=True
hits=[];t=time.time()
for x in md.disasm(d,base):
 if x.mnemonic=='bl' and x.operands and x.operands[0].type==2 and x.operands[0].imm==target:
  hits.append({'address':hex(x.address),'file_offset':hex(x.address-base),'bytes':x.bytes.hex()})
result={'input':str(p),'target':hex(target),'direct_bl_callers':hits,'elapsed_seconds':round(time.time()-t,2)}
out=root/'a6600_port/analysis/liro-fault-static/timeout-callers.json';out.write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result,indent=2))
