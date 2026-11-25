"""Find direct Thumb BL callers of the observed callback wrapper."""
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
import json,time
root=Path(__file__).resolve().parent;p=root/'qemu_in/av-cam.bin';d=p.read_bytes();base=0x635c6000
TARGETS={0x63cefcaA:'callback_wrapper',0x638529d8:'timeout_callback'}
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.skipdata=True;md.detail=True
hits={k:[] for k in TARGETS};t=time.time()
for x in md.disasm(d,base):
 if x.mnemonic=='bl' and x.operands and x.operands[0].type==2:
  name=TARGETS.get(x.operands[0].imm)
  if name:hits[name].append({'address':hex(x.address),'offset':hex(x.address-base),'bytes':x.bytes.hex()})
out={'input_sha256':__import__('hashlib').sha256(d).hexdigest(),'targets':{hex(k):v for k,v in TARGETS.items()},'hits':hits,'elapsed_seconds':round(time.time()-t,2)}
(root/'a6600_port/analysis/liro-fault-static/callback-xrefs.json').write_text(json.dumps(out,indent=2),encoding='utf-8');print(json.dumps(out,indent=2))
