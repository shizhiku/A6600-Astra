"""Offline parse of captured 4 KiB page: test candidate frame slots and CRCs."""
from pathlib import Path
import hashlib,json,struct
root=Path(__file__).resolve().parent
cap=root/'a6600_port/captures/submicro-candidate-20261121'
data=(cap/'page-0x03443000.bin').read_bytes()
if len(data)!=4096:raise SystemExit('unexpected capture length')
def crc16(b):
 c=0xffff
 for x in b:
  c^=x<<8
  for _ in range(8):c=((c<<1)^0x1021)&0xffff if c&0x8000 else (c<<1)&0xffff
 return c
slots={'slot_A_RX':0x3a4,'slot_C_RX':0x424,'slot_B_RX':0x4a4,'slot_A_TX':0x5c8,'slot_C_TX':0x648,'slot_B_TX':0x6c8}
out={'input_sha256':hashlib.sha256(data).hexdigest(),'candidate_slots':{},'crc_valid_frames_anywhere':[]}
for name,off in slots.items():
 f=data[off:off+128]
 observed=int.from_bytes(f[126:128],'little') if len(f)==128 else None
 out['candidate_slots'][name]={'offset':hex(off),'address':hex(0x03443000+off),'len':len(f),'type':f[0] if f else None,'header_hex':f[:12].hex(),'crc16_ccitt_false':hex(crc16(f[:126])) if len(f)==128 else None,'stored_crc16':hex(observed) if observed is not None else None,'crc_valid':len(f)==128 and crc16(f[:126])==observed}
for off in range(0,len(data)-127,4):
 f=data[off:off+128]
 if f[0] in (0x20,0x21,0x30,0x31,0x60,0x61) and crc16(f[:126])==int.from_bytes(f[126:128],'little'):
  out['crc_valid_frames_anywhere'].append({'offset':hex(off),'address':hex(0x03443000+off),'type':hex(f[0]),'head':f[:16].hex()})
(cap/'page-analysis.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
print(json.dumps(out,indent=2))
