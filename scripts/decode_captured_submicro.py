"""Decode captured frames with the repository's documented four-byte TLV codec."""
from pathlib import Path
import sys,json
root=Path(__file__).resolve().parent
sys.path.insert(0,str(root/'bionz'))
from src.a6400.execution.submicro_link import decode_slot_b_frame,verify_frame_crc
cap=root/'a6600_port/captures/submicro-candidate-20261121'
d=(cap/'page-0x03443000.bin').read_bytes()
slots={'slot_A_RX':0x3a4,'slot_C_RX':0x424,'slot_B_RX':0x4a4,'slot_A_TX':0x5c8,'slot_C_TX':0x648,'slot_B_TX':0x6c8}
out={}
for name,off in slots.items():
 f=d[off:off+128]
 row={'offset':hex(off),'type':hex(f[0]),'crc_valid':verify_frame_crc(f),'byte28':hex(f[28]) if f[0] in (0x20,0x21) else None}
 if f[0] in (0x30,0x31):
  b=decode_slot_b_frame(f);row['declared_tlv_byte_count']=b.tlv_byte_count;row['tlvs']=[{'id':hex(x.tlv_id),'len':len(x.data),'data':x.data.hex()} for x in b.records]
 out[name]=row
(cap/'decoded-frames.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
print(json.dumps(out,indent=2))
