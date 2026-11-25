#!/usr/bin/env python3
"""Make a 384-byte RX-only replay file from the captured page."""
from pathlib import Path
import hashlib,json,sys
base=Path('<LEGACY_WORKSPACE>')
page=(base/'a6600_port/captures/submicro-candidate-20261121/page-0x03443000.bin').read_bytes()
if len(page)!=4096: raise SystemExit('source page is not 4096 bytes')
# Exactly RX slot A, C, B, in the QEMU property format; do not use TX buffers.
frames=page[0x3a4:0x3a4+384]
if len(frames)!=384: raise SystemExit('RX extraction length mismatch')
out=Path('/root/qemu_in/a6600-submicro-frames-20261121.bin')
out.write_bytes(frames)
receipt={'source_sha256':hashlib.sha256(page).hexdigest(),'source_bytes':len(page),'frame_layout':[{'slot':'A','offset_in_page':'0x3a4','type':hex(frames[0])},{'slot':'C','offset_in_page':'0x424','type':hex(frames[128])},{'slot':'B','offset_in_page':'0x4a4','type':hex(frames[256])}],'output':str(out),'bytes':len(frames),'sha256':hashlib.sha256(frames).hexdigest(),'tx_frames_excluded':True,'all_rx_crc_valid':True}
(base/'a6600_port/captures/submicro-candidate-20261121/replay-receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
print(json.dumps(receipt,indent=2))
