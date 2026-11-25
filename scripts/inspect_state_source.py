"""Compare the first observed state-copy source with the captured Backup.bin."""
from pathlib import Path
import json,struct
r=Path(__file__).resolve().parent
backup=(r/'a6600_port/captures/boot-20261120T151656Z-26869/05-setting__Backup.bin').read_bytes()
load=struct.unpack_from('<I',backup)[0]
source_va=0x62ee7f74-32  # candidate: preceding LDMIA advances source by eight words
source_pa=source_va-0x60000000
off=source_pa-load
print('backup RAM candidate offset',hex(off),'bytes',backup[off:off+96].hex())
print('target expected first96 unknown beyond first64; first32 from fatal stop:')
stop=json.loads((r/'a6600_port/emulation/breakpoint-20261120T153013Z-27606/breakpoint.json').read_text())
print(stop['state_r7']['hex'])
