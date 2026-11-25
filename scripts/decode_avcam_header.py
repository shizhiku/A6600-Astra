"""Decode the av-cam image header and its memory-map descriptor."""
from pathlib import Path
import struct, json

BASE = Path(r'<WORKSPACE>')
IMG = BASE / '05-原始固件/qemu_in/av-cam.bin'
LOAD = 0x035C6000          # documented physical load address
VA_BASE = 0x635C6000       # same address with the 0x60000000 mapping

d = IMG.read_bytes()
hdr = {}
hdr['file_bytes'] = len(d)
hdr['branch'] = hex(struct.unpack_from('<I', d, 0)[0])
hdr['magic'] = d[4:8].decode('latin1')
hdr['version'] = hex(struct.unpack_from('<I', d, 8)[0])
hdr['pre_entry'] = hex(struct.unpack_from('<I', d, 12)[0])
hdr['entry'] = hex(struct.unpack_from('<I', d, 16)[0])
hdr['memmap_ptr'] = hex(struct.unpack_from('<I', d, 20)[0])
hdr['unk24'] = hex(struct.unpack_from('<I', d, 24)[0])
hdr['unk28'] = hex(struct.unpack_from('<I', d, 28)[0])

# decode memMap struct at memmap_ptr (VA -> file offset)
def voff(va):
    return va - VA_BASE

mp = int(hdr['memmap_ptr'], 16)
off = voff(mp)
if 0 <= off <= len(d) - 32:
    fields = struct.unpack_from('<8I', d, off)
    names = ['ramBase', 'ramLen', 'bssBase', 'bssLen', 'tailBase', 'tailLen', 'limitBase', 'limitLen']
    hdr['memmap'] = {n: hex(v) for n, v in zip(names, fields)}
    hdr['memmap_raw_offset'] = hex(off)
else:
    hdr['memmap'] = None
    hdr['memmap_error'] = f'pointer {hdr["memmap_ptr"]} outside image (offset {off:#x})'

(BASE / '03-证据/静态分析/avcam-header.json').write_text(json.dumps(hdr, indent=2), encoding='utf-8')
print(json.dumps(hdr, indent=2))
