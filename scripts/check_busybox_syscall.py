"""Find busybox and determine which rlimit syscall number it embeds.

Patterns (little-endian bytes):
  Thumb-2 mov.w ip,#0xbf -> 4f f0 bf 0c
  Thumb-2 mov.w ip,#0x4c -> 4f f0 4c 0c
  ARM     mov  ip,#0xbf  -> bf c0 a0 e3
  ARM     mov  ip,#0x4c  -> 4c c0 a0 e3
"""
from pathlib import Path
import importlib.util

BASE = Path(r'<WORKSPACE>')
PART = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev'
INITRD = BASE / '05-原始固件/qemu_in/nflasha3-initrd'

PATTERNS = {
    'thumb191': bytes.fromhex('4ff0bf0c'),
    'thumb76': bytes.fromhex('4ff04c0c'),
    'arm191': bytes.fromhex('bfc0a0e3'),
    'arm76': bytes.fromhex('4cc0a0e3'),
}

def scan(name, data):
    print(f'--- {name}: {len(data)} bytes ---')
    for k, p in PATTERNS.items():
        i = data.find(p)
        cnt = 0
        offs = []
        while i >= 0 and cnt < 5:
            offs.append(hex(i))
            cnt += 1
            i = data.find(p, i + 1)
        print(f'  {k:9s} count>= {cnt} at {offs}')

# 1) find busybox in the /usr partition
spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fs = m.Ext2(str(PART / 'nflasha15'))
for path, ino, is_dir in fs.walk():
    if is_dir:
        continue
    if path.rsplit('/', 1)[-1] == 'busybox':
        data = fs.read_file(ino)
        print('found busybox at', path, len(data))
        out = BASE / '03-证据/静态分析/busybox'
        out.write_bytes(data)
        scan('busybox (usr)', data)
        break
else:
    print('busybox not found in /usr partition')

# 2) scan the initrd raw (may be compressed; just check)
if INITRD.exists():
    raw = INITRD.read_bytes()
    print('initrd head:', raw[:4].hex())
    if raw[:2] == b'\x1f\x8b':
        import gzip
        try:
            dec = gzip.decompress(raw)
            scan('initrd (gunzipped)', dec)
            idx = dec.find(b'busybox')
            print('  "busybox" string at', idx)
        except Exception as exc:
            print('  gunzip failed:', exc)
    else:
        scan('initrd raw', raw)
