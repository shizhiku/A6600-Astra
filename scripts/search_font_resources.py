"""Search the firmware images for the Chinese font resource identifiers."""
from pathlib import Path

BASE = Path(r'<WORKSPACE>')
PART = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev'
INITRD = BASE / '05-原始固件/qemu_in/nflasha3-initrd'

TERMS = [b'FONT_S_CHINESE', b'FONT_T_CHINESE', b'CHINESE']

targets = []
for name in ('nflasha15', 'nflasha7', 'nflasha5'):
    p = PART / name
    if p.exists():
        targets.append((name, p))
if INITRD.exists():
    targets.append(('initrd', INITRD))

for name, path in targets:
    data = path.read_bytes()
    print(f'--- {name} ({len(data):#x} bytes) ---')
    for t in TERMS:
        idx = data.find(t)
        cnt = 0
        i = idx
        while i >= 0 and cnt < 5:
            cnt += 1
            i = data.find(t, i + 1)
        print(f'  {t.decode():16s} first={hex(idx) if idx >= 0 else "none"} count(<=5)={cnt}')
        if idx >= 0:
            seg = data[max(0, idx - 32): idx + 48]
            printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in seg)
            print(f'      ctx: {printable}')
