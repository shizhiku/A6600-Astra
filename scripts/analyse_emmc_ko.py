"""Analyse emmc.ko: locate the tuning warning and the branch that retries forever."""
from pathlib import Path
import struct, importlib.util
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

BASE = Path(r'<WORKSPACE>')
spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fs = m.Ext2(str(BASE / '05-原始固件/qemu_in/nflasha3-initrd'))

blob = None
for path, ino, is_dir in fs.walk():
    if not is_dir and path == '/kmod/emmc.ko':
        blob = fs.read_file(ino)
        break
if blob is None:
    raise SystemExit('emmc.ko not found in initrd')
out = BASE / '03-证据/静态分析/emmc.ko'
out.write_bytes(blob)
print('emmc.ko size', len(blob), '->', out.name)

i = blob.find(b'Software Tuning')
print('warning string at', hex(i))
seg = blob[max(0, i - 80): i + 160]
print('context:', ''.join(chr(c) if 32 <= c < 127 else '.' for c in seg))

# find ARM code that references this string via pc-relative literal
TARGET = i
cands = []
for A in range(0, len(blob) - 4, 4):
    V = struct.unpack_from('<I', blob, A)[0]
    if V == 0 or V > 0x1000000:
        continue
    B = TARGET - V - 8
    if 0 <= B < len(blob) - 8 and (B % 2 == 0):
        cands.append((B, A, V))
print(f'candidates: {len(cands)}')

md_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM); md_arm.skipdata = True
md_th = Cs(CS_ARCH_ARM, CS_MODE_THUMB); md_th.skipdata = True
for B, A, V in cands[:6]:
    print(f'\n=== candidate add@{B:#x} literal@{A:#x} V={V:#x} ===')
    start = max(0, B - 0x50)
    for x in md_arm.disasm(blob[start:B + 0x30], start):
        mark = '   <== ref' if x.address == B else ''
        print(f'{x.address:06x} {x.bytes.hex():8} {x.mnemonic:8} {x.op_str}{mark}')
