"""Create a diagnostic av-cam variant whose entry points return immediately.

Purpose: test whether the rest of the firmware (4th-gen UI) can boot when av-cam
initialisation is skipped. This is an emulator-input experiment only; the real
image and the camera are untouched.
"""
from pathlib import Path
import struct, hashlib

BASE = Path(r'<WORKSPACE>')
SRC = BASE / '05-原始固件/qemu_in/av-cam-live.bin'
DST = BASE / '05-原始固件/qemu_in/av-cam-noinit.bin'
VA0 = 0x635C6000
ENTRIES = [0x635C6044, 0x635C6058]   # pre_entry, entry_main
BX_LR_ARM = 0xE12FFF1E

data = bytearray(SRC.read_bytes())
for va in ENTRIES:
    off = va - VA0
    data[off:off + 4] = struct.pack('<I', BX_LR_ARM)

DST.write_bytes(bytes(data))
print('wrote', DST)
print('size', len(data))
print('sha256', hashlib.sha256(bytes(data)).hexdigest())
for va in ENTRIES:
    off = va - VA0
    print(f'  entry {va:#x} -> {bytes(data[off:off+4]).hex()}')
