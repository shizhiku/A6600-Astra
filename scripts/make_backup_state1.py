"""Create a Backup.bin variant with property 0x00170000 byte[2]=1, checksum fixed.

Diagnostic only: emulates a camera whose previous shutdown completed normally.
"""
from pathlib import Path
import sys, io, hashlib, struct

BASE = Path(r'<WORKSPACE>')
VENDOR = Path(r'<LEGACY_WORKSPACE>\repo\tools\flash\camtool\vendor')
SRC = BASE / '03-证据/相机采集/boot-20261120T151656Z-26869/05-setting__Backup.bin'
DST = BASE / '05-原始固件/qemu_in/Backup-state1.bin'

sys.path.insert(0, str(VENDOR))
from pmca.backup import BackupFile

raw = bytearray(SRC.read_bytes())
bf = BackupFile(io.BytesIO(bytes(raw)))
ptr = bf._readProperty(0x00170000)
prop = bf.getProperty(0x00170000)
needle = bytes(prop.data)
idx = raw.find(needle)
if idx < 0:
    raise SystemExit('payload not found')
print(f'payload at {idx:#x}; before={raw[idx:idx+8].hex()}')

raw[idx + 2] = 0x01

# recompute checksum: sum of all bytes except the 4-byte checksum field at 0x20
size = bf.header.dataOffset + bf.header.dataSize
data = bytes(raw[:size])
checksum = sum(data[:0x20] + data[0x24:]) & 0xFFFFFFFF
struct.pack_into('<I', raw, 0x20, checksum)

DST.write_bytes(bytes(raw))
print('after :', bytes(raw[idx:idx + 8]).hex())

# verify
bf2 = BackupFile(io.BytesIO(bytes(raw)))
print('re-read:', bytes(bf2.getProperty(0x00170000).data[:8]).hex())
print('checksum', hex(checksum), 'sha256', hashlib.sha256(bytes(raw)).hexdigest())
