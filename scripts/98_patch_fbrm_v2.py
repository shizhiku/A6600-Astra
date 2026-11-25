"""Reference-faithful patch of GRM_fbrmCheckUpdateFinished (no capstone needed).

Original at 0x115618 (12 bytes):
    80 b5        push {r7,lr}
    00 af        add  r7, sp, #0
    0a f0 a3 f8  bl   0x11F766      <- keep: preserves side effects
    02 4b        ldr  r3, [pc, #8]
    01 28        cmp  r0, #1
    14 bf        ite  ne
    18 46        movne r0, r3
    ...

Patch: keep bytes 0..7 (push/add/bl), replace bytes 8..11 with
    00 20 80 bd  = movs r0,#0 ; pop {r7,pc}
=> calls the original, then forces return 0 (success), matching the reference
   project's QEMU branch: return (rc != 0) ? 0 : rc;

Return semantics (verified): 0 = success, 0xFFFFD8F1 = not finished.
"""
import importlib.util
import hashlib
from pathlib import Path

ROOT = Path('<WORKSPACE>')
spec = importlib.util.spec_from_file_location('u', str(ROOT / '02-脚本/97_ext2.py'))
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)

fs = u.Ext2('/root/astra/97/m1-verified/astra-m1-astra7.img')
names = {p: i for p, i, d in fs.walk() if not d}
img = bytearray(fs.read_file(names['/lib/a5bObj.so']))

ENTRY = 0x115618
before = bytes(img[ENTRY:ENTRY + 12])
print('before:', before.hex(' '))
expected = bytes.fromhex('80b500af0af0a3f8024b0128')
assert before == expected, 'unexpected bytes: %s' % before.hex()

img[ENTRY + 8:ENTRY + 12] = bytes.fromhex('002080bd')
after = bytes(img[ENTRY:ENTRY + 12])
print('after :', after.hex(' '))

OUT = ROOT / '03-证据/静态分析/97_abi/a5bObj_fbrm2.img.so'
OUT.write_bytes(bytes(img))
print('wrote', OUT, len(img))
print('sha256', hashlib.sha256(img).hexdigest())
