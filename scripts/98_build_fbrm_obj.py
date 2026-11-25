"""Build the final patched a5bObj.so = reference libObj.so
   + rename patches (li->a5, da->a5, exactly as in the image)
   + GRM_fbrmCheckUpdateFinished patch (0x115618 -> movs r0,#0 ; bx lr)

The image's /lib/a5bObj.so differs from the pristine gen5 libObj.so by exactly
20 bytes (10 x 2-byte string renames).  We must preserve those.
"""
import importlib.util
import hashlib
from pathlib import Path

ROOT = Path('<WORKSPACE>')
spec = importlib.util.spec_from_file_location('u', str(ROOT / '02-脚本/97_ext2.py'))
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)

# image copy = already renamed
fs = u.Ext2('/root/astra/97/m1-verified/astra-m1-astra7.img')
names = {p: i for p, i, d in fs.walk() if not d}
img = bytearray(fs.read_file(names['/lib/a5bObj.so']))
print('image a5bObj size', len(img),
      'sha', hashlib.sha256(img).hexdigest()[:16])

ENTRY = 0x115618          # file offset == VA (verified: .text addr==off==0x3d080)
before = bytes(img[ENTRY:ENTRY + 4])
print('before at %#x: %s' % (ENTRY, before.hex(' ')))
assert before == bytes.fromhex('80b500af'), 'unexpected bytes: %s' % before.hex()

img[ENTRY:ENTRY + 4] = bytes.fromhex('00207047')   # movs r0,#0 ; bx lr
print('after  at %#x: %s' % (ENTRY, bytes(img[ENTRY:ENTRY + 4]).hex(' ')))

OUT = ROOT / '03-证据/静态分析/97_abi/a5bObj_fbrm.img.so'
OUT.write_bytes(bytes(img))
print('wrote', OUT, len(img), 'sha', hashlib.sha256(img).hexdigest())
