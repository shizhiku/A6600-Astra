"""Verify the image's /lib/a5bObj.so matches our extracted libObj.so before
swapping in the patched version."""
import importlib.util
import hashlib
from pathlib import Path

ROOT = Path('<WORKSPACE>')
spec = importlib.util.spec_from_file_location('u', str(ROOT / '02-脚本/97_ext2.py'))
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)

IMG = '/root/astra/97/m1-verified/astra-m1-astra7.img'
fs = u.Ext2(IMG)
names = {p: i for p, i, d in fs.walk() if not d}
target = '/lib/a5bObj.so'
print('present:', target in names)
if target in names:
    b = fs.read_file(names[target])
    print('image size:', len(b))
    print('image sha256:', hashlib.sha256(b).hexdigest())

ref = ROOT / '03-证据/静态分析/grm/lib/libObj.so'
rb = ref.read_bytes()
print('ref size:', len(rb))
print('ref sha256:', hashlib.sha256(rb).hexdigest())
print('MATCH:', hashlib.sha256(b).hexdigest() == hashlib.sha256(rb).hexdigest())
