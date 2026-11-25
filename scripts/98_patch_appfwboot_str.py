from pathlib import Path

ROOT = Path('<WORKSPACE>')
src = ROOT / '05-原始固件/zv1m2_fw/gen5/appFwBoot.so'
out = ROOT / '03-证据/静态分析/97_abi/appFwBoot_a5.so'
d = bytearray(src.read_bytes())

old = b'appFw.so\x00'
new = b'a5pFw.so\x00'
n = d.count(old)
print('appFw.so occurrences:', n)
assert n >= 1, 'string not found'
d = bytearray(bytes(d).replace(old, new))
out.write_bytes(bytes(d))
print('wrote', out, len(d), 'count now', d.count(new))
