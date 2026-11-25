"""Extract gen5 libs + missing deps from the ZV-1M2 image to a staging directory."""
from pathlib import Path
import importlib.util

BASE = Path('<WORKSPACE>')
ZV = BASE / '05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15'
GEN5 = BASE / '05-原始固件/zv1m2_fw/gen5'
OUT = Path('/root/astra/stage')

# gen5 libs come from the gen5 folder; deps are pulled out of the ZV image
WANT_ZV = ['AdjChkConfig.so', 'libInfraSKD.so', 'libBackupManager.so', 'libqrencode.so',
           'libopus.so.0.8.0', 'libSoundTouch.so.1.0.0']

OUT.mkdir(parents=True, exist_ok=True)

spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
fs = m.Ext2(str(ZV))

targets = {}
for path, ino, is_dir in fs.walk():
    if is_dir or not path.startswith('/lib/'):
        continue
    name = path.rsplit('/', 1)[-1]
    if name in WANT_ZV and name not in targets:
        targets[name] = ino

for name, ino in targets.items():
    data = fs.read_file(ino)
    (OUT / name).write_bytes(data)
    print(f'zv   {name:24} {len(data):>10,} B')

for name in ('appFw.so', 'libObj.so', 'libmpr.so', 'libIMDB.so', 'appFwBoot.so'):
    src = GEN5 / name
    if src.exists():
        (OUT / name).write_bytes(src.read_bytes())
        print(f'gen5 {name:24} {src.stat().st_size:>10,} B')

total = sum(p.stat().st_size for p in OUT.iterdir())
print(f'\nstaged {len(list(OUT.iterdir()))} files, {total/1048576:.1f} MB in {OUT}')
