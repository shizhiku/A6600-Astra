"""List ZV-1M2 /usr image contents relevant to ASTRA porting (libs + UI resources)."""
from pathlib import Path
import importlib.util

BASE = Path('<WORKSPACE>')
IMG = BASE / '05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15'

spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
fs = m.Ext2(str(IMG))

NEEDED = ['libNetCommon.so', 'libGOConnectionManager.so', 'AdjChkConfig.so',
          'libopus.so.0', 'libSoundTouch.so.1', 'libqrencode.so', 'libInfraSKD.so',
          'libutil_date.so', 'dataflowInfraFramework.so', 'libcompassutil.so',
          'libInfraUsbCmn.so', 'libsencore.so', 'libNetContUtil.so',
          'libUsbControl.so', 'libBackupManager.so', 'libInfraMediaCommon.so',
          'libbackup.so', 'libexpat.so.1', 'libstdc++.so.6', 'libgcc_s.so.1']

libs = {}
dirs = set()
for path, ino, is_dir in fs.walk():
    if is_dir:
        dirs.add(path)
        continue
    name = path.rsplit('/', 1)[-1]
    mode, size, _ = fs.inode(ino)
    libs.setdefault(name, []).append((path, size))

print('image:', IMG.name, 'files:', sum(len(v) for v in libs.values()))
print('\n=== dependency check ===')
for n in NEEDED:
    if n in libs:
        for p, s in libs[n]:
            print(f'  OK   {n:28} {s:>10,} B  {p}')
    else:
        print(f'  MISS {n}')

print('\n=== gen5 UI libs present? ===')
for n in ('appFw.so', 'libObj.so', 'libmpr.so', 'libIMDB.so', 'appFwBoot.so'):
    print(f'  {n:16} {"present" if n in libs else "MISSING"}')

print('\n=== top-level dirs ===')
print(' ', sorted(d for d in dirs if d.count("/") <= 1)[:40])
