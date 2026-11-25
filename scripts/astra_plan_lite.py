"""Plan the ASTRA-lite /usr: which gen5 deps already exist in a6600, and the space math."""
from pathlib import Path
import importlib.util

BASE = Path(r'<WORKSPACE>')
A6 = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
ZV = BASE / '05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15'
GEN5 = BASE / '05-原始固件/zv1m2_fw/gen5'

spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def libmap(img):
    fs = m.Ext2(str(img))
    out = {}
    for path, ino, is_dir in fs.walk():
        if is_dir or not path.startswith('/lib/'):
            continue
        mode, size, _ = fs.inode(ino)
        out.setdefault(path.rsplit('/', 1)[-1], (path, size, ino))
    return fs, out


a6fs, a6 = libmap(A6)
zvfs, zv = libmap(ZV)

DEPS = ['libNetCommon.so', 'libGOConnectionManager.so', 'AdjChkConfig.so',
        'libopus.so.0', 'libSoundTouch.so.1', 'libqrencode.so', 'libInfraSKD.so',
        'libutil_date.so', 'dataflowInfraFramework.so', 'libcompassutil.so',
        'libInfraUsbCmn.so', 'libsencore.so', 'libNetContUtil.so',
        'libUsbControl.so', 'libBackupManager.so', 'libInfraMediaCommon.so',
        'libbackup.so', 'libexpat.so.1']

GEN5_LIBS = ['appFw.so', 'libObj.so', 'libmpr.so', 'libIMDB.so',
             'appFwBoot.so', 'AdjChkConfig.so']

print('=== deps: a6600 has? ===')
add_bytes = 0
for d in DEPS:
    in_a6 = d in a6
    size = zv[d][1] if d in zv else 0
    tag = 'REUSE a6600' if in_a6 else 'ADD from ZV'
    if not in_a6:
        add_bytes += size
    print(f'  {d:28} {tag:12} zv_size={size:>10,}')

print('\n=== gen5 libs ===')
gen5_bytes = 0
for g in GEN5_LIBS:
    p = GEN5 / g
    s = p.stat().st_size if p.exists() else 0
    gen5_bytes += s
    print(f'  {g:20} {s:>12,} B')

REMOVE = ['libObj.so', 'libmpr.so', 'CautionConfig.so', 'viewUnified2.so',
          'viewUnified4.so', 'viewUnified3.so', 'viewUnified5.so',
          'viewUnified6.so', 'viewUnified7.so', 'libmintx.so']
free_bytes = 0
print('\n=== a6600 files to remove ===')
for r in REMOVE:
    if r in a6:
        free_bytes += a6[r][1]
        print(f'  {r:20} {a6[r][1]:>12,} B')

sb_free = 9521 * 1024   # from superblock: 9521 free 1K blocks
print(f'\nadd_bytes(deps)   = {add_bytes:,}')
print(f'gen5_bytes        = {gen5_bytes:,}')
print(f'free_bytes(remove)= {free_bytes:,}')
print(f'fs free           = {sb_free:,}')
delta = add_bytes + gen5_bytes - free_bytes
print(f'net needed        = {delta:,} B ({delta/1048576:.1f} MB)')
print(f'after             = {(sb_free - delta)/1048576:.1f} MB free '
      f'({"FITS" if sb_free >= delta else "SHORT by %.1f MB" % ((delta-sb_free)/1048576)})')
