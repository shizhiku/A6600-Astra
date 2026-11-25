"""Inject the camera font into a copy of the /usr image and repoint fontlist.dat.

Runs under WSL; uses POSIX paths and debugfs (no mount needed).
Output: 05-原始固件/qemu_in/nflasha15-font (original untouched).
"""
from pathlib import Path
import subprocess, shutil, hashlib, sys

BASE = Path('<WORKSPACE>')
SRC = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
DST = BASE / '05-原始固件/qemu_in/nflasha15-font'
FONT = BASE / '03-证据/相机采集/live-fonts-20261121/tmp_images_MYingHeiC-GB18030-SJ_wIcon.ltt'
NEWLIST = BASE / '05-原始固件/qemu_in/fontlist-new.dat'
OLDLIST = BASE / '03-证据/静态分析/fontlist.dat'
FONT_DEST = '/share/app/MYingHeiC-GB18030-SJ_wIcon.ltt'
LIST_DEST = '/share/app/fontlist.dat'

for p in (SRC, FONT, OLDLIST):
    if not p.exists():
        raise SystemExit(f'missing {p}')

t = OLDLIST.read_bytes().decode('latin1')
t2 = t.replace('/tmp/images/MYingHeiC-GB18030-SJ_wIcon.ltt',
               '/usr/share/app/MYingHeiC-GB18030-SJ_wIcon.ltt')
if t2 == t:
    raise SystemExit('fontlist replacement did not change anything')
NEWLIST.write_bytes(t2.encode('latin1'))
print('new fontlist.dat:')
print(t2.replace('\t', ' | '))

if not DST.exists():
    print('copying image (215 MB) ...', flush=True)
    shutil.copyfile(SRC, DST)
else:
    print('image copy already exists')

def run(*args, quiet=False):
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0 and not quiet:
        print('cmd failed:', args[0], r.stderr[-300:])
    return r

print('writing font via debugfs ...', flush=True)
run('debugfs', '-w', '-R', f'write {FONT} {FONT_DEST}', str(DST))
run('debugfs', '-w', '-R', f'rm {LIST_DEST}', str(DST), quiet=True)
run('debugfs', '-w', '-R', f'write {NEWLIST} {LIST_DEST}', str(DST))
run('e2fsck', '-fy', str(DST), quiet=True)

print('\n--- verify ---')
for cmd in (f'stat {FONT_DEST}', f'cat {LIST_DEST}'):
    r = run('debugfs', '-R', cmd, str(DST))
    print(r.stdout[-600:])

print('image size:', DST.stat().st_size)
print('sha256:', hashlib.sha256(DST.read_bytes()).hexdigest()[:32])
