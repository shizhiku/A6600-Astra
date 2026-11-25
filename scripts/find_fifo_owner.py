"""Who references /var/fifo in the firmware (initrd rootfs and /usr)?"""
from pathlib import Path
import importlib.util

BASE = Path(r'<WORKSPACE>')
INITRD = BASE / '05-原始固件/qemu_in/nflasha3-initrd'
USR = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

TERMS = [b'/var/fifo', b'sen_host_req', b'sen_host_res', b'mkfifo']

for label, img in (('initrd', INITRD), ('/usr', USR)):
    fs = m.Ext2(str(img))
    print(f'--- {label} ---')
    hits = 0
    for path, ino, is_dir in fs.walk():
        if is_dir:
            continue
        mode, size, _ = fs.inode(ino)
        if size == 0 or size > 40 * 1024 * 1024:
            continue
        data = fs.read_file(ino)
        found = [t.decode() for t in TERMS if t in data]
        if found:
            hits += 1
            print(f'  {path}  size={size}  -> {found}')
            if hits > 20:
                print('  ...')
                break
    if hits == 0:
        print('  (no references)')
