from pathlib import Path
import importlib.util
from collections import Counter

ROOT = Path('<WORKSPACE>')
spec = importlib.util.spec_from_file_location('usr', ROOT / '02-脚本/a6600_usr.py')
usr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(usr)


def share_dirs(img):
    fs = usr.Ext2(img)
    c = Counter()
    for p, i, d in fs.walk():
        if p.startswith('/share/') and not d:
            parts = p.split('/')
            if len(parts) > 2:
                c['/share/' + parts[2]] += 1
    return c


ours = share_dirs('/root/astra/97/m1-verified/astra-m1-rwx5.img')
gen5 = share_dirs(str(ROOT / '05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15'))
keys = sorted(set(ours) | set(gen5))
for k in keys:
    print(f'{k:40s} ours={ours.get(k,0):6d} gen5={gen5.get(k,0):6d}')
