from pathlib import Path
import importlib.util

ROOT = Path('<WORKSPACE>')
spec = importlib.util.spec_from_file_location('usr', ROOT / '02-脚本/a6600_usr.py')
usr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(usr)

src = ROOT / '05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15'
fs = usr.Ext2(str(src))
idx = {p: i for p, i, d in fs.walk() if not d}
out = ROOT / '03-证据/静态分析/kmod_g5'
out.mkdir(parents=True, exist_ok=True)
for name in ('upm.ko', 'osal_uipc.ko'):
    p = '/kmod/' + name
    if p not in idx:
        print('missing', p)
        continue
    b = fs.read_file(idx[p])
    (out / name).write_bytes(b)
    print('wrote', out / name, len(b))
