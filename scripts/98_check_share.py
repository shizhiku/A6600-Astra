from pathlib import Path
import importlib.util

ROOT = Path('<WORKSPACE>')
spec = importlib.util.spec_from_file_location('usr', ROOT / '02-脚本/a6600_usr.py')
usr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(usr)

ours = usr.Ext2('/root/astra/97/m1-verified/astra-m1-rwx5.img')
gen5 = usr.Ext2(str(ROOT / '05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15'))
gen4 = usr.Ext2(str(ROOT / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'))
for name, fs in (('ours', ours), ('gen5', gen5), ('gen4', gen4)):
    names = [p for p, i, d in fs.walk() if not d]
    share = [n for n in names if n.startswith('/share/')]
    app = [n for n in share if n.startswith('/share/app/')]
    print(name, 'share', len(share), 'app', len(app))
    for probe in ('/share/app/global.xdb', '/share/app/area_check_data.dat'):
        print('  ', probe, probe in names)
    keys = [n for n in app if n.endswith('.xdb')][:6]
    print('   xdb', keys)
