"""Collect the transitive DT_NEEDED set of /usr libraries and list missing files."""
from pathlib import Path
import importlib.util, io
from elftools.elf.elffile import ELFFile

BASE = Path(r'<WORKSPACE>')
USR = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fs = m.Ext2(str(USR))

files = {}
for path, ino, is_dir in fs.walk():
    if is_dir:
        continue
    files[path] = ino

libs = {p.rsplit('/', 1)[-1]: p for p in files if p.endswith('.so') or '.so.' in p}
print('libs found in /usr:', len(libs))

needed_all = set()
for name, path in list(libs.items()):
    try:
        data = fs.read_file(files[path])
        e = ELFFile(io.BytesIO(data))
        dyn = e.get_section_by_name('.dynamic')
        if dyn is None:
            continue
        for t in dyn.iter_tags():
            if t.entry.d_tag == 'DT_NEEDED':
                needed_all.add(t.needed)
    except Exception:
        continue

missing = sorted(n for n in needed_all if n not in libs)
print('\nunion of DT_NEEDED:', len(needed_all))
print('missing from /usr:')
for n in missing:
    print('  ', n)

# which libs need each missing one
print('\nwho needs the missing ones:')
for n in missing:
    users = []
    for name, path in list(libs.items()):
        try:
            data = fs.read_file(files[path])
            if n.encode() in data:
                users.append(name)
        except Exception:
            pass
    print(f'  {n}: {users[:6]}{" ..." if len(users) > 6 else ""}')
