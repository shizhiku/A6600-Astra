"""Compare gen5 (ZV-1M2) library imports against a6600 runtime exports."""
from pathlib import Path
import importlib.util, io, sys
from elftools.elf.elffile import ELFFile

BASE = Path(r'<WORKSPACE>')
A6600_USR = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
GEN5 = BASE / '05-原始固件/zv1m2_fw/gen5'

spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
fs = m.Ext2(str(A6600_USR))


def exports_from_bytes(data):
    """Return set of exported (GLOBAL DEFAULT, defined) symbol names."""
    out = set()
    try:
        with ELFFile(io.BytesIO(data)) as e:
            for sym in e.get_section_by_name('.dynsym').iter_symbols():
                if not sym.name:
                    continue
                if sym['st_shndx'] == 'SHN_UNDEF':
                    continue
                if sym['st_info']['bind'] in ('STB_GLOBAL', 'STB_WEAK'):
                    out.add(sym.name)
    except Exception:
        pass
    return out


def imports_from_path(path):
    out = set()
    with open(path, 'rb') as f:
        e = ELFFile(f)
        for sym in e.get_section_by_name('.dynsym').iter_symbols():
            if sym.name and sym['st_shndx'] == 'SHN_UNDEF':
                out.add(sym.name)
    return out


# Compare against every shared library in a6600 /lib (full runtime surface).
provided = {}
libcount = 0
for path, ino, is_dir in fs.walk():
    if is_dir:
        continue
    if not path.startswith('/lib/'):
        continue
    name = path.rsplit('/', 1)[-1]
    if '.so' not in name:
        continue
    data = fs.read_file(ino)
    if not data[:4] == b'\x7fELF':
        continue
    libcount += 1
    provided.setdefault(name, set()).update(exports_from_bytes(data))

all_provided = set().union(*provided.values()) if provided else set()
print('a6600 /lib shared objects scanned:', libcount,
      '| total exported symbols:', len(all_provided))

# Also treat ZV-1M2's own /lib as shippable (the ASTRA port would carry these).
ZV_USR = BASE / '05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15'
fs2 = m.Ext2(str(ZV_USR))
zv_exports = set()
zv_libs = 0
for path, ino, is_dir in fs2.walk():
    if is_dir or not path.startswith('/lib/'):
        continue
    name = path.rsplit('/', 1)[-1]
    if '.so' not in name:
        continue
    data = fs2.read_file(ino)
    if not data[:4] == b'\x7fELF':
        continue
    zv_libs += 1
    zv_exports |= exports_from_bytes(data)
print('ZV-1M2 /lib shared objects scanned:', zv_libs,
      '| exported symbols:', len(zv_exports))

combined = all_provided | zv_exports
print('combined provided symbols:', len(combined))

# a6600 rootfs (/lib of nflasha7) holds libc and friends; include it too.
ROOTFS = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha7'
fs3 = m.Ext2(str(ROOTFS))
root_exports = set()
root_libs = 0
for path, ino, is_dir in fs3.walk():
    if is_dir or not path.startswith('/lib/'):
        continue
    name = path.rsplit('/', 1)[-1]
    if '.so' not in name:
        continue
    data = fs3.read_file(ino)
    if not data[:4] == b'\x7fELF':
        continue
    root_libs += 1
    root_exports |= exports_from_bytes(data)
print('a6600 rootfs /lib shared objects scanned:', root_libs,
      '| exported symbols:', len(root_exports))

combined = combined | root_exports
print('final provided symbols (usr+rootfs+zv1m2):', len(combined))

for lib in ('appFw.so', 'libObj.so', 'libmpr.so', 'libIMDB.so'):
    p = GEN5 / lib
    if not p.exists():
        continue
    need = imports_from_path(p)
    missing_a6600 = sorted(s for s in need if s not in all_provided)
    missing_all = sorted(s for s in need if s not in combined)
    print(f'\n=== {lib}: imports={len(need)} '
          f'missing_with_a6600_only={len(missing_a6600)} '
          f'missing_even_with_zv1m2_libs={len(missing_all)} ===')
    for s in missing_all[:40]:
        print('   STILL MISS', s)
    if len(missing_all) > 40:
        print(f'   ... and {len(missing_all) - 40} more')
