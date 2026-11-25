#!/usr/bin/env python3
"""Re-verify every claim in the evidence chain against the CURRENT artifacts.

Run:  python3 scripts/audit_all.py
Exit code 0 only if all checks pass.
"""
import hashlib
import subprocess
import sys
from pathlib import Path

BASE = Path('${WORKSPACE}/04-产物/a6600-port')
REL = BASE / 'release'
REPO = Path('${REPO}')
GEN4 = REPO / 'firmware/gen4'
GEN5 = REPO / 'firmware/gen5/lib'
BRIDGE = REPO / 'build_out/a6600_bridge'
SHIM = REPO / 'build_out/rehost/appFwBoot.so'
ROLLBACK = Path('${RUN}/rollback')

USR_IMG = REL / 'usr_astra_a6600.img'
ETC_IMG = REL / 'etc_nflasha10_preload.img'
TMP = Path('/tmp/audit_extract')

results = []


def check(name, ok, detail=''):
    results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ''))


def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


print('=' * 62)
print(' a6600 ASTRA deliverable audit')
print('=' * 62)

# ---------- 1. release files ----------
print('\n[1] release package')
if not USR_IMG.exists() or not ETC_IMG.exists():
    check('release images present', False)
    sys.exit(1)
check('usr image size', USR_IMG.stat().st_size == 314572800, f'{USR_IMG.stat().st_size}')
check('etc image size', ETC_IMG.stat().st_size == 12582912, f'{ETC_IMG.stat().st_size}')

man = (REL / 'MANIFEST.txt').read_text()
for name, img in (('usr_astra_a6600.img', USR_IMG), ('etc_nflasha10_preload.img', ETC_IMG)):
    line = [l for l in man.splitlines() if l.startswith(name)]
    if not line:
        check(f'{name} listed in MANIFEST', False)
        continue
    want = line[0].split()[-1]
    got = sha(img)
    check(f'{name} sha256 matches MANIFEST', want == got, got[:16])

# ---------- 2. filesystem integrity ----------
print('\n[2] filesystem')
r = sh(f'e2fsck -fn "{USR_IMG}"')
check('usr image e2fsck clean', r.returncode == 0)
r2 = sh(f'e2fsck -fn "{USR_IMG}" 2>&1 | grep -E "files|blocks" | tail -1')
print(f'       {r2.stdout.strip()}')

# ---------- 3. stock binaries untouched ----------
print('\n[3] original system binaries are byte-identical to stock')
TMP.mkdir(parents=True, exist_ok=True)
for name, in_img in (('im.elf', '/bin/im.elf'), ('libObj.so', '/lib/libObj.so'),
                     ('libMWF.so', '/lib/libMWF.so'), ('libIMDB.so', '/lib/libIMDB.so')):
    out = TMP / name
    if out.exists():
        out.unlink()
    sh(f'debugfs -R "dump {in_img} {out}" "{USR_IMG}"')
    stock = GEN4 / ('bin/' + name)
    if not stock.exists():
        stock = GEN4 / ('lib/' + name)
    if not out.exists():
        check(f'{name} extracted', False)
        continue
    check(f'{name} == stock', sha(out) == sha(stock), sha(out)[:16])

# ---------- 4. shim in image matches the build ----------
print('\n[4] deployed shim matches the built artifact')
out = TMP / 'appFwBoot.so'
if out.exists():
    out.unlink()
sh(f'debugfs -R "dump /lib/appFwBoot.so {out}" "{USR_IMG}"')
if out.exists() and SHIM.exists():
    check('appFwBoot.so in image == build_out/rehost', sha(out) == sha(SHIM), sha(out)[:16])
    check('shim size', out.stat().st_size == SHIM.stat().st_size, f'{out.stat().st_size}')
else:
    check('shim present', False)

# ---------- 5. appFw.so differs by exactly 302 bytes ----------
print('\n[5] 5th-gen appFw.so patch surface')
out5 = TMP / 'appFw.so'
if out5.exists():
    out5.unlink()
sh(f'debugfs -R "dump /lib/appFw.so {out5}" "{USR_IMG}"')
orig = GEN5 / 'appFw.so'
if out5.exists() and orig.exists():
    a, b = orig.read_bytes(), out5.read_bytes()
    check('appFw.so same length as original', len(a) == len(b), f'{len(a)} vs {len(b)}')
    if len(a) == len(b):
        diff = sum(1 for i in range(len(a)) if a[i] != b[i])
        check('exactly 302 bytes differ', diff == 302, f'{diff}')

# ---------- 6. /etc preload content ----------
print('\n[6] /etc(nflasha10) image')
pre = TMP / 'ld.so.preload'
if pre.exists():
    pre.unlink()
sh(f'mcopy -o -i "{ETC_IMG}" ::ld.so.preload "{pre}" 2>/dev/null')
if pre.exists():
    txt = pre.read_text().strip()
    check('ld.so.preload points at appFwBoot.so',
          txt == '/usr/lib/appFwBoot.so', repr(txt))
else:
    check('ld.so.preload present', False)
r = sh(f'mdir -i "{ETC_IMG}" ::/')
check('/etc image is valid vfat', 'images' in r.stdout)

# ---------- 7. rollback sources ----------
print('\n[7] rollback sources')
for name, size in (('stock_usr.img', 314572800), ('stock_etc.img', 12582912)):
    p = ROLLBACK / name
    if not p.exists():
        check(f'{name} present', False)
        continue
    check(f'{name} size', p.stat().st_size == size, f'{p.stat().st_size}')
    if name == 'stock_usr.img':
        check('stock_usr.img e2fsck clean', sh(f'e2fsck -fn "{p}"').returncode == 0)

# ---------- 8. scripts ----------
print('\n[8] scripts syntax')
for s in ('live_loop.py', 'build_shim_a6600.py', 'patch_qemu_touch.py'):
    p = BASE / 'scripts' / s
    r = sh(f'python3 -c "import ast;ast.parse(open(\'{p}\',encoding=\'utf-8\').read())"')
    check(f'{s} parses', r.returncode == 0)
for s in ('probe_camera_ro.sh', 'flash_astra.sh'):
    p = BASE / 'scripts' / s
    check(f'{s} sh -n', sh(f'sh -n "{p}"').returncode == 0)
p = BASE / 'webui.py'
check('webui.py parses', sh(f'python3 -c "import ast;ast.parse(open(\'{p}\',encoding=\'utf-8\').read())"').returncode == 0)

# ---------- summary ----------
print('\n' + '=' * 62)
bad = [r for r in results if not r[1]]
print(f' {len(results) - len(bad)}/{len(results)} checks passed')
if bad:
    print(' FAILURES:')
    for n, _, d in bad:
        print(f'   - {n} {d}')
print('=' * 62)
sys.exit(0 if not bad else 1)
