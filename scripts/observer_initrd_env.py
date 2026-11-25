"""Add INITRD_IMG support to the observer."""
from pathlib import Path
import ast

p = Path(r'<WORKSPACE>\02-脚本\qemu_fault_breakpoint.py')
s = p.read_text(encoding='utf-8')
if 'INITRD_IMG' in s:
    print('already patched')
else:
    old = "str(DATA/'nflasha3-initrd')"
    if old not in s:
        print('anchor not found; initrd occurrences:')
        for line in s.splitlines():
            if 'initrd' in line:
                print('   ', line.strip()[:160])
        raise SystemExit(1)
    new = "os.environ.get('INITRD_IMG', str(DATA / 'nflasha3-initrd'))"
    s = s.replace(old, new)
    ast.parse(s)
    p.write_text(s, encoding='utf-8')
    print('patched initrd override')
