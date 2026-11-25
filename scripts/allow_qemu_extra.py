"""Allow the boot script to append extra QEMU options (e.g. -d int)."""
from pathlib import Path

p = Path(r'<WORKSPACE>\02-脚本\boot_strip_exception.sh')
s = p.read_text(encoding='utf-8', newline='')
if 'QEMU_EXTRA' in s:
    print('already patched')
else:
    old = '  -icount shift=0,sleep=on > "$R/serial.log" 2> "$R/stderr.log"'
    if old not in s:
        raise SystemExit('anchor not found')
    s = s.replace(old, '  -icount shift=0,sleep=on ${QEMU_EXTRA:-} > "$R/serial.log" 2> "$R/stderr.log"')
    p.write_text(s, encoding='utf-8', newline='')
    print('patched')
print([l for l in s.splitlines() if 'QEMU_EXTRA' in l])
