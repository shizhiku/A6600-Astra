"""Allow the boot script to use an alternate initrd via INITRD_IMG."""
from pathlib import Path

p = Path(r'<WORKSPACE>\02-脚本\boot_strip_exception.sh')
s = p.read_text(encoding='utf-8', newline='')
old = '-initrd /root/qemu_in/nflasha3-initrd'
if old not in s:
    print('anchor not found; current initrd lines:')
    print([l for l in s.splitlines() if 'initrd' in l])
else:
    if 'INITRD_IMG' in s:
        print('already patched')
    else:
        s = s.replace(old, '${INITRD_IMG:--initrd /root/qemu_in/nflasha3-initrd}')
        p.write_text(s, encoding='utf-8', newline='')
        print('patched')
    print([l for l in s.splitlines() if 'INITRD_IMG' in l])
