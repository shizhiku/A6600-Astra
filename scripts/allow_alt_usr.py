"""Allow the boot script to use an alternate /usr image via USR_IMG."""
from pathlib import Path

p = Path(r'<WORKSPACE>\02-脚本\boot_strip_exception.sh')
s = p.read_text(encoding='utf-8', newline='')
old = 'USR_IMG="$BASE/05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15"'
if 'USR_IMG="${' in s:
    print('already patched')
elif old in s:
    s = s.replace(old, 'USR_IMG="${USR_IMG_OVERRIDE:-$BASE/05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15}"')
    p.write_text(s, encoding='utf-8', newline='')
    print('patched')
else:
    print('anchor not found')
print([l for l in s.splitlines() if 'USR_IMG' in l])
