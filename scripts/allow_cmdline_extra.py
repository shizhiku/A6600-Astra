"""Allow appending extra kernel cmdline options to the diagnostic boot script."""
from pathlib import Path

p = Path(r'<WORKSPACE>\02-脚本\boot_strip_exception.sh')
s = p.read_text(encoding='utf-8', newline='')
if 'CMDLINE_EXTRA' in s:
    print('already patched')
else:
    anchor = 'printf \'%s\' "$CMD" > "$R/cmdline.txt"'
    if anchor not in s:
        raise SystemExit('anchor not found')
    s = s.replace(anchor, 'CMD="$CMD ${CMDLINE_EXTRA:-}"\n' + anchor)
    p.write_text(s, encoding='utf-8', newline='')
    print('patched cmdline extra')
print([l for l in s.splitlines() if 'CMDLINE_EXTRA' in l or 'printf' in l])
