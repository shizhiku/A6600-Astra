"""Allow the boot script to select an alternate av-cam image."""
from pathlib import Path

p = Path(r'<WORKSPACE>\02-脚本\boot_strip_exception.sh')
s = p.read_text(encoding='utf-8')
old = 'LIVE_AVCAM="$BASE/05-原始固件/qemu_in/av-cam-live.bin"'
new = 'LIVE_AVCAM="${AVCAM_IMG:-$BASE/05-原始固件/qemu_in/av-cam-live.bin}"'
if old not in s:
    if 'AVCAM_IMG' in s:
        print('already patched')
    else:
        raise SystemExit('anchor not found')
else:
    s = s.replace(old, new)
    p.write_text(s, encoding='utf-8')
    print('patched')
print([l for l in s.splitlines() if 'LIVE_AVCAM=' in l])
