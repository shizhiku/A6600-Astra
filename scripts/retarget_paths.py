"""Retarget the offline observer script to the new working directory."""
from pathlib import Path

p = Path(r'<WORKSPACE>\02-脚本\qemu_fault_breakpoint.py')
s = p.read_text(encoding='utf-8')

old_base = "BASE = Path('<LEGACY_WORKSPACE>')"
new_base = "BASE = Path('<WORKSPACE>')"
if old_base not in s:
    raise SystemExit('base line not found')
s = s.replace(old_base, new_base)

s = s.replace("DATA = Path('/root/qemu_in')",
              "DATA = BASE / '05-原始固件/qemu_in'\nEMMC = Path('/root/qemu_in/emmc.img')")
s = s.replace("CTRL = Path('/root/a6600-emulation/captured-stock-20261120T151942Z-27058')",
              "CTRL = BASE / '03-证据/模拟器运行/captured-stock-20261120T151942Z-27058'")
s = s.replace("str(DATA/'emmc.img')", "str(EMMC)")

p.write_text(s, encoding='utf-8')
print('patched:')
for line in s.splitlines()[:16]:
    print('  ' + line)
