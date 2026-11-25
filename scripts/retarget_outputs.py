"""Redirect observer run outputs into the new evidence folder."""
from pathlib import Path
import ast

p = Path(r'<WORKSPACE>\02-脚本\qemu_fault_breakpoint.py')
s = p.read_text(encoding='utf-8')
old = "destination = BASE/'a6600_port/emulation'/name"
new = "destination = BASE/'03-证据/模拟器运行'/name"
if old not in s:
    raise SystemExit('destination line not found')
s = s.replace(old, new)
ast.parse(s)
p.write_text(s, encoding='utf-8')
print('patched')
for line in s.splitlines():
    if 'destination =' in line:
        print('  ' + line.strip())
