"""Switch the observer's av-cam input to the camera's own image."""
from pathlib import Path
import ast

p = Path(r'<WORKSPACE>\02-脚本\qemu_fault_breakpoint.py')
s = p.read_text(encoding='utf-8')
old = "DATA/'av-cam.bin'"
new = "DATA/'av-cam-live.bin'"
if old not in s:
    raise SystemExit('pattern not found')
s = s.replace(old, new)
ast.parse(s)
p.write_text(s, encoding='utf-8')
print('observer now loads av-cam-live.bin')
