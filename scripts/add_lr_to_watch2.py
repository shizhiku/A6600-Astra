"""Record LR in watch-mode events so the originating call site can be identified."""
from pathlib import Path
import ast
import re

p = Path(r'<WORKSPACE>\02-脚本\qemu_fault_breakpoint.py')
s = p.read_text(encoding='utf-8')

m = re.search(r"\{'index': wcount, 'pc': hex\(pc\),[^\n]*\n", s)
if not m:
    raise SystemExit('anchor not found')
line = m.group(0)
if "'lr'" in line:
    print('already patched')
else:
    new_line = line.replace("{'index': wcount, 'pc': hex(pc),",
                            "{'index': wcount, 'pc': hex(pc), 'lr': hex(regs[14]),")
    s = s.replace(line, new_line)
    ast.parse(s)
    p.write_text(s, encoding='utf-8')
    print('patched:', new_line.strip()[:120])
