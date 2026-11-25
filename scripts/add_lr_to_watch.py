"""Record LR in watch-mode events so the originating call site can be identified."""
from pathlib import Path
import ast

p = Path(r'<WORKSPACE>\02-脚本\qemu_fault_breakpoint.py')
s = p.read_text(encoding='utf-8')
old = "{'index': wcount, 'pc': hex(pc), 'value': reads.get(hex(args.watch_target), reads.get(next(iter(reads), ''), '')),"
if old not in s:
    # try a looser match
    import re
    m = re.search(r"\{'index': wcount, 'pc': hex\(pc\),[^\n]*\n", s)
    print('pattern:', m.group(0) if m else 'NOT FOUND')
    raise SystemExit('anchor not found')
s = s.replace(old, "{'index': wcount, 'pc': hex(pc), 'lr': hex(regs[14]),"
ast.parse(s)
p.write_text(s, encoding='utf-8')
print('patched watch events with LR')
