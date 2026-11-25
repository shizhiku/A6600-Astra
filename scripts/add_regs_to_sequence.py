"""Record core registers in sequence-mode events."""
from pathlib import Path
import ast

p = Path(r'<WORKSPACE>\02-脚本\qemu_fault_breakpoint.py')
s = p.read_text(encoding='utf-8')

old = """                    events.append({'index': index, 'pc': hex(pc),
                                   'thread': stop.split('thread:')[1].rstrip(';') if 'thread:' in stop else None,
                                   'reads': reads})"""
new = """                    events.append({'index': index, 'pc': hex(pc),
                                   'r0': hex(regs[0]), 'r1': hex(regs[1]),
                                   'r2': hex(regs[2]), 'r3': hex(regs[3]),
                                   'thread': stop.split('thread:')[1].rstrip(';') if 'thread:' in stop else None,
                                   'reads': reads})"""
assert old in s, 'sequence event block not found'
s = s.replace(old, new)
ast.parse(s)
p.write_text(s, encoding='utf-8')
print('patched')
