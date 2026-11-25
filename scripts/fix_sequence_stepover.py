"""Make sequence mode step over the breakpoint so hits represent real re-entry."""
from pathlib import Path
import ast

p = Path(r'<WORKSPACE>\02-脚本\qemu_fault_breakpoint.py')
s = p.read_text(encoding='utf-8')

old = """                for index in range(args.count_limit):
                    stop = rsp.command('c')
                    regs = rsp.registers()
                    pc = regs[15]
                    reads = {hex(a): rsp.memory(a, 4).get('hex') for a in args.read_address}"""
new = """                for index in range(args.count_limit):
                    stop = rsp.command('c')
                    regs = rsp.registers()
                    pc = regs[15]
                    reads = {hex(a): rsp.memory(a, 4).get('hex') for a in args.read_address}
                    # step off the breakpoint so the next continue makes real progress
                    for addr in args.sequence_breakpoint:
                        rsp.command(f'z1,{addr:x},2')
                    rsp.command('s')"""
assert old in s, 'sequence loop head not found'
s = s.replace(old, new)

old2 = """                    if pc == FATAL_PC:
                        status = 'fatal_pc_reached'
                        break
                report['sequence_events'] = events"""
new2 = """                    if pc == FATAL_PC:
                        status = 'fatal_pc_reached'
                        break
                    for addr in args.sequence_breakpoint:
                        rsp.command(f'Z1,{addr:x},2')
                report['sequence_events'] = events"""
assert old2 in s, 'sequence loop tail not found'
s = s.replace(old2, new2)

ast.parse(s)
p.write_text(s, encoding='utf-8')
print('patched: sequence mode now steps over breakpoints')
