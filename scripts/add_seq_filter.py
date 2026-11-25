"""Add conditional register filtering to sequence mode."""
from pathlib import Path
import ast

p = Path(r'<WORKSPACE>\02-脚本\qemu_fault_breakpoint.py')
s = p.read_text(encoding='utf-8')

# 1) CLI options
if '--seq-filter-reg' not in s:
    anchor = "    ap.add_argument('--wall-seconds', type=int, default=120)\n"
    assert anchor in s
    s = s.replace(anchor, anchor
                  + "    ap.add_argument('--seq-filter-reg', type=int)\n"
                    "    ap.add_argument('--seq-filter-value', type=lambda x: int(x, 0))\n")

# 2) loop restructure
old_head = """            if args.sequence_breakpoint:
                events = []
                status = 'sequence_budget_exhausted'
                for index in range(args.count_limit):
                    stop = rsp.command('c')"""
new_head = """            if args.sequence_breakpoint:
                events = []
                status = 'sequence_budget_exhausted'
                matched = 0
                max_iter = max(args.count_limit * 500, 1000)
                for _iteration in range(max_iter):
                    if matched >= args.count_limit:
                        break
                    stop = rsp.command('c')"""
assert old_head in s
s = s.replace(old_head, new_head)

# 3) filter check after the single-step (registers were captured before it)
old_step = """                    rsp.command('s')
                    for spec in args.read_reg:"""
new_step = """                    rsp.command('s')
                    if args.seq_filter_reg is not None and \\
                            regs[args.seq_filter_reg] != args.seq_filter_value:
                        for addr in args.sequence_breakpoint:
                            rsp.command(f'Z1,{addr:x},2')
                        continue
                    index = matched
                    matched += 1
                    for spec in args.read_reg:"""
assert old_step in s
s = s.replace(old_step, new_step)

ast.parse(s)
p.write_text(s, encoding='utf-8')
print('patched conditional filtering')
