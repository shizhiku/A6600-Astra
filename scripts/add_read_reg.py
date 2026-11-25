"""Add register-relative memory reads to the offline observer."""
from pathlib import Path
import ast

p = Path(r'<WORKSPACE>\02-脚本\qemu_fault_breakpoint.py')
s = p.read_text(encoding='utf-8')

# 1. new CLI option
anchor = "    ap.add_argument('--sequence-breakpoint', type=lambda x: int(x, 0), action='append', default=[])\n"
assert anchor in s
s = s.replace(anchor, anchor + "    ap.add_argument('--read-reg', action='append', default=[],\n"
                              "                    help='reg:size, e.g. r0:8 reads memory at the address held in r0')\n")

# 2. helper to decode "reg:size"
helper = (
    "\ndef parse_read_reg(spec):\n"
    "    reg, _, size = spec.partition(':')\n"
    "    reg = reg.strip().lower()\n"
    "    if not reg.startswith('r'):\n"
    "        raise ValueError(f'bad register {reg!r}')\n"
    "    return int(reg[1:]), int(size or '4', 0)\n"
    "\n"
)
marker = "\ndef file_limit():"
assert marker in s
s = s.replace(marker, helper + marker)

# 3. use it in the sequence branch
old_reads = "reads = {hex(a): rsp.memory(a, 4).get('hex') for a in args.read_address}"
new_reads = ("reads = {hex(a): rsp.memory(a, 4).get('hex') for a in args.read_address}\n"
             "                    for spec in args.read_reg:\n"
             "                        idx, size = parse_read_reg(spec)\n"
             "                        addr = regs[idx]\n"
             "                        reads[f'{spec}@{addr:#x}'] = rsp.memory(addr, size).get('hex')")
assert old_reads in s
s = s.replace(old_reads, new_reads)

ast.parse(s)
p.write_text(s, encoding='utf-8')
print('patched and syntax ok')
