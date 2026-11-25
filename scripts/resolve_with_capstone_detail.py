"""Re-resolve the counter address using Capstone operand details, not hand arithmetic."""
from pathlib import Path
import json
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_OP_REG, CS_OP_IMM
from capstone.arm import ARM_OP_MEM, ARM_OP_REG as AREG

root = Path(__file__).resolve().parent
d = (root / 'qemu_in/av-cam.bin').read_bytes()
base = 0x635c6000
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.detail = True
md.skipdata = True

# Find every instruction that writes the register later used as an address,
# within the routine window, and print full operand detail.
start, end = 0x638529d8, 0x63852a60
rows = []
for ins in md.disasm(d[start - base:end - base], start):
    entry = {'addr': hex(ins.address), 'text': f'{ins.mnemonic} {ins.op_str}'}
    detail = []
    for op in ins.operands:
        if op.type == AREG:
            detail.append({'type': 'reg', 'reg': ins.reg_name(op.reg)})
        elif op.type == CS_OP_IMM:
            detail.append({'type': 'imm', 'value': hex(op.imm) if op.imm >= 0 else op.imm})
        elif op.type == ARM_OP_MEM:
            mem = {'type': 'mem', 'base': ins.reg_name(op.mem.base) if op.mem.base else None,
                   'index': ins.reg_name(op.mem.index) if op.mem.index else None,
                   'disp': op.mem.disp}
            detail.append(mem)
    entry['operands'] = detail
    if ins.mnemonic in ('add', 'ldr', 'ldrb', 'strb', 'eor', 'and', 'cmp', 'movs'):
        rows.append(entry)

out = {'window': f'{start:#x}-{end:#x}', 'instructions': rows}
(root / 'a6600_port/analysis/liro-fault-static/retry-gate-detail.json').write_text(
    json.dumps(out, indent=2), encoding='utf-8')
for r in rows:
    print(f"{r['addr']}  {r['text']:32s} {r['operands']}")
