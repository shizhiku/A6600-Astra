"""Resolve the PC-relative literals inside the retry-gate routine."""
from pathlib import Path
import struct, json
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

root = Path(__file__).resolve().parent
d = (root / 'qemu_in/av-cam.bin').read_bytes()
base = 0x635c6000
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.detail = True

LOADERS = [
    (0x638529dc, 'module_globals_base'),
    (0x638529e2, 'object_pointer_slot'),
    (0x638529ea, 'global_byte'),
    (0x638529f0, 'state_pointer_slot'),
    (0x63852a0e, 'state_pointer_slot2'),
    (0x63852a1a, 'counter_slot'),
    (0x63852a28, 'counter_slot2'),
]

def literal_addr(insn_addr):
    return ((insn_addr + 4) & ~3) + 0

out = {'routine': '0x638529d8', 'literals': []}
for addr, label in LOADERS:
    ins = next(md.disasm(d[addr-base:addr-base+4], addr), None)
    if ins is None:
        continue
    ops = ins.op_str
    imm = None
    try:
        imm = int(ops.split('#')[1].split(']')[0], 0)
    except Exception:
        pass
    lit = ((addr + 4) & ~3) + (imm or 0)
    raw = struct.unpack_from('<H', d, lit - base)[0] if 0 <= lit - base <= len(d) - 2 else None
    entry = {'insn': hex(addr), 'label': label, 'mnemonic': ins.mnemonic,
             'op_str': ops, 'imm': imm, 'literal_at': hex(lit), 'literal_value': hex(raw) if raw is not None else None}
    if raw is not None and ins.mnemonic == 'ldr':
        # add rX, pc follows: target = ((addr_of_add + 4) & ~3) + raw
        add_addr = addr + 2
        target = ((add_addr + 4) & ~3) + raw
        entry['resolved_target'] = hex(target)
    out['literals'].append(entry)

(root / 'a6600_port/analysis/liro-fault-static/retry-gate-literals.json').write_text(
    json.dumps(out, indent=2), encoding='utf-8')
print(json.dumps(out, indent=2))
