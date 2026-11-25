"""Resolve retry-gate literals with 32-bit loads and non-aligned Thumb PC."""
from pathlib import Path
import struct, json

root = Path(__file__).resolve().parent
d = (root / 'qemu_in/av-cam.bin').read_bytes()
base = 0x635c6000

# (instruction address, add-instruction address or None, disp)
ITEMS = [
    (0x638529dc, 0x638529e4, 0x80, 'r4_base'),
    (0x638529e2, None, 0x80, 'r3_offset_for_obj'),
    (0x638529ea, 0x638529ec, 0x7c, 'global_byte'),
    (0x638529f0, None, 0x78, 'r3_offset_for_state'),
    (0x63852a0e, None, 0x60, 'r3_offset_for_state2'),
    (0x63852a1a, 0x63852a1e, 0x58, 'counter_clear'),
    (0x63852a28, 0x63852a2a, 0x4c, 'counter_increment'),
]

out = {'rule': 'Thumb 16-bit add Rd,PC uses PC=(insn_addr+4) without 4-byte alignment; ldr literals are 32-bit', 'items': []}
for insn, addpc, disp, label in ITEMS:
    lit = ((insn + 4) & ~3) + disp
    value = struct.unpack_from('<I', d, lit - base)[0]
    entry = {'label': label, 'ldr_at': hex(insn), 'literal_at': hex(lit), 'literal_value': hex(value)}
    if addpc is not None:
        entry['add_pc_value'] = hex((addpc + 4))
        entry['resolved'] = hex((addpc + 4) + value)
    else:
        entry['resolved'] = hex(value)
    out['items'].append(entry)

# compose object/state pointers
r4 = next(e['resolved'] for e in out['items'] if e['label'] == 'r4_base')
obj_slot = int(r4, 16) + int(next(e['literal_value'] for e in out['items'] if e['label'] == 'r3_offset_for_obj'), 16)
state_slot = int(r4, 16) + int(next(e['literal_value'] for e in out['items'] if e['label'] == 'r3_offset_for_state'), 16)
out['r4_base'] = r4
out['object_pointer_slot'] = hex(obj_slot)
out['state_pointer_slot'] = hex(state_slot)

(root / 'a6600_port/analysis/liro-fault-static/retry-gate-corrected.json').write_text(
    json.dumps(out, indent=2), encoding='utf-8')
print(json.dumps(out, indent=2))
