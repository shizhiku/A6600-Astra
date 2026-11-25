"""Raise the REA_BP hit cap so long open() traces are not truncated."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/accel/tcg/cpu-exec.c')
s = p.read_text()
old = 'if (!rea_bp_va || rea_bp_hits >= 64) {'
if 'rea_bp_hits >= 4000' in s:
    print('already raised')
else:
    assert old in s, 'cap check not found'
    s = s.replace(old, 'if (!rea_bp_va || rea_bp_hits >= 4000) {', 1)
    p.write_text(s)
    print('raised cap to 4000')
