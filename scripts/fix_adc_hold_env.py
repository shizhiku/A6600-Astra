"""Treat an empty REA_ADC_HOLD as unset."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/arm/sony_a6400.c')
s = p.read_text()
old = '    if (getenv("REA_ADC_HOLD")) {'
new = '    const char *hold_env = getenv("REA_ADC_HOLD");\n\n    if (hold_env && *hold_env) {'
if 'hold_env' in s:
    print('already fixed')
else:
    assert old in s
    s = s.replace(old, new, 1)
    p.write_text(s)
    print('empty-env bug fixed')
