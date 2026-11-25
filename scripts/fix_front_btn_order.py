"""Move the front-button injector below the state variable declarations."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/arm/sony_a6400.c')
s = p.read_text()

start = s.index('static void sony_a6400_front_inject(void)')
end = s.index('static void sony_a6400_submicro_tick(void *opaque)')
block = s[start:end]
s = s[:start] + s[end:]

anchor = 'static uint16_t sony_a6400_front_pressed;\n'
assert anchor in s, 'state var not found'
s = s.replace(anchor, anchor + '\n' + block, 1)
p.write_text(s)
print('moved injector after state vars')
print('call sites:', s.count('sony_a6400_front_inject();'))
