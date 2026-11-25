"""Add a forward declaration for the front-button injector."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/arm/sony_a6400.c')
s = p.read_text()
anchor = 'static void sony_a6400_submicro_tick(void *opaque)'
decl = 'static void sony_a6400_front_inject(void);\n\n'
if decl in s:
    print('already declared')
else:
    assert anchor in s
    s = s.replace(anchor, decl + anchor, 1)
    p.write_text(s)
    print('forward decl added')
