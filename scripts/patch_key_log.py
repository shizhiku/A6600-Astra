"""Add REA_KEY_LOG: log when the synthetic submicro frame carries front-button bits."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/arm/sony_a6400.c')
s = p.read_text()

old = """    if (sony_a6400_rear_controls && out[0] == 0x20 && sony_a6400_front_pressed) {"""
new = """    if (getenv("REA_KEY_LOG") && out[0] == 0x20) {
        fprintf(stderr, "[KEY] submicro slot-A reply: front=0x%04x out28_before=0x%02x\\n",
                sony_a6400_front_pressed, out[28]);
    }
    if (getenv("REA_KEY_LOG")) {
        static int logged;
        if (sony_a6400_front_pressed && logged < 20) {
            fprintf(stderr, "[KEY] front_pressed=0x%04x rear_controls=%d\\n",
                    sony_a6400_front_pressed, (int)sony_a6400_rear_controls);
            logged++;
        }
    }
    if (sony_a6400_rear_controls && out[0] == 0x20 && sony_a6400_front_pressed) {"""

if 'REA_KEY_LOG' in s:
    print('already patched')
else:
    assert old in s, 'anchor missing'
    s = s.replace(old, new, 1)
    p.write_text(s)
    print('patched key logging')
