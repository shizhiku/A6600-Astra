"""Log every key event that reaches the machine's input handler."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/arm/sony_a6400.c')
s = p.read_text()
anchor = """static void sony_a6400_rear_key(DeviceState *dev, QemuConsole *src,
                               QemuInputEvent *event)
{"""
if 'REA_KEYIN' in s:
    print('already patched')
else:
    assert anchor in s, 'anchor missing'
    s = s.replace(anchor, anchor + """
    if (getenv("REA_KEY_LOG")) {
        fprintf(stderr, "[KEYIN] key=%d down=%d\\n",
                (int)event->key.key, (int)event->key.down);
    }""", 1)
    p.write_text(s)
    print('patched key entry log')
