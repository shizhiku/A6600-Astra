"""Log ADC reads that return a pressed (non-idle) level."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/misc/cxd90014_adc.c')
s = p.read_text()

old = """    if (off >= 0x14 && off < 0x14 + 4 * 12) {
        return s->result[(off - 0x14) / 4];
    }"""
new = """    if (off >= 0x14 && off < 0x14 + 4 * 12) {
        unsigned ch = (off - 0x14) / 4;
        uint16_t v = s->result[ch];
        if (v != 1023 && getenv("REA_ADC_LOG")) {
            static int n;
            if (n < 40) {
                fprintf(stderr, "[ADCRD] ch=%u val=0x%04x\\n", ch, v);
                n++;
            }
        }
        return v;
    }"""

if 'REA_ADC_LOG' in s:
    print('already patched')
else:
    assert old in s, 'anchor missing'
    s = s.replace(old, new, 1)
    p.write_text(s)
    print('patched adc read log')
