"""Log PSC fill parameters (address, size, value, bpp) in the DMP model."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/display/dmp_smaph.c')
s = p.read_text()
old = '    trace_dmp_smaph_job("psc-fill", a, e - a);'
if 'REA_PSC_LOG' in s:
    print('already patched')
else:
    assert old in s
    new = ('    if (getenv("REA_PSC_LOG")) {\n'
           '        fprintf(stderr, "[PSC] a=0x%" HWADDR_PRIx " size=%" HWADDR_PRIu\n'
           '                " val=0x%08x bpp=%u\\n", a, e - a, v, bpp);\n'
           '    }\n' + old)
    s = s.replace(old, new, 1)
    p.write_text(s)
    print('patched psc log')
