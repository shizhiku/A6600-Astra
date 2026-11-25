from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/display/dmp_smaph.c')
s = p.read_text()
if 'REA_GPE_TRACE' in s:
    print('already patched')
    raise SystemExit

s = s.replace('#include "hw/core/irq.h"', '#include "hw/core/irq.h"\n#include <stdlib.h>')

old_update = 'static void smaph_update(SmaphState *s)\n{\n    qemu_set_irq(s->irq, s->status != 0);\n}'
new_update = '''static void smaph_update(SmaphState *s)
{
    static uint32_t last_status = 0xFFFFFFFFu;
    static int trace_mode = -1;
    if (trace_mode < 0) {
        trace_mode = getenv("REA_GPE_TRACE") ? 1 : 0;
    }
    if (trace_mode && s->status != last_status) {
        fprintf(stderr, "[GPETRACE] irq status 0x%08x -> 0x%08x\\n",
                last_status, s->status);
        last_status = s->status;
    }
    qemu_set_irq(s->irq, s->status != 0);
}'''
assert old_update in s
s = s.replace(old_update, new_update)

old_write = ('static void smaph_write(void *opaque, hwaddr off, uint64_t v, unsigned size)\n'
             '{\n'
             '    SmaphState *s = opaque;\n'
             '    s->reg[off / 4] = v;')
new_write = ('static void smaph_write(void *opaque, hwaddr off, uint64_t v, unsigned size)\n'
             '{\n'
             '    SmaphState *s = opaque;\n'
             '    static int trace_mode = -1;\n'
             '    static unsigned long trace_n;\n'
             '    if (trace_mode < 0) {\n'
             '        const char *e = getenv("REA_GPE_TRACE");\n'
             '        trace_mode = e ? atoi(e) : 0;\n'
             '    }\n'
             '    if (trace_mode && trace_n < 4000) {\n'
             '        fprintf(stderr, "[GPETRACE] w %04x = %08x (status %x)\\n",\n'
             '                (unsigned)off, (unsigned)v, s->status);\n'
             '        trace_n++;\n'
             '    }\n'
             '    s->reg[off / 4] = v;')
assert old_write in s
s = s.replace(old_write, new_write)

old_read = ('static uint64_t smaph_read(void *opaque, hwaddr off, unsigned size)\n'
            '{\n'
            '    SmaphState *s = opaque;\n'
            '    if (off == 0x34) {\n'
            '        return s->status;\n'
            '    }')
new_read = ('static uint64_t smaph_read(void *opaque, hwaddr off, unsigned size)\n'
            '{\n'
            '    SmaphState *s = opaque;\n'
            '    static int trace_mode = -1;\n'
            '    static unsigned long read_n;\n'
            '    if (trace_mode < 0) {\n'
            '        const char *e = getenv("REA_GPE_TRACE");\n'
            '        trace_mode = (e && atoi(e) >= 2) ? 2 : 0;\n'
            '    }\n'
            '    if (trace_mode == 2 && read_n < 500) {\n'
            '        fprintf(stderr, "[GPETRACE] r %04x -> %08x\\n", (unsigned)off,\n'
            '                off == 0x34 ? s->status : s->reg[off / 4]);\n'
            '        read_n++;\n'
            '    }\n'
            '    if (off == 0x34) {\n'
            '        return s->status;\n'
            '    }')
assert old_read in s
s = s.replace(old_read, new_read)

p.write_text(s)
print('patched dmp_smaph.c')
