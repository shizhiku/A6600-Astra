"""Dump P3D command-list entries in the DMP model (env REA_DMP_DUMP)."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/display/dmp_smaph.c')
s = p.read_text()

anchor = '''    g_autofree uint32_t *w = g_new(uint32_t, 2 * n);
    address_space_read(&address_space_memory, pa, MEMTXATTRS_UNSPECIFIED,
                       w, 8 * n);'''
if 'REA_DMP_DUMP' in s:
    print('already patched')
else:
    assert anchor in s, 'anchor missing'
    new = anchor + '''
    if (getenv("REA_DMP_DUMP")) {
        static int lists;
        if (lists < 40) {
            fprintf(stderr, "[DMPLIST] pa=0x%" HWADDR_PRIx " n=%u:", pa, n);
            for (uint32_t q = 0; q < n && q < 16; q++) {
                fprintf(stderr, " [%u]h=%08x v=%08x",
                        q, le32_to_cpu(w[2 * q]), le32_to_cpu(w[2 * q + 1]));
            }
            fprintf(stderr, "\\n");
            lists++;
        }
    }'''
    s = s.replace(anchor, new, 1)
    p.write_text(s)
    print('patched dump')
