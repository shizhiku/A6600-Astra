"""Add REA_BP_MEMREG: dump memory at the address held in a given register."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/accel/tcg/cpu-exec.c')
s = p.read_text()

anchor = '        {\n            const char *m = getenv("REA_BP_MEMVA");'
if 'REA_BP_MEMREG' in s:
    print('already patched')
else:
    assert anchor in s, 'mem dump block not found'
    new_block = '''        {
            const char *rg = getenv("REA_BP_MEMREG");
            if (rg) {
                int rn = atoi(rg);
                GByteArray *rb = g_byte_array_new();
                if (cpu->cc->gdb_read_register) {
                    cpu->cc->gdb_read_register(cpu, rb, rn);
                }
                if (rb->len >= 4) {
                    uint32_t mva = ldl_le_p(rb->data);
                    int len = 128;
                    const char *l = getenv("REA_BP_MEMLEN");
                    unsigned char mbuf[512];
                    int i;
                    if (l) {
                        len = atoi(l);
                    }
                    if (len > (int)sizeof(mbuf)) {
                        len = (int)sizeof(mbuf);
                    }
                    if (cpu_memory_rw_debug(cpu, mva, mbuf, len, 0) == 0) {
                        fprintf(stderr, "REA_MEMREG r%d=%#x len=%d:", rn, mva, len);
                        for (i = 0; i < len; i++) {
                            fprintf(stderr, "%02x", mbuf[i]);
                        }
                        fprintf(stderr, "\\n");
                    } else {
                        fprintf(stderr, "REA_MEMREG r%d=%#x unreadable\\n", rn, mva);
                    }
                }
                g_byte_array_free(rb, TRUE);
            }
        }
''' + anchor
    s = s.replace(anchor, new_block, 1)
    p.write_text(s)
    print('patched MEMREG support')
