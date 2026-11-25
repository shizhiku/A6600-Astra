"""Add string filtering to the REA_BP hook: only dump when memory contains a marker."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/accel/tcg/cpu-exec.c')
s = p.read_text()

old = '''        rea_bp_hits++;
        fprintf(stderr, "REA_BP hit=%d va=%#llx tb_pc=%#llx size=%u\\n",
                rea_bp_hits, (unsigned long long)rea_bp_va,
                (unsigned long long)pc, (unsigned)tb->size);
        cpu_dump_state(cpu, stderr, 0);'''

new = '''        rea_bp_hits++;
        {
            const char *needle = getenv("REA_BP_MEMSTR");
            if (needle && needle[0]) {
                static const int regs[] = {0, 1, 2, 3, 4, 5, 6, 7};
                int found = 0, i, j;
                unsigned char sbuf[128];
                for (i = 0; i < 8 && !found; i++) {
                    GByteArray *rb = g_byte_array_new();
                    if (cpu->cc->gdb_read_register) {
                        cpu->cc->gdb_read_register(cpu, rb, regs[i]);
                    }
                    if (rb->len >= 4) {
                        uint32_t addr = ldl_le_p(rb->data);
                        if (addr > 0x1000 &&
                            cpu_memory_rw_debug(cpu, addr, sbuf, sizeof(sbuf), 0) == 0) {
                            sbuf[sizeof(sbuf) - 1] = 0;
                            if (strstr((const char *)sbuf, needle)) {
                                found = 1;
                                fprintf(stderr, "REA_BP hit=%d va=%#llx reg=r%d str=%s\\n",
                                        rea_bp_hits, (unsigned long long)rea_bp_va,
                                        i, (const char *)sbuf);
                                cpu_dump_state(cpu, stderr, 0);
                                fflush(stderr);
                            }
                        }
                    }
                    g_byte_array_free(rb, TRUE);
                }
                if (!found) {
                    rea_bp_hits--;
                    return;
                }
            } else {
                fprintf(stderr, "REA_BP hit=%d va=%#llx tb_pc=%#llx size=%u\\n",
                        rea_bp_hits, (unsigned long long)rea_bp_va,
                        (unsigned long long)pc, (unsigned)tb->size);
                cpu_dump_state(cpu, stderr, 0);
            }
        }'''

if 'REA_BP_MEMSTR' in s:
    print('already patched')
elif old in s:
    s = s.replace(old, new, 1)
    p.write_text(s)
    print('patched string filter')
else:
    print('anchor not found')
