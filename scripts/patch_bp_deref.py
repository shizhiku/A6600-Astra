"""Add pointer dereference support to the REA_BP memory dump (REA_BP_DEREF)."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/accel/tcg/cpu-exec.c')
s = p.read_text()

anchor = '''            const char *m = getenv("REA_BP_MEMVA");
            if (m) {
                unsigned long long mva = strtoull(m, NULL, 0);'''
if 'REA_BP_DEREF' in s:
    print('already patched')
else:
    assert anchor in s, 'anchor missing'
    new = '''            const char *m = getenv("REA_BP_MEMVA");
            if (m) {
                unsigned long long mva = strtoull(m, NULL, 0);
                const char *dr = getenv("REA_BP_DEREF");
                if (dr) {
                    unsigned long long off2 = strtoull(dr, NULL, 0);
                    uint32_t ptr = 0;
                    if (cpu_memory_rw_debug(cpu, mva, (uint8_t *)&ptr, 4, 0) == 0) {
                        mva = (unsigned long long)ptr + off2;
                        fprintf(stderr, "REA_DEREF base_ptr=%#x off=%#llx -> %#llx\\n",
                                ptr, off2, mva);
                    } else {
                        fprintf(stderr, "REA_DEREF base unreadable %#llx\\n", mva);
                    }
                }'''
    s = s.replace(anchor, new, 1)
    p.write_text(s)
    print('patched deref support')
