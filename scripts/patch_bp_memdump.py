"""Add memory dump capability to the REA_BP hook."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/accel/tcg/cpu-exec.c')
s = p.read_text()

old = """        cpu_dump_state(cpu, stderr, 0);
        fflush(stderr);"""
new = """        cpu_dump_state(cpu, stderr, 0);
        {
            const char *m = getenv("REA_BP_MEMVA");
            if (m) {
                unsigned long long mva = strtoull(m, NULL, 0);
                int len = 128;
                const char *l = getenv("REA_BP_MEMLEN");
                unsigned char buf[256];
                if (l) {
                    len = atoi(l);
                }
                if (len > (int)sizeof(buf)) {
                    len = (int)sizeof(buf);
                }
                if (cpu_memory_rw_debug(cpu, mva, buf, len, 0) == 0) {
                    int i;
                    fprintf(stderr, "REA_MEM %#llx len=%d:", mva, len);
                    for (i = 0; i < len; i++) {
                        fprintf(stderr, "%02x", buf[i]);
                    }
                    fprintf(stderr, "\\n");
                } else {
                    fprintf(stderr, "REA_MEM %#llx unreadable\\n", mva);
                }
            }
        }
        fflush(stderr);"""
if new in s:
    print('already patched')
elif old in s:
    s = s.replace(old, new)
    p.write_text(s)
    print('patched memory dump')
else:
    print('anchor not found')
