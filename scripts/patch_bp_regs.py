"""Add REA_BP_REGS: print r0..r3 at the hit instead of the full CPU dump."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/accel/tcg/cpu-exec.c')
s = p.read_text()

old = '''                fprintf(stderr, "REA_BP hit=%d va=%#llx tb_pc=%#llx size=%u\\n",
                        rea_bp_hits, (unsigned long long)rea_bp_va,
                        (unsigned long long)pc, (unsigned)tb->size);
                cpu_dump_state(cpu, stderr, 0);'''

new = '''                if (getenv("REA_BP_REGS")) {
                    uint32_t *rr = (uint32_t *)((char *)cpu + 0);
                    (void)rr;
                    fprintf(stderr,
                            "REA_BP hit=%d va=%#llx r0=%08x r1=%08x r2=%08x r3=%08x\\n",
                            rea_bp_hits, (unsigned long long)rea_bp_va,
                            (unsigned)cpu->env.regs[0],
                            (unsigned)cpu->env.regs[1],
                            (unsigned)cpu->env.regs[2],
                            (unsigned)cpu->env.regs[3]);
                } else {
                    fprintf(stderr, "REA_BP hit=%d va=%#llx tb_pc=%#llx size=%u\\n",
                            rea_bp_hits, (unsigned long long)rea_bp_va,
                            (unsigned long long)pc, (unsigned)tb->size);
                    cpu_dump_state(cpu, stderr, 0);
                }'''

if 'REA_BP_REGS' in s:
    print('already patched')
else:
    assert old in s, 'anchor missing'
    s = s.replace(old, new, 1)
    p.write_text(s)
    print('patched bp regs')
