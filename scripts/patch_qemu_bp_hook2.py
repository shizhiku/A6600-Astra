"""Rewrite the QEMU hit hook to be target-agnostic (uses cpu_dump_state)."""
from pathlib import Path
import re

p = Path('/root/qemu-11.1.3/accel/tcg/cpu-exec.c')
s = p.read_text()

# remove the previous helper block
start = s.find('/* REA: diagnostic virtual-address hit logger')
if start >= 0:
    end = s.find('static inline void cpu_loop_exec_tb(CPUState *cpu, TranslationBlock *tb,')
    s = s[:start] + s[end:]
    print('removed old helper')

helper = '''/* REA: diagnostic virtual-address hit logger (REA_BP_VA=<hex>) */
static int rea_bp_ready;
static vaddr rea_bp_va;
static int rea_bp_hits;

static void rea_bp_check(CPUState *cpu, vaddr pc, TranslationBlock *tb)
{
    if (!rea_bp_ready) {
        const char *e = getenv("REA_BP_VA");
        rea_bp_va = e ? (vaddr)strtoull(e, NULL, 0) : 0;
        rea_bp_ready = 1;
    }
    if (!rea_bp_va || rea_bp_hits >= 64) {
        return;
    }
    if (pc <= rea_bp_va && rea_bp_va < pc + tb->size) {
        rea_bp_hits++;
        fprintf(stderr, "REA_BP hit=%d va=%#llx tb_pc=%#llx size=%u\\n",
                rea_bp_hits, (unsigned long long)rea_bp_va,
                (unsigned long long)pc, (unsigned)tb->size);
        cpu_dump_state(cpu, stderr, 0);
        fflush(stderr);
    }
}

'''
anchor = 'static inline void cpu_loop_exec_tb(CPUState *cpu, TranslationBlock *tb,'
assert anchor in s
s = s.replace(anchor, helper + anchor, 1)

if 'rea_bp_check(cpu, pc, tb);' not in s:
    old_body = """    trace_exec_tb(tb, pc);
    tb = cpu_tb_exec(cpu, tb, tb_exit);"""
    new_body = """    rea_bp_check(cpu, pc, tb);
    trace_exec_tb(tb, pc);
    tb = cpu_tb_exec(cpu, tb, tb_exit);"""
    assert old_body in s
    s = s.replace(old_body, new_body, 1)

p.write_text(s)
print('rewrote helper (target-agnostic)')
