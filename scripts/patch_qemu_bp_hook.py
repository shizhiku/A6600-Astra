"""Add an in-QEMU virtual-address hit logger (REA_BP_VA) to the TCG loop.

Works per translation block using the *virtual* PC, so it does not depend on
gdbstub breakpoint translation and is reliable for user-space addresses.
"""
from pathlib import Path
import re

p = Path('/root/qemu-11.1.3/accel/tcg/cpu-exec.c')
s = p.read_text()

helper = '''
/* REA: diagnostic virtual-address hit logger (REA_BP_VA=<hex>) */
static int rea_bp_ready;
static uint64_t rea_bp_va;
static int rea_bp_hits;

static void rea_bp_check(CPUState *cpu, vaddr pc, TranslationBlock *tb)
{
#ifdef TARGET_ARM
    if (!rea_bp_ready) {
        const char *e = getenv("REA_BP_VA");
        rea_bp_va = e ? strtoull(e, NULL, 0) : 0;
        rea_bp_ready = 1;
    }
    if (!rea_bp_va || rea_bp_hits >= 32) {
        return;
    }
    if (pc <= rea_bp_va && rea_bp_va < pc + tb->size) {
        CPUARMState *env = cpu->env_ptr;
        rea_bp_hits++;
        fprintf(stderr,
                "REA_BP hit=%d va=%#llx tb_pc=%#llx lr=%08x r0=%08x r1=%08x "
                "r2=%08x r3=%08x r7=%08x cpsr=%08x\\n",
                rea_bp_hits, (unsigned long long)rea_bp_va,
                (unsigned long long)pc,
                env->regs[14], env->regs[0], env->regs[1], env->regs[2],
                env->regs[3], env->regs[7], env->uncached_cpsr);
    }
#else
    (void)cpu;
    (void)pc;
    (void)tb;
#endif
}

'''

anchor = 'static inline void cpu_loop_exec_tb(CPUState *cpu, TranslationBlock *tb,'
assert anchor in s
if 'rea_bp_check' in s:
    print('already patched')
else:
    s = s.replace(anchor, helper + anchor, 1)
    old_body = """    trace_exec_tb(tb, pc);
    tb = cpu_tb_exec(cpu, tb, tb_exit);"""
    new_body = """    rea_bp_check(cpu, pc, tb);
    trace_exec_tb(tb, pc);
    tb = cpu_tb_exec(cpu, tb, tb_exit);"""
    assert old_body in s
    s = s.replace(old_body, new_body, 1)
    p.write_text(s)
    print('patched cpu-exec with REA_BP_VA hook')
