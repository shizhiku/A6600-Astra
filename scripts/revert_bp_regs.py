"""Revert the REA_BP_REGS branch (CPUState has no env in target-agnostic code)."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/accel/tcg/cpu-exec.c')
s = p.read_text()

start = s.find('                if (getenv("REA_BP_REGS")) {')
if start < 0:
    print('branch not present')
else:
    end = s.find('                } else {', start)
    # find the matching close of the else block: the original two lines
    tail_marker = '                    cpu_dump_state(cpu, stderr, 0);\n                }'
    tail = s.find(tail_marker, end)
    assert tail > 0
    tail_end = tail + len(tail_marker)
    original = ('                fprintf(stderr, "REA_BP hit=%d va=%#llx tb_pc=%#llx size=%u\\n",\n'
                '                        rea_bp_hits, (unsigned long long)rea_bp_va,\n'
                '                        (unsigned long long)pc, (unsigned)tb->size);\n'
                '                cpu_dump_state(cpu, stderr, 0);')
    s = s[:start] + original + s[tail_end:]
    p.write_text(s)
    print('reverted to full dump')
