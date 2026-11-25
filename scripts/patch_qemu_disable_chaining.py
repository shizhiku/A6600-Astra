"""Disable TB chaining while REA_BP_VA is set so the VA hook sees every block."""
from pathlib import Path

p = Path('/root/qemu-11.1.3/accel/tcg/translate-all.c')
s = p.read_text()

anchor = 'TranslationBlock *tb_gen_code(CPUState *cpu,'
assert anchor in s, 'tb_gen_code not found'

# find the opening brace and insert after the function's variables are set up is risky;
# instead insert right after the function signature block by locating the first '{' after anchor
if 'REA_BP disable chaining' in s:
    print('already patched')
else:
    idx = s.find(anchor)
    brace = s.find('{', idx)
    assert brace > 0
    ins = brace + 1
    patch = ('\n    /* REA_BP disable chaining so the VA hook observes every TB */\n'
             '    if (getenv("REA_BP_VA")) {\n'
             '        cflags |= CF_NO_GOTO_TB | CF_NO_GOTO_PTR;\n'
             '    }\n')
    s = s[:ins] + patch + s[ins:]
    p.write_text(s)
    print('patched translate-all for chaining disable')
