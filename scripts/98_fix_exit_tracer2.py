from pathlib import Path
p = Path('04-产物/98_exit_trace_preload.c')
s = p.read_text()
start = s.find('__attribute__((noreturn)) void exit(int status)')
if start >= 0:
    end = s.find('__attribute__((destructor))', start)
    s = s[:start] + s[end:]
for line in ('extern void real_exit_sym(int);\n',
             '__asm__(".symver real_exit_sym,exit@GLIBC_2.4");\n'):
    s = s.replace(line, '')
p.write_text(s)
print('cleaned', 'exit(' in s)
