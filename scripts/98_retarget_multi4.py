from pathlib import Path

p = Path('04-产物/98_multi_preload.c')
s = p.read_text()

old = ('static const unsigned long offs[N] = {0x54F6D2, 0x54F6E6, 0x54F70E, 0x54F722};\n'
       'static const char *labels[N] = {"X_54F6D2", "Y_54F6E6", "Z_54F70E", "AA_54F722"};')
new = ('static const unsigned long offs[N] = {0x2B1B534, 0x2B1B53C, 0x60E2AE, 0x60E2C2};\n'
       'static const char *labels[N] = {"L_after_schedlock", "M_after_munmap_wrap", '
       '"N_after_9257D8", "O_after_924500"};')
assert old in s, 'pattern not found'
s = s.replace(old, new)
p.write_text(s)
print('retargeted: sched_lock / munmap wrapper / loop points')
