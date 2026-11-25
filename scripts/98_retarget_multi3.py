from pathlib import Path

p = Path('04-产物/98_multi_preload.c')
s = p.read_text()

old = ('static const unsigned long offs[N] = {0x54F68E, 0x54F698, 0x54F6AA, 0x54F6C2};\n'
       'static const char *labels[N] = {"T_54F68E", "U_54F698", "V_54F6AA", "W_54F6C2"};')
new = ('static const unsigned long offs[N] = {0x54F6D2, 0x54F6E6, 0x54F70E, 0x54F722};\n'
       'static const char *labels[N] = {"X_54F6D2", "Y_54F6E6", "Z_54F70E", "AA_54F722"};')
assert old in s, 'pattern not found'
s = s.replace(old, new)
p.write_text(s)
print('retargeted to 0x54F6D2/6E6/70E/722')
