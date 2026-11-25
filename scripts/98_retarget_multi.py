from pathlib import Path

p = Path('04-产物/98_multi_preload.c')
s = p.read_text()

old = ('static const unsigned long offs[N] = {0x54EF90, 0x54EF96, 0x54EFA6, 0x54F678};\n'
       'static const char *labels[N] = {"P_54EF90", "Q_54EF96", "R_54EFA6", "S_54F678"};')
new = ('static const unsigned long offs[N] = {0x54F690, 0x54F6A0, 0x54F6B4, 0x54F716};\n'
       'static const char *labels[N] = {"T_54F690", "U_54F6A0", "V_54F6B4", "W_54F716"};')
assert old in s, 'pattern not found'
s = s.replace(old, new)
p.write_text(s)
print('retargeted MULTI probe to 0x54F690/6A0/6B4/716')
