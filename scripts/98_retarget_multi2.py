from pathlib import Path

p = Path('04-产物/98_multi_preload.c')
s = p.read_text()

old = ('static const unsigned long offs[N] = {0x54F690, 0x54F6A0, 0x54F6B4, 0x54F716};\n'
       'static const char *labels[N] = {"T_54F690", "U_54F6A0", "V_54F6B4", "W_54F716"};')
new = ('static const unsigned long offs[N] = {0x54F68E, 0x54F698, 0x54F6AA, 0x54F6C2};\n'
       'static const char *labels[N] = {"T_54F68E", "U_54F698", "V_54F6AA", "W_54F6C2"};')
assert old in s, 'pattern not found'
s = s.replace(old, new)
p.write_text(s)
print('retargeted to verified instruction boundaries: 0x54F68E/698/6AA/6C2')
