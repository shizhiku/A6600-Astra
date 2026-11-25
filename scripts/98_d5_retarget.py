from pathlib import Path

p = Path('04-产物/98_d5_preload.c')
s = p.read_text()

old_offs = 'static unsigned long offs[NT] = {0x54EF74, 0x54833C, 0x54D2B0};'
new_offs = 'static unsigned long offs[NT] = {0x925FB0, 0x9256A8, 0x9246B8};'
assert old_offs in s
s = s.replace(old_offs, new_offs)

old_names = ('static const char *names[NT] = {"c1_54EF74", "c2_54833C", '
             '"appstart_54D2B0"};')
new_names = ('static const char *names[NT] = {"c3_925FB0", "c4_9256A8", '
             '"c5_9246B8"};')
assert old_names in s
s = s.replace(old_names, new_names)

p.write_text(s)
print('patched to next three calls')
