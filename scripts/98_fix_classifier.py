from pathlib import Path
p = Path('02-脚本/97_astra_trials.py')
s = p.read_text(encoding='utf-8')
old = r'^[0-9a-f]+-[0-9a-f]+\s+r-xp?\s+'
new = r'^[0-9a-f]+-[0-9a-f]+\s+\S+\s+'
if old in s:
    s = s.replace(old, new)
    p.write_text(s, encoding='utf-8')
    print('regex fixed')
else:
    print('pattern not found')
