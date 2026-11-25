"""Allow the observer to use an alternate av-cam image via AVCAM_IMG."""
from pathlib import Path
import ast

p = Path(r'<WORKSPACE>\02-脚本\qemu_fault_breakpoint.py')
s = p.read_text(encoding='utf-8')
if 'AVCAM_IMG' in s:
    print('already patched')
else:
    old = "{DATA}/av-cam-live.bin"
    assert old in s, 'marker not found'
    new = "{os.environ.get('AVCAM_IMG', str(DATA / 'av-cam-live.bin'))}"
    s = s.replace(old, new)
    if 'import os' not in s.split('\n')[0:40].__str__():
        s = s.replace('import json', 'import json\nimport os', 1)
    ast.parse(s)
    p.write_text(s, encoding='utf-8')
    print('patched observer for AVCAM_IMG')
