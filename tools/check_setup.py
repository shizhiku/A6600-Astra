import ast
from pathlib import Path

p = Path('${WORKSPACE}/04-产物/a6600-port/scripts/live_loop.py')
ast.parse(p.read_text(encoding='utf-8'))
print('live_loop.py syntax OK')
for f in ('${RUN}/tmpcheck/setting_after.img',
          '${RUN}/inputs-v2/setting.img'):
    q = Path(f)
    print(f'{f}: exists={q.exists()} size={q.stat().st_size if q.exists() else 0}')
