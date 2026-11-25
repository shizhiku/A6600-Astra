"""Find user-mode (EL0) undefined-instruction exceptions in the QEMU -d int log."""
from pathlib import Path
import re

LOG = Path(r'<WORKSPACE>\03-证据\模拟器运行\cmdline-20261120T201519Z-45704\stderr.log')

pat_exc = re.compile(r'Taking exception (\d+) \[([^\]]+)\] on CPU (\d+)')
pat_from = re.compile(r'\.\.\.from (EL\d) to (EL\d)')
pat_ret = re.compile(r'Exception return from AArch32 (\w+) to (\w+) PC (0x[0-9a-f]+)')

user_undef = []
pending = None
with LOG.open('r', errors='replace') as fh:
    for line in fh:
        m = pat_exc.search(line)
        if m:
            pending = {'type': int(m.group(1)), 'name': m.group(2), 'cpu': int(m.group(3))}
            continue
        if pending is None:
            continue
        m = pat_from.search(line)
        if m:
            pending['from'] = m.group(1)
            pending['to'] = m.group(2)
            continue
        m = pat_ret.search(line)
        if m:
            pending['ret_from'] = m.group(1)
            pending['ret_to'] = m.group(2)
            pending['ret_pc'] = m.group(3)
            if pending['type'] == 1 and pending.get('from') == 'EL0':
                user_undef.append(dict(pending))
            pending = None

print('user-mode undefined-instruction exceptions:', len(user_undef))
for e in user_undef[-10:]:
    print(f"  cpu={e['cpu']} from={e['from']} ret={e['ret_from']}->{e['ret_to']} pc={e['ret_pc']}")

# also dump the tail of the log before termination
print('\n--- last 6 lines ---')
with LOG.open('rb') as fh:
    fh.seek(-800, 2)
    print(fh.read().decode('utf-8', 'replace'))
