"""Probe batch 7: count how many times each resume point fires.

Key insight from batch 5/6: STAIR2 (serial one-at-a-time) is unreliable because
re-arming lags.  MULTI (all armed at once) is reliable.  So we arm 4 points and
look at the COUNTS, not just first-hit.

Points (verified instruction boundaries):
   0x60E288  loop body start (each iteration)
   0x60E2AE  after blx 0x9257D8  (per iteration)
   0x60E2C2  after blx 0x924500  (per iteration)
   0x60E2E8  loop exit (pop)
If 0x60E288 fires twice but 0x60E2AE only once -> block inside iteration 2 at
the 0x9257D8 call.
"""
from pathlib import Path

p = Path('04-产物/98_multi_preload.c')
s = p.read_text()

old = ('static const unsigned long offs[N] = {0x2B1B534, 0x2B1B53C, 0x2B749D6, 0x2B749E6};\n'
       'static const char *labels[N] = {"P2_after_lock", "P3_after_munmapfn", '
       '"P4_inside_munmap", "P5_after_extcall"};')
new = ('static const unsigned long offs[N] = {0x60E288, 0x60E2AE, 0x60E2C2, 0x60E2E8};\n'
       'static const char *labels[N] = {"i_loop_start", "ii_after_9257D8", '
       '"iii_after_924500", "iv_loop_exit"};')
assert old in s, 'pattern not found'
s = s.replace(old, new)
p.write_text(s)
print('retargeted to loop iteration counting')
