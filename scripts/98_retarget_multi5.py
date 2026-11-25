"""Probe inside the sched_lock wrapper 0x2B1B524 during SECOND iteration.

Established:
  - 1st iteration of 0x60E274 completes (M_after_munmap_wrap hit once)
  - 2nd iteration blocks, before 0x60E2AE is reached again
  - 0x60E2AE is right after `blx 0x9257D8` -> -> 0x2B1B524
So the second call into 0x2B1B524 (sched_lock(0xf,0xf) + 0x2B749CC + unlock)
does not return.

Probe points inside 0x2B1B524 / 0x2B749CC (all verified instruction boundaries):
   0x2B1B534  after sched_lock returns
   0x2B1B53C  after 0x2B749CC returns
   0x2B749D6  inside 0x2B749CC before the first external call
   0x2B749E6  after blx 0x2BA0FAC (first external call)
"""
from pathlib import Path

p = Path('04-产物/98_multi_preload.c')
s = p.read_text()

old = ('static const unsigned long offs[N] = {0x2B1B534, 0x2B1B53C, 0x60E2AE, 0x60E2C2};\n'
       'static const char *labels[N] = {"L_after_schedlock", "M_after_munmap_wrap", '
       '"N_after_9257D8", "O_after_924500"};')
new = ('static const unsigned long offs[N] = {0x2B1B534, 0x2B1B53C, 0x2B749D6, 0x2B749E6};\n'
       'static const char *labels[N] = {"P2_after_lock", "P3_after_munmapfn", '
       '"P4_inside_munmap", "P5_after_extcall"};')
assert old in s, 'pattern not found'
s = s.replace(old, new)
p.write_text(s)
print('retargeted to inner probe points')
