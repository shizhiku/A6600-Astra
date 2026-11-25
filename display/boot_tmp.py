#!/usr/bin/env python3
"""Boot a6600 QEMU with a chosen /usr image AND a chosen /tmp(=etc) image.

usage: boot_tmp.py <usr.img> <tag> <wall> <usr_size> <tmp.img>
"""
import datetime
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path('${RUN}')
INPUT = ROOT / 'inputs-v2'
Q = Path('/root/qemu-11.1.3/build')
EMMC = Path('/root/qemu_in/emmc.img')
SETTING = Path(sys.argv[6]) if len(sys.argv) > 6 else INPUT / 'setting.img'
OFF = 771751936
SETOFF = 16777216
SETSIZE = 20971520
TMPOFF = 188743680
TMPSIZE = 12582912

usr = Path(sys.argv[1])
tag = sys.argv[2]
WALL = int(sys.argv[3])
SIZE = int(sys.argv[4])
tmpimg = Path(sys.argv[5])

stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
r = ROOT / ('run-' + stamp + '-' + tag)
r.mkdir(parents=True)
o = r / 'overlay.qcow2'
subprocess.run([str(Q / 'qemu-img'), 'create', '-q', '-f', 'qcow2',
                '-F', 'raw', '-b', str(EMMC), str(o)], check=True)
subprocess.run([str(Q / 'qemu-io'), '-f', 'qcow2',
                '-c', 'write -s %s %d %d' % (usr, OFF, SIZE),
                '-c', 'write -s %s %d %d' % (SETTING, SETOFF, SETSIZE),
                '-c', 'write -s %s %d %d' % (tmpimg, TMPOFF, TMPSIZE),
                str(o)], check=True, stdout=subprocess.DEVNULL)

c = ' '.join((INPUT / 'kemco.txt').read_text().split())
c = c.removeprefix('kemco').strip()
c = c.replace('console=ttynull', 'console=ttyAM0,115200n8 amba2.console=1')
c += ' norandmaps'

args = [
    str(Q / 'qemu-system-arm'),
    '-M', 'sony-a6400,rear-controls=on,submicro-frames=%s/submicro.bin' % INPUT,
    '-m', '1G', '-display', 'none', '-monitor', 'none', '-serial', 'stdio',
    '-qmp', 'unix:%s/qmp.sock,server=on,wait=off' % r,
    '-kernel', str(INPUT / 'kernel'),
    '-initrd', str(INPUT / 'initrd'),
    '-append', c,
    '-drive', 'if=sd,format=qcow2,file=%s' % o,
    '-device', 'loader,file=%s/Backup.bin,addr=0x02E80000,force-raw=on' % INPUT,
    '-device', 'loader,file=%s/av-cam.bin,addr=0x035C6000,force-raw=on' % INPUT,
    '-icount', 'shift=0,sleep=on',
]
env = {k: v for k, v in os.environ.items() if not k.startswith('REA_')}
env.update(REA_FB_PATH=str(r / 'fb'), REA_FB_VSYNC='1200,1800,2400,3000,3600,4200',
           REA_FRONT_BTN='4,0,0,4', REA_FRONT_T0='25000',
           REA_ADC_SEQ='3:32', REA_ADC_T0='12000')
print('RUN', r, flush=True)
print('TMP', tmpimg, flush=True)
lg = (r / 'serial.log').open('wb')
er = (r / 'stderr.log').open('wb')
p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=lg, stderr=er, env=env)
t = time.monotonic()
seen = set()
try:
    while p.poll() is None and time.monotonic() - t < WALL:
        time.sleep(1)
        err = (r / 'stderr.log').read_text(errors='replace')
        for im in sorted(r.glob('fb.*.ppm')):
            if im.name not in seen and im.name in err:
                seen.add(im.name)
                print('FRAME', im.name, flush=True)
finally:
    if p.poll() is None:
        p.terminate()
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
    lg.close()
    er.close()
print('DONE', r, flush=True)
