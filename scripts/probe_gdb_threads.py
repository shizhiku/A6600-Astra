"""Probe how this QEMU reports threads in GDB stop replies and per-thread registers."""
from pathlib import Path
import socket, subprocess, time, json, datetime, shutil, os

BASE = Path('<LEGACY_WORKSPACE>')
DATA = Path('/root/qemu_in'); QEMU = Path('/root/qemu-11.1.3/build')
CTRL = Path('/root/a6600-emulation/captured-stock-20261120T151942Z-27058')
run = Path('/root/a6600-emulation')/('threadprobe-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+f'-{os.getpid()}')
run.mkdir(parents=True)
subprocess.run([str(QEMU/'qemu-img'),'create','-q','-f','qcow2','-F','raw','-b',str(DATA/'emmc.img'),str(run/'overlay.qcow2')],check=True)
for n in ('stock-usr.bin','setting.img'): shutil.copyfile(CTRL/n, run/n)
with (run/'overlay.log').open('wb') as log:
    subprocess.run([str(QEMU/'qemu-io'),'-f','qcow2','-c','write -s stock-usr.bin 771751936 215517184','-c','write -s setting.img 16777216 20971520','overlay.qcow2'],cwd=run,stdout=log,stderr=log,check=True)

argv=[str(QEMU/'qemu-system-arm'),'-M','sony-a6400','-m','1G','-display','none','-monitor','none','-serial','stdio',
      '-kernel',str(DATA/'nflasha3-Image'),'-initrd',str(DATA/'nflasha3-initrd'),'-append',(CTRL/'cmdline.txt').read_text(),
      '-drive',f'if=sd,format=qcow2,file={run}/overlay.qcow2',
      '-device',f'loader,file={CTRL}/Backup.bin,addr=0x02E80000,force-raw=on',
      '-device',f'loader,file={DATA}/av-cam.bin,addr=0x035C6000,force-raw=on',
      '-icount','shift=0,sleep=on','-S','-gdb',f'unix:{run}/gdb.sock,server=on,wait=off']
class RSP:
    def __init__(s,c): s.s=c
    def exact(s,n):
        b=b''
        while len(b)<n:
            c=s.s.recv(n-len(b))
            if not c: raise EOFError
            b+=c
        return b
    def recv(s):
        while s.exact(1)!=b'$': pass
        raw=b''
        while True:
            b=s.exact(1)
            if b==b'#': break
            raw+=b
        s.s.sendall(b'+' if int(s.exact(2),16)==(sum(raw)&255) else b'-')
        return raw.decode('ascii')
    def cmd(s,t):
        b=t.encode(); s.s.sendall(b'$'+b+b'#'+f'{sum(b)&255:02x}'.encode()); return s.recv()

proc=None; s=None
report={'commands':{}}
try:
    with (run/'serial.log').open('wb') as so,(run/'stderr.log').open('wb') as se:
        proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=so,stderr=se)
        dl=time.monotonic()+60
        while not (run/'gdb.sock').exists():
            if proc.poll() is not None: raise RuntimeError('qemu exited')
            if time.monotonic()>dl: raise TimeoutError('no socket')
            time.sleep(.05)
        s=socket.socket(socket.AF_UNIX); s.settimeout(120); s.connect(str(run/'gdb.sock')); r=RSP(s)
        for c in ('qSupported','?','qC','qfThreadInfo','qsThreadInfo'):
            report['commands'][c]=r.cmd(c)
        report['breakpoint']=r.cmd('Z1,63852a34,2')
        report['stop']=r.cmd('c')
        report['g_after_stop']=r.cmd('g')[:64]
        report['thread_1_regs']=r.cmd('Hg1')+' / '+r.cmd('g')[:64] if False else None
        report['stop2']=r.cmd('c')
        report['g_after_stop2']=r.cmd('g')[:64]
finally:
    if s: s.close()
    if proc and proc.poll() is None:
        proc.terminate()
        try: proc.wait(timeout=5)
        except subprocess.TimeoutExpired: proc.kill()
    (BASE/'a6600_port/analysis/liro-fault-static/thread-probe.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
