"""Verify running instruction bytes against the file and parse ARM32 'g' with 4-byte registers."""
from pathlib import Path
import socket, subprocess, time, json, datetime, shutil, os, struct

BASE = Path('<LEGACY_WORKSPACE>')
DATA = Path('/root/qemu_in'); QEMU = Path('/root/qemu-11.1.3/build')
CTRL = Path('/root/a6600-emulation/captured-stock-20261120T151942Z-27058')
IMG = DATA/'av-cam.bin'
base_va = 0x635c6000
run = Path('/root/a6600-emulation')/('codecheck-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+f'-{os.getpid()}')
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

def regs32(g):
    raw = bytes.fromhex(g)
    return [int.from_bytes(raw[i*4:(i+1)*4], 'little') for i in range(16)]

proc=None; s=None; out={'checks':{}}
try:
    with (run/'serial.log').open('wb') as so,(run/'stderr.log').open('wb') as se:
        proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=so,stderr=se)
        dl=time.monotonic()+60
        while not (run/'gdb.sock').exists():
            if proc.poll() is not None: raise RuntimeError('qemu exited')
            if time.monotonic()>dl: raise TimeoutError('no socket')
            time.sleep(.05)
        s=socket.socket(socket.AF_UNIX); s.settimeout(120); s.connect(str(run/'gdb.sock')); r=RSP(s)
        out['supported']=r.cmd('qSupported'); out['initial']=r.cmd('?')
        out['bp_fatal']=r.cmd('Z1,63849f30,2')
        out['bp_count']=r.cmd('Z1,63852a34,2')
        out['stop1']=r.cmd('c')
        g1=r.cmd('g'); rr=regs32(g1)
        out['count_stop']={'thread_reply':out['stop1'],'regs':{f'r{i}':hex(v) for i,v in enumerate(rr)}}
        # read the running bytes of the routine window
        mem=r.cmd(f'm{0x63852a20:x},18')
        out['running_bytes_63852a20']=mem
        f=IMG.read_bytes()
        out['file_bytes_63852a20']=f[0x63852a20-base_va:0x63852a20-base_va+0x18].hex()
        out['checks']['running_matches_file']=mem==out['file_bytes_63852a20']
        # what is at the counter the code computed (file-derived) and the observed one?
        for label, addr in (('static_counter_0x6385e3a8',0x6385e3a8),('observed_0x644ae3aa',0x644ae3aa)):
            m=r.cmd(f'm{addr:x},8')
            out['checks'][label]={'bytes':m}
        s.settimeout(120)
        out['stop2']=r.cmd('c')
        g2=r.cmd('g'); rr2=regs32(g2)
        out['fatal_stop']={'thread_reply':out['stop2'],'regs':{f'r{i}':hex(v) for i,v in enumerate(rr2)}}
finally:
    if s: s.close()
    if proc and proc.poll() is None:
        proc.terminate()
        try: proc.wait(timeout=5)
        except subprocess.TimeoutExpired: proc.kill()
    (BASE/'a6600_port/analysis/liro-fault-static/code-identity-check.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
    print(json.dumps(out,indent=2))
