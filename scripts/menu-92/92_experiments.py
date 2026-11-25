"""Isolated a6600 menu experiments. Run under WSL; no physical-device I/O.
Usage: python3 92_experiments.py prepare | run MODE [--rep N] [--wall N]
MODE: baseline, empty, signal7. All conditions use the same frozen input artifacts.
"""
from pathlib import Path
import argparse,subprocess,hashlib,json,datetime,os,shutil,time,socket,re
BASE=Path('<WORKSPACE>')
ROOT=Path('${RUN}'); INPUT=ROOT/'inputs-v2'; Q=Path('/root/qemu-11.1.3/build')
SRC=BASE/'05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
CAP=BASE/'03-证据/相机采集/boot-20261120T151656Z-26869';FONTS=BASE/'03-证据/相机采集/live-fonts-20261121'
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for x in iter(lambda:f.read(4*1024*1024),b''):h.update(x)
 return h.hexdigest()
def cmd(a,**kw):return subprocess.run([str(x) for x in a],check=True,**kw)
def fat(p,mb):
 with p.open('wb') as f:f.truncate(mb*1024*1024)
 cmd(['mkfs.vfat','-F','16',p],stdout=subprocess.DEVNULL)
def cpinto(img,src,dst):cmd(['mcopy','-o','-i',img,src,'::'+dst])
def prepare():
 if INPUT.exists():raise SystemExit('Inputs already exist; never overwrite frozen inputs.')
 INPUT.mkdir(parents=True)
 for source,name in [(Q/'qemu-system-arm','qemu-system-arm'),(BASE/'05-原始固件/qemu_in/nflasha3-initrd-nt','initrd'),(Path('/root/qemu_in/nflasha3-Image'),'kernel'),(BASE/'05-原始固件/qemu_in/Backup-state1.bin','Backup.bin'),(BASE/'05-原始固件/qemu_in/av-cam-live.bin','av-cam.bin'),(Path('/root/qemu_in/a6600-submicro-frames-20261121.bin'),'submicro.bin')]:shutil.copy2(source,INPUT/name)
 setting=INPUT/'setting.img';fat(setting,20)
 for src,n in [(INPUT/'Backup.bin','Backup.bin'),(CAP/'06-setting__kemco.txt','kemco.txt'),(CAP/'07-setting__ulogio.bin','ulogio.bin'),(CAP/'08-setting__DmmConfig.bin','DmmConfig.bin')]:cpinto(setting,src,n)
 shutil.copy2(CAP/'06-setting__kemco.txt',INPUT/'kemco.txt')
 fat(INPUT/'tmp-baseline.img',12);cmd(['mmd','-i',INPUT/'tmp-baseline.img','::images'])
 for n in ['MYingHeiC-GB18030-SJ_wIcon.ltt','MYingHeiC-Big5-SJ_wIcon.ltt','Sony_DI_Icons.ttf']:cpinto(INPUT/'tmp-baseline.img',FONTS/('tmp_images_'+n),'images/'+n)
 (INPUT/'empty.c').write_text('int rea_empty_marker = 1;\n')
 cmd(['arm-linux-gnueabi-gcc','-shared','-nostartfiles','-fPIC','-O2','-o',INPUT/'libempty.so',INPUT/'empty.c'])
 shutil.copy2(Path('<LEGACY_WORKSPACE>/inject_menu7.c'),INPUT/'inject_menu7.c')
 cmd(['arm-linux-gnueabi-gcc','-std=gnu11','-shared','-fPIC','-O2','-o',INPUT/'libsignal7.so',INPUT/'inject_menu7.c'])
 for mode,lib in [('empty','libempty.so'),('signal7','libsignal7.so')]:
  shutil.copy2(INPUT/'tmp-baseline.img',INPUT/f'tmp-{mode}.img')
  cpinto(INPUT/f'tmp-{mode}.img',INPUT/lib,lib)
  p=INPUT/f'ld.so.preload-{mode}';p.write_text('/tmp/'+lib+'\n');cpinto(INPUT/f'tmp-{mode}.img',p,'ld.so.preload')
 overlay=INPUT/'base.qcow2';cmd([Q/'qemu-img','create','-q','-f','qcow2','-F','raw','-b','/root/qemu_in/emmc.img',overlay])
 # qemu-io parses whitespace but retains quote characters; these checked paths have no spaces.
 cmd([Q/'qemu-io','-f','qcow2','-c',f'write -s {SRC} 771751936 215517184','-c',f'write -s {setting} 16777216 20971520',overlay])
 files=[INPUT/n for n in ['qemu-system-arm','kernel','initrd','Backup.bin','av-cam.bin','submicro.bin','setting.img','kemco.txt','tmp-baseline.img','tmp-empty.img','tmp-signal7.img','libempty.so','libsignal7.so']]+[SRC,Path('/root/qemu_in/emmc.img')]
 manifest={str(p):{'size':p.stat().st_size,'sha256':sha(p)} for p in files};(INPUT/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2))
 print('PREPARED',INPUT,flush=True)
def qmp_connect(p):
 s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect(str(p));f=s.makefile('rwb',buffering=0);f.readline();f.write(b'{"execute":"qmp_capabilities"}\n')
 while True:
  o=json.loads(f.readline())
  if 'return' in o:break
 return s,f
def qmp(f,name,args=None):
 d={'execute':name}
 if args:d['arguments']=args
 f.write((json.dumps(d)+'\n').encode())
 while True:
  o=json.loads(f.readline())
  if 'return'in o or 'error'in o:return o

def run(mode,rep,wall):
 if mode not in ['baseline','empty','signal7','native','front']:raise SystemExit('Unknown mode')
 if mode=='native':
  extra=ROOT/'native-v1';extra.mkdir(exist_ok=True)
  if not (extra/'tmp-native.img').exists():
   shutil.copy2(INPUT/'tmp-baseline.img',extra/'tmp-native.img');shutil.copy2(BASE/'04-产物/libnative_menu92.so',extra/'libnative_menu92.so')
   cpinto(extra/'tmp-native.img',extra/'libnative_menu92.so','libnative_menu92.so');(extra/'ld.so.preload').write_text('/tmp/libnative_menu92.so\n');cpinto(extra/'tmp-native.img',extra/'ld.so.preload','ld.so.preload')
 r=ROOT/('run-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+mode+'-'+str(rep));r.mkdir(parents=True)
 o=r/'overlay.qcow2';cmd([Q/'qemu-img','create','-q','-f','qcow2','-F','qcow2','-b',INPUT/'base.qcow2',o]);tmp=(ROOT/'native-v1/tmp-native.img') if mode=='native' else INPUT/f'tmp-{"baseline" if mode=="front" else mode}.img'
 cmd([Q/'qemu-io','-f','qcow2','-c',f'write -s {tmp} 188743680 12582912',o],stdout=subprocess.DEVNULL)
 c=' '.join((INPUT/'kemco.txt').read_text().split()).removeprefix('kemco').strip().replace('console=ttynull','console=ttyAM0,115200n8 amba2.console=1')+' norandmaps'
 args=[str(INPUT/'qemu-system-arm'),'-M',f'sony-a6400,rear-controls=on,submicro-frames={INPUT}/submicro.bin','-m','1G','-display','none','-monitor','none','-serial','stdio','-qmp',f'unix:{r}/qmp.sock,server=on,wait=off','-kernel',str(INPUT/'kernel'),'-initrd',str(INPUT/'initrd'),'-append',c,'-drive',f'if=sd,format=qcow2,file={o}','-device',f'loader,file={INPUT}/Backup.bin,addr=0x02E80000,force-raw=on','-device',f'loader,file={INPUT}/av-cam.bin,addr=0x035C6000,force-raw=on','-icount','shift=0,sleep=on']
 env={k:v for k,v in os.environ.items() if not k.startswith('REA_')};env.update(REA_FB_PATH=str(r/'fb'),REA_FB_VSYNC='1200,1800,2400,3000,3600,4200')
 if mode=='front':env.update(REA_FRONT_BTN='4,0,0,4',REA_FRONT_T0='25000',REA_ADC_SEQ='3:32',REA_ADC_T0='12000',REA_BP_VA='0x060439cc',REA_BP_MEMREG='1',REA_BP_MEMLEN='24')
 meta={'variant_tmp':{'path':str(tmp),'sha256':sha(tmp),'size':tmp.stat().st_size},'mode':mode,'rep':rep,'args':args,'env':{k:v for k,v in env.items() if k.startswith('REA_')},'input_manifest':json.loads((INPUT/'manifest.json').read_text()),'wall_limit':wall};(r/'run.json').write_text(json.dumps(meta,ensure_ascii=False,indent=2))
 print('RUN',r,flush=True);lg=(r/'serial.log').open('wb');er=(r/'stderr.log').open('wb');p=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=lg,stderr=er,env=env);t=time.monotonic();sent=False;captured=set();records=[];sock=None;f=None
 try:
  while p.poll() is None and time.monotonic()-t<wall:
   time.sleep(1)
   for image in sorted(r.glob('fb.*.ppm')):
    if image.name in captured:continue
    # Dump is complete once the model logged its path.
    err=(r/'stderr.log').read_text(errors='replace')
    if str(image) not in err:continue
    captured.add(image.name);entry={'frame':image.name,'host_elapsed_s':time.monotonic()-t,'sha256':sha(image),'size':image.stat().st_size}
    try:p.stdin.write(('echo FRAME92_'+image.name+'; cat /proc/uptime\n').encode());p.stdin.flush()
    except BrokenPipeError:pass
    try:
     if f is None:sock,f=qmp_connect(r/'qmp.sock')
     entry['clocks']=qmp(f,'human-monitor-command',{'command-line':'info clocks'})
    except Exception as ex:entry['qmp_error']=str(ex);f=None
    records.append(entry);print('FRAME',mode,rep,image.name,flush=True)
   if not sent and time.monotonic()-t>95:
    shell='echo DIAG92_BEGIN; for p in /proc/[0-9]*; do if grep -q libObj.so "$p/maps" 2>/dev/null; then echo OWNER=$p; grep libObj.so "$p/maps"; fi; done; echo DIAG92_END\n'
    try:p.stdin.write(shell.encode());p.stdin.flush();sent=True
    except BrokenPipeError:break
   if len(captured)>=6:break
 finally:
  if p.poll() is None:p.terminate()
  try:p.wait(timeout=8)
  except subprocess.TimeoutExpired:p.kill();p.wait()
  if sock:sock.close()
  lg.close();er.close()
 summary={'mode':mode,'rep':rep,'elapsed_s':time.monotonic()-t,'rc':p.returncode,'frames':records,'injection_logs':re.findall(r'INJ7:[^\r\n]*',(r/'serial.log').read_text(errors='replace'))}
 (r/'summary.json').write_text(json.dumps(summary,indent=2));dest=BASE/'03-证据/模拟器运行'/r.name;dest.mkdir(exist_ok=True)
 for z in r.iterdir():
  if z.is_file() and z.suffix in ['.log','.json','.ppm']:shutil.copy2(z,dest/z.name)
 print('DONE',dest,flush=True)
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('action',choices=['prepare','run']);a.add_argument('mode',nargs='?',default='baseline');a.add_argument('--rep',type=int,default=1);a.add_argument('--wall',type=int,default=260);n=a.parse_args();prepare() if n.action=='prepare' else run(n.mode,n.rep,n.wall)
