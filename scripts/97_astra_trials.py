"""Offline-only ASTRA/stock controlled QEMU trials. Never accesses a camera.
Uses new qcow2 overlays and records actual guest mount/loader state instead of
classifying the expected compressed-device fallback as a mount failure.
Run in WSL: python3 97_astra_trials.py --image /path/usr.img --label astra --repeat 2
"""
from pathlib import Path
import argparse,subprocess,os,hashlib,json,time,datetime,shutil,threading,re,struct
ROOT=Path('<WORKSPACE>')
DEPLOY=Path('/root/astra/97');ARCHIVE=ROOT/'03-证据/ASTRA-97';Q=Path('/root/qemu-11.1.3/build')
CAP=ROOT/'03-证据/相机采集/boot-20261120T151656Z-26869';FONTS=ROOT/'03-证据/相机采集/live-fonts-20261121'
SCRIPT_SNAPSHOT=Path(__file__).read_bytes()
PRELOAD=None
_cache={}
def sha(p):
 p=Path(p);st=p.stat();key=(str(p),st.st_size,st.st_mtime_ns)
 if key not in _cache:
  h=hashlib.sha256()
  with p.open('rb') as f:
   for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
  _cache[key]=h.hexdigest()
 return {'path':str(p),'bytes':st.st_size,'sha256':_cache[key]}
def run(cmd,log=None,cwd=None):
 x=subprocess.run([str(v) for v in cmd],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,cwd=cwd)
 if log:Path(log).write_bytes(x.stdout)
 if x.returncode:raise RuntimeError(f'{cmd[0]} failed {x.returncode}: '+x.stdout.decode(errors='replace')[-1500:])
 return x.stdout

def trial(image,label,wall,rep):
 name=f'{label}-{datetime.datetime.now(datetime.timezone.utc):%Y%m%dT%H%M%SZ}-{os.getpid()}-{rep}'
 r=DEPLOY/name;r.mkdir(parents=True,exist_ok=False);dest=ARCHIVE/name;dest.mkdir(parents=True,exist_ok=False)
 backup=ROOT/'05-原始固件/qemu_in/Backup-state1.bin';initrd=ROOT/'05-原始固件/qemu_in/nflasha3-initrd-nt';av=ROOT/'05-原始固件/qemu_in/av-cam-live.bin';kernel=Path('/root/qemu_in/nflasha3-Image');emmc=Path(os.environ.get('ASTRA97_EMMC','/root/qemu_in/emmc.img'));sub=Path('/root/qemu_in/a6600-submicro-frames-20261121.bin')
 for src,n in [(backup,'Backup.bin'),(CAP/'06-setting__kemco.txt','kemco.txt'),(CAP/'07-setting__ulogio.bin','ulogio.bin'),(CAP/'08-setting__DmmConfig.bin','DmmConfig.bin')]:shutil.copy2(src,r/n)
 for n,size in [('setting.img',20*1024**2),('tmp.img',12*1024**2)]:
  with (r/n).open('wb') as f:f.truncate(size)
  run(['mkfs.vfat','-F','16',r/n],r/(n+'.mkfs.log'))
 for n in ['Backup.bin','kemco.txt','ulogio.bin','DmmConfig.bin']:run(['mcopy','-o','-i',r/'setting.img',r/n,'::'+n])
 run(['mmd','-i',r/'tmp.img','::images'])
 for n in ['MYingHeiC-GB18030-SJ_wIcon.ltt','MYingHeiC-Big5-SJ_wIcon.ltt','Sony_DI_Icons.ttf']:run(['mcopy','-o','-i',r/'tmp.img',FONTS/('tmp_images_'+n),'::images/'+n])
 if PRELOAD:
  shutil.copy2(PRELOAD,r/'preload.so')
  (r/'ld.so.preload').write_text('/tmp/preload.so\n')
  run(['mcopy','-o','-i',r/'tmp.img',r/'preload.so','::preload.so'])
  run(['mcopy','-o','-i',r/'tmp.img',r/'ld.so.preload','::ld.so.preload'])
 run([Q/'qemu-img','create','-q','-f','qcow2','-F','raw','-b',emmc,r/'overlay.qcow2'])
 shutil.copy2(image,r/'usr.img')
 run([Q/'qemu-io','-f','qcow2','-c',f'write -s usr.img 771751936 {Path(image).stat().st_size}','-c','write -s setting.img 16777216 20971520','-c','write -s tmp.img 188743680 12582912',r/'overlay.qcow2'],r/'overlay.log',cwd=r)
 # Independent read-back of the injected ext2 superblock; all image geometries stay original here.
 run([Q/'qemu-io','-f','qcow2','-c','read -v 771752960 64',r/'overlay.qcow2'],r/'usr-superblock-readback.log')
 cmdline=(r/'kemco.txt').read_text().replace('\r',' ').replace('\n',' ').removeprefix('kemco').strip().replace('console=ttynull','console=ttyAM0,115200n8 amba2.console=1')+' norandmaps'
 machine=f'sony-a6400,rear-controls=on,submicro-frames={sub}'
 cmd=[str(Q/'qemu-system-arm'),'-M',machine,'-m','1G','-display','none','-monitor','none','-serial','stdio','-kernel',str(kernel),'-initrd',str(initrd),'-append',cmdline,'-drive','if=sd,format=qcow2,file='+str(r/'overlay.qcow2'),'-device','loader,file='+str(r/'Backup.bin')+',addr=0x02E80000,force-raw=on','-device','loader,file='+str(av)+',addr=0x035C6000,force-raw=on','-icount','shift=0,sleep=on']
 env={k:v for k,v in os.environ.items() if not k.startswith('REA_')};env.update(REA_ADC_SEQ=os.environ.get('ASTRA97_ADC_SEQ','3:32'),REA_ADC_T0=os.environ.get('ASTRA97_ADC_T0','12000'),REA_FRONT_BTN=os.environ.get('ASTRA97_FRONT_BTN','4,0,0,4'),REA_FRONT_T0=os.environ.get('ASTRA97_FRONT_T0','25000'),REA_FB_PATH=str(r/'frame'),REA_FB_VSYNC=os.environ.get('ASTRA97_FB_VSYNC','1200,1800,2400,3000'),REA_FB_FORMAT='rgba4444',REA_FB_LIVE=str(r/'live.ppm'))
 if os.environ.get('ASTRA97_GPE_TRACE'):env['REA_GPE_TRACE']=os.environ['ASTRA97_GPE_TRACE']
 manifest={'label':label,'repeat':rep,'machine':machine,'cmd':cmd,'environment':{k:v for k,v in env.items() if k.startswith('REA_')},'inputs':[sha(p) for p in [image,backup,initrd,av,kernel,sub,Q/'qemu-system-arm',emmc]],'wall_seconds':wall,'host_script_sha256':hashlib.sha256(SCRIPT_SNAPSHOT).hexdigest()}
 (r/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2));(r/'runner.py').write_bytes(SCRIPT_SNAPSHOT)
 serial=(r/'serial.log').open('wb');stderr=(r/'stderr.log').open('wb');start=time.monotonic();p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=serial,stderr=stderr,env=env)
 def _live_copy():
  for k in range(300):
   time.sleep(1)
   try:
    if (r/'live.ppm').exists():shutil.copy2(r/'live.ppm',r/f'live_{k:03d}.ppm')
   except FileNotFoundError:pass
 threading.Thread(target=_live_copy,daemon=True).start()
 print('START',name,'pid',p.pid,flush=True)
 def send():
  for ix,delay in enumerate([20,25,30]):
   time.sleep(delay)
   if p.poll() is not None:return
   c=f'echo ASTRA97_BEGIN_{ix}; cat /proc/mounts; ls -l /usr/bin/im.elf /usr/lib/libIMDB.so /usr/lib/appFw.so; ps; for x in /proc/[0-9]*; do if grep -q -e appFw.so -e a5pFw.so -e libObj.so "$x/maps" 2>/dev/null; then echo MAPOWNER=$x; cat "$x/maps"; fi; done'
   _extra=os.environ.get('ASTRA97_CMD','')
   if _extra:c+='; '+_extra
   c+=f'; echo ASTRA97_END_{ix}'
   if os.environ.get('ASTRA97_LOADER_PROBE'):
    c+='; echo ASTRA97_LOADER; LD_TRACE_LOADED_OBJECTS=1 /usr/bin/im.elf; echo IM_TRACE_RC=$?; LD_TRACE_LOADED_OBJECTS=1 /usr/bin/bootin.elf; echo BOOT_TRACE_RC=$?; cat /proc/cmdline; ls -l /sbin/init /usr/bin/launch_shell.elf /usr/bin/bootin.elf; echo ASTRA97_LOADER_END'
   try:p.stdin.write((c+'\n').encode());p.stdin.flush()
   except (BrokenPipeError,ValueError):return
 t=threading.Thread(target=send,daemon=True);t.start();why='wall_deadline'
 try:p.wait(timeout=wall)
 except subprocess.TimeoutExpired:
  p.terminate()
  try:p.wait(timeout=8)
  except subprocess.TimeoutExpired:p.kill();p.wait()
 else:why='guest_exit'
 serial.close();stderr.close();text=(r/'serial.log').read_text(errors='replace');s=(r/'stderr.log').read_text(errors='replace')
 result={'run':name,'label':label,'repeat':rep,'host_elapsed':round(time.monotonic()-start,2),'returncode':p.returncode,'termination':why,'guest_usr_mounted':bool(re.search(r'^\S+ /usr \S+ ',text,re.M)),'has_appFw_mapping':bool(re.search(r'^[0-9a-f]+-[0-9a-f]+\s+\S+\s+.*(?:/|\s)(?:appFw|a5pFw)\.so(?:\s|$)',text,re.M)),'bridge_trace_lines':[l for l in text.splitlines() if '[ASTRA97]' in l],'has_libObj_mapping':bool(re.search(r'^[0-9a-f]+-[0-9a-f]+ .*libObj\.so',text,re.M)),'compressed_fallback_seen':'mounting1 /dev/dnflasha15' in text,'loader_error_lines':[l for l in text.splitlines() if re.search('undefined symbol|symbol lookup error|error while loading|not found|required by',l,re.I)],'exception_monitor':'Entering exception monitor' in text,'frames':[p.name for p in r.glob('frame*')]}
 (r/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
 for n in ['manifest.json','result.json','serial.log','stderr.log','overlay.log','usr-superblock-readback.log','runner.py']:shutil.copy2(r/n,dest/n)
 for f in r.glob('frame*'):
  if f.is_file():shutil.copy2(f,dest/f.name)
 print('RESULT',json.dumps(result,ensure_ascii=False),flush=True);return result
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--image',required=True);ap.add_argument('--label',required=True);ap.add_argument('--repeat',type=int,default=2);ap.add_argument('--wall',type=int,default=100);ap.add_argument('--preload');a=ap.parse_args()
 DEPLOY.mkdir(exist_ok=True,parents=True);ARCHIVE.mkdir(exist_ok=True,parents=True);PRELOAD=Path(a.preload) if a.preload else None
 disk=Path(os.environ.get('ASTRA97_EMMC','/root/qemu_in/emmc.img'))
 with disk.open('rb') as f:
  f.seek(0x800000);sdm=f.read(512)
 if sdm[:8]!=b'82461.00':raise SystemExit('Unknown disk partition table')
 start,extent,typ,flags=struct.unpack_from('<IIII',sdm,0x100)
 if start!=0x2d800000 or not 215517184<=Path(a.image).stat().st_size<=extent:raise SystemExit('Image exceeds audited /usr SDM extent')
 results=[trial(Path(a.image),a.label,a.wall,i+1) for i in range(a.repeat)]
 (ARCHIVE/(a.label+'-summary.json')).write_text(json.dumps(results,ensure_ascii=False,indent=2))
