"""Run an isolated emulator copy and collect late maps, task stacks, input and OSAL diagnostics.
No camera access. Existing firmware/emulator files are not changed.
"""
from pathlib import Path
import subprocess,shutil,json,time,socket,os,datetime
BASE=Path('<WORKSPACE>')
Q=Path('/root/qemu-11.1.3/build')
old=Path('/root/a6600-emulation/procinput-20261121T114856Z-116993')
R=Path('/root/a6600-emulation')/('probe84-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+str(os.getpid()))
R.mkdir()
for n in ['Backup.bin','kemco.txt']:shutil.copy2(old/n,R/n)
# Reuse the completed overlay read-only as a backing file; all new writes go to our fresh overlay.
subprocess.run([str(Q/'qemu-img'),'create','-q','-f','qcow2','-F','qcow2','-b',str(old/'overlay.qcow2'),str(R/'overlay.qcow2')],check=True)
if os.environ.get('UI84_SHIM'):
 shutil.copy2(old/'tmp.img',R/'tmp.img')
 (R/'ld.so.preload').write_text('/tmp/libui_state84.so\n')
 subprocess.run(['mcopy','-o','-i',str(R/'tmp.img'),str(BASE/'04-产物/libui_state84.so'),'::libui_state84.so'],check=True)
 subprocess.run(['mcopy','-o','-i',str(R/'tmp.img'),str(R/'ld.so.preload'),'::ld.so.preload'],check=True)
 subprocess.run([str(Q/'qemu-io'),'-f','qcow2','-c','write -s '+str(R/'tmp.img')+' 188743680 12582912',str(R/'overlay.qcow2')],check=True)
cmd=(R/'kemco.txt').read_text().replace('\r',' ').replace('\n',' ').removeprefix('kemco').strip().replace('console=ttynull','console=ttyAM0,115200n8 amba2.console=1')+' norandmaps'
args=[str(Q/'qemu-system-arm'),'-M','sony-a6400,rear-controls=on,submicro-frames=/root/qemu_in/a6600-submicro-frames-20261121.bin','-m','1G','-display','none','-monitor','none','-serial','stdio','-qmp','unix:'+str(R/'qmp.sock')+',server=on,wait=off','-gdb','unix:'+str(R/'gdb.sock')+',server=on,wait=off','-kernel','/root/qemu_in/nflasha3-Image','-initrd',str(BASE/'05-原始固件/qemu_in/nflasha3-initrd-nt'),'-append',cmd,'-drive','if=sd,format=qcow2,file='+str(R/'overlay.qcow2'),'-device','loader,file='+str(R/'Backup.bin')+',addr=0x02E80000,force-raw=on','-device','loader,file='+str(BASE/'05-原始固件/qemu_in/av-cam-live.bin')+',addr=0x035C6000,force-raw=on','-icount','shift=0,sleep=on']
(R/'launch.json').write_text(json.dumps({'args':args,'source_overlay':str(old/'overlay.qcow2')},ensure_ascii=False,indent=2))
print('RUN',R,flush=True)
err=(R/'stderr.log').open('wb'); log=(R/'serial.log').open('wb')
env=os.environ.copy();env.update(REA_KEY_LOG='1',REA_FRONT_BTN='4',REA_FRONT_T0='25000',REA_FRONT_T1='27000')
p=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=log,stderr=err,env=env)
(R/'pid').write_text(str(p.pid))
commands=[
 ('late_maps',"echo MARK84_MAPS; for p in /proc/[0-9]*; do if grep -q libObj \"$p/maps\" 2>/dev/null; then echo OWNER=$p; cat \"$p/comm\"; cat \"$p/maps\"; fi; done; echo MARK84_MAPS_END"),
 ('proc_inventory','echo MARK84_PROC; ls -l /proc/udm/input /proc/liro /proc/osal; cat /proc/osal/minfo; echo MARK84_PROC_END'),
 ('input_get','echo MARK84_INPUT; echo get > /proc/udm/input; cat /proc/udm/input; echo MARK84_INPUT_END'),
 ('input_table','echo MARK84_TABLE; echo table > /proc/udm/input; cat /proc/udm/input; echo MARK84_TABLE_END'),
 ('osal','echo MARK84_OSAL; cat /proc/osal/uipc; echo MARK84_OSAL_END'),
 ('tasks','echo MARK84_TASKS; ps; for p in /proc/[0-9]*; do if grep -q libObj "$p/maps" 2>/dev/null; then for t in "$p"/task/*; do echo TASK=$t; cat "$t/comm" "$t/status" "$t/wchan" "$t/syscall" "$t/stack" 2>/dev/null; done; fi; done; echo MARK84_TASKS_END'),
 ('kallsyms','echo MARK84_SYMBOLS; grep -E "osal_|liro_|getkey|kbd_|dmp|sugilite" /proc/kallsyms; echo MARK84_SYMBOLS_END')]
try:
 time.sleep(85)
 for name,c in commands:
  if p.poll() is not None:break
  p.stdin.write((c+'\n').encode());p.stdin.flush();print('SENT',name,flush=True);time.sleep(5 if name!='tasks' else 12)
 print('COLLECTION_COMPLETE',flush=True)
 # Leave a short window for host GDB inspection if another script attaches.
 time.sleep(30)
finally:
 if p.poll() is None:p.terminate()
 try:p.wait(timeout=8)
 except subprocess.TimeoutExpired:p.kill();p.wait()
 log.close();err.close()
 dest=BASE/'03-证据/模拟器运行'/R.name;dest.mkdir(exist_ok=True)
 for n in ['serial.log','stderr.log','launch.json']:shutil.copy2(R/n,dest/n)
 print('DONE',dest, 'rc',p.returncode,flush=True)
