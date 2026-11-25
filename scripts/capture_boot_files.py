#!/usr/bin/env python3
"""Read existing a6600 files via Senser; no terminal, file writes, or backup generation on camera."""
from pathlib import Path
import argparse,datetime,hashlib,io,json,sys,time,traceback

FILES=[
 ('/proc/uptime',65536),
 ('/proc/version',65536),
 ('/proc/cmdline',65536),
 ('/proc/mounts',262144),
 ('/proc/partitions',65536),
 ('/setting/Backup.bin',16*1024*1024),
 ('/setting/kemco.txt',65536),
 ('/setting/ulogio.bin',4*1024*1024),
 ('/setting/DmmConfig.bin',4*1024*1024),
 ('/etc/ld.so.preload',65536),
 ('/setting/mode/dmode',65536),
 ('/setting/mode/preload',65536),
 ('/proc/uptime',65536),
]
class BoundedOutput(io.BytesIO):
 def __init__(self,limit): super().__init__(); self.limit=limit
 def write(self,b):
  if self.tell()+len(b)>self.limit: raise RuntimeError('Read limit exceeded; stop acquisition')
  return super().write(b)

def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--out',required=True); ap.add_argument('--pmca-dir',default='/root/a6600/pmca-vendor'); a=ap.parse_args()
 out=Path(a.out); out.mkdir(parents=True,exist_ok=False)
 sys.path.insert(0,a.pmca_dir); sys.path.insert(0,str(Path(__file__).resolve().parent))
 report={'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Existing file reads only; Senser authentication changes USB mode; no terminal execution or persistent camera write','callback_entered':False,'files':[]}
 def save(): (out/'receipt.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
 save()
 from pmca.commands.usb import senserShellCommand
 def cb(cam):
  report['callback_entered']=True; save()
  for index,(remote,limit) in enumerate(FILES):
   item={'remote':remote,'max_bytes':limit,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
   buf=BoundedOutput(limit); t=time.monotonic()
   try:
    cam.readFile(remote,buf)
    data=buf.getvalue(); dest=f'{index:02d}-'+remote.strip('/').replace('/','__')
    (out/dest).write_bytes(data)
    item.update(status='read',local=dest,bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
    print(f'READ {remote}: {len(data)} bytes',flush=True)
   except Exception as exc:
    item.update(status='error',error_type=type(exc).__name__,error=str(exc),partial_bytes=buf.tell())
    print(f'ERROR {remote}: {type(exc).__name__}: {exc}',flush=True)
    report['files'].append(item); save()
    if isinstance(exc,RuntimeError) or type(exc).__name__ in ('GenericUsbException','USBError'): raise
    continue
   item['seconds']=round(time.monotonic()-t,3); report['files'].append(item); save()
 try: senserShellCommand(driverName='libusb',complete=cb)
 except Exception as exc:
  report['session_error']=f'{type(exc).__name__}: {exc}'; save(); raise
 finally:
  report['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat(); save()
 if not report['callback_entered']: raise SystemExit(2)
 print('CAPTURE_COMPLETE '+str(out),flush=True)
if __name__=='__main__': main()
