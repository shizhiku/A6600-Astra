#!/usr/bin/env python3
"""Read exactly one candidate 4 KiB a6600 RAM page via Senser memory-dump API.

No camera shell, file write, memory write, settings operation, or scan.
"""
from pathlib import Path
import sys,json,hashlib,datetime
BASE=Path('<LEGACY_WORKSPACE>')
OUT=BASE/'a6600_port/captures/submicro-candidate-20261121'
ADDRESS=0x03443000
SIZE=4096

def main():
 if OUT.exists(): raise SystemExit(f'Refusing to overwrite {OUT}')
 OUT.mkdir(parents=True)
 sys.path.insert(0,'/root/a6600/pmca-vendor')
 sys.path.insert(0,'/root/a6600/probe')
 from pmca.commands.usb import senserShellCommand
 receipt={'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'One bounded, read-only 4 KiB candidate page; Senser USB mode transition only; no camera file or RAM writes','candidate_address':hex(ADDRESS),'length':SIZE,'address_basis':'a6400 capture address, inside a6600 update cmdline wbimem reservation; target buffer identity is not established before capture','callback_entered':False}
 def cb(cam):
  receipt['callback_entered']=True
  receipt['read_started_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
  data=cam.readMemory(ADDRESS,SIZE)
  if len(data)!=SIZE: raise RuntimeError(f'Expected {SIZE}, got {len(data)}')
  p=OUT/'page-0x03443000.bin';p.write_bytes(data)
  receipt.update(read_status='complete',bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),local_file=p.name,read_finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
  print(json.dumps(receipt,indent=2),flush=True)
 try:
  senserShellCommand(driverName='libusb',complete=cb)
 except Exception as e:
  receipt['session_error']=f'{type(e).__name__}: {e}'
  raise
 finally:
  receipt['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
  (OUT/'receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
 if not receipt['callback_entered']: raise SystemExit('No capture: Senser callback not reached; do not auto-retry')
 print('CAPTURE '+str(OUT),flush=True)
if __name__=='__main__':main()
