#!/usr/bin/env python3
"""Preserve the prior QEMU run that failed only during report serialization."""
from pathlib import Path
import shutil,json,datetime
base=Path('<LEGACY_WORKSPACE>')
runs=sorted(Path('/root/a6600-emulation').glob('observe-*'),key=lambda p:p.stat().st_mtime,reverse=True)
if not runs:raise SystemExit('no prior run')
src=runs[0];dest=base/'a6600_port/emulation/replay-serialization-failed-20261121';dest.mkdir(parents=True,exist_ok=False)
for n in ('serial.log','stderr.log','overlay.log','unimplemented.log'):
 if (src/n).exists():shutil.copyfile(src/n,dest/n)
receipt={'status':'QEMU reached the known fatal-PC breakpoint and stopped; host evidence finalization then failed because argparse Path object was not JSON serializable','wsl_run_directory':str(src),'submicro_input':'/root/qemu_in/a6600-submicro-frames-20261121.bin','preserved_files':[p.name for p in dest.iterdir()],'preserved_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'no_camera_access':True,'limitation':'Result cannot be claimed successful; rerun after serializer fix.'}
(dest/'failure-receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
print(json.dumps(receipt,indent=2))
