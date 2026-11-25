"""Read liro.ko from the local /usr image and map the observed module offset."""
from pathlib import Path
import importlib.util,json
root=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('usr',root/'a6600_usr.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
fs=m.Ext2(str(root/'a6600_fw/extracted/0700_part_image/dev/nflasha15'))
target=None
for path,ino,isdir in fs.walk():
    if path in ('/kmod/liro.ko','/usr/kmod/liro.ko'):
        target=(path,fs.read_file(ino));break
if not target: raise SystemExit('liro.ko not found in image')
path,data=target
out=root/'a6600_port/analysis/liro-fault-static/liro.ko'
out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(data)
print('extracted',path,len(data),'bytes ->',out)
import hashlib;print('sha256',hashlib.sha256(data).hexdigest())
