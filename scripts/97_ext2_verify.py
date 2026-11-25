"""Regression check for sparse ELF-style gaps, double-indirect holes and fast links."""
from pathlib import Path
import subprocess,hashlib,json
from importlib import import_module
O=Path('/root/astra/97/ext2-reader-check');O.mkdir(exist_ok=False,parents=True);src=O/'sparse.payload';img=O/'test.img'
with src.open('wb') as f:f.write(b'ELF-CHECK\n');f.seek(2*1024*1024+17);f.write(b'END-CHECK')
with img.open('wb') as f:f.truncate(16*1024**2)
subprocess.run(['mke2fs','-q','-t','ext2','-F','-b','1024',str(img)],check=True)
for command in ['write '+str(src)+' /sparse','symlink /shortlink sparse']:
 subprocess.run(['debugfs','-w','-R',command,str(img)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
Safe=import_module('97_ext2').Ext2;Legacy=import_module('a6600_usr').Ext2;f=Safe(str(img));idx={p:i for p,i,d in f.walk()if not d};safe=f.read_file(idx['/sparse']);link=f.read_file(idx['/shortlink']);legacy=Legacy(str(img)).read_file(idx['/sparse']);expected=src.read_bytes()
assert safe==expected,'Sparse content mismatch';assert link==b'sparse','Fast link mismatch';assert legacy!=expected,'Regression did not exercise old sparse bug'
result={'expected_bytes':len(expected),'legacy_returned_bytes':len(legacy),'safe_bytes':len(safe),'sha256':hashlib.sha256(safe).hexdigest(),'fast_symlink':link.decode(),'result':'PASS'};(O/'result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
