from pathlib import Path
from importlib import import_module
import json,hashlib,argparse
P=argparse.ArgumentParser();P.add_argument('--image',required=True);P.add_argument('--manifest',required=True);P.add_argument('--output',required=True);A=P.parse_args();E=import_module('97_ext2').Ext2;d=json.loads(Path(A.manifest).read_text());f=E(A.image);idx={p:i for p,i,dr in f.walk()if not dr};bad=[];count=0
for row in d['libraries']:
 p='/lib/'+row['new'];data=f.read_file(idx[p]) if p in idx else None
 if 'symlink' in row:ok=data==row['symlink'].encode()
 else:ok=data is not None and hashlib.sha256(data).hexdigest()==row['staged_sha256']
 count+=1
 if not ok:bad.append(p)
for row in d['resources']:
 p=row['path'];data=f.read_file(idx[p])if p in idx else None;ok=data is not None and len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256'];count+=1
 if not ok:bad.append(p)
result={'image':A.image,'manifest':A.manifest,'checked':count,'mismatches':bad,'result':'PASS' if not bad else 'FAIL'};Path(A.output).write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
if bad:raise SystemExit(1)
