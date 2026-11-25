from pathlib import Path
from collections import defaultdict
import importlib.util,json
R=Path(__file__).resolve().parents[1];s=importlib.util.spec_from_file_location('usr',R/'02-脚本/a6600_usr.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
fs=m.Ext2(str(R/'05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15'));d=defaultdict(lambda:[0,0]);big=[]
for p,i,dr in fs.walk():
 if dr:continue
 mode,n,bl=fs.inode(i);parts=p.strip('/').split('/');key='/'.join(parts[:3]) if p.startswith('/share/') else parts[0];d[key][0]+=n;d[key][1]+=1
 if p.startswith('/share/'):big.append((n,p))
out=R/'03-证据/静态分析/97_resources';out.mkdir(exist_ok=True,parents=True)
result={'by_directory':sorted([(k,*v)for k,v in d.items()],key=lambda x:-x[1]),'largest_share_files':sorted(big,reverse=True)[:70]};(out/'inventory.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps({'by_directory':result['by_directory'][:35],'largest':result['largest_share_files'][:20]},ensure_ascii=True,indent=2))
