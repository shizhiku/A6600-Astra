"""Fetch public text references directly when GitHub API rate limit is exhausted."""
from pathlib import Path
import urllib.request
root=Path(__file__).resolve().parent/'a6600_port/analysis/github-similar'
urls=[('settings-template.txt','https://gist.githubusercontent.com/RomanHargrave/9b7a194ee166972b3c21b892df126bf5/raw/'),('pmca-597.html','https://github.com/ma1co/Sony-PMCA-RE/issues/597'),('bionz-pr52.html','https://github.com/ivica00/bionz-x-research/pull/52')]
for name,url in urls:
 try:
  req=urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0'})
  with urllib.request.urlopen(req,timeout=30) as resp:data=resp.read(8*1024*1024)
  (root/name).write_bytes(data);print('FETCHED',name,len(data),flush=True)
 except Exception as exc:print('ERROR',name,exc,flush=True)
