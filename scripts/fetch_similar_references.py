"""Fetch primary GitHub discussions and a linked settings template as research data."""
from pathlib import Path
import urllib.request,json
root=Path(__file__).resolve().parent/'a6600_port/analysis/github-similar'
items=[('pmca-597-comments','https://api.github.com/repos/ma1co/Sony-PMCA-RE/issues/597/comments?per_page=100'),('settings-gist','https://api.github.com/gists/9b7a194ee166972b3c21b892df126bf5'),('bionz-22-comments','https://api.github.com/repos/ivica00/bionz-x-research/issues/22/comments?per_page=100'),('bionz-52','https://api.github.com/repos/ivica00/bionz-x-research/pulls/52')]
for name,url in items:
 try:
  req=urllib.request.Request(url,headers={'User-Agent':'a6600-offline-research','Accept':'application/vnd.github+json'})
  with urllib.request.urlopen(req,timeout=30) as resp:d=json.load(resp)
  (root/(name+'.json')).write_text(json.dumps(d,ensure_ascii=False,indent=2),encoding='utf-8')
  if name=='settings-gist':
   for i,(fname,f) in enumerate(d.get('files',{}).items()):
    content=f.get('content','');(root/f'gist-{i}.txt').write_text(content,encoding='utf-8');print(fname,len(content),'truncated',f.get('truncated'),flush=True)
  elif isinstance(d,list):
   print(name,'comments',len(d),flush=True)
   for c in d:
    body=c.get('body','')
    if any(x in body.lower() for x in ['liro','0x17','backup','fault']): print(body[:5000],flush=True)
  else:print(name,d.get('title'),flush=True)
 except Exception as exc:print(name,'ERROR',exc,flush=True)
