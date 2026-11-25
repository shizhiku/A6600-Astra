"""Read-only GitHub issue searches for the observed a6600 emulator boundary."""
from pathlib import Path
import urllib.request,urllib.parse,json,datetime,time
root=Path(__file__).resolve().parent
out=root/'a6600_port/analysis/github-similar';out.mkdir(parents=True,exist_ok=True)
queries=['repo:ivica00/bionz-x-research liro','repo:ivica00/bionz-x-research a6600','"0x170000" sony','"liro" "fault"','repo:cokeenet/zve10-qemu assert','repo:nolan2628/ZVE10-Astra-Public a6600']
all=[]
for q in queries:
 url='https://api.github.com/search/issues?'+urllib.parse.urlencode({'q':q,'per_page':10})
 try:
  req=urllib.request.Request(url,headers={'User-Agent':'a6600-offline-research','Accept':'application/vnd.github+json'})
  with urllib.request.urlopen(req,timeout=30) as resp: data=json.load(resp)
  entry={'query':q,'url':url,'total_count':data.get('total_count'),'items':[{'number':x['number'],'title':x['title'],'url':x['html_url'],'state':x['state'],'body':x.get('body'),'created_at':x['created_at'],'updated_at':x['updated_at']} for x in data.get('items',[])]}
  print(q,'=>',entry['total_count'],flush=True)
  for x in entry['items']: print(' ',x['title'],x['url'],flush=True)
 except Exception as exc:
  entry={'query':q,'error':str(exc)};print(q,'ERROR',exc,flush=True)
 all.append(entry)
 (out/'issue-searches.json').write_text(json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'searches':all},ensure_ascii=False,indent=2),encoding='utf-8')
 time.sleep(2)
