"""Summarize completed run92 frames; run with bundled Python (Pillow)."""
from pathlib import Path
from PIL import Image
import json,hashlib,re
BASE=Path(__file__).resolve().parents[1];ROOT=BASE/'03-证据/模拟器运行'
KNOWN={'a6087ec5178c7619d8136de2aa159dde7161d56f9e4c3b899b7165935d0353d8':'black','261759d395c6a58884154fed1c0b4d8c45879314fa06af650be35fac96ffb87d':'verified-menu-setting4','2f890494b1409bdb0f2914747ef84232bd7309f2a4624357f2171be366b060ca':'verified-no-card-osd','3d94248936dfb8fccc9e750c348d8571ab712581ec99342b6e2ee362248993b9':'verified-ntsc-caution'}
results=[]
for p in sorted(ROOT.glob('run-20261121T15*')):
 if not (p/'summary.json').exists():continue
 meta=json.loads((p/'run.json').read_text(encoding='utf-8'));summary=json.loads((p/'summary.json').read_text());err=(p/'stderr.log').read_text(errors='replace');ser=(p/'serial.log').read_text(errors='replace')
 x={'run':p.name,'mode':meta['mode'],'rep':meta['rep'],'machine':meta['args'][meta['args'].index('-M')+1],'rc':summary['rc'],'injection_logs':re.findall(r'\[(?:NATIVE92)\][^\r\n]*|INJ7:[^\r\n]*',ser),'frames':[]}
 for i,f in enumerate(sorted(p.glob('fb.*.ppm'))):
  d=f.read_bytes();sha=hashlib.sha256(d).hexdigest();im=Image.open(f);im.save(f.with_suffix('.png'))
  mm=re.search(r'\[REA_FB\] dumped (\d+)x(\d+) from (0x[0-9a-f]+) to [^\r\n]*'+re.escape(f.name),err)
  after=re.search(r'^FRAME92_'+re.escape(f.name)+r'\r?\n(.{0,4000})',ser,re.M|re.S);uptime=None
  if after:
   um=re.search(r'^(\d+\.\d+)\s+\d+\.\d+\s*$',after.group(1),re.M)
   if um:uptime=float(um.group(1))
  x['frames'].append({'name':f.name,'vsync_target':[1200,1800,2400,3000,3600,4200][i],'framebuffer_base':mm.group(3) if mm else None,'sha256':sha,'pixel_bbox':im.getbbox(),'classification':KNOWN.get(sha,'nonblack-unclassified' if im.getbbox() else 'black'),'guest_uptime_sample_after_capture':uptime})
 # Extract common callback logger payloads if enabled.
 callbacks=[]
 for match in re.finditer(r'REA_BP hit=.*?(?=REA_BP hit=|\Z)',err,re.S):
  block=match.group(0)
  if 'va=0x60439cc' not in block:continue
  if re.search(r'00 01 01 15|00010115|15010100',block,re.I):callbacks.append(block[:1800])
 x['menu_callback_matches']=len(callbacks)
 x['callback_probe_note']='Not an absence proof: logger samples TB entry; watched BLX can lie later in the TB. Native/control modes do not enable this probe.'
 if callbacks:(p/'menu-callbacks.txt').write_text('\n\n'.join(callbacks),encoding='utf-8')
 (p/'analysis.json').write_text(json.dumps(x,ensure_ascii=False,indent=2),encoding='utf-8');results.append(x)
OUT=BASE/'03-证据/静态分析/92_results.json';OUT.write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
for r in results:print(r['run'],r['machine'],','.join(f['classification'] for f in r['frames']),'menu_callbacks',r['menu_callback_matches'])
