"""Extract visible primary-source discussion text without executing page scripts."""
from pathlib import Path
from html.parser import HTMLParser
class Text(HTMLParser):
 def __init__(self): super().__init__();self.out=[];self.skip=0
 def handle_starttag(self,t,a):
  if t in ('script','style'):self.skip+=1
  if t in ('p','div','li','tr','h1','h2','h3','pre','br'):self.out.append('\n')
 def handle_endtag(self,t):
  if t in ('script','style'):self.skip=max(0,self.skip-1)
  if t in ('p','div','li','tr','h1','h2','h3','pre'):self.out.append('\n')
 def handle_data(self,s):
  if not self.skip:self.out.append(s)
root=Path(__file__).resolve().parent/'a6600_port/analysis/github-similar'
for p in root.glob('*.html'):
 parser=Text();parser.feed(p.read_text(errors='replace'))
 lines=[x.strip() for x in ''.join(parser.out).splitlines() if x.strip()]
 p.with_suffix('.txt').write_text('\n'.join(lines),encoding='utf-8')
 print(p.name,len(lines))
