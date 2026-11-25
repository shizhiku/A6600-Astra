"""Static direct-import coverage for sharing original hardware service DSOs."""
from pathlib import Path
import json
B=Path(__file__).resolve().parents[1];O=B/'03-证据/静态分析/97_abi';I=json.loads((O/'inventory.json').read_text(encoding='utf8'));a=I['a6usr'];z=I['zvusr']
roots=['appFw.so','libObj.so','libmpr.so','appFwBoot.so','AdjChkConfig.so'];hw=['libInfraUsbCmn.so','libUsbControl.so','libbackup.so','libNetCommon.so','libGOConnectionManager.so','libNetContUtil.so','libMWF.so','libInfraMediaCommon.so','libsencore.so','libInfraPtpControl.so','dataflowInfraFramework.so','libutil_date.so','libcompassutil.so','libBackupManager.so','libInfraSKD.so','libptp.so','libosal_utm.so','libosal_uipc.so']
rows=[]
for consumer in roots+hw:
 x=z.get('/lib/'+consumer)
 if not x:continue
 for dep in hw:
  new=z.get('/lib/'+dep);old=a.get('/lib/'+dep)
  if not new or not old or consumer==dep:continue
  used=sorted(n for n,v in x['und'].items() if v['bind']!='STB_WEAK' and n in new['defs'])
  if not used:continue
  syms=[{'name':n,'old_has':n in old['defs'],'old_size':old['defs'].get(n,{}).get('size'),'new_size':new['defs'][n]['size'],'old_type':old['defs'].get(n,{}).get('type'),'new_type':new['defs'][n]['type']} for n in used]
  rows.append({'consumer':consumer,'provider':dep,'is_declared_needed':dep in x['needed'],'used_count':len(used),'missing_in_old':[n for n in used if n not in old['defs']],'symbols':syms,'old_sha256':old['sha256'],'new_sha256':new['sha256']})
(O/'boundary_coverage.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf8')
for r in rows:
 if r['consumer'] in roots or r['provider'] in ('libInfraUsbCmn.so','libUsbControl.so','libbackup.so','libNetCommon.so','libGOConnectionManager.so','libNetContUtil.so'):
  print(r['consumer'],'->',r['provider'],'used',r['used_count'],'missing_old',r['missing_in_old'])
