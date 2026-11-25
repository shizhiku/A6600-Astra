"""Finalize offline audit manifest and recheck preserved inputs; no device APIs."""
from pathlib import Path
import hashlib,json,datetime
B=Path(__file__).resolve().parents[1];O=B/'03-证据/静态分析/97_flash'
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
initial=json.loads((O/'97_flash_input_manifest.json').read_text(encoding='utf-8'));checks=[]
for rel,meta in initial.items():
 p=B/rel;actual=sha(p);checks.append({'path':rel,'sha256':actual,'unchanged':actual==meta['sha256'],'bytes':p.stat().st_size})
for rel,expected in [('05-原始固件/a6600_fw/updater.img','5abbc90976dd9fef6962af743bf414e287def2f039b9fecd4236495a628baa74'),('05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha7','6bc8802e44686f4d8bf9158e7a8fa496a019a57c281564204bf714d5bb55ced9'),('05-原始固件/qemu_in/nflasha3-initrd','cba24946cafa515e7cdad01dc9255d9c6e4892539bec40396e210f8238bb4c50')]:
 p=B/rel;actual=sha(p);checks.append({'path':rel,'sha256':actual,'unchanged':actual==expected,'bytes':p.stat().st_size})
for qname,expected in [('emmc.img','8305fdf72050570811c15943a835bee7a0f935f15203e3aaadf14ec290782f01'),('sdm.bin','11e7349e6f419882c5d65fd598a9d18f3d4b7ffec1e3373c0208d56baad128c2')]:
 p=Path(r'\\wsl.localhost\Ubuntu\root\qemu_in')/qname;actual=sha(p);checks.append({'path':str(p),'sha256':actual,'unchanged':actual==expected,'bytes':p.stat().st_size})
sources=[]
for rel in ['pmca/commands/usb.py','pmca/usb/sony.py','updatershell/pack.py','pmca/platform/backend/senser.py','pmca/platform/backend/usb/__init__.py']:
 p=B/'_public_research/pmca-src/Sony-PMCA-RE-master'/rel;sources.append({'path':str(p.relative_to(B)),'sha256':sha(p),'primary_url':'https://github.com/ma1co/Sony-PMCA-RE/blob/master/'+rel})
artifacts=[]
for p in sorted(list(O.glob('97_flash_*'))+list((B/'02-脚本').glob('97_flash*.py'))+list((B/'01-文档').glob('97_flash*.md'))):
 if p.is_file():artifacts.append({'path':str(p.relative_to(B)),'bytes':p.stat().st_size,'sha256':sha(p)})
result={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'command':'python 02-脚本/97_flash_finalize.py','preserved_inputs':checks,'all_preserved_inputs_unchanged':all(x['unchanged'] for x in checks),'primary_local_sources':sources,'downloaded_primary_urls':{'97_flash_primary_fdat.py':'https://raw.githubusercontent.com/ma1co/fwtool.py/master/fwtool/sony/fdat.py','97_flash_primary_flash.py':'https://raw.githubusercontent.com/ma1co/fwtool.py/master/fwtool/sony/flash.py','97_flash_primary_sony_ilce6600_v110.html':'https://service.sony.com.cn/download/firm/00002943.html'},'artifacts':artifacts}
result['firmware_and_packaging_inputs_unchanged']=all(x['unchanged'] for x in checks if not x['path'].startswith('01-文档'))
result['scope_note']='96 taskbook changed concurrently; preserved as input drift, not written by this audit. All firmware/packaging/emulator inputs checked separately.'
p=O/'97_flash_final_manifest_v2.json'
with p.open('x',encoding='utf-8') as f:json.dump(result,f,ensure_ascii=False,indent=2)
print('preserved_inputs',len(checks),'unchanged',result['all_preserved_inputs_unchanged'],'artifacts',len(artifacts),'manifest_sha256',sha(p))
if not result['firmware_and_packaging_inputs_unchanged']:raise SystemExit(2)
print('firmware_and_packaging_inputs_unchanged',result['firmware_and_packaging_inputs_unchanged'])
