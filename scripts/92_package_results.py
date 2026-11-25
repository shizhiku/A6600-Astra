from pathlib import Path
import shutil,hashlib,json
ROOT=Path(__file__).resolve().parents[1];DEST=Path(r'<WORKSPACE_MENU92>')/'92-菜单已打通';DEST.mkdir(exist_ok=True)
items=[
('01-文档/92-菜单已打通与91问题闭环.md','README.md'),
('01-文档/89-问题追踪表.md','分析/89-问题追踪表-已更新.md'),
('01-文档/91-当前具体问题陈述.md','分析/91-当前具体问题陈述-已更新.md'),
('01-文档/92_menu_map-真实MENU与ENTER映射.md','分析/MENU与ENTER映射.md'),
('01-文档/92_menu_send_B静态结论.md','分析/驱动发送与过滤.md'),
('03-证据/静态分析/92_menu_consumer_report.md','分析/NTSC提示与菜单消费者.md'),
('01-文档/92_menu_visual-截图核验.md','分析/截图核验.md'),
('03-证据/模拟器运行/run-20261121T153655Z-front-2/fb.1.png','MENU-纯硬件输入.png'),
('03-证据/模拟器运行/run-20261121T152425Z-native-1/fb.1.png','MENU-普通线程注入.png'),
('03-证据/模拟器运行/run-20261121T152444Z-baseline-2/fb.3.png','NTSC-基线提示.png'),
('03-证据/模拟器运行/run-20261121T152425Z-native-1/fb.3.png','OSD-菜单关闭后.png'),
('04-产物/92_native_menu_probe.c','代码/92_native_menu_probe.c'),
('04-产物/libnative_menu92.so','代码/libnative_menu92.so'),
('02-脚本/92_experiments.py','代码/92_experiments.py'),
('02-脚本/92_analyze_results.py','代码/92_analyze_results.py'),
('02-脚本/92_correct_key_table.py','代码/92_correct_key_table.py'),
('02-脚本/92_menu_map.py','代码/92_menu_map.py'),
('03-证据/静态分析/92_results.json','证据/92_results.json'),
('03-证据/静态分析/92_menu_map/mapping_evidence.json','证据/mapping_evidence.json'),
('03-证据/静态分析/92_menu_map/corrected_physical_key_table.json','证据/corrected_physical_key_table.json')]
for p in (ROOT/'03-证据/模拟器运行').glob('run-20261121T15*'):
 for n in ['run.json','summary.json','analysis.json','serial.log','stderr.log']:
  if (p/n).exists():items.append((str((p/n).relative_to(ROOT)),str(Path('证据')/p.name/n)))
manifest=[]
for src,dst in items:
 s=ROOT/src;t=DEST/dst;t.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(s,t)
 a=hashlib.sha256(s.read_bytes()).hexdigest();b=hashlib.sha256(t.read_bytes()).hexdigest()
 if a!=b:raise RuntimeError('Hash mismatch '+str(t))
 manifest.append({'file':dst,'size':t.stat().st_size,'sha256':b})
(DEST/'交付清单-SHA256.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
# Update the obsolete original diagnostic's warning in the user's earlier output.
shutil.copy2(ROOT/'04-产物/inject_menu_preload.c',DEST.parent/'inject_menu_preload.c')
print('PACKAGED',DEST,'files',len(manifest))
