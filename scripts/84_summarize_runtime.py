from pathlib import Path
import re,json
R=Path(__file__).resolve().parents[1];p=R/'03-证据/模拟器运行/probe84-20261121T115805Z-118001/serial.log';text=p.read_text(errors='replace');tasks=[]
for m in re.finditer(r'TASK=/proc/(\d+)/task/(\d+)\n(.*?)(?=TASK=/proc/|MARK84_TASKS_END)',text,re.S):
 pid,tid,b=m.groups();name=re.search(r'^Name:\s*(.*)',b,re.M);state=re.search(r'^State:\s*(.*)',b,re.M);w=b.strip().splitlines()[-1]
 tasks.append({'pid':int(pid),'tid':int(tid),'name':name.group(1) if name else b.splitlines()[0],'state':state.group(1) if state else '', 'wchan':w})
out=R/'03-证据/静态分析/probe84/runtime-task-summary.json';out.write_text(json.dumps(tasks,ensure_ascii=False,indent=2),encoding='utf-8')
for t in tasks:
 if re.search('UI|View|Root|Input|Draw|Gfx|GLES|App|INFRA|GPU|Render',t['name'],re.I):print(t)
print('tasks',len(tasks))
