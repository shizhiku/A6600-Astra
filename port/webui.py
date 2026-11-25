#!/usr/bin/env python3
"""a6600 ASTRA simulator web UI.

Serves a camera-body panel with a live framebuffer image and labelled buttons.
Button presses append a control character to live/cmd.txt, which the WSL-side
harness drains into the QEMU control FIFO.

Usage:  python webui.py [port]
"""
import http.server
import socketserver
import subprocess
import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LIVE = ROOT / 'live'
LIVE.mkdir(exist_ok=True)
CMD = LIVE / 'cmd.txt'
if not CMD.exists():
    CMD.write_text('')

# --- simulator restart -----------------------------------------------------
WSL_DISTRO = 'Ubuntu'
USR_IMG = '${REPO}/build_out/a6600_v40_redraw.img'
ETC_IMG = str(ROOT / 'release' / 'etc_nflasha10_preload.img').replace(
    'C:\\', '/mnt/c/').replace('\\', '/')
LIVE_LOOP = str(ROOT / 'scripts' / 'live_loop.py').replace(
    'C:\\', '/mnt/c/').replace('\\', '/')
RUN_SECONDS = 7200


RESTART_SH = str(ROOT / 'scripts' / 'restart_sim.sh').replace(
    'C:\\', '/mnt/c/').replace('\\', '/')


def restart_simulator():
    """Kill any running QEMU/live_loop and start a fresh one (detached).

    Delegates to scripts/restart_sim.sh: running the pkill inline would match
    this very command line (it contains the script name) and kill the shell.
    """
    try:
        r = subprocess.run(
            ['wsl', '-d', WSL_DISTRO, '-e', 'bash', RESTART_SH,
             USR_IMG, ETC_IMG, str(RUN_SECONDS)],
            capture_output=True, text=True, timeout=60)
        return r.returncode == 0, (r.stdout + r.stderr)[-300:]
    except Exception as e:
        return False, str(e)

# 名称, ctl 字符, 键码, 功能说明, 确认度
KEYS = [
    ("MENU",  "m", "0x1AB", "菜单键（前置按钮 bit2）", "已确认"),
    ("ENTER", "e", "0x1AC", "确认 / 执行（ADC ch3）", "已确认"),
    ("SEL1-1", "1", "—", "预设快捷档位 1-1（短按，1.2s 后自动释放）", "用户定义"),
    ("SEL1-2", "2", "—", "预设快捷档位 1-2", "用户定义"),
    ("SEL1-3", "3", "—", "预设快捷档位 1-3", "用户定义"),
    ("SEL1-4", "4", "—", "预设快捷档位 1-4", "用户定义"),
    ("SEL1-5", "5", "—", "预设快捷档位 1-5", "用户定义"),
    ("SEL2-1", "6", "—", "预设快捷档位 2-1（短按，1.2s 后自动释放）", "用户定义"),
    ("SEL2-2", "7", "—", "预设快捷档位 2-2", "用户定义"),
    ("SEL2-3", "8", "—", "预设快捷档位 2-3", "用户定义"),
    ("SEL2-4", "9", "—", "预设快捷档位 2-4", "用户定义"),
    ("SEL2-5", "0", "—", "预设快捷档位 2-5", "用户定义"),
]

# 分组按键表： (组标题, [ (显示名, 短名, event_on, event_off, 说明) ... ])
# event id 取自垫片内置 g5_tact_key_table（五代固件定义）
KEY_GROUPS = [
    ("核心拍摄与拨轮", [
        ("S1 · 半按快门", "S1", 0x020e000e, 0x020e000f, "快门第一行程：自动对焦 + 测光"),
        ("S2 · 全按快门", "S2", 0x020e0000, 0x020e0001, "快门第二行程：完成拍摄"),
        ("REC · 录制",    "REC", 0x020f000d, 0x020f000e, "视频开始 / 停止录制"),
        ("WHEEL_L · 拨轮左", "WHEEL_L", 0x02050001, 0, "前拨轮左转：光圈/快门/ISO"),
        ("WHEEL_R · 拨轮右", "WHEEL_R", 0x02050000, 0, "前拨轮右转：光圈/快门/ISO"),
        ("MS_UP · 摇杆上",  "MS_UP", 0x02010011, 0x02010012, "五维摇杆向上：移对焦点 / 选菜单"),
        ("MS_DN · 摇杆下",  "MS_DN", 0x02010014, 0x02010015, "五维摇杆向下"),
        ("MS_LF · 摇杆左",  "MS_LF", 0x02010017, 0x02010018, "五维摇杆向左"),
        ("MS_RT · 摇杆右",  "MS_RT", 0x0201001a, 0x0201001b, "五维摇杆向右"),
        ("MS_ENT · 摇杆按下", "MS_ENT", 0x0201001d, 0x0201001e, "摇杆按下确认，近似 ENTER"),
    ]),
    ("导航与功能", [
        ("UP · 上",    "UP",    0x02010000, 0x02010001, "方向键上"),
        ("DOWN · 下",  "DOWN",  0x02010003, 0x02010004, "方向键下"),
        ("LEFT · 左/返回", "LEFT", 0x02010006, 0x02010007, "方向键左；子页面时为返回上一级"),
        ("RIGHT · 右", "RIGHT", 0x02010009, 0x0201000a, "方向键右"),
        ("ENTER · 确认", "ENTER", 0x0201000c, 0x0201000d, "选中选项后确认"),
        ("MENU · 菜单",  "MENU",  0x0201000f, 0x02010010, "打开相机系统设置菜单"),
        ("FN · 快捷菜单", "FN",   0x02020000, 0x02020001, "自定义功能键：调出快速设置"),
        ("PLAY · 回看",  "PLAY",  0x02020003, 0x02020004, "进入回看界面看照片/视频"),
        ("DELETE · 删除", "DELETE", 0x02030000, 0x02030001, "删除当前回看的文件"),
        ("C1 · 自定义1", "C1",    0x02060000, 0x02060001, "自定义按键 1（对焦切换 / 参数调整）"),
    ]),
]

PAGE = """<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<title>ILCE-6600 · ASTRA 模拟操作台</title>
<style>
 body{margin:0;background:#15171c;color:#d7dae0;font:14px/1.5 -apple-system,"Segoe UI",sans-serif}
 .wrap{display:flex;gap:18px;padding:18px;align-items:flex-start;flex-wrap:wrap}
 .cam{background:#0b0c0f;border:1px solid #2a2e37;border-radius:10px;padding:14px}
 .cam h2{margin:0 0 10px;font-size:15px;color:#9aa4b2;font-weight:600}
 #shot{width:640px;height:480px;image-rendering:pixelated;background:#000;border-radius:6px;display:block}
 .side{flex:1;min-width:360px}
 .panel{background:#1b1e25;border:1px solid #2a2e37;border-radius:10px;padding:12px;margin-bottom:14px}
 .panel h3{margin:0 0 10px;font-size:13px;color:#8f9aab;text-transform:uppercase;letter-spacing:.06em}
 .row{display:flex;flex-wrap:wrap;gap:8px}
 button{background:#262b35;color:#e6e9ee;border:1px solid #3a4150;border-radius:8px;
        padding:10px 14px;font-size:13px;cursor:pointer;transition:.12s}
 button:hover{background:#323947;border-color:#4d5768}
 button:active{transform:translateY(1px)}
 button.hot{background:#2f4a3a;border-color:#3f6b52}
 table{width:100%;border-collapse:collapse;font-size:12.5px}
 th,td{text-align:left;padding:5px 6px;border-bottom:1px solid #262b35}
 th{color:#8f9aab;font-weight:600}
 code{background:#11131a;padding:1px 5px;border-radius:4px;color:#8fd0ff}
 .ok{color:#7fd18a}.unk{color:#d7b36a}
 pre{background:#11131a;border:1px solid #232833;border-radius:8px;padding:10px;
     height:230px;overflow:auto;font-size:11.5px;color:#9fb0c4;margin:0}
 .hint{color:#6f7a8a;font-size:12px;margin-top:8px}
 .gtitle{color:#8fd0ff;font-size:12.5px;font-weight:600;margin:12px 0 8px;letter-spacing:.04em}
 .gtitle:first-child{margin-top:0}
</style></head><body>
<div class="wrap">
  <div class="cam">
    <h2>ILCE-6600 · 实时画面（ASTRA UI · QEMU）</h2>
    <img id="shot" src="live.png" alt="framebuffer">
    <div class="hint" id="age">等待画面…</div>
  </div>
  <div class="side">
    <div class="panel">
      <h3>模拟器控制</h3>
      <div class="row">
        <button id="btnRestart" class="hot">重启模拟器</button>
      </div>
      <div class="hint" id="restartMsg">卡住时点这里重启；约 3~4 分钟出画面，之后需点几下 OK 过引导页。</div>
    </div>
    <div class="panel">
      <h3>按键 · 五代事件直注 <span style="font-weight:400;color:#6f7a8a;font-size:12px">（测功能请用这里）</span></h3>
      <div class="hint" style="margin:0 0 10px">按住时长
        <input id="hold" type="number" value="80" min="10" max="3000" style="width:70px"> ms
      </div>
      <div id="groups"></div>
    </div>
    <div class="panel">
      <h3>SEL 快捷档位（ADC 通道，短按后 1.2 s 自动释放）</h3>
      <div class="row" id="btns"></div>
      <div class="hint">这类档位是模拟量控制，触发后自动结束；用于快速切换参数预设 / 调用自定义功能。</div>
    </div>
    <div class="panel">
      <h3>按键映射说明</h3>
      <table>
        <thead><tr><th>按键</th><th>功能</th></tr></thead>
        <tbody id="legend5"></tbody>
      </table>
    </div>
    <div class="panel">
      <h3>串口日志（尾部）</h3>
      <pre id="log"></pre>
    </div>
  </div>
</div>
<script>
const GROUPS = __GROUPS__;
document.getElementById('btnRestart').onclick = async () => {
  const m = document.getElementById('restartMsg');
  m.textContent = '正在重启模拟器…（约 3~4 分钟出画面）';
  try {
    const r = await fetch('restart');
    const j = await r.json();
    m.textContent = j.ok ? '重启命令已发出，等待 3~4 分钟。' : ('重启失败：' + j.info);
  } catch (e) {
    m.textContent = '重启请求失败：' + e;
  }
};
const gwrap = document.getElementById('groups');
GROUPS.forEach(g => {
  const t = document.createElement('div');
  t.className = 'gtitle';
  t.textContent = g[0];
  gwrap.appendChild(t);
  const row = document.createElement('div');
  row.className = 'row';
  g[1].forEach(k => {
    const b = document.createElement('button');
    b.textContent = k[0];
    b.title = `${k[4]}\n按下事件 on=0x${k[2].toString(16)}  抬起事件 off=0x${k[3].toString(16)}`;
    b.onclick = () => press5(k[2], k[3], k[1]);
    row.appendChild(b);
  });
  gwrap.appendChild(row);
});
async function press5(on, off, shortName){
  const hold = parseInt(document.getElementById('hold').value || '80', 10);
  await fetch(`key?on=${on}&off=${off}&hold=${hold}`);
  document.getElementById('age').textContent =
    `已按 [${{'S1':'S1','S2':'S2'}[shortName] || shortName}]  hold=${hold}ms  @ `
    + new Date().toLocaleTimeString();
}
const lg5 = document.getElementById('legend5');
GROUPS.forEach(g => {
  g[1].forEach(k => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td><code>${k[1]}</code> ${k[0].split('·').pop().trim()}</td><td>${k[4]}</td>`;
    tr.firstChild.style.whiteSpace = 'nowrap';
    lg5.appendChild(tr);
  });
});
const KEYS = __KEYS__;
const bw = document.getElementById('btns');
KEYS.forEach(k => {
  if (!k[0].startsWith('SEL')) return;
  const b = document.createElement('button');
  b.textContent = k[0];
  b.title = k[3];
  b.onclick = () => press(k[1]);
  bw.appendChild(b);
});
async function press(c){ await fetch('press?c='+encodeURIComponent(c)); }
const shot = document.getElementById('shot');
shot.style.cursor = 'crosshair';
let downAt = null;
function toScreen(e){
  const r = shot.getBoundingClientRect();
  return [Math.round((e.clientX - r.left) * 640 / r.width),
          Math.round((e.clientY - r.top) * 480 / r.height)];
}
shot.onmousedown = (e) => { downAt = toScreen(e); e.preventDefault(); };
shot.onmouseup = (e) => {
  if (!downAt) return;
  const [x2, y2] = toScreen(e);
  const [x1, y1] = downAt;
  downAt = null;
  if (Math.abs(x2 - x1) + Math.abs(y2 - y1) > 12) tap4(x1, y1, x2, y2);
  else tap(x1, y1);
};
document.addEventListener('mouseup', () => { downAt = null; });
async function tap(x,y){
  await fetch('tap?x='+x+'&y='+y);
  const a = document.getElementById('age');
  a.textContent = `点击 (${x}, ${y})  @ ` + new Date().toLocaleTimeString();
}
async function tap4(x1,y1,x2,y2){
  await fetch(`tap?x=${x1}&y=${y1}&x2=${x2}&y2=${y2}`);
  const a = document.getElementById('age');
  a.textContent = `滑动 (${x1},${y1}) → (${x2},${y2})  @ ` + new Date().toLocaleTimeString();
}
const age  = document.getElementById('age');
let last = 0;
function tick(){
  shot.src = 'live.png?t=' + Date.now();
  fetch('status.txt?t=' + Date.now()).then(r=>r.ok?r.text():'')
    .then(t=>{ document.getElementById('log').textContent = t; });
}
setInterval(tick, 200); tick();
shot.onload = () => { age.textContent = '画面已更新 ' + new Date().toLocaleTimeString(); };
</script></body></html>
"""


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(LIVE), **kw)

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        if p.path in ('/', '/index.html'):
            groups = [[g[0], [[k[0], k[1], k[2], k[3], k[4]] for k in g[1]]]
                      for g in KEY_GROUPS]
            body = (PAGE.replace('__KEYS__', repr(
                [[k[0], k[1], k[2], k[3], k[4]] for k in KEYS]))
                .replace('__GROUPS__', repr(groups))).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if p.path == '/press':
            q = urllib.parse.parse_qs(p.query)
            c = (q.get('c') or [''])[0]
            if c:
                with CMD.open('a') as f:
                    f.write(c)
                sys.stderr.write(f'[press] {c!r}\n')
            self.send_response(204)
            self.end_headers()
            return
        if p.path == '/restart':
            ok, info = restart_simulator()
            sys.stderr.write(f'[restart] ok={ok} {info}\n')
            body = (f'{{"ok": {str(ok).lower()}, "info": {info!r}}}').encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if p.path == '/key':
            q = urllib.parse.parse_qs(p.query)
            on = int((q.get('on') or ['0'])[0], 0)
            off = int((q.get('off') or ['0'])[0], 0)
            hold = int((q.get('hold') or ['80'])[0])
            with (LIVE / 'touch.txt').open('a') as f:
                f.write(f'k {on} {off} {hold}\n')
            sys.stderr.write(f'[key] on=0x{on:x} off=0x{off:x} hold={hold}\n')
            self.send_response(204)
            self.end_headers()
            return
        if p.path == '/tap':
            q = urllib.parse.parse_qs(p.query)
            nums = []
            for k in ('x', 'y', 'x2', 'y2'):
                if k in q:
                    nums.append(int(q[k][0]))
            if len(nums) == 4:
                line = f'{nums[0]} {nums[1]} {nums[2]} {nums[3]}\n'
            elif len(nums) >= 2:
                line = f'{nums[0]} {nums[1]}\n'
            else:
                line = ''
            if line:
                with (LIVE / 'touch.txt').open('a') as f:
                    f.write(line)
            sys.stderr.write(f'[tap] {line.strip()}\n')
            self.send_response(204)
            self.end_headers()
            return
        if p.path == '/live.png':
            f = LIVE / 'live.png'
            if not f.exists():
                self.send_response(404)
                self.end_headers()
                return
            data = f.read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'image/png')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        return super().do_GET()

    def log_message(self, *a):
        pass


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8790
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(('127.0.0.1', port), Handler) as httpd:
        print(f'open http://127.0.0.1:{port}/', flush=True)
        httpd.serve_forever()
