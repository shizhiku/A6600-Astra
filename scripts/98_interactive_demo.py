"""Interactive stock-firmware demo: QEMU headless + web page with buttons.

The page shows the live panel framebuffer (exported by the patched VPH model)
and injects front MENU / ADC ENTER / selector levels through a control FIFO.
Run in WSL: python3 98_interactive_demo.py --port 8765
"""
from pathlib import Path
import argparse, subprocess, os, shutil, time, datetime, zlib, struct, json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ROOT = Path('<WORKSPACE>')
Q = Path('/root/qemu-11.1.3/build')
CAP = ROOT/'03-证据/相机采集/boot-20261120T151656Z-26869'
FONTS = ROOT/'03-证据/相机采集/live-fonts-20261121'
STOCK = ROOT/'05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
A = argparse.ArgumentParser()
A.add_argument('--port', type=int, default=8765)
A.add_argument('--image', default=str(STOCK))
A.add_argument('--wall', type=int, default=3600)
ARGS = A.parse_args()

RUN = Path('/root/astra/interactive')/datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
RUN.mkdir(parents=True, exist_ok=False)
FIFO = RUN/'ctl.fifo'
PPM = RUN/'live.ppm'
LOG = RUN/'serial.log'
ERR = RUN/'stderr.log'
if FIFO.exists(): FIFO.unlink()
os.mkfifo(FIFO)

def run(cmd):
    p = subprocess.run([str(x) for x in cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode: raise SystemExit(str(cmd[:2]) + ': ' + p.stdout.decode(errors='replace')[-1200:])
    return p.stdout

backup = ROOT/'05-原始固件/qemu_in/Backup-state1.bin'
initrd = ROOT/'05-原始固件/qemu_in/nflasha3-initrd-nt'
av = ROOT/'05-原始固件/qemu_in/av-cam-live.bin'
kernel = Path('/root/qemu_in/nflasha3-Image')
emmc = Path('/root/qemu_in/emmc.img')
sub = Path('/root/qemu_in/a6600-submicro-frames-20261121.bin')
for src, n in [(backup,'Backup.bin'),(CAP/'06-setting__kemco.txt','kemco.txt'),
               (CAP/'07-setting__ulogio.bin','ulogio.bin'),(CAP/'08-setting__DmmConfig.bin','DmmConfig.bin')]:
    shutil.copy2(src, RUN/n)
for n, size in [('setting.img', 20*1024**2), ('tmp.img', 12*1024**2)]:
    with (RUN/n).open('wb') as f: f.truncate(size)
    run(['mkfs.vfat','-F','16',RUN/n])
for n in ['Backup.bin','kemco.txt','ulogio.bin','DmmConfig.bin']:
    run(['mcopy','-o','-i',RUN/'setting.img',RUN/n,'::'+n])
run(['mmd','-i',RUN/'tmp.img','::images'])
for n in ['MYingHeiC-GB18030-SJ_wIcon.ltt','MYingHeiC-Big5-SJ_wIcon.ltt','Sony_DI_Icons.ttf']:
    run(['mcopy','-o','-i',RUN/'tmp.img',FONTS/('tmp_images_'+n),'::images/'+n])
image = Path(ARGS.image); shutil.copy2(image, RUN/'usr.img')
run([Q/'qemu-img','create','-q','-f','qcow2','-F','raw','-b',emmc,RUN/'overlay.qcow2'])
run([Q/'qemu-io','-f','qcow2',
     '-c', f'write -s {RUN/"usr.img"} 771751936 {image.stat().st_size}',
     '-c', f'write -s {RUN/"setting.img"} 16777216 20971520',
     '-c', f'write -s {RUN/"tmp.img"} 188743680 12582912',
     str(RUN/'overlay.qcow2')])
cmdline = (RUN/'kemco.txt').read_text().replace('\r',' ').replace('\n',' ').removeprefix('kemco').strip()
cmdline = cmdline.replace('console=ttynull','console=ttyAM0,115200n8 amba2.console=1') + ' norandmaps'
cmd = [str(Q/'qemu-system-arm'), '-M', f'sony-a6400,rear-controls=on,submicro-frames={sub}',
       '-m','1G','-display','none','-monitor','none','-serial',f'file:{LOG}',
       '-kernel',str(kernel),'-initrd',str(initrd),'-append',cmdline,
       '-drive','if=sd,format=qcow2,file='+str(RUN/'overlay.qcow2'),
       '-device','loader,file='+str(RUN/'Backup.bin')+',addr=0x02E80000,force-raw=on',
       '-device','loader,file='+str(av)+',addr=0x035C6000,force-raw=on',
       '-icount','shift=0,sleep=on']
env = {k: v for k, v in os.environ.items() if not k.startswith('REA_')}
env.update(REA_CTL_FIFO=str(FIFO), REA_FB_LIVE=str(PPM), REA_FB_FORMAT='rgba4444')
proc = subprocess.Popen(cmd, stdout=open(LOG,'ab'), stderr=open(ERR,'wb'), env=env)

def ppm_to_png(data):
    head, rest = data.split(b'\n', 1)
    if head.strip() != b'P6': raise ValueError('not P6')
    dims, rest = rest.split(b'\n', 1)
    w, h = map(int, dims.split())
    maxv, pixels = rest.split(b'\n', 1)[0], rest.split(b'\n', 1)[1]
    stride = w * 3
    raw = b''.join(b'\x00' + pixels[y*stride:(y+1)*stride] for y in range(h))
    def chunk(t, b):
        return struct.pack('>I', len(b)) + t + b + struct.pack('>I', zlib.crc32(t+b) & 0xffffffff)
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw, 6)) + chunk(b'IEND', b''))

cache = {'mtime': None, 'png': None}
def screen_png():
    try:
        st = PPM.stat()
    except FileNotFoundError:
        return None
    if cache['mtime'] != st.st_mtime_ns:
        cache['png'] = ppm_to_png(PPM.read_bytes()); cache['mtime'] = st.st_mtime_ns
    return cache['png']

HTML = '''<!doctype html><html><head><meta charset="utf-8"><title>a6600 demo</title>
<style>body{background:#111;color:#ddd;font-family:sans-serif;margin:12px}
#screen{border:1px solid #444;width:640px;image-rendering:pixelated}
button{margin:3px;padding:8px 12px;font-size:14px;background:#333;color:#eee;border:1px solid #555;border-radius:6px}
button:active{background:#666} .grp{margin:8px 0}</style></head><body>
<h3>a6600 原厂 UI 交互演示</h3>
<div><img id="screen" src="/screen.png" width="640" height="480"></div>
<div class="grp"><b>MENU</b> <button onclick="c('m')">MENU (front bit2)</button>
<b>ENTER</b> <button onclick="c('e')">ENTER (ADC ch3)</button></div>
<div class="grp"><b>选择器 ch4</b>
<button onclick="c('1')">1 0x000</button><button onclick="c('2')">2 0x05b</button>
<button onclick="c('3')">3 0x112</button><button onclick="c('4')">4 0x1b7</button>
<button onclick="c('5')">5 0x258</button></div>
<div class="grp"><b>选择器 ch5</b>
<button onclick="c('6')">6 0x000</button><button onclick="c('7')">7 0x05b</button>
<button onclick="c('8')">8 0x112</button><button onclick="c('9')">9 0x1b7</button>
<button onclick="c('0')">0 0x258</button></div>
<p>选择器通道/电平对应关系尚未验证，可用它们探索方向键效果。</p>
<script>
function c(x){fetch('/cmd?c='+x)}
setInterval(()=>{document.getElementById('screen').src='/screen.png?t='+Date.now()},700);
</script></body></html>'''

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        if u.path == '/':
            body = HTML.encode(); self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
        elif u.path == '/screen.png':
            try:
                fd = os.open(FIFO, os.O_WRONLY | os.O_NONBLOCK)
                os.write(fd, b's')
                os.close(fd)
                time.sleep(0.35)
            except OSError:
                pass
            png = screen_png()
            if not png:
                self.send_response(404); self.end_headers(); return
            self.send_response(200); self.send_header('Content-Type','image/png'); self.send_header('Content-Length',str(len(png))); self.end_headers(); self.wfile.write(png)
        elif u.path == '/cmd':
            c = (q.get('c') or [''])[0][:1]
            ok = False
            if c:
                try:
                    fd = os.open(FIFO, os.O_WRONLY | os.O_NONBLOCK); os.write(fd, c.encode()); os.close(fd); ok = True
                except OSError as e:
                    pass
            body = json.dumps({'ok': ok, 'cmd': c}).encode(); self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(body)
        elif u.path == '/log':
            try: body = LOG.read_bytes()[-4000:]
            except FileNotFoundError: body = b''
            self.send_response(200); self.send_header('Content-Type','text/plain; charset=utf-8'); self.end_headers(); self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()

print('RUN', RUN)
print('URL http://localhost:%d/' % ARGS.port)
try:
    ThreadingHTTPServer(('0.0.0.0', ARGS.port), H).serve_forever()
finally:
    proc.terminate()
    try: proc.wait(timeout=8)
    except subprocess.TimeoutExpired: proc.kill()
