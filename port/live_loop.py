#!/usr/bin/env python3
"""a6600 ASTRA live harness.

Boots QEMU with an interactive control FIFO, then loops:
  * drain command file  -> write chars into REA_CTL_FIFO (key injection)
  * pmemsave the ASTRA present buffer via QMP -> decode Morton RGBA4444 -> PNG
  * publish serial tail for the web UI

Run inside WSL, root.
"""
import json
import os
import socket
import struct
import subprocess
import sys
import time
import zlib
from pathlib import Path

ROOT = Path('${RUN}')
INPUT = ROOT / 'inputs-v2'
Q = Path('/root/qemu-11.1.3/build')
EMMC = Path('/root/qemu_in/emmc.img')
LIVE = Path('${WORKSPACE}/04-产物/a6600-port/live')
FIFO = ROOT / 'rea_ctl.fifo'
FRAME_RAW = ROOT / 'frame.raw'

USR = Path(sys.argv[1])
TMPIMG = Path(sys.argv[2])
WALL = int(sys.argv[3]) if len(sys.argv) > 3 else 1800
# optional: settings partition image.  Using a previously-persisted one keeps the
# app from re-entering its first-boot wizard (which makes MENU go back to the guide).
SETTING_IMG = Path(sys.argv[4]) if len(sys.argv) > 4 else INPUT / 'setting.img'

# ASTRA present target (guest physical), from the shim's own log line
FB_PHYS = 0x20557300
FB_W, FB_H = 640, 480
FB_BYTES = FB_W * FB_H * 2

LIVE.mkdir(parents=True, exist_ok=True)
CMD = LIVE / 'cmd.txt'
STAT = LIVE / 'status.txt'
PNG = LIVE / 'live.png'
if CMD.exists():
    CMD.unlink()
CMD.write_text('')


def morton(lx, ly):
    return ((lx & 1) | ((ly & 1) << 1) | ((lx & 2) << 1) |
            ((ly & 2) << 2) | ((lx & 4) << 2) | ((ly & 4) << 3))


def write_png(w, h, rows, out):
    raw = bytearray()
    for r in rows:
        raw.append(0)
        raw += r

    def chunk(tag, payload):
        return (struct.pack('>I', len(payload)) + tag + payload +
                struct.pack('>I', zlib.crc32(tag + payload) & 0xFFFFFFFF))

    png = b'\x89PNG\r\n\x1a\n'
    png += chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))
    png += chunk(b'IDAT', zlib.compress(bytes(raw), 1))
    png += chunk(b'IEND', b'')
    tmp = out.with_suffix('.tmp')
    tmp.write_bytes(png)
    tmp.replace(out)


def decode_to_png(raw_path, out_path):
    """Decode the Morton-tiled RGBA4444 present buffer into a PNG (vectorised)."""
    data = raw_path.read_bytes()
    if len(data) < FB_BYTES:
        return False
    try:
        import numpy as np
    except ImportError:
        return decode_to_png_slow(raw_path, out_path)

    tiles_x, tiles_y = FB_W // 8, FB_H // 8
    v = np.frombuffer(data, dtype='<u2', count=FB_W * FB_H).reshape(tiles_y, tiles_x, 64)

    # index of each (ly,lx) inside a tile
    idx = np.empty((8, 8), dtype=np.int32)
    for ly in range(8):
        for lx in range(8):
            idx[ly, lx] = morton(lx, ly)

    px = v[:, :, idx.ravel()].reshape(tiles_y, tiles_x, 8, 8)
    img = px.transpose(0, 2, 1, 3).reshape(FB_H, FB_W)

    r = ((img >> 12) & 0xF).astype(np.uint8) * 17
    g = ((img >> 8) & 0xF).astype(np.uint8) * 17
    b = ((img >> 4) & 0xF).astype(np.uint8) * 17
    rgb = np.stack([r, g, b], axis=2)[::-1]          # stored bottom-up

    rows = [rgb[y].tobytes() for y in range(FB_H)]
    write_png(FB_W, FB_H, rows, out_path)
    return True


def decode_to_png_slow(raw_path, out_path):
    data = raw_path.read_bytes()
    if len(data) < FB_BYTES:
        return False
    tiles_x, tiles_y = FB_W // 8, FB_H // 8
    rows = []
    for ty in range(tiles_y):
        band = [bytearray(FB_W * 3) for _ in range(8)]
        for tx in range(tiles_x):
            base = (ty * tiles_x + tx) * 64
            for ly in range(8):
                row = band[ly]
                for lx in range(8):
                    off = base + morton(lx, ly)
                    v = data[off * 2] | (data[off * 2 + 1] << 8)
                    x = (tx * 8 + lx) * 3
                    row[x] = ((v >> 12) & 0xF) * 17
                    row[x + 1] = ((v >> 8) & 0xF) * 17
                    row[x + 2] = ((v >> 4) & 0xF) * 17
        rows.extend(band)
    rows.reverse()
    write_png(FB_W, FB_H, rows, out_path)
    return True


class GdbMem:
    """Minimal GDB-RSP client: writes guest physical memory via QEMU's gdbstub."""

    def __init__(self, host='127.0.0.1', port=1235):
        self.host, self.port = host, port

    def write(self, addr, data):
        csum = 0
        payload = b'M%x,%x:%s' % (addr, len(data), data.hex().encode())
        for b in payload:
            csum = (csum + b) & 0xFF
        pkt = b'$' + payload + b'#' + ('%02x' % csum).encode()
        try:
            s = socket.create_connection((self.host, self.port), timeout=3)
        except OSError as e:
            return False, f'connect: {e}'
        try:
            s.sendall(pkt)
            s.settimeout(3)
            ack = s.recv(64)
            s.sendall(b'D')          # detach, let the guest run
            return True, ack[:16]
        except OSError as e:
            return False, f'xfer: {e}'
        finally:
            s.close()


def parse_touch_phys(serial_path):
    import re
    try:
        txt = Path(serial_path).read_text(errors='replace')
    except Exception:
        return 0
    m = None
    for m in re.finditer(r'TOUCH_MB: virt=(0x[0-9a-f]+) phys=(0x[0-9a-f]+)', txt):
        pass
    return int(m.group(2), 16) if m else 0


class Qmp:
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        for _ in range(120):
            try:
                self.s.connect(str(path))
                break
            except OSError:
                time.sleep(0.5)
        else:
            raise RuntimeError('qmp connect failed')
        self.buf = b''
        self._read_obj()                      # greeting
        self.cmd({'execute': 'qmp_capabilities'})

    def _read_obj(self):
        while True:
            nl = self.buf.find(b'\n')
            while nl < 0:
                d = self.s.recv(65536)
                if not d:
                    raise RuntimeError('qmp closed')
                self.buf += d
                nl = self.buf.find(b'\n')
            line, self.buf = self.buf[:nl], self.buf[nl + 1:]
            line = line.strip()
            if line:
                return json.loads(line.decode())

    def cmd(self, obj):
        self.s.sendall((json.dumps(obj) + '\n').encode())
        while True:
            r = self._read_obj()
            if 'return' in r or 'error' in r:
                return r


# ---------- boot ----------
if FIFO.exists():
    FIFO.unlink()
os.mkfifo(FIFO)

o = ROOT / 'live_overlay.qcow2'
if o.exists():
    o.unlink()
subprocess.run([str(Q / 'qemu-img'), 'create', '-q', '-f', 'qcow2', '-F', 'raw',
                '-b', str(EMMC), str(o)], check=True)
subprocess.run([str(Q / 'qemu-io'), '-f', 'qcow2',
                '-c', 'write -s %s %d %d' % (USR, 771751936, 314572800),
                '-c', 'write -s %s %d %d' % (SETTING_IMG, 16777216, 20971520),
                '-c', 'write -s %s %d %d' % (TMPIMG, 188743680, 12582912),
                str(o)], check=True, stdout=subprocess.DEVNULL)

c = ' '.join((INPUT / 'kemco.txt').read_text().split()).removeprefix('kemco').strip()
c = c.replace('console=ttynull', 'console=ttyAM0,115200n8 amba2.console=1') + ' norandmaps'
# web_ui=1 makes the shim run its render pump continuously (interactive mode);
# without it the pump stops after 45 cycles and the app stops repainting.
# NOTE: it must go BEFORE the '*' marker in kemco.txt, because everything after
# that marker appears to be dropped from the guest's /proc/cmdline.
if 'web_ui=1' not in c:
    c = 'web_ui=1 ' + c

QPMSOCK = ROOT / 'live_qmp.sock'
if QPMSOCK.exists():
    QPMSOCK.unlink()

env = {k: v for k, v in os.environ.items() if not k.startswith('REA_')}
env.update(REA_CTL_FIFO=str(FIFO))

args = [str(Q / 'qemu-system-arm'),
        '-M', 'sony-a6400,rear-controls=on,submicro-frames=%s/submicro.bin' % INPUT,
        '-m', '1G', '-display', 'none', '-monitor', 'none',
        '-serial', 'file:%s/live_serial.log' % ROOT,
        '-qmp', 'unix:%s,server=on,wait=off' % QPMSOCK,
        '-gdb', 'tcp:127.0.0.1:1235',
        '-kernel', str(INPUT / 'kernel'),
        '-initrd', str(INPUT / 'initrd'),
        '-append', c,
        '-drive', 'if=sd,format=qcow2,file=%s' % o,
        '-device', 'loader,file=%s/Backup.bin,addr=0x02E80000,force-raw=on' % INPUT,
        '-device', 'loader,file=%s/av-cam.bin,addr=0x035C6000,force-raw=on' % INPUT,
        '-icount', 'shift=0,sleep=on']

SER = ROOT / 'live_serial.log'
if SER.exists():
    SER.unlink()
p = subprocess.Popen(args, cwd=str(ROOT), stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=open('/tmp/live_qemu.err', 'wb'), env=env)
STAT.write_text('booting qemu...\n')
print('QEMU started, qmp', QPMSOCK, flush=True)

try:
    q = Qmp(QPMSOCK)
    print('QMP ready', flush=True)
except Exception as e:
    STAT.write_text(f'qmp failed: {e}\n')
    p.kill()
    sys.exit(1)

deadline = time.monotonic() + WALL
sent = 0
DBG = Path('/tmp/live_dbg.log')
DBG.write_text('start\n')
frame_ok = 0
last_blob = None
status_tick = 0
TOUCHF = LIVE / 'touch.txt'
TOUCHF.write_text('')
touch_sent = 0
touch_seq = 0
gdb = GdbMem()
while time.monotonic() < deadline and p.poll() is None:
    # 1b) host -> guest touch mailbox
    try:
        ttxt = TOUCHF.read_text()
    except Exception:
        ttxt = ''
    if ttxt and len(ttxt) > touch_sent:
        pending = ttxt[touch_sent:]
        touch_sent = len(ttxt)
        for ln in pending.strip().splitlines():
            parts = ln.split()
            try:
                if len(parts) >= 4 and parts[0] == 'k':
                    # key:  k <ev_on> <ev_off> <hold_ms>   (all hex allowed)
                    kind = 3
                    tx1 = int(parts[1], 0) & 0xFFFFFFFF
                    ty1 = int(parts[2], 0) & 0xFFFFFFFF
                    tx2 = int(parts[3], 0)
                    ty2 = 0
                elif len(parts) >= 4:
                    kind = 2
                    tx1, ty1, tx2, ty2 = (int(v) for v in parts[:4])
                elif len(parts) >= 2:
                    kind = 1
                    tx1 = tx2 = int(parts[0])
                    ty1 = ty2 = int(parts[1])
                else:
                    continue
            except ValueError:
                continue
            phys = parse_touch_phys(SER)
            if not phys:
                with DBG.open('a') as f:
                    f.write(f'touch {tx1},{ty1} dropped: mailbox phys unknown\n')
                continue
            touch_seq += 1
            pkt = b'T' + struct.pack('<IIIIIII', phys, touch_seq, kind,
                                     tx1, ty1, tx2, ty2)
            ok, info = False, 'fifo error'
            try:
                wfd = os.open(str(FIFO), os.O_WRONLY | os.O_NONBLOCK)
                os.write(wfd, pkt)
                os.close(wfd)
                ok, info = True, 'sent'
            except OSError as e:
                ok, info = False, str(e)
            with DBG.open('a') as f:
                f.write(f'touch kind={kind} ({tx1},{ty1})->({tx2},{ty2}) '
                        f'seq={touch_seq} phys=0x{phys:x} ok={ok} {info}\n')
    # 1) drain commands
    try:
        txt = CMD.read_text()
    except Exception:
        txt = ''
    if txt:
        new = txt[sent:]
        if new:
            try:
                wfd = os.open(str(FIFO), os.O_WRONLY | os.O_NONBLOCK)
                os.write(wfd, new.encode('utf-8', 'ignore'))
                os.close(wfd)
                sent = len(txt)
                with DBG.open('a') as f:
                    f.write(f'sent {new!r}\n')
            except OSError:
                pass
        else:
            sent = len(txt)
    # 2) frame
    try:
        r = q.cmd({'execute': 'human-monitor-command',
                   'arguments': {'command-line':
                                 f'pmemsave {FB_PHYS} {FB_BYTES} frame.raw'}})
        if frame_ok < 3:
            with DBG.open('a') as f:
                f.write(f'qmp#{frame_ok}: {json.dumps(r)[:300]}\n')
        if 'return' in r and FRAME_RAW.exists():
            blob = FRAME_RAW.read_bytes()
            if blob != last_blob:
                last_blob = blob
                FRAME_RAW.write_bytes(blob)
                ok = decode_to_png(FRAME_RAW, PNG)
                frame_ok += 1
                if frame_ok <= 3:
                    with DBG.open('a') as f:
                        f.write(f'frame#{frame_ok} decode={ok} '
                                f'size={len(blob)}\n')
    except Exception as e:
        with DBG.open('a') as f:
            f.write(f'frame error: {e}\n')
    # 3) status (only every ~10 loops, it is far slower than the frame path)
    status_tick += 1
    if status_tick % 10 == 0:
        try:
            tail = SER.read_text(errors='replace').splitlines()[-25:]
            STAT.write_text('\n'.join(tail) + '\n')
        except Exception:
            pass
    time.sleep(0.05)

p.terminate()
try:
    p.wait(10)
except Exception:
    p.kill()
STAT.write_text(STAT.read_text() + '\n[harness stopped]\n')
