"""Compare the camera's av-cam.bin with the update-package copy."""
from pathlib import Path
import hashlib, json

BASE = Path(r'<WORKSPACE>')
LIVE = BASE / '03-证据/相机采集/live-avcam-file-20261121/system_av-cam.bin'
LOCAL = BASE / '05-原始固件/qemu_in/av-cam.bin'

live = LIVE.read_bytes()
local = LOCAL.read_bytes()
out = {
    'live_bytes': len(live), 'local_bytes': len(local),
    'size_delta': len(live) - len(local),
    'live_sha256': hashlib.sha256(live).hexdigest(),
    'local_sha256': hashlib.sha256(local).hexdigest(),
    'live_head64': live[:64].hex(),
    'local_head64': local[:64].hex(),
    'head64_equal': live[:64] == local[:64],
}

# find the first differing offset
first = next((i for i in range(min(len(live), len(local))) if live[i] != local[i]), None)
out['first_diff_offset'] = hex(first) if first is not None else None

# block-wise equality on 4 KiB blocks over the common prefix
blocks = []
step = 0x1000
same = 0
diff = 0
first_diff_block = None
for off in range(0, min(len(live), len(local)) - step + 1, step):
    if live[off:off + step] == local[off:off + step]:
        same += 1
    else:
        diff += 1
        if first_diff_block is None:
            first_diff_block = off
out['blocks_4k'] = {'equal': same, 'different': diff, 'first_different_block': hex(first_diff_block) if first_diff_block is not None else None}

(BASE / '03-证据/静态分析/avcam-build-compare.json').write_text(json.dumps(out, indent=2), encoding='utf-8')
print(json.dumps(out, indent=2))
