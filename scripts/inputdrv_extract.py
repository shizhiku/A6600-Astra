# -*- coding: utf-8 -*-
"""inputdrv_extract.py — 只读提取 a6600(四代) 与 zv1m2(五代) 镜像中的输入/uipc 相关文件。

复用 02-脚本/a6600_usr.py 的 Ext2 类（只读，不改动该脚本）。
产物：03-证据/静态分析/input_drv/*.bin(.so/.ko) + input_drv_manifest.json
"""
import hashlib
import io
import json
import struct
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
OUT = BASE / '03-证据/静态分析/input_drv'
OUT.mkdir(parents=True, exist_ok=True)

A6600_IMG = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
ZV1M2_IMG = BASE / '05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15'

TARGETS = {
    'g4': {
        A6600_IMG: [
            '/kmod/input.ko',
            '/kmod/osal_uipc.ko',
            '/lib/libosal_uipc.so',
            '/lib/libObj.so',
            '/lib/libosal.so',
            '/lib/libosal_ulogio.so',
            '/lib/libsencore.so',
            '/bin/im.elf',
        ],
    },
    'g5': {
        ZV1M2_IMG: [
            '/kmod/input.ko',
            '/kmod/osal_uipc.ko',
            '/lib/libosal_uipc.so',
            '/lib/libObj.so',
            '/lib/libosal.so',
            '/lib/libosal_ulogio.so',
            '/bin/im.elf',
        ],
    },
}


def load_ext2(path):
    import importlib.util
    spec = importlib.util.spec_from_file_location('usr_mod', BASE / '02-脚本/a6600_usr.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.Ext2(str(path))


def build_index(fs):
    idx = {}
    for p, ino, is_dir in fs.walk():
        if not is_dir:
            idx[p] = ino
    return idx


def main():
    manifest = []
    for gen, per_img in TARGETS.items():
        for img, paths in per_img.items():
            if not img.exists():
                print('[skip] missing image', img)
                continue
            print('[open]', gen, img.name, img.stat().st_size)
            fs = load_ext2(img)
            idx = build_index(fs)
            for p in paths:
                ino = idx.get(p)
                if ino is None:
                    print('  MISSING', gen, p)
                    continue
                data = fs.read_file(ino)
                dest = OUT / f'g4_{Path(p).name}' if gen == 'g4' else OUT / f'g5_{Path(p).name}'
                # g4/g5 同名文件加前缀；同代不同路径同名（如两处 input.ko）不会发生
                if dest.exists() and dest.read_bytes() != data:
                    raise RuntimeError(f'existing differs: {dest}')
                dest.write_bytes(data)
                rec = dict(gen=gen, image=str(img.relative_to(BASE)), path=p, inode=ino,
                           size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                           file=str(dest.relative_to(BASE)))
                manifest.append(rec)
                print(f'  {gen} {p:28s} {len(data):10d} {rec["sha256"][:16]}')
    (OUT / 'input_drv_manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                                                 encoding='utf-8')
    print('manifest ->', OUT / 'input_drv_manifest.json')


if __name__ == '__main__':
    main()
