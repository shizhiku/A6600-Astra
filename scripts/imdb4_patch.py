"""imdb4_patch.py — 生成“禁用四代 InfraInput”最小补丁件与清单（不写任何镜像）。

只读输入 / 新产物：
  输入 03-证据/静态分析/97_abi/97_abi_libIMDB_appboot.so  我们镜像里的 libIMDB（SHA e503…）
  输入 03-证据/静态分析/97_abi/a6_libObj.so               我们镜像里的 libObj（SHA ebb6…）
  输出 03-证据/静态分析/imdb4/imdb4_libIMDB_rec31_*.so    两种 record 31 变体
  输出 03-证据/静态分析/imdb4/imdb4_libObj_noInput*.so    两种 libObj 变体
  输出 03-证据/静态分析/imdb4/imdb4_patch_manifest.json   偏移/原字节/新字节/SHA256
用法：python 02-脚本/imdb4_patch.py
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
ABI = BASE / "03-证据/静态分析/97_abi"
EVID = BASE / "03-证据/静态分析/imdb4"

IMDB = ABI / "97_abi_libIMDB_appboot.so"
IMDB_SHA = "e503cb7061b06e5abed7d7abd093b4b7b0bf21d1b93fb4e2818247599e4371b5"
LIBOBJ = ABI / "a6_libObj.so"
LIBOBJ_SHA = "ebb6cd0475ebfdb592fb7bdd2a54df8bc694e2e0520733fb84d7dfd31c84038a"

REC31 = 0x6128          # 记录 31 的文件偏移（表基址 0x5BD4 + 31*44）
# 记录字段偏移（44 字节记录，11 x u32）：
# +0 type, +4 flag, +8 target, +12 me(u16), +14 psid(u16), +16 file, +20 init,
# +24 exit, +28 sus, +32 res, +36 inact/argA, +40 act/argB
F_TYPE, F_FLAG, F_TARGET, F_FILE, F_INIT = 0, 4, 8, 16, 20
F_PSID = 14

# libObj 补丁点
GETINSTANCE = 0x860874      # _ZN10InfraInput11GetInstanceEv
CTOR = 0x860554             # InfraInput 构造函数/初始化：创建 4 条 I-Input* 线程
THREAD_CREATE = [0x8606A0, 0x8606E4, 0x860728, 0x86076C]  # 4 x BLX osal_create_waitable_thread@plt


def sha(b):
    return hashlib.sha256(b).hexdigest()


def only_diffs(old, new, allowed, name):
    diffs = [i for i in range(len(old)) if old[i] != new[i]]
    bad = [i for i in diffs if i not in allowed]
    if bad:
        raise SystemExit(f"[FAIL] {name} 出现非预期改动: {[hex(i) for i in bad[:10]]}")
    return diffs


def le32(b, off):
    return struct.unpack_from("<I", b, off)[0]


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    EVID.mkdir(parents=True, exist_ok=True)
    imdb = IMDB.read_bytes()
    libobj = LIBOBJ.read_bytes()
    assert sha(imdb) == IMDB_SHA, "libIMDB 不是我们镜像里的那一份"
    assert sha(libobj) == LIBOBJ_SHA, "libObj 与镜像 /lib/libObj.so 不一致"
    # 自证 record 31 字段与字符串 VA
    raw31 = imdb[REC31:REC31 + 44]
    assert le32(raw31, F_TYPE) == 0x20000001
    assert le32(raw31, F_FLAG) == 1
    assert le32(raw31, F_TARGET) == 0xFFFFFFBF
    assert struct.unpack_from("<H", raw31, F_PSID)[0] == 2043
    assert le32(raw31, F_FILE) == 0x3431 and le32(raw31, F_INIT) == 0x3442
    assert imdb[0x3431:0x3442] == b"libInfraInput.so\0"
    assert imdb[0x3442:0x3453] == b"infra_input_init\0"

    manifest = {
        "note": "只生成证据目录内的新文件；不写镜像、不覆盖任何现有产物。",
        "guest_paths": {"libIMDB": "/lib/libIMDB.so", "libObj": "/lib/libObj.so"},
        "inputs": {
            "libIMDB": {"path": str(IMDB), "sha256": sha(imdb), "bytes": len(imdb)},
            "libObj": {"path": str(LIBOBJ), "sha256": sha(libobj),
                       "bytes": len(libobj)},
        },
        "record31": {
            "index": 31, "file_offset": hex(REC31), "va": hex(REC31 + 0x8000),
            "raw": raw31.hex(" "),
            "fields": {
                "type": hex(le32(raw31, F_TYPE)),
                "flag(+4)": hex(le32(raw31, F_FLAG)),
                "target(+8)": hex(le32(raw31, F_TARGET)),
                "me(+12,u16)": struct.unpack_from("<H", raw31, 12)[0],
                "psid(+14,u16)": struct.unpack_from("<H", raw31, F_PSID)[0],
                "file(+16)": hex(le32(raw31, F_FILE)),
                "init(+20)": hex(le32(raw31, F_INIT)),
            },
        },
        "patches": [],
    }

    def emit(name, blob, base, desc, patches, note):
        out = EVID / name
        out.write_bytes(blob)
        entry = {"name": name, "desc": desc, "sha256": sha(blob),
                 "bytes": len(blob), "note": note, "patches": patches}
        manifest["patches"].append(entry)
        print(f"[ok] {name}  sha256={entry['sha256']}")
        for p in patches:
            print(f"     +0x{p['file_offset']:x}  {p['old']} -> {p['new']}  {p['meaning']}")
        return entry

    # ---------- A. record 31: init 指针置 0（推荐） ----------
    d = bytearray(imdb)
    allowed = set(range(REC31 + F_INIT, REC31 + F_INIT + 4))
    struct.pack_into("<I", d, REC31 + F_INIT, 0)
    only_diffs(imdb, d, allowed, "libIMDB_rec31_noinit")
    emit("imdb4_libIMDB_rec31_noinit.so", bytes(d), REC31,
         "record31 init 指针清零：仍按原顺序 dlopen(/usr/lib/libObj.so)，但不调用 infra_input_init",
         [{"file_offset": REC31 + F_INIT, "old": "42 34 00 00",
           "new": "00 00 00 00", "meaning": "record31.init -> NULL，b200 处理器跳过 dlsym/调用"}],
         "最保守的 IMDB 级补丁；libObj 加载时机不变，不影响后续记录。")

    # ---------- B. record 31: flag(+4)=0（整条记录被跳过） ----------
    d = bytearray(imdb)
    allowed = set(range(REC31 + F_FLAG, REC31 + F_FLAG + 4))
    struct.pack_into("<I", d, REC31 + F_FLAG, 0)
    only_diffs(imdb, d, allowed, "libIMDB_rec31_off")
    emit("imdb4_libIMDB_rec31_off.so", bytes(d), REC31,
         "record31 flag 清零：扫描器跳过该记录，libObj 首次加载推迟到 record 39",
         [{"file_offset": REC31 + F_FLAG, "old": "01 00 00 00",
           "new": "00 00 00 00", "meaning": "flag(+4)=0，b5ec 过滤条件失败"}],
         "会改变 libObj 的首次加载时机（record 32-35 在它之前），有加载顺序风险。")

    # ---------- C. libObj: 不创建 4 条 I-Input* 线程（推荐的有效补丁） ----------
    d = bytearray(libobj)
    allowed = set()
    plist = []
    for off in THREAD_CREATE:
        allowed |= set(range(off, off + 4))
        plist.append({"file_offset": off, "old": libobj[off:off + 4].hex(" "),
                      "new": "00 bf 00 bf",
                      "meaning": "BLX osal_create_waitable_thread@plt -> nop;nop"})
    for off in THREAD_CREATE:
        d[off:off + 4] = b"\x00\xbf\x00\xbf"
    only_diffs(libobj, d, allowed, "libObj_noInputThreads")
    emit("imdb4_libObj_noInputThreads.so", bytes(d), 0,
         "InfraInput 构造器不再创建 4 条 I-Input* 线程（Main/Recv/Event/Repeat），"
         "单例与 SetCallback/SetEventKeyList 等 API 保持可用",
         plist,
         "真正阻止四代 InfraInput 从 uipc 取事件；若运行期有代码等待这些线程/"
         "信号量，需要实测。")

    # ---------- D. libObj: GetInstance 直接返回 NULL（更强，风险更高） ----------
    d = bytearray(libobj)
    allowed = set(range(GETINSTANCE, GETINSTANCE + 4))
    d[GETINSTANCE:GETINSTANCE + 4] = b"\x00\x20\x70\x47"  # movs r0,#0 ; bx lr
    only_diffs(libobj, d, allowed, "libObj_noInputInstance")
    emit("imdb4_libObj_noInputInstance.so", bytes(d), 0,
         "InfraInput::GetInstance 直接返回 NULL：不创建单例、不创建线程",
         [{"file_offset": GETINSTANCE,
           "old": libobj[GETINSTANCE:GETINSTANCE + 4].hex(" "),
           "new": "00 20 70 47", "meaning": "movs r0,#0; bx lr"}],
         "任何未判空就解引用的四代调用方会崩溃（libBizFw2/libNetRemote 等），"
         "只建议作为隔离/定位实验，不建议直接进主线。")

    # ---------- 过滤逻辑模拟（b5ec/b694） ----------
    records = json.loads((EVID / "imdb4_records_patched.json").read_text(
        encoding="utf-8"))["records"]

    def selected(recs, target_mode, flag_mask):
        out = []
        for r in recs:
            if r["tag"] == 40:
                break
            if (r["mode"] & target_mode) == 0:      # +8 target & g_target
                continue
            if (r["version"] & flag_mask) == 0:     # +4 flag & thread/phase mask
                continue
            out.append(r["index"])
        return out

    before = selected(records, target_mode=1, flag_mask=0xFF)
    recs_a = json.loads((EVID / "imdb4_records_patched.json").read_text(
        encoding="utf-8"))["records"]
    # 变体 A 只在 b200 处理器层面生效，记录仍被选中
    only_diffs(imdb, bytearray(d[:0]) or imdb, set(), "noop") if False else None
    manifest["filter_sim"] = {
        "rule": "enabled = (record.target(+8) & g_target) and (record.flag(+4) & thread_mask)",
        "default_boot": {"g_target": 1, "phase_mask": "0xFF(主线程相位状态机)",
                         "infra0_mask": 1},
        "record31_before": {"selected": 31 in before,
                            "position": before.index(31) + 1 if 31 in before else None,
                            "phase": "tag3(idx19)~tag4(idx36) 之间，由主线程 b694(0,4,1) 扫描"},
        "variant_A_noinit": "记录仍被选中，但 b200 因 init==NULL 跳过 dlsym/调用",
        "variant_B_off": "flag=0 -> 记录不被选中（整条跳过）",
    }
    (EVID / "imdb4_patch_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[ok] manifest -> {EVID/'imdb4_patch_manifest.json'}")
    print(f"[i] record31 在 default boot 被选中: {31 in before}，"
          f"所选记录数 {len(before)}")


if __name__ == "__main__":
    main()
