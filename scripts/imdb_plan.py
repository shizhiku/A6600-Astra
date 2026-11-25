"""S2-1c: 定位 testcmd 条目 + 生成 a6600 的 libIMDB 改造方案。"""
import os
import struct

ROOT = r"<LEGACY_WORKSPACE>"
A = os.path.join(ROOT, "a6600_fw", "usr", "lib", "libIMDB.so")
B = os.path.join(ROOT, "zv1m2_fw", "gen5", "libIMDB.so")

APPFW = 0x496F        # a6600: 'appFw.so' 字符串
ENTRY_APPFW = 0x70F8  # a6600: Application_System_Init 条目
SLOT = 0x4CC9         # a6600: 'testcmd_scn.so' 字符串槽


def find_refs(data, value):
    """找所有 4 字节等于 value 的位置（文件偏移）。"""
    needle = struct.pack("<I", value)
    out, i = [], 0
    while True:
        i = data.find(needle, i)
        if i < 0:
            return out
        out.append(i)
        i += 1


def cstr(data, off, maxlen=120):
    end = data.find(b"\x00", off)
    if end < 0 or end - off > maxlen:
        return None
    s = data[off:end]
    if not s or any(c < 32 or c > 126 for c in s):
        return None
    return s.decode("ascii", "replace")


def show(path, label, slot):
    data = open(path, "rb").read()
    print(f"\n=== {label} ===")
    print(f"引用槽位 {slot:#x} 的位置:")
    for off in find_refs(data, slot):
        # 判断是否像条目（off 是 file 字段，即条目 +16）
        base = off - 16
        if base < 0:
            continue
        vals = struct.unpack_from("<6I", data, base)
        tag, ver, mode, psid, fptr, iptr = vals
        s = cstr(data, fptr) if fptr < len(data) else None
        t = cstr(data, iptr) if iptr < len(data) else None
        ok = (tag == 0x20000004 and ver == 1 and s and t)
        print(f"  file字段@{off:#06x}  条目@{base:#06x}  tag={tag:#010x} mode={mode:#010x} "
              f"psid={psid:#010x} file={s!r} init={t!r}  {'✔ 条目' if ok else '（非条目）'}")


def plan():
    data = open(A, "rb").read()
    print("\n" + "=" * 78)
    print("a6600 libIMDB 改造方案")
    print("=" * 78)
    slot_str = cstr(data, SLOT)
    print(f"[1] 字符串槽 {SLOT:#06x} 当前 = {slot_str!r}（{len(slot_str)} 字符）")
    new = b"appFwBoot.so\x00"
    print(f"    → 覆写为 {new!r}（{len(new)-1} 字符），剩余 {14 - (len(new)-1)} 字节补零")

    tag, ver, mode, psid, fptr, iptr = struct.unpack_from("<6I", data, ENTRY_APPFW)
    print(f"[2] 入口条目 {ENTRY_APPFW:#06x}:")
    print(f"    psid {psid:#010x} -> 0x00000083")
    print(f"    file {fptr:#06x} '{cstr(data, fptr)}' -> {SLOT:#06x} 'appFwBoot.so'")

    print(f"[3] 需要禁用的 testcmd 条目：见上方引用列表（把该条目 +8 的 mode 清零）")
    print(f"[4] 其余候选禁用项（ZV-E10 曾禁用）：sata_drv / EthernetService / gps / fan / vssapp")


if __name__ == "__main__":
    show(A, "a6600", SLOT)
    show(B, "ZV-1M2", 0x593A)  # ZV-1M2 的 testcmd_scn.so 槽
    plan()
