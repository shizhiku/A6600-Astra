"""imdb4_parse.py — 解析四代 a6600 libIMDB 模块表（README 见 01-文档/111）。

只读分析：不运行目标、不修改任何镜像或既有脚本。
输入：
  03-证据/静态分析/97_abi/a6usr_libIMDB.so        原版 4 代 libIMDB（SHA 0579...）
  03-证据/静态分析/97_abi/97_abi_libIMDB_appboot.so  我们 patched 过的 4 代 libIMDB（SHA e503...）
  03-证据/静态分析/imdb4/imdb_from_astra-m1-rwx2.img.so  从 m1-verified 镜像 /lib/libIMDB.so 提取的副本
输出：
  03-证据/静态分析/imdb4/imdb4_records_<label>.json   全部记录（index/offset/VA/字段/字符串）
  03-证据/静态分析/imdb4/imdb4_records_summary.txt     人读摘要 + 输入关键字命中
用法：
  python 02-脚本/imdb4_parse.py
"""
import hashlib
import io
import json
import re
import struct
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

BASE = Path(__file__).resolve().parents[1]
EVID = BASE / "03-证据/静态分析/imdb4"
ABI = BASE / "03-证据/静态分析/97_abi"

STRIDE = 44          # 记录固定 44 字节 = 11 x u32
HEADER_LEN = 132     # imdb_raw 头部 132 字节；IMDB_get_entries 返回 raw+132
TERMINATOR = 40      # type 40 (0x28) 为终止项

INPUT_KEYWORDS = (
    "input", "dial", "tp", "lanc", "sircs", "selector", "indctr",
    "key", "btn", "button", "touch", "evt", "event", "irq", "gpio",
    "remote", "ir_", "_ir", "usb", "hid",
)
# 精确一些的输入子系统关键字（用于报告分类）
INPUT_STRICT = (
    "infra_input", "InfraInput", "infra_tp", "InfraTp", "infra_dial", "InfraDial",
    "infra_sircs", "InfraLircs", "infra_lanc", "InfraLanc", "Selector",
    "indctr", "InputService", "key_status", "input_", "_input", "dial_", "tp_init",
)


def sha256(b):
    return hashlib.sha256(b).hexdigest()


class IMDB:
    """按 PT_LOAD 段做 VA<->文件偏移映射，解析 imdb_raw 处的记录表。"""

    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.sha = sha256(self.data)
        self.elf = ELFFile(io.BytesIO(self.data))
        self.segs = []
        for s in self.elf.iter_segments():
            if s["p_type"] != "PT_LOAD":
                continue
            self.segs.append((s["p_vaddr"], s["p_offset"], s["p_filesz"]))
        self.imdb_raw = self.sym_value("imdb_raw")

    def sym_value(self, name):
        dyn = self.elf.get_section_by_name(".dynsym")
        if dyn is None:
            return None
        for s in dyn.iter_symbols():
            if s.name == name:
                return s["st_value"]
        return None

    def off_of(self, va):
        for vaddr, off, filesz in self.segs:
            if vaddr <= va < vaddr + filesz:
                return off + (va - vaddr)
        return None

    def read(self, va, n):
        o = self.off_of(va)
        if o is None:
            return b""
        return self.data[o:o + n]

    def cstr(self, va, maxlen=160):
        o = self.off_of(va)
        if o is None or o >= len(self.data):
            return None
        end = self.data.find(b"\x00", o, o + maxlen + 1)
        if end < 0:
            return None
        raw = self.data[o:end]
        if not raw:
            return None
        if any(b < 32 or b > 126 for b in raw):
            return None
        return raw.decode("ascii")

    def parse(self):
        raw = self.imdb_raw
        header = list(struct.unpack("<33I", self.read(raw, HEADER_LEN)))
        header_strings = {}
        for i, w in enumerate(header):
            s = self.cstr(w) if w else None
            if s:
                header_strings[i * 4] = s
        records = []
        for i in range(1000):
            va = raw + HEADER_LEN + STRIDE * i
            b = self.read(va, STRIDE)
            if len(b) < STRIDE:
                break
            w = list(struct.unpack("<11I", b))
            strings = {}
            for j, v in enumerate(w):
                if v == 0:
                    continue
                s = self.cstr(v)
                if s:
                    strings[j * 4] = s
            rec = {
                "index": i,
                "va": va,
                "file_offset": self.off_of(va),
                "tag": w[0],
                "version": w[1],
                "mode": w[2],
                "psid_word": w[3],
                "me_psid": w[3] & 0xFFFF,
                "flags16": (w[3] >> 16) & 0xFFFF,
                "u16_off8": struct.unpack_from("<H", b, 8)[0],
                "u16_off10": struct.unpack_from("<H", b, 10)[0],
                "u16_off12": struct.unpack_from("<H", b, 12)[0],
                "u16_off14": struct.unpack_from("<H", b, 14)[0],
                "words": w,
                "words_hex": [hex(v) for v in w],
                "strings": {str(k): v for k, v in strings.items()},
                "raw_hex": b.hex(" "),
            }
            records.append(rec)
            if w[0] == TERMINATOR:
                break
        return {"path": str(self.path), "sha256": self.sha, "imdb_raw": raw,
                "header_words": [hex(v) for v in header],
                "header_strings": header_strings, "records": records}


def is_inputish(rec):
    text = rec["file"] + " " + rec["init"] + " " + rec["other_strings"]
    low = text.lower()
    return any(k.lower() in low for k in INPUT_KEYWORDS)


def display(rec):
    """补上 file/init/其他字符串的便利字段。"""
    s = rec["strings"]
    rec["file"] = s.get("16", "")
    rec["init"] = s.get("20", "")
    rec["other_strings"] = " | ".join(
        f"+{k}:{v}" for k, v in s.items() if k not in ("16", "20"))
    rec["inputish"] = is_inputish(rec)
    rec["input_strict"] = [k for k in INPUT_STRICT
                           if k.lower() in (rec["file"] + " " + rec["init"]
                                            + " " + rec["other_strings"]).lower()]
    return rec


def tag_name(tag):
    names = {
        0x1: "type1-??",
        0x3: "type3-env",
        0x28: "type40-END",
        0x10000001: "type1.1",
        0x10000002: "type1.2",
        0x20000001: "type2.1",
        0x20000002: "type2.2",
        0x20000003: "type2.3",
        0x20000004: "type2.4-Application",
        0x40000001: "type4.1-msg",
    }
    return names.get(tag, "?")


def main():
    EVID.mkdir(parents=True, exist_ok=True)
    targets = [
        ("orig", ABI / "a6usr_libIMDB.so"),
        ("patched", ABI / "97_abi_libIMDB_appboot.so"),
        ("image_rwx2", EVID / "imdb_from_astra-m1-rwx2.img.so"),
        ("gen5_zv", ABI / "zvusr_libIMDB.so"),
    ]
    summary = []
    for label, path in targets:
        if not path.exists():
            print(f"[skip] {label}: {path} 不存在")
            continue
        im = IMDB(path)
        parsed = im.parse()
        recs = [display(r) for r in parsed["records"]]
        parsed["record_count"] = len(recs)
        parsed["tag_histogram"] = {}
        for r in recs:
            t = hex(r["tag"])
            parsed["tag_histogram"][t] = parsed["tag_histogram"].get(t, 0) + 1
        out = EVID / f"imdb4_records_{label}.json"
        out.write_text(json.dumps(parsed, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"\n=== {label}: {path.name}  sha256={parsed['sha256']}")
        print(f"    imdb_raw=0x{parsed['imdb_raw']:x}  记录数={len(recs)}  "
              f"tag 分布={parsed['tag_histogram']}")
        print(f"    -> {out}")

        lines = [f"# {label}  {path}",
                 f"# sha256={parsed['sha256']}  imdb_raw=0x{parsed['imdb_raw']:x}  "
                 f"记录数={len(recs)}", "",
                 f"{'idx':>4} {'file_off':>9} {'VA':>9} {'tag':>10} {'ver':>4} "
                 f"{'mode':>10} {'psid':>6} {'fl16':>6}  {'file':<28} init / 其他字符串"]
        for r in recs:
            lines.append(
                f"{r['index']:>4} {r['file_offset']:#09x} {r['va']:#09x} "
                f"{r['tag']:#010x} {r['version']:>4} {r['mode']:#010x} "
                f"{r['me_psid']:>6} {r['flags16']:>6}  {r['file']:<28} {r['init']}")
            if r["other_strings"]:
                lines.append(f"{'':>62} 其他: {r['other_strings']}")
        summary.append("\n".join(lines))

        hits = [r for r in recs if r["inputish"]]
        print(f"    输入关键字命中 {len(hits)} 条:")
        for r in hits:
            print(f"      idx={r['index']:>3} off={r['file_offset']:#07x} "
                  f"tag={r['tag']:#010x} mode={r['mode']:#010x} "
                  f"file={r['file']!r} init={r['init']!r}"
                  + (f" 其他={r['other_strings']}" if r["other_strings"] else ""))
    (EVID / "imdb4_records_summary.txt").write_text(
        "\n\n".join(summary) + "\n", encoding="utf-8")
    print(f"\n[ok] 摘要 -> {EVID / 'imdb4_records_summary.txt'}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
