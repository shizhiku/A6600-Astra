"""imdb4_xrefs.py — 找 libObj 里谁创建 InfraInput 线程 / 谁调用 InfraInput API（只读）。

只读：不运行目标、不修改镜像。
输出：03-证据/静态分析/imdb4/libObj_xrefs.json / libObj_xrefs.txt
用法：python 02-脚本/imdb4_xrefs.py [--full]
"""
import bisect
import io
import json
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_OP_IMM
from elftools.elf.elffile import ELFFile

BASE = Path(__file__).resolve().parents[1]
ABI = BASE / "03-证据/静态分析/97_abi"
EVID = BASE / "03-证据/静态分析/imdb4"
LIBOBJ = ABI / "a6_libObj.so"
LIBMWF = ABI / "a6_libMWF.so"
USRLIB = BASE / "05-原始固件/a6600_fw/usr/lib"

# doc 79/92 已有分析给出的内部（非导出）InfraInput 线程函数地址（偶数地址）
INFRA_THREADS = {
    0x860A68: "InfraInput::EventThread(推测, doc79)",
    0x862430: "InfraInput::MainThread(推测, doc92)",
    0x862D60: "InfraInput::RecvThread(推测, doc92)",
    0x863158: "InfraInput::RepeatThread(推测, doc92)",
}
INFRA_SYMS = [
    "_ZN10InfraInput11GetInstanceEv", "_ZN10InfraInput15ReleaseInstanceEv",
    "_ZN10InfraInput9SetOsalIdEPii",
    "_ZN10InfraInput11SetCallbackEPiPFviP16_InfraInputEventE",
    "_ZN10InfraInput10RmCallbackEi",
    "_ZN10InfraInput14GetEventStatusEiiP16_InfraInputEvent",
    "_ZN10InfraInput17SendEventInitDataEi",
    "_ZN10InfraInput15SetEventKeyListEiP18_InfraInputKeyListi",
    "_ZN10InfraInput14RmEventKeyListEiP18_InfraInputKeyListi",
    "infra_input_init", "infra_input_sus", "infra_input_res", "infra_input_exit",
    "infra_tp_init", "infra_dial_init", "infra_lanc_init", "infra_sircs_init",
    "Selector_init", "infra_indctr_init",
]


class El:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.elf = ELFFile(io.BytesIO(self.data))
        self.segs = [(s["p_vaddr"], s["p_offset"], s["p_filesz"])
                     for s in self.elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        self.dynsym = self.elf.get_section_by_name(".dynsym")
        self.syms = {}
        self.funcs = []
        for s in self.dynsym.iter_symbols():
            if not (s.name and s["st_value"]):
                continue
            v = s["st_value"]
            if s["st_info"]["type"] == "STT_FUNC":
                v &= ~1
                self.funcs.append(v)
            self.syms.setdefault(v, s.name)
        self.sorted_funcs = sorted(set(self.funcs))
        self.plt_to_name = {}
        self._build_plt()

    def off(self, va):
        for vaddr, off, filesz in self.segs:
            if vaddr <= va < vaddr + filesz:
                return off + (va - vaddr)
        return None

    def _build_plt(self):
        """libObj 的 .plt 是 ARM 桩（add ip,pc,#imm; add ip,ip,#imm; ldr pc,[ip,#imm]）。
        桩尺寸不全是 0xC，按 4 字节步进暴力匹配 GOT 槽，得到 桩地址->导入名。"""
        got2name = {}
        for sec in self.elf.iter_sections():
            if sec.name == ".rel.plt":
                for rel in sec.iter_relocations():
                    nm = self.dynsym.get_symbol(rel["r_info_sym"]).name
                    if nm:
                        got2name[rel["r_offset"]] = nm
        plt = self.elf.get_section_by_name(".plt")
        if plt is None:
            return
        start = plt["sh_addr"]
        raw = plt.data()
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        md.detail = True
        for i in range(0, len(raw) - 12, 4):
            addr = start + i
            insns = list(md.disasm(raw[i:i + 12], addr))
            if len(insns) < 3 or insns[0].mnemonic != "add" or \
                    insns[1].mnemonic != "add" or not insns[2].mnemonic.startswith("ldr"):
                continue
            try:
                got = (addr + 8) + insns[0].operands[2].imm + \
                    insns[1].operands[2].imm + insns[2].operands[1].mem.disp
            except (IndexError, AttributeError):
                continue
            if got in got2name:
                self.plt_to_name[addr] = got2name[got]

    def next_func_name(self, va):
        i = bisect.bisect_right(self.sorted_funcs, va)
        if i:
            start = self.sorted_funcs[i - 1]
            return self.syms.get(start, hex(start)), start
        return None, None


def thumb_calls(el, targets, label):
    """按 Thumb-2 BL/BLX 编码直接扫描 .text（不依赖 capstone 线性解码）。"""
    text = el.elf.get_section_by_name(".text")
    va, raw = text["sh_addr"], text.data()
    hits, n = [], 0
    n = len(raw) // 2
    for o in range(0, len(raw) - 3, 2):
        hw1 = raw[o] | (raw[o + 1] << 8)
        if (hw1 & 0xF800) != 0xF000:
            continue
        hw2 = raw[o + 2] | (raw[o + 3] << 8)
        top = hw2 & 0xD000
        if top == 0xD000:
            mn = "bl"
        elif top == 0xC000:
            mn = "blx"
        else:
            continue
        s = (hw1 >> 10) & 1
        imm10 = hw1 & 0x3FF
        j1 = (hw2 >> 13) & 1
        j2 = (hw2 >> 11) & 1
        i1 = (~(j1 ^ s)) & 1
        i2 = (~(j2 ^ s)) & 1
        imm = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | ((hw2 & 0x7FF) << 1)
        if s:
            imm -= 1 << 25
        addr = va + o
        tgt = (addr + 4 + imm) & 0xFFFFFFFF
        if mn == "blx":
            tgt &= ~1
        if tgt in targets:
            fname, faddr = el.next_func_name(addr)
            hits.append({"at": hex(addr), "target": targets[tgt],
                         "target_addr": hex(tgt), "in_func": fname,
                         "func_start": hex(faddr) if faddr else None})
    return hits, n


def scan_imm32_refs(el, values):
    """在 .text/.rodata 中搜 4 字节立即数（字面量池）引用。"""
    out = {}
    for v in values:
        needle = struct.pack("<I", v)
        pos = []
        i = el.data.find(needle)
        while i >= 0:
            pos.append(i)
            i = el.data.find(needle, i + 1)
        out[hex(v)] = [hex(p) for p in pos[:40]]
    return out


def imports_filter(path, keys):
    el = El(path)
    res = {}
    for s in el.dynsym.iter_symbols():
        if s["st_shndx"] != "SHN_UNDEF" or not s.name:
            continue
        if any(k in s.name for k in keys):
            res.setdefault(s.name, []).append(hex(s["st_value"]))
    return res, el


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    report = {}
    obj = El(LIBOBJ)

    # 1) 主符号地址
    syms = {}
    for s in obj.dynsym.iter_symbols():
        if s.name in INFRA_SYMS and s["st_value"]:
            syms[s.name] = s["st_value"] & ~1
    report["infra_symbols"] = {k: hex(v) for k, v in syms.items()}

    # 2) 找 osal_create_waitable_thread 的 PLT 桩
    plt_thread = [a for a, n in obj.plt_to_name.items() if n == "osal_create_waitable_thread"]
    report["plt_osal_create_waitable_thread"] = [hex(a) for a in plt_thread]
    targets = {}
    for a in plt_thread:
        targets[a] = "osal_create_waitable_thread@plt"
    for a, n in obj.plt_to_name.items():
        if n.startswith(("_ZN10InfraInput", "_ZN12InputService")) or \
                n in ("osal_create_waitable_thread", "osal_create_thread", "initializeConfig"):
            targets[a] = n + "@plt"
    # 全 PLT（数据量大，但能给出完整外部调用边；分析时再过滤）
    for a, n in obj.plt_to_name.items():
        targets.setdefault(a, n + "@plt")
    for k, v in syms.items():
        targets[v] = k
    for a, n in INFRA_THREADS.items():
        targets[a] = n
    report["plt_targets"] = {hex(a): n for a, n in targets.items()}

    # 3) 全 .text BL/BLX 扫描
    hits, ninsn = thumb_calls(obj, targets, "libobj")
    report["text_insn_scanned"] = ninsn
    report["call_hits"] = hits

    # 4) InfraInput 线程函数地址的字面量引用（函数指针传递）
    thread_addrs = list(INFRA_THREADS) + [v | 1 for v in INFRA_THREADS]
    report["thread_addr_imm_refs"] = scan_imm32_refs(obj, thread_addrs)

    # 5) .init_array 里有没有落在 InfraInput 区域的构造器
    ia = None
    for secname in (".init_array",):
        sec = obj.elf.get_section_by_name(secname)
        if sec is not None:
            ia = sec
            break
    init_array = []
    if ia is not None:
        va = ia["sh_addr"]
        raw = ia.data()
        for i in range(0, len(raw) - 3, 4):
            v = struct.unpack_from("<I", raw, i)[0]
            init_array.append(v)
    report["init_array_count"] = len(init_array)
    report["init_array_in_infra_area"] = [
        hex(v & ~1) for v in init_array if 0x840000 <= (v & ~1) <= 0x870000]

    # 6) 4 代 libMWF / libmpr 对 InfraInput/InputService 的 UND 引用
    for p in (LIBMWF, USRLIB / "libmpr.so", ABI / "a6_libObj.so"):
        if not p.exists():
            continue
        try:
            imp, _ = imports_filter(p, ("InfraInput", "InputService", "infra_input",
                                        "Selector", "infra_tp", "infra_dial"))
            report[f"imports::{Path(p).name}"] = imp
        except Exception as e:  # noqa: BLE001
            report[f"imports::{Path(p).name}"] = f"ERROR {e}"

    # 7) 所有 4 代 usr lib 里 “infra_input_init” 字符串的出现（dlsym by name）
    name_hits = {}
    for p in sorted(list(USRLIB.glob("*.so")) + list(USRLIB.glob("*.so.*"))):
        try:
            blob = p.read_bytes()
        except OSError:
            continue
        c = blob.count(b"infra_input_init")
        if c:
            name_hits[p.name] = c
    for p in (ABI / "a6usr_im.elf", ABI / "a6usr_libIMDB.so", ABI / "a6_libObj.so"):
        if p.exists():
            c = p.read_bytes().count(b"infra_input_init")
            if c:
                name_hits[p.name] = c
    report["infra_input_init_name_refs"] = name_hits

    EVID.mkdir(parents=True, exist_ok=True)
    # 只保留与输入触发点直接相关的命中，并按 (调用者, 目标) 去重，避免证据文件过大
    trigger_names = ("InfraInput", "osal_create_waitable_thread", "osal_create_thread",
                     "initializeConfig", "core_sync_set_event", "toInstanceAC",
                     "InputService8activateEbjm", "InputService16UpdateInputTableEv",
                     "StatMgr11ChangeStateEjjPvj", "InfraDial20SetDialEventIntervalEhhh",
                     "infra_input_init", "infra_tp_init", "infra_dial_init",
                     "infra_lanc_init", "infra_sircs_init", "Selector_init",
                     "infra_indctr_init", "infra_hotshoe_init")
    filtered, seen = [], set()
    for h in hits:
        if not any(k in h["target"] for k in trigger_names):
            continue
        key = (h["in_func"], h["target"])
        if key in seen:
            continue
        seen.add(key)
        filtered.append(h)
    report["call_hits"] = filtered
    report["call_hits_total"] = len(hits)
    report["plt_targets"] = {k: v for k, v in report["plt_targets"].items()
                             if any(x in v for x in trigger_names)}
    (EVID / "libObj_xrefs.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    lines = ["# libObj InfraInput xrefs",
             f"# symbols: {json.dumps(report['infra_symbols'], ensure_ascii=False)}",
             f"# plt osal_create_waitable_thread: {report['plt_osal_create_waitable_thread']}",
             f"# text instructions scanned: {ninsn}  call hits total: {len(hits)}"
             f"  (filtered: {len(filtered)})",
             "",
             "## call hits (输入/线程相关)"]
    for h in filtered:
        lines.append(f"{h['at']} -> {h['target']} ({h['target_addr']}) in {h['in_func']}")
    lines.append("")
    lines.append("## init_array in infra area: " +
                 ", ".join(report["init_array_in_infra_area"]))
    lines.append("")
    lines.append("## thread function address literals: " +
                 json.dumps(report["thread_addr_imm_refs"], ensure_ascii=False))
    lines.append("")
    lines.append("## imports: " + json.dumps(
        {k: v for k, v in report.items() if k.startswith("imports::")},
        ensure_ascii=False, indent=1))
    lines.append("## infra_input_init string refs: " +
                 json.dumps(name_hits, ensure_ascii=False))
    (EVID / "libObj_xrefs.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[ok] scanned {ninsn} insns, {len(hits)} call hits")
    for h in hits:
        print(f"  {h['at']} -> {h['target']} in {h['in_func']}")
    print("[ok] init_array in infra area:", report["init_array_in_infra_area"])
    print("[ok] imports:", json.dumps({k: len(v) if isinstance(v, dict) else v
                                       for k, v in report.items() if k.startswith("imports::")}))
    print("[ok] infra_input_init name refs:", name_hits)


if __name__ == "__main__":
    main()
