"""imdb4_entry_check.py — 验证四代 IMDB 记录 31 的调用链（只读静态分析）。

只读：不运行目标、不修改镜像。用 capstone 反汇编 libObj.so 中 InfraInput/InputService
生命周期函数与 im.elf 的 tag 分发函数，形成可引用的证据。

输入：
  03-证据/静态分析/97_abi/a6_libObj.so        四代 libObj（20,889,004 B）
  03-证据/静态分析/97_abi/a6usr_im.elf        四代 im.elf
  03-证据/静态分析/97_abi/a6_im_thumb.txt     objdump -d 的 Thumb 反汇编（既有证据）
  03-证据/静态分析/imdb4/imdb4_records_patched.json
输出：
  03-证据/静态分析/imdb4/libObj_input_lifecycle_disasm.txt
  03-证据/静态分析/imdb4/imelf_dispatch_excerpt.txt
  03-证据/静态分析/imdb4/imdb4_entry_check.json
用法：
  python 02-脚本/imdb4_entry_check.py
"""
import io
import json
import re
import struct
import sys
from pathlib import Path

from capstone import (Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_OP_IMM, CS_OP_MEM,
                      CS_OP_REG)
from elftools.elf.elffile import ELFFile

BASE = Path(__file__).resolve().parents[1]
ABI = BASE / "03-证据/静态分析/97_abi"
EVID = BASE / "03-证据/静态分析/imdb4"

LIBOBJ = ABI / "a6_libObj.so"
IMELF = ABI / "a6usr_im.elf"
THUMB_TXT = ABI / "a6_im_thumb.txt"

STOP_TAILS = (b"\x00\x00", b"\x00\xbf", b"\xaf\xf3\x00\x80", b"\x00\xf0\x20\xe3")


class El:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.elf = ELFFile(io.BytesIO(self.data))
        self.segs = [(s["p_vaddr"], s["p_offset"], s["p_filesz"])
                     for s in self.elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        self.syms = {}
        self.funcs = []
        for secname in (".dynsym", ".symtab"):
            sec = self.elf.get_section_by_name(secname)
            if sec is None:
                continue
            for s in sec.iter_symbols():
                if not (s.name and s["st_value"]):
                    continue
                val = s["st_value"]
                if s["st_info"]["type"] == "STT_FUNC":
                    val &= ~1
                    self.funcs.append(val)
                self.syms.setdefault(val, s.name)
        self.sorted_syms = sorted(self.syms)
        self.sorted_funcs = sorted(set(self.funcs))
        self.plt = {}
        dyn = self.elf.get_section_by_name(".dynsym")
        for sec in self.elf.iter_sections():
            if sec.name == ".rel.plt":
                for rel in sec.iter_relocations():
                    name = dyn.get_symbol(rel["r_info_sym"]).name
                    if name:
                        self.plt[rel["r_offset"]] = name

    def off(self, va):
        for vaddr, off, filesz in self.segs:
            if vaddr <= va < vaddr + filesz:
                return off + (va - vaddr)
        return None

    def cstr(self, va, n=160):
        o = self.off(va)
        if o is None:
            return None
        end = self.data.find(b"\0", o, o + n)
        if end < 0:
            return None
        raw = self.data[o:end]
        if not raw or any(b < 32 or b > 126 for b in raw):
            return None
        return raw.decode("ascii")

    def next_func(self, va):
        import bisect
        i = bisect.bisect_right(self.sorted_funcs, va)
        return self.sorted_funcs[i] if i < len(self.sorted_funcs) else None


def disasm_func(el, va, limit=0x800, max_insn=500):
    """反汇编 [va, min(下一个函数符号, va+limit))；遇到函数尾+对齐填充即停。"""
    va &= ~1
    o = el.off(va)
    if o is None:
        return [], []
    end = va + limit
    nf = el.next_func(va)
    if nf and 16 < nf - va <= limit:
        end = nf
    code = el.data[o:o + (end - va)]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    out, calls = [], []
    for insn in md.disasm(code, va):
        out.append(insn)
        if insn.operands:
            for op in insn.operands:
                if op.type == CS_OP_IMM and insn.mnemonic.startswith(("bl", "b")):
                    tgt = op.imm
                    calls.append((insn.address, insn.mnemonic, tgt,
                                  el.plt.get(tgt) or el.syms.get(tgt)))
                    break
        tailish = (insn.mnemonic.startswith("pop") or insn.mnemonic.startswith("ldm")
                   or insn.mnemonic == "bx") and "pc" in insn.op_str
        if insn.mnemonic.startswith("b.") or insn.mnemonic in ("b", "b.w"):
            tailish = True
        if tailish:
            nxt = insn.address + insn.size
            o2 = el.off(nxt)
            tail = el.data[o2:o2 + 4] if o2 is not None else b""
            if tail[:2] in STOP_TAILS or tail in STOP_TAILS:
                break
        if len(out) >= max_insn:
            break
    return out, calls


def fmt_disasm(insns, title):
    lines = [f"=== {title} ==="]
    for i in insns:
        lines.append(f"{i.address:#010x}: {i.bytes.hex():<12} {i.mnemonic:<8} {i.op_str}")
    return "\n".join(lines)


def pc_rel_strings(el, insns):
    """解析 ldr rX,[pc,#imm] 后 add rX,pc 的字符串基址（Thumb 字面量池）。"""
    res, last = [], {}
    for i in insns:
        ops = i.operands
        if i.mnemonic.startswith("ldr") and len(ops) >= 2 and ops[1].type == CS_OP_MEM \
                and ops[1].mem.base != 0 and i.reg_name(ops[1].mem.base) == "pc":
            lt = ((i.address + 4) & ~3) + ops[1].mem.disp
            o = el.off(lt)
            if o is not None:
                last[ops[0].reg] = struct.unpack_from("<I", el.data, o)[0]
        if i.mnemonic.startswith("add") and i.operands:
            rd = i.operands[0]
            if rd.type == CS_OP_REG and rd.reg in last:
                # add rX, pc
                src = i.operands[1] if len(i.operands) > 1 else None
                if src is not None and src.type == CS_OP_REG and i.reg_name(src.reg) == "pc":
                    tgt = last[rd.reg] + ((i.address + 4) & ~3)
                    s = el.cstr(tgt)
                    res.append((i.address, tgt, s))
    return res


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    EVID.mkdir(parents=True, exist_ok=True)
    libobj = El(LIBOBJ)
    imelf = El(IMELF)

    targets = ["infra_input_init", "infra_input_sus", "infra_input_res",
               "infra_input_exit", "infra_tp_init", "infra_tp_sus", "infra_tp_res",
               "infra_dial_init", "infra_lanc_init", "infra_sircs_init",
               "Selector_init", "infra_indctr_init", "infra_hotshoe_init",
               "_ZN10InfraInput11GetInstanceEv", "_ZN10InfraInput15GetInstanceEPv",
               "_ZN10InfraInput15ReleaseInstanceEv", "_ZN10InfraInput11SetCallbackEPiPFviP16_InfraInputEventE",
               "_ZN10InfraInput9SetOsalIdEPii", "_ZN10InfraInput14GetEventStatusEiiP16_InfraInputEvent",
               "_ZN12InputService8activateEbjm", "_ZN12InputService11createEventEmh",
               "_ZN12InputService15pushFilterEventEP5Event",
               "snd_InfraInputEvent_to_InputServant", "Application_System_Init"]
    # 内部辅助函数（无导出名，由 init 函数调用）
    extra = {"internal_104db0": 0x104db0, "internal_103c5c": 0x103c5c,
             "internal_100130": 0x100130}
    sym_by_name = {}
    for va, name in libobj.syms.items():
        if name in targets:
            sym_by_name.setdefault(name, va)
    report = {"libobj": str(LIBOBJ), "imelf": str(IMELF),
              "libobj_symbols": {k: hex(v) for k, v in sym_by_name.items()},
              "extra_symbols": {k: hex(v) for k, v in extra.items()},
              "functions": {}, "input_init_config_strings": {}}
    blocks = []
    for name in list(sym_by_name) + list(extra):
        va = sym_by_name.get(name, extra.get(name))
        if va is None:
            continue
        insns, calls = disasm_func(libobj, va)
        blocks.append(fmt_disasm(insns, f"libObj 0x{va:x}  {name}"))
        call_txt = []
        for addr, mn, tgt, nm in calls:
            call_txt.append(f"  {addr:#010x} {mn} -> {tgt:#010x} "
                            f"{('PLT:' + nm) if nm and tgt in libobj.plt else (nm or '')}")
        blocks.append("  calls:\n" + "\n".join(call_txt))
        strings = pc_rel_strings(libobj, insns)
        if strings:
            blocks.append("  pc-relative strings:\n" + "\n".join(
                f"  {a:#010x} -> {v:#010x} {s!r}" for a, v, s in strings))
        report["functions"][name] = {
            "va": hex(va), "insn_count": len(insns),
            "calls": [{"at": hex(a), "mnemonic": mn, "target": hex(t),
                       "name": nm, "is_plt": t in libobj.plt} for a, mn, t, nm in calls],
            "pc_strings": [{"at": hex(a), "va": hex(v), "text": s} for a, v, s in strings],
        }
        if "init" in name and "infra" in name:
            report["input_init_config_strings"][name] = [s for _, _, s in strings if s]
    (EVID / "libObj_input_lifecycle_disasm.txt").write_text(
        "\n\n".join(blocks) + "\n", encoding="utf-8")

    # ---- im.elf 关键函数摘录（从既有 objdump Thumb 文本截取） ----
    txt = THUMB_TXT.read_text(encoding="utf-8", errors="replace")
    funcs = {"b5ec": ("条目扫描/过滤（flag&线程掩码、target&目标位）", 0x180),
             "b200": ("0x20000001/02/03 模块启动：psid!=0 -> dlopen(libObj)", 0x90),
             "b3dc": ("tag 分发入口", 0x100),
             "b14c": ("0x20000004 Application 启动：psid!=0 -> dlopen(NULL)", 0xb0),
             "b694": ("扫描包装（线程掩码=0xFF）", 0x12),
             "9a5c": ("启动相位状态机（按 IMSSI 消息推进 tag 边界）", 0x1c0),
             "94f8": ("THREAD_APP：扫描 tag7..tag8（Application 记录）", 0xa0),
             "954c": ("THREAD_INFRA0/1/2：扫描 tag5..tag7", 0x90)}
    lines = txt.splitlines()
    addr_re = re.compile(r"^\s*([0-9a-f]{4}):\s")
    excerpt = ["# im.elf (a6usr_im.elf) Thumb 反汇编摘录：来源 97_abi/a6_im_thumb.txt",
               "# 由 02-脚本/imdb4_entry_check.py 生成；地址为 VA。", ""]
    imelf_map = {}
    for key, (desc, span) in funcs.items():
        va = int(key, 16)
        sel = []
        for ln in lines:
            m = addr_re.match(ln)
            if not m:
                continue
            a = int(m.group(1), 16)
            if va <= a < va + span:
                sel.append(ln)
        excerpt.append(f"=== 0x{va:x}  {desc} （{len(sel)} 条） ===")
        excerpt.extend(sel)
        excerpt.append("")
        imelf_map[key] = {"va": hex(va), "desc": desc, "lines": len(sel)}
    (EVID / "imelf_dispatch_excerpt.txt").write_text("\n".join(excerpt) + "\n",
                                                     encoding="utf-8")

    recs = json.loads((EVID / "imdb4_records_patched.json").read_text(encoding="utf-8"))
    r31 = recs["records"][31]
    report["record31"] = {k: r31[k] for k in ("index", "va", "file_offset", "tag",
                                              "version", "mode", "psid_word", "me_psid",
                                              "flags16", "strings", "words_hex")}
    report["imelf_funcs"] = imelf_map
    (EVID / "imdb4_entry_check.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[ok] libObj 符号: {json.dumps(report['libobj_symbols'], ensure_ascii=False)}")
    print(f"[ok] init 配置字符串: {report['input_init_config_strings']}")
    print(f"[ok] 输出: {EVID/'libObj_input_lifecycle_disasm.txt'}")


if __name__ == "__main__":
    main()
