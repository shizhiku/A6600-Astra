"""imdb4_reach.py — 从四代 IMDB 记录入口出发，反向追踪谁创建了 InfraInput（只读）。

只读：不运行目标、不修改镜像。做法：
  1) 用 .ARM.exidx 解析 libObj 全部 59k 个函数起点（比导出符号精确）；
  2) 完整解析 .plt（含本地符号桩：读 GOT 初值匹配符号），得到 桩->符号 映射；
  3) 扫描 .text 里全部 Thumb-2 BL/BLX，建立 函数->函数 / 函数->导入符号 调用图；
  4) 从 InfraInput::GetInstance 的调用点反向 BFS，找出哪些四代 IMDB 记录 init 入口能到达它。
输出：03-证据/静态分析/imdb4/libObj_reach.json / libObj_reach.txt
用法：python 02-脚本/imdb4_reach.py
"""
import bisect
import io
import json
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BASE = Path(__file__).resolve().parents[1]
ABI = BASE / "03-证据/静态分析/97_abi"
EVID = BASE / "03-证据/静态分析/imdb4"
LIBOBJ = ABI / "a6_libObj.so"
from elftools.elf.elffile import ELFFile


class Obj:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.elf = ELFFile(io.BytesIO(self.data))
        self.segs = [(s["p_vaddr"], s["p_offset"], s["p_filesz"])
                     for s in self.elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        self.dynsym = self.elf.get_section_by_name(".dynsym")
        self.syms = {}
        self.func_syms = {}
        for s in self.dynsym.iter_symbols():
            if not (s.name and s["st_value"]):
                continue
            v = s["st_value"]
            self.syms.setdefault(v, s.name)
            if s["st_info"]["type"] == "STT_FUNC":
                self.func_syms[v & ~1] = s.name
        self._exidx()
        self._plt()

    def off(self, va):
        for vaddr, off, filesz in self.segs:
            if vaddr <= va < vaddr + filesz:
                return off + (va - vaddr)
        return None

    def _exidx(self):
        sec = self.elf.get_section_by_name(".ARM.exidx")
        raw, base = sec.data(), sec["sh_addr"]
        starts = set()
        for i in range(0, len(raw) - 7, 8):
            w = struct.unpack_from("<I", raw, i)[0]
            if not w:
                continue
            v = w & 0x7FFFFFFF
            if v & 0x40000000:
                v -= 0x80000000
            starts.add((base + i + v) & 0xFFFFFFFF)
        self.func_starts = sorted(starts)
        self.func_set = set(starts)

    def func_of(self, va):
        i = bisect.bisect_right(self.func_starts, va) - 1
        return self.func_starts[i] if i >= 0 else None

    def name_of(self, va):
        """函数起点附近的名字：优先精确导出名，否则最近导出名+偏移。"""
        va &= ~1
        if va in self.func_syms:
            return self.func_syms[va]
        keys = sorted(self.func_syms)
        i = bisect.bisect_right(keys, va) - 1
        if i < 0:
            return None
        k = keys[i]
        return f"{self.func_syms[k]}+{va - k:#x}"

    def _plt(self):
        """枚举 .plt 桩：addr -> (kind, name_or_addr)。
        .rel.plt 里既有真正导入，也有可抢占的本地导出符号；后者要连回函数体。"""
        got2name = {}
        for sec in self.elf.iter_sections():
            if sec.name == ".rel.plt":
                for rel in sec.iter_relocations():
                    nm = self.dynsym.get_symbol(rel["r_info_sym"]).name
                    if nm:
                        got2name[rel["r_offset"]] = nm
        defined = {}
        for s in self.dynsym.iter_symbols():
            if s.name and s["st_value"] and s["st_shndx"] != "SHN_UNDEF":
                defined.setdefault(s.name, s["st_value"] & ~1)
        # 本地符号的 PLT 桩 GOT 初值在文件里就是符号地址
        addr2name = {}
        plt = self.elf.get_section_by_name(".plt")
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        md.detail = True
        raw = plt.data()
        start = plt["sh_addr"]
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
                nm = got2name[got]
                if nm in defined:
                    addr2name[addr] = ("local", defined[nm])
                else:
                    addr2name[addr] = ("ext", nm)
                continue
            o = self.off(got)
            if o is None or o + 4 > len(self.data):
                continue
            init = struct.unpack_from("<I", self.data, o)[0]
            tgt = init & ~1
            if tgt in self.func_syms:
                addr2name[addr] = ("local", tgt)
        self.plt_map = addr2name


def iter_bl(obj):
    text = obj.elf.get_section_by_name(".text")
    va, raw = text["sh_addr"], text.data()
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
            tgt &= ~3
        yield addr, tgt


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    obj = Obj(LIBOBJ)
    print(f"[i] exidx 函数起点 {len(obj.func_starts)}, plt 桩 {len(obj.plt_map)}")

    # 调用图：caller_fn -> set(callee_node)
    edges, rev = {}, {}
    nbl = 0
    for addr, tgt in iter_bl(obj):
        caller = obj.func_of(addr)
        if caller is None:
            continue
        if tgt in obj.plt_map:
            kind, name = obj.plt_map[tgt]
            callee = name if kind == "local" else "ext:" + name
        elif (tgt & ~1) in obj.func_set:
            callee = tgt & ~1
        else:
            continue
        nbl += 1
        edges.setdefault(caller, set()).add(callee)
        rev.setdefault(callee, set()).add(caller)
    print(f"[i] BL/BLX 调用边 {nbl}")

    # InfraInput::GetInstance 的调用点函数
    getinst = None
    for v, n in obj.func_syms.items():
        if n == "_ZN10InfraInput11GetInstanceEv":
            getinst = v
    ctor = obj.func_of(0x860554)
    getinst_callers = sorted(rev.get("ext:_ZN10InfraInput11GetInstanceEv", set()))
    # 直接 BL 到 GetInstance 的情况也并入
    getinst_callers += [c for c in rev.get(getinst, set()) if c not in getinst_callers]
    report = {"libobj": str(LIBOBJ), "func_starts": len(obj.func_starts),
              "plt_stubs": len(obj.plt_map), "bl_edges": nbl,
              "getinstance": hex(getinst) if getinst else None,
              "getinstance_callers": [
                  {"fn": hex(c), "name": obj.name_of(c)} for c in getinst_callers],
              "ctor_860554_name": obj.name_of(ctor) if ctor else None}

    # IMDB 记录 init 入口（只取 libObj 里存在的导出名）
    entries = {}
    recs = json.loads((EVID / "imdb4_records_patched.json").read_text(encoding="utf-8"))
    for r in recs["records"]:
        init = r["strings"].get("20")
        if not init:
            continue
        # 记录 me 与记录号一起保留，便于报告
        for v, n in obj.func_syms.items():
            if n == init:
                entries.setdefault(init, []).append(r["index"])
                entries[init] = entries[init]
                break
    entry_addr = {}
    for v, n in obj.func_syms.items():
        if n in entries:
            entry_addr.setdefault(v, n)
    report["imdb_init_entries_in_libobj"] = {
        n: {"va": hex(v), "record_indexes": entries[n]} for v, n in entry_addr.items()}

    # 反向 BFS：从 GetInstance 调用点函数回溯到 IMDB init 入口
    targets = set(getinst_callers)
    # 反向边：callee -> callers。ext 节点反向：ext:name -> callers
    def rev_of(node):
        return rev.get(node, set())

    results = []
    for t in targets:
        # BFS from t backwards
        from collections import deque
        prev = {t: None}
        q = deque([t])
        found = []
        while q:
            cur = q.popleft()
            if cur in entry_addr:
                # reconstruct
                path = []
                x = cur
                while x is not None:
                    path.append(x)
                    x = prev[x]
                results.append({"target": {"fn": hex(t), "name": obj.name_of(t)},
                                "entry": {"fn": hex(cur), "name": obj.name_of(cur),
                                          "record_indexes": entries[obj.name_of(cur)]},
                                "path": [(hex(p), obj.name_of(p)) for p in path][:30]})
            for p in rev_of(cur):
                if p not in prev:
                    prev[p] = cur
                    q.append(p)
    report["reverse_paths"] = results

    # 正查：从每个 IMDB init 入口出发，GetInstance 是否可达（含深度）
    fwd_results = []
    for v, n in sorted(entry_addr.items(), key=lambda kv: kv[1]):
        from collections import deque
        dist = {v: 0}
        q = deque([v])
        hit = None
        while q:
            cur = q.popleft()
            if cur in targets and hit is None:
                hit = cur
            if dist[cur] > 40:
                continue
            for c in edges.get(cur, ()):
                if isinstance(c, int) and c not in dist:
                    dist[c] = dist[cur] + 1
                    q.append(c)
        fwd_results.append({"entry": n, "va": hex(v), "records": entries[n],
                            "reaches_getinstance": bool(hit),
                            "at": obj.name_of(hit) if hit else None})
    report["forward_from_imdb_inits"] = fwd_results

    EVID.mkdir(parents=True, exist_ok=True)
    (EVID / "libObj_reach.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    lines = ["# libObj reachability (IMDB init -> InfraInput::GetInstance)",
             f"# func_starts={len(obj.func_starts)} plt={len(obj.plt_map)} bl={nbl}",
             f"# InfraInput::GetInstance = {hex(getinst) if getinst else None}",
             "", "## GetInstance 调用点所在函数:"]
    for item in report["getinstance_callers"]:
        lines.append(f"  {item['fn']}  {item['name']}")
    lines.append("")
    lines.append("## IMDB init 入口(在 libObj 内):")
    for n, d in report["imdb_init_entries_in_libobj"].items():
        lines.append(f"  {d['va']}  {n}  records={d['record_indexes']}")
    lines.append("")
    lines.append("## 反向路径（GetInstance 调用点 <- ... <- IMDB init 入口）:")
    for r in results:
        lines.append(f"  target {r['target']['fn']} {r['target']['name']}"
                     f"  <= entry {r['entry']['name']} records={r['entry']['record_indexes']}")
        lines.append("      " + " <- ".join(f"{a}({b})" for a, b in r["path"]))
    lines.append("")
    lines.append("## 从 IMDB init 正向可达 GetInstance:")
    for f in fwd_results:
        lines.append(f"  {f['entry']:<34} reach={f['reaches_getinstance']} at={f['at']}")
    (EVID / "libObj_reach.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[ok] GetInstance callers: {len(getinst_callers)}")
    for item in report["getinstance_callers"]:
        print("   ", item["fn"], item["name"])
    print(f"[ok] 反向路径 {len(results)} 条 -> {EVID/'libObj_reach.txt'}")
    for r in results:
        print(f"   {r['entry']['name']} records={r['entry']['record_indexes']}"
              f" -> {r['target']['name']}")


if __name__ == "__main__":
    main()
