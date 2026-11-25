"""Read-only relocation-aware evidence dump for input/liro/osal proc nodes."""
from pathlib import Path
from io import BytesIO
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "input": (ROOT / "03-证据/静态分析/input_sen/input.ko", ["kbd_probe"]),
    "liro": (ROOT / "03-证据/静态分析/liro-fault-static/liro.ko", ["liro_init", "liro_proc_init", "liro_proc_exit", "liro_create_entry", "proc_suspend", "proc_delay_write"]),
    "osal": (ROOT / "03-证据/静态分析/input_sen/osal_uipc.ko", ["k_osal_init", "k_uipc_init", "__k_minfo_proc_read", "__k_uipc_proc_read", "__k_uipc_proc_write", "msgq_dump", "bsem_dump"]),
}
OUT = ROOT / "03-证据/静态分析/84_proc_static.txt"


def cstr(data, offset):
    if not (0 <= offset < len(data)):
        return None
    raw = data[offset:].split(b"\0", 1)[0]
    if not raw or any((c < 0x20 and c not in (9, 10, 13)) or c >= 0x7f for c in raw):
        return None
    return raw.decode("ascii")


def analyze(label, path, selected):
    raw = path.read_bytes()
    elf = ELFFile(BytesIO(raw))
    sections = list(elf.iter_sections())
    symtab = elf.get_section_by_name(".symtab")
    syms = list(symtab.iter_symbols())
    rel_by_target = {}
    for relsec in sections:
        if relsec["sh_type"] != "SHT_REL":
            continue
        target = int(relsec["sh_info"])
        rel_by_target.setdefault(target, {})
        for rel in relsec.iter_relocations():
            rel_by_target[target][int(rel["r_offset"])] = (
                syms[int(rel["r_info_sym"])], int(rel["r_info_type"])
            )
    funcs = {s.name: s for s in syms if s["st_info"]["type"] == "STT_FUNC" and isinstance(s["st_shndx"], int)}
    lines = [f"=== {label}: {path.relative_to(ROOT)} ==="]
    imports = sorted(s.name for s in syms if s["st_shndx"] == "SHN_UNDEF" and any(k in s.name.lower() for k in ("proc", "seq", "task", "queue", "wait", "stat")))
    lines.append("imports: " + ", ".join(imports))
    if label == "osal":
        strsec = elf.get_section_by_name(".rodata.str1.1")
        lines.append("proc-relevant strings:")
        pos = 0
        data = strsec.data()
        while pos < len(data):
            end = data.find(b"\0", pos)
            if end < 0:
                end = len(data)
            text = cstr(data, pos)
            if text:
                lines.append(f"  .rodata.str1.1+0x{pos:x}: {text!r}")
            pos = end + 1
    for name in selected:
        s = funcs[name]
        sec_idx = int(s["st_shndx"])
        sec = sections[sec_idx]
        start, size = int(s["st_value"]), int(s["st_size"])
        code = sec.data()[start:start + size]
        rels = rel_by_target.get(sec_idx, {})
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        lines.append(f"\nFUNCTION {name} {sec.name}+0x{start:x} size=0x{size:x}")
        for ins in md.disasm(code, start):
            notes = []
            for off in range(ins.address, ins.address + ins.size):
                if off in rels:
                    rs, typ = rels[off]
                    addend = int.from_bytes(sec.data()[off:off + 4], "little")
                    target_name = rs.name
                    if not target_name and isinstance(rs["st_shndx"], int):
                        target_name = sections[int(rs["st_shndx"])].name
                    note = f"RELOC(type={typ}) {target_name}+0x{addend:x}"
                    if isinstance(rs["st_shndx"], int):
                        target_sec = sections[int(rs["st_shndx"])]
                        text = cstr(target_sec.data(), int(rs["st_value"]) + addend)
                        if text is not None:
                            note += f" => {text!r}"
                    notes.append(note)
            if ins.mnemonic.startswith("ldr") and len(ins.operands) > 1 and ins.operands[1].type == ARM_OP_MEM and ins.reg_name(ins.operands[1].mem.base) == "pc":
                lit = ins.address + 8 + ins.operands[1].mem.disp
                if lit in rels:
                    rs, typ = rels[lit]
                    addend = int.from_bytes(sec.data()[lit:lit + 4], "little")
                    target_name = rs.name
                    if not target_name and isinstance(rs["st_shndx"], int):
                        target_name = sections[int(rs["st_shndx"])].name
                    note = f"LITERAL@0x{lit:x} {target_name}+0x{addend:x}"
                    if isinstance(rs["st_shndx"], int):
                        target_sec = sections[int(rs["st_shndx"])]
                        text = cstr(target_sec.data(), int(rs["st_value"]) + addend)
                        if text is not None:
                            note += f" => {text!r}"
                    notes.append(note)
            lines.append(f"{ins.address:08x} {ins.mnemonic:8} {ins.op_str:30}" + (" ; " + "; ".join(notes) if notes else ""))
    return "\n".join(lines)


parts = [analyze(label, path, selected) for label, (path, selected) in TARGETS.items()]
OUT.write_text("\n\n".join(parts) + "\n", encoding="utf-8")
print(OUT)
