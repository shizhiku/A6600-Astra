"""Read-only first-frame gate analysis for a6600 libObj.so.

Disassembles selected View/dirty/GraphicsEngine functions and finds direct Thumb
BL/BLX callers. It never modifies the input ELF.
"""
from pathlib import Path
from collections import defaultdict
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_GRP_CALL
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
ELF_PATH = ROOT / "03-证据/静态分析/libObj.so"
TARGET_PATTERNS = (
    "_ZN4View10drawDirectEv",
    "_ZNK4View7getViewEv",
    "_ZN4ViewC2EP11ViewManager",
    "_ZN4View17endLayoutChanging",
    "_ZN20LayoutableWidgetBase16handleDirtyEventEv",
    "_ZN20LayoutableWidgetBase24checkAndHandleDirtyEventEv",
    "_ZN20LayoutableWidgetBase18activeWidgetUpdateEv",
    "_ZN20LayoutableWidgetBase12widgetUpdateEv",
    "_ZN20LayoutableWidgetBase21activeWidgetUpdateAll",
    "_ZN20LayoutableWidgetBase16sendInitialEventEv",
    "_ZN2ux6gfxeng14GraphicsEngine14updateResourceEv",
    "_ZN13ScalarAppfwIF16IsViewModeDiademEv",
)
RAW_TARGETS = {
    0x001041D4: "GraphicsEngine::updateResource@plt",
    0x00845AA6: "ViewManager::drawDirect? internal target",
    0x00847960: "ViewManager draw backend",
    0x00844E96: "ViewManager::endLayoutChanging? internal target",
    0x004131A8: "LayoutableWidgetBase dirty dispatch internal target",
    0x00412D40: "dirty queue empty predicate implementation",
    0x00412D50: "dirty queue predicate/helper",
}


def main():
    with ELF_PATH.open("rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".dynsym")
        text = elf.get_section_by_name(".text")
        if not symtab or not text:
            raise SystemExit("missing .dynsym or .text")
        symbols = []
        by_addr = {}
        targets = {}
        for sym in symtab.iter_symbols():
            name = sym.name
            addr = int(sym["st_value"]) & ~1
            size = int(sym["st_size"])
            if addr and name:
                symbols.append((addr, size, name))
                by_addr[addr] = name
            if any(name.startswith(p) for p in TARGET_PATTERNS):
                targets[addr] = (name, size)
        for addr, name in RAW_TARGETS.items():
            targets[addr] = (name, 0x100 if addr >= 0x00400000 else 0x10)
        symbols.sort()
        data = text.data()
        base = int(text["sh_addr"])
        end = base + len(data)
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        md.detail = True

        callers = defaultdict(list)
        for ins in md.disasm(data, base):
            if CS_GRP_CALL not in ins.groups or not ins.operands:
                continue
            op = ins.operands[0]
            if op.type != 2:  # ARM_OP_IMM
                continue
            dest = int(op.imm) & ~1
            if dest in targets:
                owner = "<unknown>"
                for a, sz, n in symbols:
                    if a > ins.address:
                        break
                    if sz and a <= ins.address < a + sz:
                        owner = n
                callers[dest].append((ins.address, owner, ins.mnemonic, ins.op_str))

        for addr, (name, size) in sorted(targets.items()):
            print(f"\n=== {name} @ {addr:#010x} size={size:#x} ===")
            if not (base <= addr < end):
                print("outside .text")
                continue
            off = addr - base
            blob = data[off: off + max(size, 0x80)]
            for ins in md.disasm(blob, addr):
                if size and ins.address >= addr + size:
                    break
                print(f"{ins.address:08x}  {ins.bytes.hex():10s} {ins.mnemonic:8s} {ins.op_str}")
            print("-- direct callers --")
            for call_addr, owner, mnemonic, op_str in callers.get(addr, []):
                print(f"{call_addr:08x}  {owner}  {mnemonic} {op_str}")
            if not callers.get(addr):
                print("(none found in .text direct calls)")


if __name__ == "__main__":
    main()
