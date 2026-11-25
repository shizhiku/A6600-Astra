"""Rescan liro .init.text with correct section addressing to find the segment-log call."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_MEM

KO = Path(r'<WORKSPACE>\03-证据\静态分析\liro-fault-static\liro.ko')
with open(KO, 'rb') as f:
    e = ELFFile(f)
    for name in ('.init.text', '.text'):
        s = e.get_section_by_name(name)
        if s is None:
            continue
        code = s.data()
        sa = s['sh_addr']
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        md.detail = True
        hits = []
        for off in range(0, len(code) - 3, 4):
            for x in md.disasm(code[off:off + 4], sa + off):
                if not x.mnemonic.startswith('ldr'):
                    continue
                if len(x.operands) < 2 or x.operands[1].type != ARM_OP_MEM:
                    continue
                if x.operands[1].mem.base != 15:
                    continue
                tgt = x.address + 8 + x.operands[1].mem.disp
                if not (sa <= tgt < sa + len(code) - 3):
                    continue
                val = int.from_bytes(code[tgt - sa:tgt - sa + 4], 'little')
                if val == 0x4A0:  # offset of "%llx -> %p : %x %x loaded (%s)"
                    hits.append((hex(x.address), x.op_str, hex(tgt),
                                 x.reg_name(x.operands[0].reg)))
        print(name, 'sh_addr', hex(sa), 'size', hex(len(code)), 'hits', hits)
