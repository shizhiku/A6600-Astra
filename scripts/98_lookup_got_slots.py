"""Look up the import symbol bound to specific GOT slot VMAs, using .rel.plt /
.rel.dyn relocations.  Doc 136 supplied these slots:

  drawFramebuffer          0x377AFE0
  processSystemMessage     0x377ACEC
  processEvent             0x377B334
  GRM_fbrmCheckUpdateFinished 0x377B270
  notifyDraw               0x377B440
  GRM_fbrmRegisterTriggerFrameworkCb 0x377B3E8
  WidgetSystem::updateFrame 0x377B480
"""
from elftools.elf.elffile import ELFFile
from pathlib import Path
import io

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / '03-证据/静态分析/97_abi/a5pFw_upmfix_nonotify.so'
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))

SLOTS = {
    0x377AFE0: 'drawFramebuffer',
    0x377ACEC: 'processSystemMessage',
    0x377B334: 'processEvent',
    0x377B270: 'GRM_fbrmCheckUpdateFinished',
    0x377B440: 'notifyDraw',
    0x377B3E8: 'GRM_fbrmRegisterTriggerFrameworkCb',
    0x377B480: 'WidgetSystem::updateFrame',
}

rel_info = {}
for sec in e.iter_sections():
    if sec['sh_type'] in ('SHT_REL', 'SHT_RELA'):
        st = e.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            sym = st.get_symbol(r['r_info_sym'])
            rel_info[r['r_offset']] = (sec.name, sym.name, r['r_info_type'])

print('%-34s %-12s %s' % ('slot', 'section', 'bound symbol'))
print('-' * 90)
for slot, label in SLOTS.items():
    info = rel_info.get(slot)
    if info:
        print('%#010x %-18s %-12s %s' % (slot, label, info[0], info[1]))
    else:
        print('%#010x %-18s %-12s %s' % (slot, label, '(none)', 'NO RELOC FOUND'))
