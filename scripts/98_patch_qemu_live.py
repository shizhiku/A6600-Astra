"""Add an on-demand framebuffer dump command ('s') to the interactive model."""
from pathlib import Path
SRC=Path('/root/qemu-11.1.3');ARM=SRC/'hw/arm/sony_a6400.c';VPH=SRC/'hw/misc/cxd90014_vph.c'
def patch(p,edits):
    t=p.read_text()
    for old,new in edits:
        if new in t: print('already',p.name,old[:30]); continue
        if old not in t: raise SystemExit('anchor missing in %s: %r'%(p,old[:60]))
        t=t.replace(old,new,1)
    p.write_text(t);print('patched',p)
patch(VPH,[
 ('#define R(o) (s->vph[(o) / 4])',
  '#define R(o) (s->vph[(o) / 4])\n\nstatic VphState *rea_live_vph;\n\nvoid cxd90014_vph_live_dump(void);'),
 ('static void vph_tick(void *opaque)\n{\n    VphState *s = opaque;\n',
  'static void vph_tick(void *opaque)\n{\n    VphState *s = opaque;\n    rea_live_vph = s;\n'),
 ('static void vph_vlower(void *opaque)',
  'void cxd90014_vph_live_dump(void)\n{\n    const char *p = getenv("REA_FB_LIVE");\n    VphState *s = rea_live_vph;\n    if (!p || !s || !R(AIF(2) + 0x20)) {\n        return;\n    }\n    rea_fb_dump(R(AIF(2) + 0x20), R(AIF(2) + 0x24), R(AIF(2) + 0x2C) + 1, p);\n}\n\nstatic void vph_vlower(void *opaque)'),
])
patch(ARM,[
 ('static void sony_a6400_rea_ctl(void);',
  'static void sony_a6400_rea_ctl(void);\nvoid cxd90014_vph_live_dump(void);'),
 ("        if (c == 'm') {",
  "        if (c == 's') {\n            cxd90014_vph_live_dump();\n        } else if (c == 'm') {"),
])
print('done')
