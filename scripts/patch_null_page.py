"""Map a writable scratch page at address 0 so the firmware's null store does not oops.

Gated behind REA_NULL_PAGE=1. Diagnostic: reveals the next boot boundary when
av-cam's error path performs an intentional null write.
"""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/arm/sony_a6400.c')
s = p.read_text()

helper = '''
/*
 * DIAGNOSTIC ONLY (REA_NULL_PAGE=1): writable scratch page at address 0.
 * av-cam's error path performs an intentional store to NULL; with this page the
 * store completes instead of raising a data abort, which lets the rest of the
 * boot be observed. Not a fidelity model.
 */
static uint64_t sony_nullpage_read(void *opaque, hwaddr off, unsigned size)
{
    return 0;
}
static void sony_nullpage_write(void *opaque, hwaddr off, uint64_t v,
                                unsigned size)
{
}
static const MemoryRegionOps sony_nullpage_ops = {
    .read = sony_nullpage_read,
    .write = sony_nullpage_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

'''

anchor = 'static void sony_a6400_submicro_tick(void *opaque)'
assert anchor in s
s = s.replace(anchor, helper + anchor, 1)

# insert mapping right after sysmem is defined in init
marker = '    MemoryRegion *sysmem = get_system_memory();'
assert marker in s
ins = marker + '''
    if (getenv("REA_NULL_PAGE")) {
        MemoryRegion *np = g_new0(MemoryRegion, 1);
        memory_region_init_io(np, OBJECT(machine), &sony_nullpage_ops, NULL,
                              "a6600.nullpage", 0x1000);
        memory_region_add_subregion_overlap(sysmem, 0x0, np, -1000);
    }'''
s = s.replace(marker, ins, 1)

p.write_text(s)
print('patched null page (REA_NULL_PAGE)')
