"""a6600 /usr ELF-level checks: preload hook, bootin, libObj hook points, libmpr patch site."""
import os, struct, sys

from elftools.elf.elffile import ELFFile

BASE = os.path.dirname(os.path.abspath(__file__))
USR = os.path.join(BASE, "a6600_fw", "usr")

A6400_PROLOGUE = bytes.fromhex("2de9f04788b04ff0140801 22".replace(" ", ""))
A6400_HOOK_OFFS = (0x5F1D48, 0x5F1DC0)


def sections(path):
    with open(path, "rb") as f:
        e = ELFFile(f)
        return e, {s.name: (s["sh_offset"], s["sh_size"], s["sh_addr"]) for s in e.iter_sections()}


def main():
    print("=" * 78)
    print("1) /lib/libAK8975.so -- A6400 boot-hook target (PATCH_ADDR must be 0x988)")
    p = os.path.join(USR, "lib", "libAK8975.so")
    e, secs = sections(p)
    print("   e_machine=%s e_flags=%#x" % (e["e_machine"], e["e_flags"]))
    for name in (".text", ".rodata", ".dynamic", ".init_array"):
        if name in secs:
            off, size, addr = secs[name]
            print("   %-12s file_off=%#08x size=%#x" % (name, off, size))
    print("   => .text at %#x, expected 0x988 by tools/build_autoexec_hook.py" % secs[".text"][0])

    print("=" * 78)
    print("2) /bin/bootin.elf -- LD_PRELOAD mechanism")
    p = os.path.join(USR, "bin", "bootin.elf")
    raw = open(p, "rb").read()
    for needle in (b"LD_PRELOAD", b"/setting/mode/preload", b"/setting/mode/dmode", b"change_mode", b"im.elf"):
        print("   %-24s occurrences=%d" % (needle.decode(), raw.count(needle)))
    e, secs = sections(p)
    print("   e_type=%s entry=%#x" % (e["e_type"], e["e_entry"]))
    print("   sections:", ", ".join("%s@%#x" % (n, v[0]) for n, v in secs.items() if n and v[1]))

    print("=" * 78)
    print("3) /lib/libObj.so -- A6400 UI hook points")
    p = os.path.join(USR, "lib", "libObj.so")
    raw = open(p, "rb").read()
    hits = []
    start = 0
    while True:
        i = raw.find(A6400_PROLOGUE, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
    print("   size=%d  A6400 12-byte prologue occurrences=%d" % (len(raw), len(hits)))
    print("   first offsets: %s" % ", ".join(hex(h) for h in hits[:8]))
    for off in A6400_HOOK_OFFS:
        print("   bytes @%#x: %s" % (off, raw[off:off + 12].hex()))
    for sym in (b"Application_System_Init", b"Application_Start", b"WidgetSystem"):
        print("   string %-24s present=%s" % (sym.decode(), sym in raw))

    print("=" * 78)
    print("4) /lib/libmpr.so -- anlock6600 1080p patch site (expect 4f f4 87 63 @0x87fe08)")
    p = os.path.join(USR, "lib", "libmpr.so")
    raw = open(p, "rb").read()
    print("   size=%d bytes@0x87fe08=%s" % (len(raw), raw[0x87FE08:0x87FE08 + 4].hex()))
    print("   bytes@0x87fdd4=%s" % raw[0x87FDD4:0x87FDD4 + 8].hex())

    print("=" * 78)
    print("5) /lib/libIMDB.so -- module table")
    p = os.path.join(USR, "lib", "libIMDB.so")
    raw = open(p, "rb").read()
    for needle in (b"appFwBoot", b"libupdaterufp", b"psid", b"viewUnified"):
        print("   %-16s count=%d" % (needle.decode(), raw.count(needle)))


if __name__ == "__main__":
    main()
