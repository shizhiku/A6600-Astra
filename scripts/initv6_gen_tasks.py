#!/usr/bin/env python3
"""Generate 04-产物/97_astra_inits_v6.h for bridge v6.

Reads the 5th-gen IMDB decode results (03-证据/静态分析/imdb5) and the ASTRA
run image (/root/astra/97/m1-verified/astra-m1-rwx5.img), keeps only init
tasks that are actually executable in that image, and emits a C table ordered
exactly like the factory IMDB table.

Filter rules (from the task spec):
  * psid != 0            -> the init entry must be exported by the 5th-gen
                            libObj statically merged into /lib/a5bObj.so;
                            emitted with lib = NULL (libObj handle).
  * psid == 0, file begins with "lib"
                         -> /lib/a5b<file>.so must exist in the run image and
                            export the init entry in .dynsym; emitted with
                            lib = "/usr/lib/a5b<file>.so".
  * anything else        -> skipped and recorded with a reason.

group (see flag in imdb5_records.tsv):
  0 = main, 1 = INFRA0, 2 = INFRA1, 3 = INFRA2
  flag 0x1 -> 1, 0x2 -> 2, 0x4 -> 3, flag 0x0F / 0xFF -> 0 (main).

Usage (WSL):
  python3 <WORKSPACE>/02-脚本/initv6_gen_tasks.py
"""

import argparse
import hashlib
import importlib.util
import struct
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
TSV_DIR = ROOT / "03-证据" / "静态分析" / "imdb5"
DEFAULT_IMAGE = "/root/astra/97/m1-verified/astra-m1-rwx5.img"
DEFAULT_OUT = ROOT / "04-产物" / "97_astra_inits_v6.h"

GROUP_NAMES = {0: "main", 1: "INFRA0", 2: "INFRA1", 3: "INFRA2"}

SKIP_REASONS = {
    "no-init": "记录没有 init 入口（type1 仅 dlopen / 非库记录 / insmod）",
    "non-lib-file": "psid=0 且 file 不是 lib*.so（无法按 a5b 规则映射）",
    "flag-unknown": "flag 无法映射到 main/INFRA0/1/2",
    "libobj-symbol-missing": "psid!=0 但 /lib/a5bObj.so 的 .dynsym 未导出该入口",
    "image-lib-missing": "psid=0 但运行镜像中缺少 /lib/a5b<file>.so",
    "image-lib-no-entry": "/lib/a5b<file>.so 存在但 .dynsym 未导出 init 入口",
    "image-lib-bad-elf": "/lib/a5b<file>.so 不是可解析的 ELF32",
}


# --------------------------------------------------------------------------
# inputs
# --------------------------------------------------------------------------
def load_ext2_module():
    """Import 97_ext2.py (name starts with a digit, so no plain import)."""
    spec = importlib.util.spec_from_file_location(
        "_astra97_ext2_reader", str(HERE / "97_ext2.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read_tsv(path):
    text = path.read_text(encoding="utf-8-sig")
    lines = text.splitlines()
    if not lines:
        raise SystemExit("empty TSV: %s" % path)
    header = lines[0].split("\t")
    rows = []
    for lineno, line in enumerate(lines[1:], start=2):
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) != len(header):
            raise SystemExit("%s:%d: %d fields, expected %d"
                             % (path, lineno, len(fields), len(header)))
        rows.append(dict(zip(header, fields)))
    return header, rows


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------
# minimal ELF32 .dynsym reader (ARM little endian, section headers)
# --------------------------------------------------------------------------
SHT_DYNSYM = 11
SHN_UNDEF = 0


def elf32_dynsym_names(data):
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if data[4] != 1 or data[5] != 1:
        raise ValueError("not ELF32 little-endian (class=%d data=%d)"
                         % (data[4], data[5]))
    e_shoff = struct.unpack_from("<I", data, 32)[0]
    e_shentsize = struct.unpack_from("<H", data, 46)[0]
    e_shnum = struct.unpack_from("<H", data, 48)[0]
    if e_shoff == 0 or e_shnum == 0 or e_shentsize != 40:
        raise ValueError("no usable section header table")
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if off + 40 > len(data):
            raise ValueError("section header table truncated")
        sections.append(struct.unpack_from("<IIIIIIIIII", data, off))

    names = set()
    for sh in sections:
        sh_type, sh_offset, sh_size, sh_link, sh_entsize = sh[1], sh[4], sh[5], sh[6], sh[9]
        if sh_type != SHT_DYNSYM:
            continue
        if sh_entsize != 16:
            raise ValueError("unexpected .dynsym entry size %d" % sh_entsize)
        if sh_link >= len(sections):
            raise ValueError("bad .dynsym sh_link")
        str_off = sections[sh_link][4]
        for k in range(sh_size // 16):
            off = sh_offset + k * 16
            if off + 16 > len(data):
                raise ValueError(".dynsym truncated")
            st_name, _value, _size, _info, _other, _shndx = \
                struct.unpack_from("<IIIBBH", data, off)
            if st_name == 0:
                continue
            start = str_off + st_name
            end = data.find(b"\x00", start)
            if start >= len(data) or end < 0:
                raise ValueError("bad .dynstr offset")
            names.add(data[start:end].decode("latin1"))
    if not names:
        raise ValueError("empty .dynsym")
    return names


# --------------------------------------------------------------------------
# run image inventory
# --------------------------------------------------------------------------
class RunImage:
    def __init__(self, ext2mod, image):
        self.path = str(image)
        self.fs = ext2mod.Ext2(self.path)
        self.size = Path(self.path).stat().st_size
        self.lib_ino = None
        for name, ino, ftype in self.fs.listdir(2):
            if name == "lib" and (ftype == 2 or self.fs.inode(ino)[0] & 0xF000 == 0x4000):
                self.lib_ino = ino
                break
        if self.lib_ino is None:
            raise SystemExit("run image has no /lib directory")
        self.lib_files = {}
        for name, ino, ftype in self.fs.listdir(self.lib_ino):
            if ftype == 2:
                continue
            self.lib_files[name] = (ino, self.fs.inode(ino)[1])
        self._sym_cache = {}

    def read_lib(self, name):
        ino, _size = self.lib_files[name]
        return self.fs.read_file(ino)

    def dynsym(self, name):
        if name not in self._sym_cache:
            try:
                self._sym_cache[name] = elf32_dynsym_names(self.read_lib(name))
            except ValueError as exc:
                self._sym_cache[name] = exc
        result = self._sym_cache[name]
        if isinstance(result, ValueError):
            raise result
        return result


# --------------------------------------------------------------------------
# task classification
# --------------------------------------------------------------------------
def group_of_flag(flag_text):
    try:
        flag = int(flag_text, 16)
    except (TypeError, ValueError):
        return None
    if flag in (0x0F, 0xFF):
        return 0
    if flag in (0x01, 0x02, 0x04):
        return flag.bit_length()  # 1->1, 2->2, 4->3
    return None


def classify(tasks, records_by_index, image):
    obj_name = "a5bObj.so"
    if obj_name not in image.lib_files:
        raise SystemExit("run image lacks /lib/%s" % obj_name)
    obj_syms = image.dynsym(obj_name)

    accepted = []
    skipped = []
    for row in tasks:
        index = row["index"]
        flag_row = records_by_index.get(index)
        if flag_row is None:
            skipped.append(dict(row, reason="flag-unknown", group=None))
            continue
        group = group_of_flag(flag_row.get("flag", ""))
        if group is None:
            skipped.append(dict(row, reason="flag-unknown", group=None))
            continue
        file_name = row.get("file", "")
        entry = row.get("init", "")
        try:
            psid = int(row.get("psid", ""), 16)
        except ValueError:
            psid = 0
        if not entry:
            skipped.append(dict(row, reason="no-init", group=group))
            continue
        if psid != 0:
            if entry in obj_syms:
                accepted.append(dict(row, group=group, lib=None, entry=entry,
                                     provider="libObj"))
            else:
                skipped.append(dict(row, reason="libobj-symbol-missing",
                                    group=group))
            continue
        if not file_name.startswith("lib"):
            skipped.append(dict(row, reason="non-lib-file", group=group))
            continue
        target = "a5b" + file_name[3:]
        if target not in image.lib_files:
            skipped.append(dict(row, reason="image-lib-missing", group=group,
                                target=target))
            continue
        try:
            syms = image.dynsym(target)
        except ValueError:
            skipped.append(dict(row, reason="image-lib-bad-elf", group=group,
                                target=target))
            continue
        if entry not in syms:
            skipped.append(dict(row, reason="image-lib-no-entry", group=group,
                                target=target))
            continue
        accepted.append(dict(row, group=group, lib="/usr/lib/" + target,
                             entry=entry, provider="a5b"))
    return accepted, skipped, obj_syms


def format_reason(row):
    reason = row["reason"]
    if reason == "image-lib-missing":
        return "image-lib-missing(%s)" % row.get("target", "")
    if reason == "image-lib-no-entry":
        return "image-lib-no-entry(%s)" % row.get("target", "")
    if reason == "image-lib-bad-elf":
        return "image-lib-bad-elf(%s)" % row.get("target", "")
    if reason == "libobj-symbol-missing":
        return "libobj-symbol-missing(%s)" % row.get("init", "")
    return reason


# --------------------------------------------------------------------------
# header emission
# --------------------------------------------------------------------------
def c_string(text):
    if text is None:
        return "NULL"
    out = []
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif 32 <= ord(ch) < 127:
            out.append(ch)
        else:
            out.append("\\%03o" % ord(ch))
    return '"' + "".join(out) + '"'


def render_header(accepted, skipped, image_sha, image_size, image_path, args):
    group_counts = Counter(item["group"] for item in accepted)
    provider_counts = Counter(item["provider"] for item in accepted)
    reason_counts = Counter(item["reason"] for item in skipped)
    lines = []
    w = lines.append
    w("/* 97_astra_inits_v6.h -- generated by 02-脚本/initv6_gen_tasks.py")
    w(" * DO NOT EDIT BY HAND; re-run the generator instead.")
    w(" *")
    w(" * inputs:")
    w(" *   tasks   : %s (%d records, factory IMDB table order)"
      % (args.tasks.name, len(accepted) + len(skipped)))
    w(" *   flags   : %s (index join, group 0=main 1=INFRA0 2=INFRA1 3=INFRA2)"
      % args.records.name)
    w(" *   image   : %s" % image_path)
    w(" *             size=%d sha256=%s" % (image_size, image_sha))
    w(" *   libObj  : /lib/a5bObj.so .dynsym entries used as lib=NULL handle")
    w(" *")
    w(" * result: %d executable init tasks, %d skipped"
      % (len(accepted), len(skipped)))
    w(" *         by group : main=%d INFRA0=%d INFRA1=%d INFRA2=%d"
      % (group_counts.get(0, 0), group_counts.get(1, 0),
         group_counts.get(2, 0), group_counts.get(3, 0)))
    w(" *         by handle: libObj=%d a5b-lib=%d"
      % (provider_counts.get("libObj", 0), provider_counts.get("a5b", 0)))
    for reason in sorted(reason_counts):
        w(" *         skipped  : %-24s = %d" % (reason, reason_counts[reason]))
    w(" */")
    w("#ifndef ASTRA97_INITS_V6_H")
    w("#define ASTRA97_INITS_V6_H")
    w("")
    w("#define ASTRA97_INIT_COUNT %d" % len(accepted))
    w("#define ASTRA97_GROUP_COUNT 4")
    w("#define ASTRA97_GROUP_MAIN 0")
    w("#define ASTRA97_GROUP_INFRA0 1")
    w("#define ASTRA97_GROUP_INFRA1 2")
    w("#define ASTRA97_GROUP_INFRA2 3")
    for group in range(4):
        w("#define ASTRA97_GROUP%d_COUNT %d"
          % (group, group_counts.get(group, 0)))
    w("")
    w("struct astra97_init {")
    w("    int group;")
    w("    const char *lib;")
    w("    const char *entry;")
    w("    const char *tag;")
    w("};")
    w("")
    w("static const struct astra97_init astra97_inits[ASTRA97_INIT_COUNT] = {")
    for item in accepted:
        index = item["index"]
        lib = item["lib"]
        entry = item["entry"]
        tag = item.get("file", "")
        group = item["group"]
        note = "IMDB #%s g=%d %s" % (index, group, GROUP_NAMES[group])
        if item["provider"] == "libObj":
            note += " libObj"
        else:
            note += " " + item.get("file", "")
        w("    /* %-42s */ { %d, %-46s %-30s %s },"
          % (note, group, c_string(lib) + ",", c_string(entry) + ",",
             c_string(tag)))
    w("};")
    w("")
    w("/* skipped records (kept for traceability, not executed by bridge6):")
    for row in skipped:
        w(" *   #%s g=%-6s %-38s %-34s %s"
          % (row["index"],
             GROUP_NAMES.get(row["group"], "?") if row["group"] is not None else "?",
             row.get("file", "")[:38], (row.get("init") or "-")[:34],
             format_reason(row)))
    w(" */")
    w("")
    w("#endif /* ASTRA97_INITS_V6_H */")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate 97_astra_inits_v6.h from 5th-gen IMDB decode")
    parser.add_argument("--image", default=DEFAULT_IMAGE,
                        help="ASTRA run image (ext2), default %(default)s")
    parser.add_argument("--tasks", type=Path,
                        default=TSV_DIR / "imdb5_before_app_tasks.tsv")
    parser.add_argument("--records", type=Path,
                        default=TSV_DIR / "imdb5_records.tsv")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)

    if not Path(args.image).exists():
        raise SystemExit("run image not found: %s (run this inside WSL)"
                         % args.image)
    if not args.tasks.exists():
        raise SystemExit("tasks TSV not found: %s" % args.tasks)
    if not args.records.exists():
        raise SystemExit("records TSV not found: %s" % args.records)

    _, tasks = read_tsv(args.tasks)
    _, records = read_tsv(args.records)
    records_by_index = {row["index"]: row for row in records}

    ext2mod = load_ext2_module()
    image = RunImage(ext2mod, args.image)
    image_sha = sha256_file(args.image)

    accepted, skipped, obj_syms = classify(tasks, records_by_index, image)
    header = render_header(accepted, skipped, image_sha, image.size,
                           args.image, args)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(header)

    group_counts = Counter(item["group"] for item in accepted)
    provider_counts = Counter(item["provider"] for item in accepted)
    reason_counts = Counter(item["reason"] for item in skipped)

    print("[initv6] image      : %s" % args.image)
    print("[initv6] image size : %d bytes" % image.size)
    print("[initv6] image sha256: %s" % image_sha)
    print("[initv6] /lib files : %d (a5bObj.so dynsym exports %d)"
          % (len(image.lib_files), len(obj_syms)))
    print("[initv6] tasks read : %d (before-Application)" % len(tasks))
    print("[initv6] executable : %d" % len(accepted))
    print("[initv6] skipped    : %d" % len(skipped))
    print("[initv6] groups     : main=%d INFRA0=%d INFRA1=%d INFRA2=%d"
          % (group_counts.get(0, 0), group_counts.get(1, 0),
             group_counts.get(2, 0), group_counts.get(3, 0)))
    print("[initv6] providers  : libObj(NULL)=%d a5b-lib=%d"
          % (provider_counts.get("libObj", 0), provider_counts.get("a5b", 0)))
    print("[initv6] skip reasons:")
    for reason in sorted(reason_counts):
        print("           %-24s %d" % (reason, reason_counts[reason]))
    print("[initv6] skip list:")
    for row in skipped:
        print("           #%-4s g=%-6s %-38s %-32s %s"
              % (row["index"],
                 GROUP_NAMES.get(row["group"], "?")
                 if row["group"] is not None else "?",
                 row.get("file", "")[:38], (row.get("init") or "-")[:32],
                 format_reason(row)))
    print("[initv6] wrote %s (%d bytes)"
          % (args.out, args.out.stat().st_size))
    print("[initv6] header sha256: %s"
          % hashlib.sha256(header.encode("utf-8")).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
