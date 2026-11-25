"""对改造后的 /usr 镜像做 DT_NEEDED 闭包自检。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util

from elftools.elf.elffile import ELFFile

ROOT = r"<LEGACY_WORKSPACE>"
IMG = os.path.join(ROOT, "a6600_port", "nflasha15_patched.bin")


def load_fs():
    spec = importlib.util.spec_from_file_location("usr", os.path.join(ROOT, "a6600_usr.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m.Ext2(IMG)


def main():
    fs = load_fs()
    files, dirs = {}, set()
    for path, ino, isdir in fs.walk():
        if isdir:
            dirs.add(path)
        else:
            files[path] = ino
    print(f"镜像内 {len(files):,} 个文件 / {len(dirs):,} 个目录")

    basenames = {os.path.basename(p) for p in files}
    # 系统里可能有 /lib 与 /usr/lib 的映射；按 basename 判断
    missing = {}
    checked = 0
    for path, ino in files.items():
        if not path.endswith(".so") and ".so." not in path:
            continue
        if path.startswith("/share/"):
            continue
        try:
            data = fs.read_file(ino)
            if data[:4] != b"\x7fELF":
                continue
            import io
            e = ELFFile(io.BytesIO(data))
            checked += 1
            for seg in e.iter_segments():
                if seg["p_type"] != "PT_DYNAMIC":
                    continue
                for t in seg.iter_tags():
                    if t.entry.d_tag == "DT_NEEDED":
                        need = t.needed
                        if need not in basenames:
                            missing.setdefault(need, []).append(path)
        except Exception as exc:
            print(f"  [warn] {path}: {exc}")

    print(f"检查 ELF 动态库 {checked} 个")
    if not missing:
        print("[+] DT_NEEDED 闭包完整：所有依赖都能在镜像内找到")
    else:
        print(f"[!] 缺失 {len(missing)} 个依赖:")
        for need, users in sorted(missing.items()):
            print(f"    {need:40s} <- {', '.join(users[:3])}")


if __name__ == "__main__":
    main()
