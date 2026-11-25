"""imdb4_usrscan.py — 在四代 /usr 镜像里找“谁会调用 InfraInput/InputService 触发点”（只读）。

只读：不运行目标、不修改镜像。用 97_ext2.Ext2 读取原厂 nflasha15（四代 /usr）与
我们镜像的 /lib，扫描每个 ELF 的 .dynsym 未定义符号，回答：
  哪个 4 代库依赖 InfraInput::GetInstance / InputService::activate 等触发点？
输出：03-证据/静态分析/imdb4/imdb4_usrscan.json / imdb4_usrscan.txt
用法：python 02-脚本/imdb4_usrscan.py
"""
import hashlib
import importlib.util
import io
import json
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

BASE = Path(__file__).resolve().parents[1]
EVID = BASE / "03-证据/静态分析/imdb4"
STOCK_USR = BASE / "05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15"
ASTRA_IMG = Path("//wsl.localhost/Ubuntu/root/astra/97/m1-verified/astra-m1-rwx2.img")

TRIGGERS = {
    "_ZN10InfraInput11GetInstanceEv": "InfraInput 单例（实例+4 条 I-Input* 线程在此创建）",
    "_ZN10InfraInput11SetCallbackEPiPFviP16_InfraInputEventE": "InfraInput 注册回调",
    "_ZN10InfraInput9SetOsalIdEPii": "InfraInput 设置 osal id",
    "_ZN12InputService8activateEbjm": "InputService 激活（4 代 UI 输入服务）",
    "_ZN12InputService16UpdateInputTableEv": "InputService 键表更新（内含 GetInstance+SetCallback）",
    "core_sync_set_event": "CoreSync 事件入口（调用 GetInstance）",
    "toInstanceAC": "toInstanceAC（调用 GetInstance）",
    "_ZN9InfraDial20SetDialEventIntervalEhhh": "InfraDial 设置转盘间隔（调用 GetInstance）",
    "_ZN7StatMgr11ChangeStateEjjPvj": "StatMgr 状态机（调用 InfraInput 查询）",
    "initializeConfig": "initializeConfig（调用 InputService::activate）",
    "infra_input_init": "IMDB 记录 31 的 init 名",
    "MWF_Init": "4 代 MWF 初始化",
}
# 宽匹配：任何输入相关符号，用于找“输入 API 的使用者”
INPUT_SUBSTR = ("InfraInput", "InputService", "infra_input", "InfraInputUtil",
                "InputServant", "SelRegister")


def load_ext2():
    spec = importlib.util.spec_from_file_location(
        "ext2", BASE / "02-脚本/97_ext2.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m.Ext2


def scan_image(fs, roots, label):
    results = {"label": label, "root": str(getattr(fs, "f", None) and fs.f.name),
               "files": 0, "elf": 0, "trigger_imports": {}, "needed_by": {}}
    stack = list(roots)
    while stack:
        path, ino = stack.pop()
        try:
            entries = fs.listdir(ino)
        except Exception as e:  # noqa: BLE001
            results.setdefault("errors", []).append(f"listdir {path}: {e}")
            continue
        for name, child, ft in entries:
            if name in (".", ".."):
                continue
            p = path + "/" + name
            try:
                mode, size, _ = fs.inode(child)
            except Exception:
                continue
            if (mode & 0xF000) == 0x4000:
                stack.append((p, child))
                continue
            if (mode & 0xF000) != 0x8000 or size < 64:
                continue
            results["files"] += 1
            try:
                head = fs.read_file(child)[:4]
            except Exception:
                continue
            if head[:4] != b"\x7fELF":
                continue
            results["elf"] += 1
            try:
                data = fs.read_file(child)
                elf = ELFFile(io.BytesIO(data))
                dyn = elf.get_section_by_name(".dynsym")
                if dyn is None:
                    continue
                und = []
                for s in dyn.iter_symbols():
                    if s.name and s["st_shndx"] == "SHN_UNDEF":
                        und.append(s.name)
            except Exception as e:  # noqa: BLE001
                results.setdefault("errors", []).append(f"{p}: {e}")
                continue
            base = p.rsplit("/", 1)[-1]
            found = [t for t in TRIGGERS if t in set(und)]
            if found:
                results["trigger_imports"].setdefault(base, {
                    "path": p, "size": size, "symbols": found})
                for f in found:
                    results["needed_by"].setdefault(f, []).append(base)
            wide = sorted({n for n in und if any(k in n for k in INPUT_SUBSTR)})
            if wide:
                results.setdefault("input_api_users", {})[base] = {
                    "path": p, "size": size, "symbols": wide}
    return results


def image_roots(fs):
    roots = []
    for name, ino, ft in fs.listdir(2):
        if name in (".", ".."):
            continue
        if name in ("lib", "local"):
            roots.append(("/" + name, ino))
        elif name == "bin":
            roots.append(("/bin", ino))
    return roots


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    EVID.mkdir(parents=True, exist_ok=True)
    Ext2 = load_ext2()
    report = {"triggers": TRIGGERS}
    if STOCK_USR.exists():
        fs = Ext2(str(STOCK_USR))
        roots = image_roots(fs)
        report["stock_usr"] = scan_image(fs, roots, "nflasha15(原厂4代/usr)")
        print("[ok] 原厂 /usr:", roots, report["stock_usr"]["files"], "files,",
              report["stock_usr"]["elf"], "ELF")
    # 我们镜像的 /lib（WSL 路径，经 \\wsl.localhost 只读访问）
    try:
        if Path(str(ASTRA_IMG)).exists():
            fs2 = Ext2(str(ASTRA_IMG))
            roots2 = image_roots(fs2)
            report["astra_img"] = scan_image(fs2, roots2, "astra-m1-rwx2.img")
            print("[ok] astra 镜像 /lib:", roots2, report["astra_img"]["files"], "files,",
                  report["astra_img"]["elf"], "ELF")
    except Exception as e:  # noqa: BLE001
        print("[warn] astra 镜像扫描失败:", e)
        report["astra_img_error"] = str(e)

    (EVID / "imdb4_usrscan.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    lines = ["# 4 代 /usr 触发点导入扫描", ""]
    for key in ("stock_usr", "astra_img"):
        r = report.get(key)
        if not r:
            continue
        lines.append(f"## {key}  files={r['files']} elf={r['elf']}")
        for sym, why in TRIGGERS.items():
            libs = r["needed_by"].get(sym, [])
            if libs:
                lines.append(f"  {sym}  ({why})")
                lines.append(f"      importers: {', '.join(sorted(libs))}")
        lines.append("")
    (EVID / "imdb4_usrscan.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"[ok] -> {EVID/'imdb4_usrscan.txt'}")


if __name__ == "__main__":
    main()
