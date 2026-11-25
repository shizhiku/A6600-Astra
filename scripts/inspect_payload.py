"""检查 ZV-E10 2.03 exe 里那个 375MB 载荷的结构。"""
import os

P = r"<LEGACY_WORKSPACE>\zve10_fw\[0]"
MAGIC = b"\x89UFU\r\n\x1a\n"


def main():
    size = os.path.getsize(P)
    print(f"size={size:,}")
    with open(P, "rb") as f:
        head = f.read(256)
    print("head:", head[:64].hex(" "))
    print("ascii:", "".join(chr(b) if 32 <= b < 127 else "." for b in head[:64]))

    with open(P, "rb") as f:
        data = f.read()
    for name, sig in [("UFU", MAGIC), ("DATV", b"DATV"), ("DEND", b"DEND"),
                      ("PK", b"PK\x03\x04"), ("7z", b"7z\xbc\xaf\x27\x1c"),
                      ("gzip", b"\x1f\x8b\x08")]:
        print(f"{name:6s} @ {hex(data.find(sig)) if data.find(sig) >= 0 else '-'}")


if __name__ == "__main__":
    main()
