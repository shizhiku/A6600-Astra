"""Check whether rlimit-related syscalls exist in the kernel image."""
from pathlib import Path

K = Path('/root/qemu_in/nflasha3-Image')
if not K.exists():
    K = Path(r'<WORKSPACE>\05-原始固件\qemu_in\nflasha3-Image')
data = K.read_bytes()
print('kernel bytes:', len(data))

for term in (b'getrlimit', b'ugetrlimit', b'setrlimit', b'prlimit64', b'sys_getrlimit',
             b'ENOSYS', b'syscall'):
    idx = data.find(term)
    print(f'{term.decode():12s} first={idx if idx >= 0 else "none"}')
    if idx >= 0:
        snippet = data[max(0, idx - 40): idx + 60]
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in snippet)
        print(f'             ctx: {printable}')
