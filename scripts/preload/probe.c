/* a6600 preload probe (no libc): proves /setting/mode/preload -> im.elf.
 * Raw ARM EABI syscalls only, so it has no DT_NEEDED and no GLIBC version refs.
 * Writes one line to /setting/mode/astra_probe.log and /tmp/astra_probe.log.
 */
#include <stddef.h>

#define O_WRONLY 01
#define O_CREAT  0100
#define O_APPEND 02000

static inline long sc3(long n, long a, long b, long c)
{
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c;
    register long r7 __asm__("r7") = n;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
    return r0;
}

static inline long sc0(long n)
{
    register long r0 __asm__("r0") = 0;
    register long r7 __asm__("r7") = n;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r7) : "memory");
    return r0;
}

static void append_line(const char *path, const char *msg, unsigned len)
{
    long fd = sc3(5 /* open */, (long)path, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd < 0)
        return;
    sc3(4 /* write */, fd, (long)msg, len);
    sc3(6 /* close */, fd, 0, 0);
}

__attribute__((constructor)) static void astra_probe_ctor(void)
{
    static char buf[64];
    static const char head[] = "ASTRA_PROBE_OK pid=";
    unsigned n = 0, i = 0;
    while (head[i]) buf[n++] = head[i++];

    long pid = sc0(20 /* getpid */);
    char num[12];
    unsigned m = 0;
    if (pid <= 0) num[m++] = '0';
    while (pid > 0 && m < sizeof(num)) { num[m++] = (char)('0' + pid % 10); pid /= 10; }
    while (m > 0) buf[n++] = num[--m];
    buf[n++] = '\n';

    append_line("/setting/mode/astra_probe.log", buf, n);
    append_line("/tmp/astra_probe.log", buf, n);
}
