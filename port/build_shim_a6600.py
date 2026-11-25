#!/usr/bin/env python3
"""Rebuild appFwBoot.so for a6600 by substituting host offsets in the source."""
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

REPO = Path('${REPO}')
SRC = REPO / 'src' / 'appFwBoot_g4host.c'
WORK = REPO / 'build_out' / 'rehost'
WORK.mkdir(parents=True, exist_ok=True)
OUT_SRC = WORK / 'appFwBoot_a6600.c'
OUT_SO = WORK / 'appFwBoot.so'

# ZV-E10 offset  ->  a6600 offset   (round-1 byte-similarity results)
MAP = {
    # *** base derivation: Application_System_Init st_value (odd=Thumb) ***
    # ZV-E10 0x8A2409  ->  a6600 0x8436FD
    0x8a2408: 0x8436FC,
    0x8a2409: 0x8436FD,
    0x774111: 0x72AB40 + 1,   # rm_exit        (thumb bit preserved)
    0x774110: 0x72AB40,
    0x6f923d: 0x70D58C + 1,   # grm_term
    0x6f923c: 0x70D58C,
    0x8c0db8: 0x85F398,       # input_retire_send
    0x775120: 0x72BB50,       # rm_wait
    0x775121: 0x72BB51,
    0x7755b0: 0x72BFE0,       # rm_wait_sig
    0x7755b1: 0x72BFE1,
    0x8c22a1: 0x860874 + 1,   # get_instance
    0x8c22a0: 0x860874,
    0x8c2825: 0x860DF8 + 1,   # set_callback
    0x8c2824: 0x860DF8,
    0x11fd46: 0x3D2EA6,       # cb_direct
    0x11fae1: 0x3D2C40 + 1,   # cb_panel
    0x11fae0: 0x3D2C40,
    0x11ece5: 0x3D1E94 + 1,   # cb_dial_signed_speed
    0x11ece4: 0x3D1E94,
    0x11cb75: 0x3CFDC4 + 1,   # cb_tp_raw
    0x11cb74: 0x3CFDC4,
}

src = SRC.read_text(encoding='utf-8', errors='replace')
subs = 0
for old, new in MAP.items():
    # match the literal in either bare or suffixed form, case-insensitive
    for pat_suffix in ('u', 'U', ''):
        needle = f'0x{old:0{len(f"{old:x}"):d}x}' if False else f'0x{old:x}{pat_suffix}'
        if needle in src:
            src = src.replace(needle, f'0x{new:x}u')
            subs += 1
OUT_SRC.write_text(src, encoding='utf-8')
print(f"[+] substituted {subs} literal occurrence(s) -> {OUT_SRC.name}")

# Neutralise the two libObj offsets we could NOT re-derive for a6600
# (0x148a6bc context-getter var, 0x854670 SetContextGetter).  Writing them on
# a6600 lands outside libObj's mapping and faults.
NEUTRAL = [
    ("*pGetterVar = (void *)dummy_context_getter;",
     "/* a6600: offset 0x148a6bc unresolved -> skipped */ (void)pGetterVar;"),
    ("set_getter(dummy_context_getter);",
     "/* a6600: offset 0x854671 unresolved -> skipped */ (void)set_getter;"),
    # The RM park uses SIGUSR2 storms to wake gen4 RM threads; on a6600 that
    # lands on unprepared threads and faults (sig=12 at fault=0x90).
    ("park_libobj_rm_thread(base);",
     "/* a6600: SIGUSR2 park disabled -> avoided */ (void)0;"),
]
txt = OUT_SRC.read_text(encoding='utf-8')
for a, b in NEUTRAL:
    if a in txt:
        txt = txt.replace(a, b)
        print(f"[+] neutralised: {a[:48]}...")
    else:
        print(f"[!] pattern not found: {a[:48]}...")
OUT_SRC.write_text(txt, encoding='utf-8')

# ---- inject a framebuffer dumper so we can see what ASTRA actually renders ----
DUMP_FN = r'''
/* ---- a6600 debug: dump g_gemini_fb as PPM (to /tmp) and ASCII (to serial) ---- */
static void g5_dump_fb_ppm(const char *path, int w, int h)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) { logf_("FBDUMP: open(%s) failed errno=%d", path, errno); return; }
    char hdr[64];
    int hn = snprintf(hdr, sizeof hdr, "P6\n%d %d\n255\n", w, h);
    if (write(fd, hdr, (size_t)hn) != (ssize_t)hn) { close(fd); return; }
    unsigned char row[640 * 3];
    for (int y = 0; y < h; y++) {
        int src_y = (h - 1) - y;
        const uint32_t *src = &g_gemini_fb[(size_t)src_y * w];
        int cw = w > 640 ? 640 : w;
        for (int x = 0; x < cw; x++) {
            uint32_t p = src[x];
            row[x * 3 + 0] = (unsigned char)(((p >> 4) & 0xf) * 17);
            row[x * 3 + 1] = (unsigned char)(((p >> 12) & 0xf) * 17);
            row[x * 3 + 2] = (unsigned char)(((p >> 20) & 0xf) * 17);
        }
        if (write(fd, row, (size_t)cw * 3) != (ssize_t)(cw * 3)) { close(fd); return; }
    }
    close(fd);
    logf_("FBDUMP: wrote %s (%dx%d)", path, w, h);
}

static void g5_dump_fb_ascii(int w, int h)
{
    static const char ramp[] = " .:-=+*#%@";
    const int cols = 80, rows = 30;
    int cw = w / cols; if (cw < 1) cw = 1;
    int ch = h / rows; if (ch < 1) ch = 1;
    logf_("G5_FBASCI %dx%d (cell %dx%d)", w, h, cw, ch);
    for (int r = 0; r < rows; r++) {
        char line[82];
        int n = 0;
        int sy = (h - 1) - (r * ch + ch / 2);
        if (sy < 0) sy = 0;
        const uint32_t *src = &g_gemini_fb[(size_t)sy * w];
        for (int c = 0; c < cols; c++) {
            int sx = c * cw + cw / 2;
            if (sx >= w) sx = w - 1;
            uint32_t p = src[sx];
            int r4 = (p >> 4) & 0xf, g4 = (p >> 12) & 0xf, b4 = (p >> 20) & 0xf;
            int lum = (r4 * 3 + g4 * 6 + b4) / 10;
            line[n++] = ramp[lum * 9 / 15];
        }
        line[n] = 0;
        logf_("|%s|", line);
    }
    logf_("G5_FBASCI_END");
}

'''
anchor = 'static void g5_pack_fb_rgba4444_morton('
if anchor in txt:
    txt = txt.replace(anchor, DUMP_FN + anchor, 1)
    print("[+] injected PPM + ASCII dumpers")
else:
    print("[!] pack function anchor not found")

CALL_ANCHOR = 'uintptr_t ret = g_orig_g5_swap ? g_orig_g5_swap(s) : 0;'
# keep the swap path untouched; we trigger dumps from the drawFramebuffer hook instead
if CALL_ANCHOR in txt:
    print("[ ] swap-return anchor left untouched")

DRAWFB_ANCHOR = 'uint32_t c = __sync_add_and_fetch(&g_draw_fb_cnt, 1);'
# Debug framebuffer dumps are DISABLED: they wrote ~2.7 MB of PPM files into the
# guest's /tmp, which pollutes a real camera's scratch partition.
DRAWFB_CALL = DRAWFB_ANCHOR
if DRAWFB_ANCHOR in txt:
    txt = txt.replace(DRAWFB_ANCHOR, DRAWFB_CALL, 1)
    print("[ ] framebuffer dumps disabled in this build")
else:
    print("[!] drawfb anchor not found")

# Guarantee a minimum period per pump cycle.  g5_touch_wait_ms() returns
# immediately whenever the touch queue is non-empty, which can turn the
# interactive pump into a hot spin (observed: 1.6M cycles in 132 s, serial
# flooded, guest starved).
PACE_ANCHOR = '            g5_touch_wait_ms(wait_ms);'
PACE_PATCH = ('            g5_touch_wait_ms(wait_ms);\n'
              '            if (wait_ms < 30u) usleep(30000u);')
if PACE_ANCHOR in txt:
    txt = txt.replace(PACE_ANCHOR, PACE_PATCH, 1)
    print("[+] injected minimum pump period (30 ms floor)")
else:
    print("[!] pump pacing anchor not found")

# ---- forced redraw: watchdog on drawFramebuffer ----
GE_ANCHOR = ('/* 拦截 appFw.so GOT[GraphicsEngine::drawFramebuffer]：观测主循环是否实际触达渲染入口 */\n'
             'static void g5_hook_appfw_draw_framebuffer(void *ge) {\n'
             '    uint32_t c = __sync_add_and_fetch(&g_draw_fb_cnt, 1);')
GE_PATCH = ('/* a6600: remember the last GraphicsEngine handle so the pump can force a\n'
            ' * repaint when no layer considers itself dirty any more. */\n'
            'static void *g_last_ge;\n'
            '/* 拦截 appFw.so GOT[GraphicsEngine::drawFramebuffer]：观测主循环是否实际触达渲染入口 */\n'
            'static void g5_hook_appfw_draw_framebuffer(void *ge) {\n'
            '    uint32_t c = __sync_add_and_fetch(&g_draw_fb_cnt, 1);\n'
            '    g_last_ge = ge;')
if GE_ANCHOR in txt:
    txt = txt.replace(GE_ANCHOR, GE_PATCH, 1)
    print("[+] injected g_last_ge capture")
else:
    print("[!] drawfb hook anchor not found")

# ---- stall diagnostics: dump thread state when drawing stops ----
DUMP_ANCHOR = 'static int16_t g5_clamp_touch_coord(long v, int16_t max_val)'
DUMP_CODE = r'''
/* a6600 STALL DUMP: when drawFramebuffer stops, record what every thread in
 * this process is blocked on.  Without this we can only see that the UI froze,
 * not why.  Only threads that are NOT plain-sleeping are printed, plus a small
 * cap, to keep the serial log readable. */
static void g5_dump_threads_once(const char *why)
{
    static int done = 0;
    if (__atomic_exchange_n(&done, 1, __ATOMIC_ACQ_REL)) return;
    DIR *d = opendir("/proc/self/task");
    if (!d) { logf_("STALLDUMP: cannot open /proc/self/task"); return; }
    logf_("STALLDUMP begin: %s", why);
    struct dirent *e;
    int shown = 0;
    while ((e = readdir(d)) != NULL && shown < 48) {
        if (e->d_name[0] == '.') continue;
        char path[128], buf[512];
        int fd, n;
        snprintf(path, sizeof path, "/proc/self/task/%s/stat", e->d_name);
        fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        n = (int)read(fd, buf, sizeof buf - 1);
        close(fd);
        if (n <= 0) continue;
        buf[n] = 0;
        char *rp = strrchr(buf, ')');
        char st = (rp && rp[1] == ' ') ? rp[2] : '?';
        if (st == 'S' && shown >= 12) continue;      /* skip most sleepers */
        snprintf(path, sizeof path, "/proc/self/task/%s/wchan", e->d_name);
        fd = open(path, O_RDONLY);
        char wc[96] = "-";
        if (fd >= 0) {
            n = (int)read(fd, wc, sizeof wc - 1);
            close(fd);
            if (n > 0) { wc[n] = 0; char *nl = strchr(wc, '\n'); if (nl) *nl = 0; }
        }
        snprintf(path, sizeof path, "/proc/self/task/%s/syscall", e->d_name);
        fd = open(path, O_RDONLY);
        char sc[96] = "-";
        if (fd >= 0) {
            n = (int)read(fd, sc, sizeof sc - 1);
            close(fd);
            if (n > 0) { sc[n] = 0; char *nl = strchr(sc, '\n'); if (nl) *nl = 0; }
        }
        logf_("STALLDUMP tid=%s state=%c wchan=%s syscall=%s", e->d_name, st, wc, sc);
        shown++;
    }
    closedir(d);
    logf_("STALLDUMP end (shown=%d)", shown);
}

static int16_t g5_clamp_touch_coord(long v, int16_t max_val)'''
if DUMP_ANCHOR in txt:
    txt = txt.replace(DUMP_ANCHOR, DUMP_CODE, 1)
    print("[+] injected STALLDUMP thread dumper")
else:
    print("[!] stall-dump anchor not found")

WATCH_ANCHOR = '        __atomic_store_n(&g_render_stage, 6u, __ATOMIC_RELAXED);'
WATCH_PATCH = (
    '        /* a6600 FORCE_REDRAW watchdog: updateFrame only paints layers whose\n'
    '         * vtable slot0 says "needs draw".  When every layer says no (which\n'
    '         * happens after some interactions) the screen freezes even though the\n'
    '         * app is alive.  If drawFramebuffer stops advancing, call it directly. */\n'
    '        {\n'
    '            static uint32_t s_dfc;\n'
    '            static int s_stall;\n'
    '            uint32_t dfc = __atomic_load_n(&g_draw_fb_cnt, __ATOMIC_RELAXED);\n'
    '            if (dfc == s_dfc) {\n'
    '                s_stall++;\n'
    '            } else {\n'
    '                s_stall = 0;\n'
    '                s_dfc = dfc;\n'
    '            }\n'
    '            if (s_stall >= 30 && g_last_ge && g_orig_draw_framebuffer) {\n'
    '                if (s_stall == 30) g5_dump_threads_once("drawfb stalled 30 cycles");\n'
    '                g_orig_draw_framebuffer(g_last_ge);\n'
    '                logf_("FORCE_REDRAW: drawfb stalled %d cycles -> forced repaint", s_stall);\n'
    '                s_stall = 0;\n'
    '            }\n'
    '        }\n'
    '        ' + WATCH_ANCHOR)
if WATCH_ANCHOR in txt:
    txt = txt.replace(WATCH_ANCHOR, WATCH_PATCH, 1)
    print("[+] injected FORCE_REDRAW watchdog")
else:
    print("[!] pump anchor not found")


# Evidence showed next==0 is legitimate: it is how the app *pops/dismisses* the
# current overlay (e.g. tapping OK on the touch guide emits
#   cur=0x2ec next=0x0
# ).  Forcing a real screen id there breaks the dismissal and freezes drawing.


# Let the scripted synthetic-touch sequence run in interactive mode too,
# otherwise the ASTRA tutorial page never gets dismissed.
TAP_GUARD = ("                if (!interactive) {\n"
             "                    const uint64_t t_zero = 0;")
TAP_OPEN = ("                if (1) {\n"
            "                    const uint64_t t_zero = 0;")
if TAP_GUARD in txt:
    txt = txt.replace(TAP_GUARD, TAP_OPEN, 1)
    print("[+] enabled synthetic tap sequence in interactive mode")
else:
    print("[!] tap guard not found")

# NOTE: an experimental "switch to ASTRA menu" trigger at render cycle 25 was
# tried here.  Setting g_pending_switch_target directly does NOT wake the app
# event loop, so it never runs.  The correct entry point is
# g5_request_screen_switch(), which also sends ASTRA_WAKE_EVT_ID.
CYCLE_ANCHOR = ('logf_("RENDER_DRIVER [轮次 %d]: g_astra_running=%d '
                'g_ws_syms_ready=%d", cycle, g_astra_running, g_ws_syms_ready);')
CYCLE_DECL = '        static int s_menu_entered = 0;\n'
CYCLE_PATCH = ('if (cycle == 2) g4_touch_mb_init();\n' + CYCLE_DECL +
               '        /* Enter the menu once, but only after pcm is available; retry on\n'
               '         * later cycles until it succeeds.  Never re-issue afterwards,\n'
               '         * so the user is not yanked back while navigating. */\n'
               '        if ((cycle == 25 || cycle == 45 || cycle == 65) && !s_menu_entered) {\n'
               '            if (__atomic_load_n(&g_pcm_obj, __ATOMIC_ACQUIRE) != NULL) {\n'
               '                g5_request_screen_switch(1, "demo_menu");\n'
               '                s_menu_entered = 1;\n'
               '            } else {\n'
               '                logf_("DEMO: pcm not ready at cycle %d, will retry", cycle);\n'
               '            }\n'
               '        }\n'
               '        if (cycle == 27) {\n'
               '            void *ws0 = g_pGetWS ? g_pGetWS() : NULL;\n'
               '            uint64_t tw0 = g5_msec_now();\n'
               '            if (ws0 && g_pMove && g_pPress && g_pRel) {\n'
               '                g_pMove(ws0, 0, 320, 12, &tw0);\n'
               '                usleep(30000);\n'
               '                g_pPress(ws0, 0, 1, &tw0);\n'
               '                usleep(60000);\n'
               '                g_pRel(ws0, 0, 1, &tw0);\n'
               '                logf_("DEMO: warm-up tap sent (absorbs the first-event swallow)");\n'
               '            }\n'
               '        }\n        ' + CYCLE_ANCHOR)
if CYCLE_ANCHOR in txt:
    txt = txt.replace(CYCLE_ANCHOR, CYCLE_PATCH, 1)
    print("[+] injected g5_request_screen_switch(menu) at render cycle 25")
else:
    print("[!] render-cycle anchor not found")

# Probe: can the shim open /dev/mem?  Decides the host->guest touch channel.
PROBE_ANCHOR = 'logf_("STUB: libObj.so 探测成功: pInjS=%p, base=%p", pInjS, (void *)base);'
PROBE = (PROBE_ANCHOR +
         '\n    {'
         '\n        int _fd = open("/dev/mem", O_RDONLY | O_SYNC);'
         '\n        logf_("DEVMEM_PROBE: /dev/mem fd=%d errno=%d uid=%d", _fd, errno, (int)getuid());'
         '\n        if (_fd >= 0) close(_fd);'
         '\n        int _fd2 = open("/dev/kmem", O_RDONLY | O_SYNC);'
         '\n        logf_("DEVMEM_PROBE: /dev/kmem fd=%d errno=%d", _fd2, errno);'
         '\n        if (_fd2 >= 0) close(_fd2);'
         '\n    }')
if PROBE_ANCHOR in txt:
    txt = txt.replace(PROBE_ANCHOR, PROBE, 1)
    print("[+] injected /dev/mem probe")
else:
    print("[!] probe anchor not found")

# ---- interactive touch mailbox: host writes coords into our own page via gdbstub ----
TOUCH_BLOCK = r'''
/* ---- a6600 interactive touch mailbox ----
 * The page below stays resident; its physical address is printed so the host
 * can write {seq, x, y} into it through QEMU's gdbstub.  We poll it and inject
 * a tap into the 5th-gen widget system. */
static volatile uint32_t *g_touch_mb;
static int g_touch_mb_started;

static void *g4_touch_poll_thread(void *arg)
{
    uint32_t last = 0;
    (void)arg;
    logf_("TOUCH_POLL: thread started");
    while (1) {
        uint32_t magic = g_touch_mb[0];
        if (magic != 0u && magic != last) {
            uint32_t kind = g_touch_mb[1];
            int x1 = (int)g_touch_mb[2], y1 = (int)g_touch_mb[3];
            int x2 = (int)g_touch_mb[4], y2 = (int)g_touch_mb[5];
            void *ws = g_pGetWS ? g_pGetWS() : NULL;
            uint64_t t0 = g5_msec_now();
            last = magic;
            logf_("TOUCH_HOST: seq=%u kind=%u (%d,%d)->(%d,%d) ws=%p",
                  magic, kind, x1, y1, x2, y2, ws);
            if (ws) {
                /* The widget system needs a pointer position before it will
                 * honour a press; the very first event after a screen switch
                 * is otherwise swallowed.  Always send a warm-up move first. */
                uint64_t tw = g5_msec_now();
                if (g_pMove) g_pMove(ws, 0, 1, 1, &tw);
                usleep(15000);
                if (kind == 3u) {
                    /* host-injected 5th-gen key: x1 = press ev, y1 = release ev,
                     * x2 = hold ms.  Bypasses the dead 4th-gen input queue. */
                    uint32_t hold = (uint32_t)x2;
                    int rc1, rc2;
                    if (hold == 0u) hold = 80u;
                    if ((uint32_t)x1 == 0x02020000u) {
                        /* FN's real target (ASTRA's Fn menu) goes through
                         * translator_string_sq_speed, which asserts on this model
                         * and leaves the UI stalled.  Until that translator is
                         * fixed, map FN to MENU: both are "settings" entry points
                         * and MENU is verified working. */
                        int rf1 = g5_send_internal_event(0x0201000fu);
                        usleep(100000);
                        {
                            int rf2 = g5_send_internal_event(0x02010010u);
                            logf_("KEY_HOST: FN -> MENU fallback rc=%d/%d "
                                  "(Fn menu blocked by sq_speed assert)", rf1, rf2);
                        }
                        __atomic_store_n(&g_boost_render_flag, 1, __ATOMIC_RELEASE);
                        g5_wake_render_driver();
                        last = magic;
                        usleep(20000);
                        continue;
                    }
                    rc1 = g5_send_internal_event((uint32_t)x1);
                    usleep(hold * 1000u);
                    rc2 = g5_send_internal_event((uint32_t)y1);
                    logf_("KEY_HOST: on=0x%x rc=%d off=0x%x rc=%d hold=%ums",
                          (unsigned)x1, rc1, (unsigned)y1, rc2, hold);
                    __atomic_store_n(&g_boost_render_flag, 1, __ATOMIC_RELEASE);
                    g5_wake_render_driver();
                    last = magic;
                    usleep(20000);
                    continue;
                }
                if (kind == 2u) {
                    int s;
                    if (g_pMove) g_pMove(ws, 0, (int16_t)x1, (int16_t)y1, &t0);
                    if (g_pPress) g_pPress(ws, 0, 1, &t0);
                    for (s = 1; s <= 8; s++) {
                        uint64_t tm = g5_msec_now();
                        int mx = x1 + (x2 - x1) * s / 8;
                        int my = y1 + (y2 - y1) * s / 8;
                        if (g_pMove) g_pMove(ws, 0, (int16_t)mx, (int16_t)my, &tm);
                        usleep(25000);
                    }
                    {
                        uint64_t tr = g5_msec_now();
                        if (g_pRel) g_pRel(ws, 0, 1, &tr);
                    }
                } else {
                    uint64_t tr;
                    if (g_pMove) g_pMove(ws, 0, (int16_t)x1, (int16_t)y1, &t0);
                    usleep(30000);
                    if (g_pPress) g_pPress(ws, 0, 1, &t0);
                    usleep(1500000);
                    tr = g5_msec_now();
                    if (g_pRel) g_pRel(ws, 0, 1, &tr);
                }
                /* Do NOT push into g_touch_q here: we already injected the tap
                 * directly above.  A non-empty queue makes g5_touch_wait_ms()
                 * return immediately, which turns the render pump into a hot
                 * spin that floods the serial console and starves the guest. */
                __atomic_store_n(&g_boost_render_flag, 1, __ATOMIC_RELEASE);
                g5_wake_render_driver();
                logf_("TOUCH_HOST: injected ok");
            }
        }
        usleep(20000);
    }
    return NULL;
}

static void g4_touch_mb_init(void)
{
    uint8_t *page = NULL;
    uint64_t phys = 0;
    int fd;
    pthread_t th;
    if (g_touch_mb_started) return;
    g_touch_mb_started = 1;
    if (posix_memalign((void **)&page, 4096u, 4096u) != 0 || !page) {
        logf_("TOUCH_MB: alloc failed");
        return;
    }
    memset(page, 0, 4096u);
    g_touch_mb = (volatile uint32_t *)(void *)page;
    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd >= 0) {
        uint64_t va = (uint64_t)(uintptr_t)page;
        uint64_t ent = 0;
        off_t off = (off_t)((va >> 12) * 8ull);
        if (pread(fd, &ent, 8, off) == 8) {
            uint64_t pfn = ent & ((1ull << 55) - 1ull);
            if (pfn != 0ull) phys = (pfn << 12) | (va & 0xfffull);
        }
        close(fd);
    }
    logf_("TOUCH_MB: virt=%p phys=0x%llx", (void *)page, (unsigned long long)phys);
    if (pthread_create(&th, NULL, g4_touch_poll_thread, NULL) == 0) {
        pthread_detach(th);
    }
}

'''
TOUCH_ANCHOR = ('static int hook_callback_tp_raw(uintptr_t a0, uintptr_t a1, '
                'uintptr_t a2, uintptr_t a3)')
if TOUCH_ANCHOR in txt:
    txt = txt.replace(TOUCH_ANCHOR, TOUCH_BLOCK + TOUCH_ANCHOR, 1)
    print("[+] injected touch mailbox + poll thread")
else:
    print("[!] touch anchor not found")



OUT_SRC.write_text(txt, encoding='utf-8')

CC = [sys.executable, '-m', 'ziglang', 'cc', '-target', 'arm-linux-gnueabi.2.4']
base_cmd = [*CC, '-mcpu=cortex_a9', '-mthumb', '-shared', '-fPIC', '-O2', '-s',
            '-I', str(REPO / 'src'),
            '-Wall', '-Wextra', '-Wno-unused-function',
            '-fvisibility=hidden', '-DASTRA_STACK_SIZE=(16u*1024u*1024u)',
            '-Wl,-z,lazy', '-Wl,-z,norelro', '-Wl,-z,max-page-size=0x1000',
            '-Wl,-soname,appFwBoot.so', '-o', str(OUT_SO), str(OUT_SRC)]
print("[*] " + " ".join(base_cmd))
p = subprocess.run(base_cmd, capture_output=True, text=True)
if p.returncode != 0:
    print("BUILD FAILED")
    print(p.stdout[-3000:])
    print(p.stderr[-6000:])
    sys.exit(1)
print("[+] built", OUT_SO, f"{OUT_SO.stat().st_size:,} B")

raw = bytearray(OUT_SO.read_bytes())
old_flags = struct.unpack_from('<I', raw, 36)[0]
struct.pack_into('<I', raw, 36, 0x05000002)
OUT_SO.write_bytes(raw)
print(f"[+] e_flags 0x{old_flags:08x} -> 0x05000002")

# ABI report
def sh(c):
    return subprocess.run(c, capture_output=True, text=True).stdout

und = [l.split()[-1] for l in sh(['readelf', '--dyn-syms', '-W', str(OUT_SO)]).splitlines()
       if ' UND ' in l and l.strip()]
verl = [l for l in sh(['readelf', '-V', '-W', str(OUT_SO)]).splitlines() if 'GLIBC' in l]
vers = sorted({m.group(0) for l in verl for m in [re.search(r'GLIBC_[0-9.]+', l)] if m})
print(f"[+] GLIBC requirements: {vers}")
bad = [v for v in vers if tuple(map(int, v[6:].split('.')[:2])) > (2, 11)]
print(f"[+] too-new requirements: {bad if bad else 'none'}")
print(f"[+] exports: {sorted({l.split()[-1] for l in sh(['readelf','--dyn-syms','-W',str(OUT_SO)]).splitlines() if ' GLOBAL ' in l and ' UND ' not in l and 'DEFAULT' in l})[:8]}")
