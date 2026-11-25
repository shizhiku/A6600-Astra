/* Emulator-only touch injector.
 *
 * Waits until the UI has loaded libObj into the global scope, then resolves
 * WidgetSystem symbols with dlsym(RTLD_DEFAULT, ...).  Touch commands are
 * consumed from /tmp/touchcmd: complete lines "x y kind" (kind 0=tap,
 * 1=down, 2=move, 3=up).  The host writes a new file atomically with
 *   printf 'x y k\n' > /tmp/touchcmd.new; mv /tmp/touchcmd.new /tmp/touchcmd
 * The preload unlinks the file after consuming it.
 * GLIBC_2.4-only symbols (no sscanf/fstat).
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define CMD_FILE "/tmp/touchcmd"

typedef void *(*get_ws_fn)(void);
typedef void (*press_fn)(void *, unsigned char, unsigned char, const uint64_t *);
typedef void (*rel_fn)(void *, unsigned char, unsigned char, const uint64_t *);
typedef void (*move_fn)(void *, unsigned char, short, short, const uint64_t *);

static void logline(const char *s)
{
    FILE *f = fopen("/dev/console", "w");
    if (f) { fputs(s, f); fputc('\n', f); fclose(f); }
}

static get_ws_fn get_ws;
static press_fn do_press;
static rel_fn do_rel;
static move_fn do_move;

static int resolve_symbols(void)
{
    get_ws = (get_ws_fn)dlsym(RTLD_DEFAULT,
                    "_ZN2ux6wgtsys12WidgetSystem15sys_getInstanceEv");
    do_press = (press_fn)dlsym(RTLD_DEFAULT,
                    "_ZN2ux6wgtsys12WidgetSystem14postMousePressEhhNS_4core8MsecTimeE");
    do_rel = (rel_fn)dlsym(RTLD_DEFAULT,
                    "_ZN2ux6wgtsys12WidgetSystem16postMouseReleaseEhhNS_4core8MsecTimeE");
    do_move = (move_fn)dlsym(RTLD_DEFAULT,
                    "_ZN2ux6wgtsys12WidgetSystem13postMouseMoveEhssNS_4core8MsecTimeE");
    return get_ws && do_press && do_rel && do_move;
}

static void apply(void *ws, int x, int y, int kind)
{
    uint64_t t = 0;
    if (kind == 1) {
        do_move(ws, 0, (short)x, (short)y, &t);
        do_press(ws, 0, 1, &t);
    } else if (kind == 2) {
        do_move(ws, 0, (short)x, (short)y, &t);
    } else if (kind == 3) {
        do_move(ws, 0, (short)x, (short)y, &t);
        do_rel(ws, 0, 1, &t);
    } else {
        do_move(ws, 0, (short)x, (short)y, &t);
        do_press(ws, 0, 1, &t);
        do_rel(ws, 0, 1, &t);
    }
}

static const char *parse_int(const char *p, int *out)
{
    int neg = 0, v = 0, any = 0;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '-') { neg = 1; p++; }
    while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; any = 1; }
    if (!any) return NULL;
    *out = neg ? -v : v;
    return p;
}

static void process_line(void *ws, char *line)
{
    int x, y, k;
    const char *p = line;
    p = parse_int(p, &x); if (!p) return;
    p = parse_int(p, &y); if (!p) return;
    p = parse_int(p, &k); if (!p) return;
    apply(ws, x, y, k);
    {
        char lb[128];
        snprintf(lb, sizeof(lb), "[TOUCHINJ] apply x=%d y=%d kind=%d", x, y, k);
        logline(lb);
    }
}

static void *touch_thread(void *arg)
{
    (void)arg;
    void *ws = NULL;
    int tries;
    char buf[4096];

    for (tries = 0; tries < 1200; tries++) {
        if (!resolve_symbols()) { usleep(250000); continue; }
        ws = get_ws();
        if (ws) break;
        usleep(250000);
    }
    if (!ws) { logline("[TOUCHINJ] WidgetSystem not ready, exit"); return NULL; }
    logline("[TOUCHINJ] WidgetSystem ready; watching /tmp/touchcmd");

    for (;;) {
        int fd = open(CMD_FILE, O_RDONLY);
        if (fd >= 0) {
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            unlink(CMD_FILE);
            if (n > 0) {
                char *p, *nl;
                buf[n] = 0;
                p = buf;
                while ((nl = strchr(p, '\n')) != NULL) {
                    *nl = 0;
                    process_line(ws, p);
                    p = nl + 1;
                }
            }
        }
        usleep(100000);
    }
    return NULL;
}

__attribute__((constructor)) static void init(void)
{
    pthread_t th;
    if (pthread_create(&th, NULL, touch_thread, NULL) == 0)
        pthread_detach(th);
}
