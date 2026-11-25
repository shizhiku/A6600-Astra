/* Emulator-only bridge v6 for the ASTRA (a6600-body + 5th-gen lib) route.
 *
 * Bridge v5 called a hand-picked list of 5th-gen init entries.  Bridge v6
 * replays the full "before Application" task list decoded from the 5th-gen
 * IMDB table (118 records), keeping only the tasks that are executable in the
 * current run image (58 tasks, see 97_astra_inits_v6.h):
 *
 *   - psid != 0  -> entry comes from the statically merged 5th-gen libObj,
 *                   reached through /usr/lib/a5bObj.so (lib == NULL),
 *   - psid == 0  -> entry comes from /usr/lib/a5b<file>.so in the run image.
 *
 * The tasks are replayed in factory IMDB table order, grouped by the IMDB
 * stage flag:
 *   group 0 = main   -> run on the calling thread, one after another,
 *   group 1 = INFRA0 -> one worker thread,
 *   group 2 = INFRA1 -> one worker thread,
 *   group 3 = INFRA2 -> one worker thread,
 * each worker thread walking the table order of its own group.
 *
 * Every init call runs in its own transient thread and is waited for at most
 * ASTRA97_INIT_TIMEOUT_MS (2000 ms) so a hanging entry (e.g. grm_init) cannot
 * block the rest of the boot.  The three infra groups are awaited together for
 * at most ASTRA97_TOTAL_WAIT_MS (90 s), then /usr/lib/a5pFwBoot.so is loaded
 * and its Application_System_Init is called, exactly like bridge v5 did.
 *
 * Build (WSL):
 *   arm-linux-gnueabi-gcc -shared -fPIC -O2 -Wall -Wextra -Werror \
 *       -o 04-产物/libastra_bridge97_v6.so 04-产物/97_astra_bridge6.c \
 *       03-证据/静态分析/97_abi/a6_libpthread.so \
 *       03-证据/静态分析/97_abi/a6_libdl_real.so
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "97_astra_inits_v6.h"

#define ASTRA97_INIT_TIMEOUT_MS 2000
#define ASTRA97_TOTAL_WAIT_MS 90000
#define ASTRA97_POLL_MS 10
#define ASTRA97_LOG_BUF 256
#define ASTRA97_MAX_HANDLES 64
#define ASTRA97_HANDLE_PATH 128

/* Always bind to the device glibc 2.11 (GLIBC_2.4 level) ABI, never to the
 * build host's newer dl* symbols. */
extern void *old_dlopen(const char *, int);
extern void *old_dlsym(void *, const char *);
extern char *old_dlerror(void);
__asm__(".symver old_dlopen,dlopen@GLIBC_2.4");
__asm__(".symver old_dlsym,dlsym@GLIBC_2.4");
__asm__(".symver old_dlerror,dlerror@GLIBC_2.4");

static int astra97_dl_flags = RTLD_LAZY | RTLD_GLOBAL | RTLD_DEEPBIND;

/* ------------------------------------------------------------------ */
/* console logging                                                     */
/* ------------------------------------------------------------------ */
static void logmsg(const char *msg)
{
    FILE *f = fopen("/dev/console", "w");
    if (f) {
        fputs(msg, f);
        fputc('\n', f);
        fclose(f);
    }
}

/* ------------------------------------------------------------------ */
/* handles                                                             */
/* ------------------------------------------------------------------ */
static void *g_obj_handle;   /* /usr/lib/a5bObj.so: lib == NULL tasks */
static void *g_mwf_handle;   /* /usr/lib/a5bMWF.so: loaded up front     */

struct astra97_handle {
    char path[ASTRA97_HANDLE_PATH];
    void *handle;
};

static struct astra97_handle g_handles[ASTRA97_MAX_HANDLES];
static int g_handle_count;
static pthread_mutex_t g_handle_lock = PTHREAD_MUTEX_INITIALIZER;

static void log_dlopen_failed(const char *path)
{
    char b[ASTRA97_LOG_BUF];
    const char *err = old_dlerror();
    snprintf(b, sizeof(b), "[INIT6] dlopen failed: %s (%s)",
             path, err ? err : "unknown");
    logmsg(b);
}

/* The three infra groups walk the table concurrently, so the handle cache
 * needs a lock; dlopen() itself is thread-safe and stays outside the lock. */
static void *astra97_get_handle(const char *lib)
{
    void *h = NULL;
    int i;

    if (lib == NULL)
        return g_obj_handle;

    pthread_mutex_lock(&g_handle_lock);
    for (i = 0; i < g_handle_count; i++) {
        if (strcmp(g_handles[i].path, lib) == 0) {
            h = g_handles[i].handle;
            break;
        }
    }
    pthread_mutex_unlock(&g_handle_lock);
    if (h != NULL)
        return h;

    h = old_dlopen(lib, astra97_dl_flags);
    if (h == NULL) {
        log_dlopen_failed(lib);
        return NULL;
    }

    pthread_mutex_lock(&g_handle_lock);
    if (g_handle_count < ASTRA97_MAX_HANDLES) {
        snprintf(g_handles[g_handle_count].path,
                 sizeof(g_handles[g_handle_count].path), "%s", lib);
        g_handles[g_handle_count].handle = h;
        g_handle_count++;
    }
    pthread_mutex_unlock(&g_handle_lock);
    return h;
}

/* ------------------------------------------------------------------ */
/* per-init transient thread                                           */
/* ------------------------------------------------------------------ */
struct astra97_job {
    void *fn;
    volatile int done;
    int rc;
};

static struct astra97_job g_jobs[ASTRA97_INIT_COUNT];

struct astra97_group_stat {
    volatile int done;
    volatile int timeout;
    volatile int skip;
};

static struct astra97_group_stat g_stat[ASTRA97_GROUP_COUNT];
static volatile int g_group_done[ASTRA97_GROUP_COUNT];

static void *astra97_init_thread(void *arg)
{
    struct astra97_job *job = (struct astra97_job *)arg;
    job->rc = ((int (*)(const char *))job->fn)(NULL);
    job->done = 1;
    return NULL;
}

/* NOTE: no gettimeofday()/clock_gettime() here.  The Ubuntu ARM cross
 * toolchain maps them to __gettimeofday64@GLIBC_2.34, which the camera
 * glibc 2.11 cannot resolve; bridge v6 therefore counts 10 ms poll ticks
 * for both the per-init cap and the 90 s group cap (GLIBC_2.4 only). */

/* Run one generated task (index into astra97_inits[]) with a 2 s cap. */
static void astra97_run_task(int idx)
{
    const struct astra97_init *task = &astra97_inits[idx];
    struct astra97_job *job = &g_jobs[idx];
    const char *libname = task->lib ? task->lib : "libObj";
    struct astra97_group_stat *st = &g_stat[task->group];
    char b[ASTRA97_LOG_BUF];
    void *handle;
    void *fn;
    pthread_t th;
    int waited;

    handle = astra97_get_handle(task->lib);
    if (handle == NULL) {
        snprintf(b, sizeof(b), "[INIT6] g=%d %s %s rc=SKIP",
                 task->group, task->entry, libname);
        logmsg(b);
        st->skip++;
        return;
    }
    fn = old_dlsym(handle, task->entry);
    if (fn == NULL) {
        snprintf(b, sizeof(b), "[INIT6] g=%d %s %s rc=SKIP",
                 task->group, task->entry, libname);
        logmsg(b);
        st->skip++;
        return;
    }

    job->fn = fn;
    job->done = 0;
    job->rc = -999;
    if (pthread_create(&th, NULL, astra97_init_thread, job) != 0) {
        snprintf(b, sizeof(b), "[INIT6] g=%d %s %s rc=SKIP",
                 task->group, task->entry, libname);
        logmsg(b);
        st->skip++;
        return;
    }
    pthread_detach(th);

    for (waited = 0; waited < ASTRA97_INIT_TIMEOUT_MS / ASTRA97_POLL_MS; waited++) {
        if (job->done)
            break;
        usleep(ASTRA97_POLL_MS * 1000);
    }
    if (!job->done) {
        snprintf(b, sizeof(b), "[INIT6] g=%d %s %s rc=TIMEOUT",
                 task->group, task->entry, libname);
        logmsg(b);
        st->timeout++;
        return;
    }
    snprintf(b, sizeof(b), "[INIT6] g=%d %s %s rc=%d",
             task->group, task->entry, libname, job->rc);
    logmsg(b);
    st->done++;
}

/* ------------------------------------------------------------------ */
/* groups                                                              */
/* ------------------------------------------------------------------ */
static void astra97_log_group_begin(int group, int tasks)
{
    char b[ASTRA97_LOG_BUF];
    snprintf(b, sizeof(b), "[INIT6] g=%d %s BEGIN tasks=%d",
             group, group == 0 ? "main" : "infra", tasks);
    logmsg(b);
}

static void astra97_log_group_end(int group)
{
    char b[ASTRA97_LOG_BUF];
    snprintf(b, sizeof(b), "[INIT6] g=%d END done=%d timeout=%d skip=%d",
             group, g_stat[group].done, g_stat[group].timeout,
             g_stat[group].skip);
    logmsg(b);
}

static void astra97_run_group(int group)
{
    int i;
    int tasks = 0;

    for (i = 0; i < ASTRA97_INIT_COUNT; i++) {
        if (astra97_inits[i].group == group)
            tasks++;
    }
    astra97_log_group_begin(group, tasks);
    for (i = 0; i < ASTRA97_INIT_COUNT; i++) {
        if (astra97_inits[i].group == group)
            astra97_run_task(i);
    }
    astra97_log_group_end(group);
}

struct astra97_group_arg {
    int group;
};

static void *astra97_group_thread(void *arg)
{
    struct astra97_group_arg *ga = (struct astra97_group_arg *)arg;
    astra97_run_group(ga->group);
    g_group_done[ga->group] = 1;
    return NULL;
}

/* ------------------------------------------------------------------ */
/* entry point                                                         */
/* ------------------------------------------------------------------ */
void Application_System_Init(const char *config)
{
    const char *translated = config;
    struct astra97_group_arg gargs[ASTRA97_GROUP_COUNT];
    pthread_t threads[ASTRA97_GROUP_COUNT];
    void *fw;
    void *boot;
    void *sym;
    void (*entry)(const char *);
    char b[ASTRA97_LOG_BUF];
    int group;
    int all_done;
    int polls;

    if (config && strcmp(config, "AdjChkConfig.so") == 0)
        translated = "a5jChkConfig.so";
    logmsg("[INIT6] bridge6 enter");

    fw = old_dlopen("/usr/lib/a5pFw.so", astra97_dl_flags);
    if (fw == NULL) {
        log_dlopen_failed("/usr/lib/a5pFw.so");
        return;
    }
    logmsg("[INIT6] a5pFw loaded");

    g_obj_handle = old_dlopen("/usr/lib/a5bObj.so", astra97_dl_flags);
    if (g_obj_handle == NULL)
        log_dlopen_failed("/usr/lib/a5bObj.so");
    else
        logmsg("[INIT6] a5bObj loaded");

    g_mwf_handle = old_dlopen("/usr/lib/a5bMWF.so", astra97_dl_flags);
    if (g_mwf_handle == NULL)
        log_dlopen_failed("/usr/lib/a5bMWF.so");
    else
        logmsg("[INIT6] a5bMWF loaded");

    for (group = 0; group < ASTRA97_GROUP_COUNT; group++) {
        g_stat[group].done = 0;
        g_stat[group].timeout = 0;
        g_stat[group].skip = 0;
        g_group_done[group] = 0;
    }

    /* main group: caller thread, factory table order */
    astra97_run_group(ASTRA97_GROUP_MAIN);
    g_group_done[ASTRA97_GROUP_MAIN] = 1;

    /* INFRA0/1/2: one worker thread each, factory table order within group */
    for (group = ASTRA97_GROUP_INFRA0; group <= ASTRA97_GROUP_INFRA2; group++) {
        gargs[group].group = group;
        if (pthread_create(&threads[group], NULL, astra97_group_thread,
                           &gargs[group]) == 0) {
            pthread_detach(threads[group]);
        } else {
            snprintf(b, sizeof(b),
                     "[INIT6] g=%d thread create failed; running inline", group);
            logmsg(b);
            astra97_run_group(group);
            g_group_done[group] = 1;
        }
    }

    /* wait for the infra groups, total cap 90 s (counted 10 ms polls) */
    polls = 0;
    for (;;) {
        all_done = 1;
        for (group = ASTRA97_GROUP_INFRA0; group <= ASTRA97_GROUP_INFRA2; group++) {
            if (!g_group_done[group])
                all_done = 0;
        }
        if (all_done)
            break;
        polls++;
        if (polls >= ASTRA97_TOTAL_WAIT_MS / ASTRA97_POLL_MS) {
            snprintf(b, sizeof(b),
                     "[INIT6] infra wait cap %d ms reached",
                     ASTRA97_TOTAL_WAIT_MS);
            logmsg(b);
            break;
        }
        usleep(ASTRA97_POLL_MS * 1000);
    }
    snprintf(b, sizeof(b),
             "[INIT6] init table done: main=%d/%d infra0=%d/%d infra1=%d/%d infra2=%d/%d",
             g_stat[0].done, ASTRA97_GROUP0_COUNT,
             g_stat[1].done, ASTRA97_GROUP1_COUNT,
             g_stat[2].done, ASTRA97_GROUP2_COUNT,
             g_stat[3].done, ASTRA97_GROUP3_COUNT);
    logmsg(b);

    /* factory boot wrapper last, exactly like bridge v5 */
    boot = old_dlopen("/usr/lib/a5pFwBoot.so", astra97_dl_flags);
    if (boot == NULL) {
        log_dlopen_failed("/usr/lib/a5pFwBoot.so");
        return;
    }
    sym = old_dlsym(boot, "Application_System_Init");
    if (sym == NULL) {
        logmsg("[INIT6] appFwBoot Application_System_Init lookup failed");
        return;
    }
    entry = (void (*)(const char *))sym;
    logmsg("[INIT6] call appFwBoot Application_System_Init");
    entry(translated);
    logmsg("[INIT6] appFwBoot Application_System_Init returned");
}
