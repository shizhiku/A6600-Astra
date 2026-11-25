/* OBSOLETE: the original 0x1AC-as-MENU assumption in this diagnostic was wrong.
 * Do not use it as a working MENU injector. Use 92_native_menu_probe.c or the
 * preload-free hardware sequence in 92_experiments.py instead.
 */
/* Diagnostic-only a6600 UI MENU injector for the emulated im.elf process.
 * Build for the camera ARM userland:
 *   arm-linux-gnueabi-gcc -shared -fPIC -O2 -pthread -ldl -o libinject_menu.so inject_menu_preload.c
 * Load only in the emulator with LD_PRELOAD. It does not access /dev/input or /dev/uipc.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

typedef void *(*create_event_fn)(void *self, unsigned long event_id,
                                 unsigned char dest);
typedef void (*push_event_fn)(void *self, void *event);
typedef void (*physical_cb_fn)(int callback_id, void *infra_input_event);

struct infra_input_event {
    uint32_t key_code;
    uint32_t sub_key_code;
    uint32_t status;
    uint32_t ex_info;
    uint32_t sub_id;
    uint32_t reserved;
};

static void *inject_thread(void *unused)
{
    static const char singleton_sym[] = "_ZN12InputService13m_pMyInstanceE";
    static const char create_sym[] = "_ZN12InputService11createEventEmh";
    static const char push_sym[] = "_ZN12InputService15pushFilterEventEP5Event";
    static const char callback_sym[] = "_ZN12InputService15callback_directEiP16_InfraInputEvent";
    void **singleton = NULL;
    create_event_fn create_event = NULL;
    push_event_fn push_event = NULL;
    physical_cb_fn physical_cb = NULL;
    unsigned int tries;

    (void)unused;
    for (tries = 0; tries < 120; ++tries) {
        singleton = (void **)dlsym(RTLD_DEFAULT, singleton_sym);
        create_event = (create_event_fn)dlsym(RTLD_DEFAULT, create_sym);
        push_event = (push_event_fn)dlsym(RTLD_DEFAULT, push_sym);
        physical_cb = (physical_cb_fn)dlsym(RTLD_DEFAULT, callback_sym);
        if (singleton && *singleton && create_event && push_event)
            break;
        usleep(250000);
    }
    if (!singleton || !*singleton || !create_event || !push_event) {
        fprintf(stderr, "[inject-menu] InputService unavailable\n");
        return NULL;
    }

    /* Let the initial View and trigger table finish attaching. */
    sleep(3);

    /* Lowest-risk path: the physical converter itself creates an Event whose
     * event_id is key_code and adds status/ex_info/sub_id parameters. Try a
     * conventional press/release pair. If its synchronous InputServant send
     * blocks in a particular build, define A6600_MENU_DIRECT_EVENT at compile
     * time to use the event bus directly instead. */
#ifndef A6600_MENU_DIRECT_EVENT
    if (physical_cb) {
        struct infra_input_event ev = {0x000001acU, 0, 1, 0, 0, 0};
        physical_cb(0, &ev);
        usleep(100000);
        ev.status = 0;
        physical_cb(0, &ev);
        fprintf(stderr, "[inject-menu] sent KEY_TACT_MENU press/release\n");
        return NULL;
    }
#endif

    {
        void *event = create_event(*singleton, 0x000001acUL, 4);
        if (event) {
            push_event(*singleton, event);
            fprintf(stderr, "[inject-menu] pushed KEY_TACT_MENU event\n");
        } else {
            fprintf(stderr, "[inject-menu] createEvent failed\n");
        }
    }
    return NULL;
}

__attribute__((constructor)) static void start_injector(void)
{
    pthread_t thread;
    if (pthread_create(&thread, NULL, inject_thread, NULL) == 0)
        pthread_detach(thread);
}
