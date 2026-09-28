/* SPDX-License-Identifier: BSD-2-Clause */
/* Deferred configuration hooks for imported FreeBSD drivers. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/sleep.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/kernel.h"
#include "compat/freebsd/sys/mutex.h"
#include "compat/freebsd/sys/taskqueue.h"

#define BSD_INTRHOOK_EINVAL 22
#define BSD_INTRHOOK_ENOMEM 12

struct oneshot_config_hook {
    struct intr_config_hook hook;
    ich_func_t function;
    void *argument;
};

static struct intr_config_hook *g_intrhook_head;
static struct intr_config_hook *g_intrhook_tail;
static struct mtx g_intrhook_lock;
static int g_intrhook_ready;
static int g_intrhook_running;

static void config_intrhook_task(void *argument, int pending);

static struct task g_intrhook_task =
    TASK_INITIALIZER(0, config_intrhook_task, 0);

MTX_SYSINIT(intr_config_hook, &g_intrhook_lock, "intr config", MTX_DEF);

static struct intr_config_hook **
config_intrhook_find_locked(struct intr_config_hook *hook)
{
    struct intr_config_hook **position = &g_intrhook_head;

    while (*position && *position != hook)
        position = &(*position)->ich_links.stqe_next;
    return position;
}

static void
config_intrhook_remove_locked(struct intr_config_hook *hook)
{
    struct intr_config_hook **position =
        config_intrhook_find_locked(hook);

    if (*position != hook)
        bsd_bridge_panic_stop();
    *position = hook->ich_links.stqe_next;
    if (g_intrhook_tail == hook) {
        g_intrhook_tail = 0;
        for (struct intr_config_hook *entry = g_intrhook_head; entry;
            entry = entry->ich_links.stqe_next)
            g_intrhook_tail = entry;
    }
    hook->ich_links.stqe_next = 0;
    __atomic_store_n(&hook->ich_state, ICHS_DONE, __ATOMIC_RELEASE);
    bsd_wakeup(hook);
}

static void
config_intrhook_run_pending(void)
{
    mtx_lock(&g_intrhook_lock);
    if (g_intrhook_running) {
        mtx_unlock(&g_intrhook_lock);
        return;
    }
    g_intrhook_running = 1;
    for (;;) {
        struct intr_config_hook *hook = g_intrhook_head;

        while (hook && __atomic_load_n(
            &hook->ich_state, __ATOMIC_ACQUIRE) != ICHS_QUEUED)
            hook = hook->ich_links.stqe_next;
        if (!hook) {
            g_intrhook_running = 0;
            mtx_unlock(&g_intrhook_lock);
            return;
        }
        __atomic_store_n(
            &hook->ich_state, ICHS_RUNNING, __ATOMIC_RELEASE);
        mtx_unlock(&g_intrhook_lock);
        hook->ich_func(hook->ich_arg);
        mtx_lock(&g_intrhook_lock);
    }
}

static void
config_intrhook_task(void *argument, int pending)
{
    (void)argument;
    (void)pending;
    config_intrhook_run_pending();
}

static void
config_intrhook_boot(void *argument)
{
    (void)argument;
    mtx_lock(&g_intrhook_lock);
    g_intrhook_ready = 1;
    mtx_unlock(&g_intrhook_lock);
    config_intrhook_run_pending();
}

SYSINIT(intr_config_hooks, SI_SUB_INT_CONFIG_HOOKS, SI_ORDER_FIRST,
    config_intrhook_boot, 0);

int
config_intrhook_establish(struct intr_config_hook *hook)
{
    int schedule;

    if (!hook || !hook->ich_func)
        return BSD_INTRHOOK_EINVAL;
    mtx_lock(&g_intrhook_lock);
    if (*config_intrhook_find_locked(hook)) {
        mtx_unlock(&g_intrhook_lock);
        return BSD_INTRHOOK_EINVAL;
    }
    hook->ich_links.stqe_next = 0;
    __atomic_store_n(&hook->ich_state, ICHS_QUEUED, __ATOMIC_RELEASE);
    if (g_intrhook_tail)
        g_intrhook_tail->ich_links.stqe_next = hook;
    else
        g_intrhook_head = hook;
    g_intrhook_tail = hook;
    schedule = g_intrhook_ready;
    mtx_unlock(&g_intrhook_lock);

    if (schedule && taskqueue_enqueue(
        taskqueue_thread, &g_intrhook_task) != 0) {
        mtx_lock(&g_intrhook_lock);
        if (*config_intrhook_find_locked(hook) == hook &&
            __atomic_load_n(&hook->ich_state,
            __ATOMIC_ACQUIRE) == ICHS_QUEUED)
            config_intrhook_remove_locked(hook);
        mtx_unlock(&g_intrhook_lock);
        return BSD_INTRHOOK_ENOMEM;
    }
    return 0;
}

void
config_intrhook_disestablish(struct intr_config_hook *hook)
{
    if (!hook)
        bsd_bridge_panic_stop();
    mtx_lock(&g_intrhook_lock);
    config_intrhook_remove_locked(hook);
    mtx_unlock(&g_intrhook_lock);
}

int
config_intrhook_drain(struct intr_config_hook *hook)
{
    uintptr_t initial_state;

    if (!hook)
        return BSD_INTRHOOK_EINVAL;
    mtx_lock(&g_intrhook_lock);
    initial_state = __atomic_load_n(
        &hook->ich_state, __ATOMIC_ACQUIRE);
    if (initial_state == ICHS_DONE) {
        mtx_unlock(&g_intrhook_lock);
        return ICHS_DONE;
    }
    if (initial_state == ICHS_QUEUED) {
        config_intrhook_remove_locked(hook);
        mtx_unlock(&g_intrhook_lock);
        return ICHS_QUEUED;
    }
    if (initial_state != ICHS_RUNNING) {
        mtx_unlock(&g_intrhook_lock);
        return BSD_INTRHOOK_EINVAL;
    }
    mtx_unlock(&g_intrhook_lock);
    while (__atomic_load_n(
        &hook->ich_state, __ATOMIC_ACQUIRE) != ICHS_DONE)
        (void)bsd_pause("confhd", 1);
    return ICHS_RUNNING;
}

static void
config_intrhook_oneshot_callback(void *argument)
{
    struct oneshot_config_hook *oneshot = argument;

    oneshot->function(oneshot->argument);
    config_intrhook_disestablish(&oneshot->hook);
    bsd_free(oneshot, M_DEVBUF);
}

void
config_intrhook_oneshot(ich_func_t function, void *argument)
{
    struct oneshot_config_hook *oneshot;

    if (!function)
        return;
    oneshot = bsd_malloc(
        sizeof(*oneshot), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!oneshot)
        return;
    oneshot->function = function;
    oneshot->argument = argument;
    oneshot->hook.ich_func = config_intrhook_oneshot_callback;
    oneshot->hook.ich_arg = oneshot;
    if (config_intrhook_establish(&oneshot->hook) != 0)
        bsd_free(oneshot, M_DEVBUF);
}
