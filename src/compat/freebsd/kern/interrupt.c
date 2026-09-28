/* SPDX-License-Identifier: MPL-2.0 */
/* Shared interrupt lifecycle for BSD drivers on EdgeOS. */

#include <stdint.h>

#include "compat/freebsd/edgeos/interrupt.h"
#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/resource.h"
#include "compat/freebsd/edgeos/taskqueue.h"
#include "compat/freebsd/machine/resource.h"
#include "compat/freebsd/sys/interrupt.h"
#include "compat/freebsd/sys/rman.h"

#define BSD_INTERRUPT_ENXIO 6
#define BSD_INTERRUPT_ENOMEM 12
#define BSD_INTERRUPT_EBUSY 16
#define BSD_INTERRUPT_EINVAL 22
#define BSD_INTERRUPT_ENOTSUP 45
#define BSD_INTERRUPT_COUNTERS 256u

static unsigned long g_interrupt_counters[BSD_INTERRUPT_COUNTERS];
static volatile unsigned int g_interrupt_counter_count;

void
intrcnt_add(const char *name, unsigned long **counter)
{
    unsigned int index;

    (void)name;
    if (!counter)
        return;
    index = __atomic_fetch_add(&g_interrupt_counter_count, 1u,
        __ATOMIC_ACQ_REL);
    if (index >= BSD_INTERRUPT_COUNTERS) {
        *counter = &g_interrupt_counters[BSD_INTERRUPT_COUNTERS - 1u];
        return;
    }
    g_interrupt_counters[index] = 0;
    *counter = &g_interrupt_counters[index];
}

typedef struct {
    bsd_interrupt_backend_ops_t operations;
    uint8_t initialized;
} bsd_interrupt_runtime_t;

typedef struct bsd_interrupt_cookie {
    struct bsd_interrupt_cookie *registry_next;
    device_t device;
    struct resource *resource;
    driver_filter_t *filter;
    driver_intr_t *handler;
    void *argument;
    void *backend_cookie;
    struct task deferred_task;
    struct taskqueue *thread_queue;
    int flags;
    volatile unsigned int active;
    volatile unsigned int drain_refs;
    volatile uint8_t tearing_down;
    volatile uint8_t suspended;
    volatile uint8_t deferred_masked;
    uint8_t uses_taskqueue;
    struct intr_event *software_event;
} bsd_interrupt_cookie_t;

struct intr_event {
    volatile unsigned int handler_count;
    int priority;
};

struct intr_event *clk_intr_event;

static bsd_interrupt_runtime_t g_interrupt_runtime;
static volatile unsigned int g_interrupt_init_guard;
static volatile unsigned int g_interrupt_registry_guard;
static bsd_interrupt_cookie_t *g_interrupt_cookies;

static void
interrupt_registry_lock(void)
{
    while (__atomic_test_and_set(&g_interrupt_registry_guard,
        __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
interrupt_registry_unlock(void)
{
    __atomic_clear(&g_interrupt_registry_guard, __ATOMIC_RELEASE);
}

static void
interrupt_registry_add(bsd_interrupt_cookie_t *cookie)
{
    interrupt_registry_lock();
    cookie->registry_next = g_interrupt_cookies;
    g_interrupt_cookies = cookie;
    interrupt_registry_unlock();
}

static void
interrupt_registry_remove(bsd_interrupt_cookie_t *cookie)
{
    bsd_interrupt_cookie_t **cursor;

    interrupt_registry_lock();
    for (cursor = &g_interrupt_cookies; *cursor;
        cursor = &(*cursor)->registry_next) {
        if (*cursor == cookie) {
            *cursor = cookie->registry_next;
            cookie->registry_next = 0;
            break;
        }
    }
    interrupt_registry_unlock();
}

static void
interrupt_relax(void)
{
#if defined(__x86_64__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__)
    __asm__ __volatile__("yield");
#endif
}

#if !defined(BSD_BRIDGE_HOST_TEST) || \
    defined(BSD_BRIDGE_INTRNG_HOST_TEST)
static int
interrupt_resource_uses_intrng(const struct resource *resource)
{
    return bsd_intrng_resource_is_mapped(resource);
}
#endif

static int
interrupt_resource_is_owned_by_lineage(device_t device,
    const struct resource *resource)
{
    device_t owner;
    device_t cursor;
    unsigned int depth;

    if (!device || !resource)
        return 0;
    owner = rman_get_device(resource);
    if (!owner)
        return 0;

    /*
     * FreeBSD buses may reserve a resource on a parent and lend the same
     * resource to a child.  atkbdc does this for its keyboard IRQ.  Preserve
     * that ownership model while rejecting resources from unrelated trees.
     */
    cursor = device;
    for (depth = 0; cursor && depth < 256; ++depth) {
        if (cursor == owner)
            return 1;
        cursor = device_get_parent(cursor);
    }
    return 0;
}

__attribute__((weak))
int
bsd_interrupt_arch_initialize(void)
{
    return BSD_INTERRUPT_ENXIO;
}

static void
interrupt_init_lock(void)
{
    while (__atomic_test_and_set(&g_interrupt_init_guard,
        __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
interrupt_init_unlock(void)
{
    __atomic_clear(&g_interrupt_init_guard, __ATOMIC_RELEASE);
}

int
bsd_interrupt_initialize(const bsd_interrupt_backend_ops_t *operations)
{
    if (!operations || !operations->register_interrupt ||
        !operations->unregister_interrupt)
        return BSD_INTERRUPT_EINVAL;
    interrupt_init_lock();
    if (g_interrupt_runtime.initialized) {
        interrupt_init_unlock();
        return BSD_INTERRUPT_EBUSY;
    }
    g_interrupt_runtime.operations = *operations;
    __atomic_store_n(&g_interrupt_runtime.initialized, 1,
        __ATOMIC_RELEASE);
    interrupt_init_unlock();
    return 0;
}

int
bsd_interrupt_is_initialized(void)
{
    return __atomic_load_n(&g_interrupt_runtime.initialized,
        __ATOMIC_ACQUIRE) != 0;
}

int
bsd_interrupt_ensure_initialized(void)
{
    int result;

    if (bsd_interrupt_is_initialized())
        return 0;
    result = bsd_interrupt_arch_initialize();
    if (result == BSD_INTERRUPT_EBUSY && bsd_interrupt_is_initialized())
        return 0;
    return bsd_interrupt_is_initialized() ? 0 : result;
}

int
bsd_interrupt_register_raw(uint32_t interrupt, uint32_t flags,
    bsd_interrupt_backend_callback_t callback, void *argument,
    void **backend_cookie)
{
    if (!callback || !backend_cookie)
        return BSD_INTERRUPT_EINVAL;
    if (bsd_interrupt_ensure_initialized() != 0)
        return BSD_INTERRUPT_ENXIO;
    return g_interrupt_runtime.operations.register_interrupt(
        g_interrupt_runtime.operations.context, interrupt, flags, 0,
        callback, argument, backend_cookie);
}

int
bsd_interrupt_unregister_raw(void *backend_cookie)
{
    if (!backend_cookie)
        return BSD_INTERRUPT_EINVAL;
    if (!bsd_interrupt_is_initialized())
        return BSD_INTERRUPT_ENXIO;
    return g_interrupt_runtime.operations.unregister_interrupt(
        g_interrupt_runtime.operations.context, backend_cookie);
}

static void
interrupt_run_thread_handler(bsd_interrupt_cookie_t *cookie)
{
    if (!__atomic_load_n(&cookie->tearing_down, __ATOMIC_ACQUIRE) &&
        !__atomic_load_n(&cookie->suspended, __ATOMIC_ACQUIRE) &&
        cookie->handler) {
        bsd_kthread_sleeping_forbid();
        cookie->handler(cookie->argument);
        bsd_kthread_sleeping_allow();
    }
}

static void
interrupt_backend_thread(void *opaque_cookie)
{
    bsd_interrupt_cookie_t *cookie = opaque_cookie;

    interrupt_run_thread_handler(cookie);
    __atomic_sub_fetch(&cookie->active, 1, __ATOMIC_ACQ_REL);
}

static void
interrupt_deferred(void *opaque_cookie, int pending)
{
    bsd_interrupt_cookie_t *cookie = opaque_cookie;
    int may_unmask;

    (void)pending;
    __atomic_add_fetch(&cookie->active, 1, __ATOMIC_ACQ_REL);
    interrupt_run_thread_handler(cookie);
    may_unmask =
        !__atomic_load_n(&cookie->tearing_down, __ATOMIC_ACQUIRE) &&
        !__atomic_load_n(&cookie->suspended, __ATOMIC_ACQUIRE);
    if (__atomic_load_n(&cookie->deferred_masked, __ATOMIC_ACQUIRE)) {
        if (may_unmask && g_interrupt_runtime.operations.unmask_interrupt)
            (void)g_interrupt_runtime.operations.unmask_interrupt(
                g_interrupt_runtime.operations.context,
                cookie->backend_cookie);
        __atomic_store_n(&cookie->deferred_masked, 0,
            __ATOMIC_RELEASE);
    }
    __atomic_sub_fetch(&cookie->active, 1, __ATOMIC_ACQ_REL);
}

static int
interrupt_schedule_deferred(bsd_interrupt_cookie_t *cookie)
{
    int masked = 0;
    int result;

    if (g_interrupt_runtime.operations.mask_interrupt) {
        if (__atomic_exchange_n(&cookie->deferred_masked, 1,
            __ATOMIC_ACQ_REL))
            return 0;
        result = g_interrupt_runtime.operations.mask_interrupt(
            g_interrupt_runtime.operations.context,
            cookie->backend_cookie);
        if (result != 0) {
            __atomic_store_n(&cookie->deferred_masked, 0,
                __ATOMIC_RELEASE);
            return result;
        }
        masked = 1;
    }
    result = bsd_taskqueue_worker_schedule(
        cookie->thread_queue, &cookie->deferred_task);
    if (result != 0 && masked) {
        (void)g_interrupt_runtime.operations.unmask_interrupt(
            g_interrupt_runtime.operations.context,
            cookie->backend_cookie);
        __atomic_store_n(&cookie->deferred_masked, 0,
            __ATOMIC_RELEASE);
    }
    return result;
}

void
swi_sched(void *opaque_cookie, int flags)
{
    bsd_interrupt_cookie_t *cookie = opaque_cookie;

    if (!cookie || !cookie->handler ||
        __atomic_load_n(&cookie->tearing_down, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&cookie->suspended, __ATOMIC_ACQUIRE))
        return;
    if ((flags & SWI_DELAY) != 0 && cookie->thread_queue) {
        (void)interrupt_schedule_deferred(cookie);
        return;
    }
    if (g_interrupt_runtime.operations.schedule_handler) {
        int result;

        __atomic_add_fetch(&cookie->active, 1, __ATOMIC_ACQ_REL);
        result = g_interrupt_runtime.operations.schedule_handler(
            g_interrupt_runtime.operations.context,
            interrupt_backend_thread, cookie);
        if (result != 0)
            __atomic_sub_fetch(&cookie->active, 1, __ATOMIC_ACQ_REL);
        return;
    }
    (void)interrupt_schedule_deferred(cookie);
}

int
swi_add(struct intr_event **event, const char *name,
    void (*handler)(void *), void *argument, int priority, int flags,
    void **cookie_out)
{
    bsd_interrupt_cookie_t *cookie;
    struct intr_event *software_event;

    (void)name;
    if (!event || !handler || !cookie_out || (flags & INTR_ENTROPY) != 0)
        return BSD_INTERRUPT_EINVAL;
    software_event = *event;
    if (!software_event) {
        software_event = bsd_malloc(sizeof(*software_event), M_DEVBUF,
            M_WAITOK | M_ZERO);
        if (!software_event)
            return BSD_INTERRUPT_ENOMEM;
        software_event->priority = priority;
        *event = software_event;
    }
    cookie = bsd_malloc(sizeof(*cookie), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!cookie)
        return BSD_INTERRUPT_ENOMEM;
    cookie->handler = handler;
    cookie->argument = argument;
    cookie->flags = flags;
    cookie->uses_taskqueue = 1;
    cookie->software_event = software_event;
    bsd_taskqueue_task_init(&cookie->deferred_task, 0,
        interrupt_deferred, cookie);
    cookie->thread_queue = bsd_taskqueue_worker_create("swi");
    if (!cookie->thread_queue) {
        bsd_free(cookie, M_DEVBUF);
        return BSD_INTERRUPT_ENOMEM;
    }
    __atomic_add_fetch(&software_event->handler_count, 1,
        __ATOMIC_ACQ_REL);
    *cookie_out = cookie;
    return 0;
}

int
swi_remove(void *opaque_cookie)
{
    bsd_interrupt_cookie_t *cookie = opaque_cookie;

    if (!cookie || !cookie->software_event)
        return BSD_INTERRUPT_EINVAL;
    if (__atomic_exchange_n(&cookie->tearing_down, 1,
        __ATOMIC_ACQ_REL))
        return BSD_INTERRUPT_EBUSY;
    bsd_taskqueue_worker_drain(cookie->thread_queue,
        &cookie->deferred_task);
    bsd_taskqueue_worker_destroy(cookie->thread_queue);
    cookie->thread_queue = 0;
    while (__atomic_load_n(&cookie->active, __ATOMIC_ACQUIRE) != 0) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
    __atomic_sub_fetch(&cookie->software_event->handler_count, 1,
        __ATOMIC_ACQ_REL);
    bsd_free(cookie, M_DEVBUF);
    return 0;
}

static void
interrupt_invoke(void *opaque_cookie)
{
    bsd_interrupt_cookie_t *cookie = opaque_cookie;
    int filter_result;

    __atomic_add_fetch(&cookie->active, 1, __ATOMIC_ACQ_REL);
    if (__atomic_load_n(&cookie->tearing_down, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&cookie->suspended, __ATOMIC_ACQUIRE)) {
        __atomic_sub_fetch(&cookie->active, 1, __ATOMIC_ACQ_REL);
        return;
    }

    filter_result = cookie->filter ?
        cookie->filter(cookie->argument) : FILTER_SCHEDULE_THREAD;
    if ((filter_result & FILTER_SCHEDULE_THREAD) && cookie->handler) {
        if (g_interrupt_runtime.operations.schedule_handler) {
            int result;

            __atomic_add_fetch(
                &cookie->active, 1, __ATOMIC_ACQ_REL);
            result = g_interrupt_runtime.operations.schedule_handler(
                g_interrupt_runtime.operations.context,
                interrupt_backend_thread, cookie);
            if (result != 0) {
                __atomic_sub_fetch(
                    &cookie->active, 1, __ATOMIC_ACQ_REL);
            }
        } else {
            (void)interrupt_schedule_deferred(cookie);
        }
    }
    __atomic_sub_fetch(&cookie->active, 1, __ATOMIC_ACQ_REL);
}

int
bsd_interrupt_setup_direct(device_t device, struct resource *resource,
    int flags,
    driver_filter_t *filter, driver_intr_t *handler, void *argument,
    void **cookie_out)
{
    bsd_interrupt_cookie_t *cookie;
    rman_res_t interrupt;
    int result;

    if (!device || !resource || !cookie_out || (!filter && !handler) ||
        !interrupt_resource_is_owned_by_lineage(device, resource) ||
        rman_get_type(resource) != SYS_RES_IRQ ||
        (rman_get_flags(resource) & (RF_ALLOCATED | RF_ACTIVE)) !=
        (RF_ALLOCATED | RF_ACTIVE))
        return BSD_INTERRUPT_EINVAL;
#if !defined(BSD_BRIDGE_HOST_TEST) || \
    defined(BSD_BRIDGE_INTRNG_HOST_TEST)
    if (interrupt_resource_uses_intrng(resource))
        return intr_setup_irq(device, resource, filter, handler,
            argument, flags, cookie_out);
#endif
    if (bsd_interrupt_ensure_initialized() != 0)
        return BSD_INTERRUPT_ENXIO;
    if (handler && !g_interrupt_runtime.operations.schedule_handler &&
        !bsd_taskqueue_runtime_is_initialized())
        return BSD_INTERRUPT_ENOTSUP;

    interrupt = rman_get_start(resource);
    if (interrupt > UINT32_MAX)
        return BSD_INTERRUPT_EINVAL;
    cookie = bsd_malloc(sizeof(*cookie), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!cookie)
        return BSD_INTERRUPT_ENOMEM;
    cookie->device = device;
    cookie->resource = resource;
    cookie->filter = filter;
    cookie->handler = handler;
    cookie->argument = argument;
    cookie->flags = flags;
    bsd_taskqueue_task_init(&cookie->deferred_task, 0,
        interrupt_deferred, cookie);
    cookie->uses_taskqueue =
        handler && !g_interrupt_runtime.operations.schedule_handler;
    if (cookie->uses_taskqueue) {
        cookie->thread_queue =
            bsd_taskqueue_worker_create("intr_thread");
        if (!cookie->thread_queue) {
            bsd_free(cookie, M_DEVBUF);
            return BSD_INTERRUPT_ENOMEM;
        }
    }
    if (!rman_claim_irq_cookie(resource, 0, cookie)) {
        if (cookie->thread_queue)
            bsd_taskqueue_worker_destroy(cookie->thread_queue);
        bsd_free(cookie, M_DEVBUF);
        return BSD_INTERRUPT_EBUSY;
    }

    result = g_interrupt_runtime.operations.register_interrupt(
        g_interrupt_runtime.operations.context, (uint32_t)interrupt,
        (uint32_t)flags,
        bsd_resource_get_interrupt_flags(resource),
        interrupt_invoke, cookie, &cookie->backend_cookie);
    if (result != 0) {
        (void)rman_claim_irq_cookie(resource, cookie, 0);
        if (cookie->thread_queue)
            bsd_taskqueue_worker_destroy(cookie->thread_queue);
        bsd_free(cookie, M_DEVBUF);
        return result;
    }
    result = bsd_resource_enable_interrupt(resource);
    if (result != 0) {
        (void)g_interrupt_runtime.operations.unregister_interrupt(
            g_interrupt_runtime.operations.context,
            cookie->backend_cookie);
        (void)rman_claim_irq_cookie(resource, cookie, 0);
        if (cookie->thread_queue)
            bsd_taskqueue_worker_destroy(cookie->thread_queue);
        bsd_free(cookie, M_DEVBUF);
        return result;
    }
    interrupt_registry_add(cookie);
    *cookie_out = cookie;
    return 0;
}

int
bus_setup_intr(device_t device, struct resource *resource, int flags,
    driver_filter_t *filter, driver_intr_t *handler, void *argument,
    void **cookie_out)
{
#ifndef BSD_BRIDGE_HOST_TEST
    if (resource && rman_get_device(resource) != device)
        return bsd_bus_setup_intr_from_parent(device, resource, flags,
            filter, handler, argument, cookie_out);
#endif
    return bsd_interrupt_setup_direct(device, resource, flags, filter,
        handler, argument, cookie_out);
}

int
bsd_interrupt_teardown_direct(device_t device, struct resource *resource,
    void *opaque_cookie)
{
    bsd_interrupt_cookie_t *cookie = opaque_cookie;
    int result;

#if !defined(BSD_BRIDGE_HOST_TEST) || \
    defined(BSD_BRIDGE_INTRNG_HOST_TEST)
    if (interrupt_resource_uses_intrng(resource))
        return intr_teardown_irq(device, resource, opaque_cookie);
#endif
    if (!cookie || cookie->device != device ||
        cookie->resource != resource ||
        rman_get_irq_cookie(resource) != cookie)
        return BSD_INTERRUPT_EINVAL;
    if (__atomic_exchange_n(&cookie->tearing_down, 1,
        __ATOMIC_ACQ_REL))
        return BSD_INTERRUPT_EBUSY;
    interrupt_registry_remove(cookie);
    result = bsd_resource_disable_interrupt(resource);
    if (result != 0) {
        interrupt_registry_add(cookie);
        __atomic_store_n(&cookie->tearing_down, 0, __ATOMIC_RELEASE);
        return result;
    }
    result = g_interrupt_runtime.operations.unregister_interrupt(
        g_interrupt_runtime.operations.context, cookie->backend_cookie);
    if (result != 0) {
        (void)bsd_resource_enable_interrupt(resource);
        interrupt_registry_add(cookie);
        __atomic_store_n(&cookie->tearing_down, 0, __ATOMIC_RELEASE);
        return result;
    }
    while (__atomic_load_n(&cookie->drain_refs, __ATOMIC_ACQUIRE) != 0)
        interrupt_relax();
    if (cookie->thread_queue) {
        bsd_taskqueue_worker_drain(
            cookie->thread_queue, &cookie->deferred_task);
        bsd_taskqueue_worker_destroy(cookie->thread_queue);
        cookie->thread_queue = 0;
    }
    while (__atomic_load_n(&cookie->active, __ATOMIC_ACQUIRE) != 0) {
        interrupt_relax();
    }
    if (!rman_claim_irq_cookie(resource, cookie, 0))
        return BSD_INTERRUPT_EBUSY;
    bsd_free(cookie, M_DEVBUF);
    return 0;
}

void
_intr_drain(int irq)
{
    bsd_interrupt_cookie_t *cookie;

    if (irq < 0)
        return;
    if (bsd_intrng_drain_irq((unsigned int)irq))
        return;

    cookie = 0;
    interrupt_registry_lock();
    for (cookie = g_interrupt_cookies; cookie;
        cookie = cookie->registry_next) {
        if (rman_get_start(cookie->resource) == (rman_res_t)irq &&
            !__atomic_load_n(&cookie->tearing_down, __ATOMIC_ACQUIRE)) {
            __atomic_add_fetch(&cookie->drain_refs, 1,
                __ATOMIC_ACQ_REL);
            break;
        }
    }
    interrupt_registry_unlock();
    if (!cookie)
        return;
    if (cookie->thread_queue)
        bsd_taskqueue_worker_drain(cookie->thread_queue,
            &cookie->deferred_task);
    while (__atomic_load_n(&cookie->active, __ATOMIC_ACQUIRE) != 0)
        interrupt_relax();
    __atomic_sub_fetch(&cookie->drain_refs, 1, __ATOMIC_ACQ_REL);
}

int
bus_teardown_intr(device_t device, struct resource *resource,
    void *opaque_cookie)
{
#ifndef BSD_BRIDGE_HOST_TEST
    if (resource && rman_get_device(resource) != device)
        return bsd_bus_teardown_intr_to_parent(device, resource,
            opaque_cookie);
#endif
    return bsd_interrupt_teardown_direct(device, resource, opaque_cookie);
}

int
bus_suspend_intr(device_t device, struct resource *resource)
{
    bsd_interrupt_cookie_t *cookie = rman_get_irq_cookie(resource);
    int result;

#if !defined(BSD_BRIDGE_HOST_TEST) || \
    defined(BSD_BRIDGE_INTRNG_HOST_TEST)
    if (interrupt_resource_uses_intrng(resource))
        return bsd_intrng_suspend_irq(device, resource);
#endif
    if (!cookie || cookie->device != device)
        return BSD_INTERRUPT_EINVAL;
    if (__atomic_load_n(&cookie->suspended, __ATOMIC_ACQUIRE))
        return 0;
    result = g_interrupt_runtime.operations.mask_interrupt ?
        g_interrupt_runtime.operations.mask_interrupt(
            g_interrupt_runtime.operations.context,
            cookie->backend_cookie) : 0;
    if (result == 0)
        result = bsd_resource_disable_interrupt(resource);
    if (result != 0 && g_interrupt_runtime.operations.unmask_interrupt) {
        (void)g_interrupt_runtime.operations.unmask_interrupt(
            g_interrupt_runtime.operations.context,
            cookie->backend_cookie);
    }
    if (result == 0)
        __atomic_store_n(&cookie->suspended, 1, __ATOMIC_RELEASE);
    return result;
}

int
bus_resume_intr(device_t device, struct resource *resource)
{
    bsd_interrupt_cookie_t *cookie = rman_get_irq_cookie(resource);
    int result;

#if !defined(BSD_BRIDGE_HOST_TEST) || \
    defined(BSD_BRIDGE_INTRNG_HOST_TEST)
    if (interrupt_resource_uses_intrng(resource))
        return bsd_intrng_resume_irq(device, resource);
#endif
    if (!cookie || cookie->device != device)
        return BSD_INTERRUPT_EINVAL;
    if (!__atomic_load_n(&cookie->suspended, __ATOMIC_ACQUIRE))
        return 0;
    result = g_interrupt_runtime.operations.unmask_interrupt ?
        g_interrupt_runtime.operations.unmask_interrupt(
            g_interrupt_runtime.operations.context,
            cookie->backend_cookie) : 0;
    if (result == 0)
        result = bsd_resource_enable_interrupt(resource);
    if (result != 0 && g_interrupt_runtime.operations.mask_interrupt) {
        (void)g_interrupt_runtime.operations.mask_interrupt(
            g_interrupt_runtime.operations.context,
            cookie->backend_cookie);
    }
    if (result == 0)
        __atomic_store_n(&cookie->suspended, 0, __ATOMIC_RELEASE);
    return result;
}

int
bus_generic_teardown_intr(device_t bus, device_t child,
    struct resource *resource, void *cookie)
{
    (void)bus;
    return bsd_interrupt_teardown_direct(child, resource, cookie);
}

int
bus_generic_suspend_intr(device_t bus, device_t child,
    struct resource *resource)
{
    (void)bus;
    return bus_suspend_intr(child, resource);
}

int
bus_generic_resume_intr(device_t bus, device_t child,
    struct resource *resource)
{
    (void)bus;
    return bus_resume_intr(child, resource);
}
