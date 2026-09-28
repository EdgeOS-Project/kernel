/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the shared BSD bridge interrupt lifecycle. */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/interrupt.h"
#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/resource.h"
#include "compat/freebsd/edgeos/taskqueue.h"
#include "compat/freebsd/machine/resource.h"

static struct task *g_scheduled_task;
static int g_no_sleeping;
static int g_worker_create_count;
static int g_worker_destroy_count;
static device_t g_parent_device;
static device_t g_child_device;

device_t
device_get_parent(device_t device)
{
    return device == g_child_device ? g_parent_device : 0;
}

void
bsd_kthread_sleeping_forbid(void)
{
    g_no_sleeping++;
}

void
bsd_kthread_sleeping_allow(void)
{
    assert(g_no_sleeping > 0);
    g_no_sleeping--;
}

int
bsd_taskqueue_runtime_is_initialized(void)
{
    return 1;
}

struct taskqueue *
bsd_taskqueue_worker_create(const char *name)
{
    assert(name != 0);
    g_worker_create_count++;
    return (struct taskqueue *)(uintptr_t)1;
}

int
bsd_taskqueue_worker_schedule(struct taskqueue *queue, struct task *task)
{
    assert(queue == (struct taskqueue *)(uintptr_t)1);
    assert(g_scheduled_task == 0);
    g_scheduled_task = task;
    return 0;
}

void
bsd_taskqueue_worker_drain(struct taskqueue *queue, struct task *task)
{
    assert(queue == (struct taskqueue *)(uintptr_t)1);
    assert(g_scheduled_task == 0 || g_scheduled_task == task);
}

void
bsd_taskqueue_worker_destroy(struct taskqueue *queue)
{
    assert(queue == (struct taskqueue *)(uintptr_t)1);
    g_worker_destroy_count++;
}

void
bsd_taskqueue_task_init(struct task *task, uint8_t priority,
    bsd_taskqueue_task_fn_t *function, void *context)
{
    task->ta_link.stqe_next = 0;
    task->ta_pending = 0;
    task->ta_priority = priority;
    task->ta_flags = 0;
    task->ta_func = function;
    task->ta_context = context;
}

int
bsd_taskqueue_task_schedule(struct task *task)
{
    assert(g_scheduled_task == 0);
    g_scheduled_task = task;
    return 0;
}

void
bsd_taskqueue_task_drain(struct task *task)
{
    assert(g_scheduled_task == 0 || g_scheduled_task == task);
}

static void
run_scheduled_task(void)
{
    struct task *task = g_scheduled_task;

    assert(task != 0);
    g_scheduled_task = 0;
    task->ta_func(task->ta_context, 1);
}

typedef struct {
    bsd_interrupt_backend_callback_t callback;
    void *argument;
    uint32_t interrupt;
    uint32_t interrupt_flags;
    int register_count;
    int unregister_count;
    int mask_count;
    int unmask_count;
    int source_enable_count;
    int source_disable_count;
    int fail_unregister;
} test_backend_t;

typedef struct {
    int filter_count;
    int handler_count;
    int handler_no_sleeping_count;
    int schedule;
} test_driver_t;

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    void *memory = 0;

    (void)context;
    if (page_count > SIZE_MAX / 4096U ||
        posix_memalign(&memory, 4096U, (size_t)page_count * 4096U) != 0)
        return 0;
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)page_count;
    (void)context;
    free(base);
}

static int
test_register(void *opaque_backend, uint32_t interrupt, uint32_t flags,
    uint32_t interrupt_flags, bsd_interrupt_backend_callback_t callback,
    void *argument, void **backend_cookie)
{
    test_backend_t *backend = opaque_backend;

    (void)flags;
    assert(backend->callback == 0);
    backend->callback = callback;
    backend->argument = argument;
    backend->interrupt = interrupt;
    backend->interrupt_flags = interrupt_flags;
    backend->register_count++;
    *backend_cookie = backend;
    return 0;
}

static int
test_unregister(void *opaque_backend, void *backend_cookie)
{
    test_backend_t *backend = opaque_backend;

    assert(backend_cookie == backend);
    backend->unregister_count++;
    if (backend->fail_unregister)
        return 5;
    backend->callback = 0;
    backend->argument = 0;
    return 0;
}

static int
test_mask(void *opaque_backend, void *backend_cookie)
{
    test_backend_t *backend = opaque_backend;

    assert(backend_cookie == backend);
    backend->mask_count++;
    return 0;
}

static int
test_unmask(void *opaque_backend, void *backend_cookie)
{
    test_backend_t *backend = opaque_backend;

    assert(backend_cookie == backend);
    backend->unmask_count++;
    return 0;
}

static int
test_source_enable(void *opaque_backend)
{
    test_backend_t *backend = opaque_backend;

    backend->source_enable_count++;
    return 0;
}

static int
test_source_disable(void *opaque_backend)
{
    test_backend_t *backend = opaque_backend;

    backend->source_disable_count++;
    return 0;
}

static int
test_filter(void *opaque_driver)
{
    test_driver_t *driver = opaque_driver;

    driver->filter_count++;
    return driver->schedule ?
        FILTER_SCHEDULE_THREAD : FILTER_HANDLED;
}

static void
test_handler(void *opaque_driver)
{
    test_driver_t *driver = opaque_driver;

    driver->handler_count++;
    if (g_no_sleeping != 0)
        driver->handler_no_sleeping_count++;
}

int
main(void)
{
    bsd_allocator_ops_t allocator_operations = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };
    test_backend_t backend = {0};
    test_driver_t driver = {0};
    bsd_interrupt_backend_ops_t interrupt_operations = {
        .register_interrupt = test_register,
        .unregister_interrupt = test_unregister,
        .mask_interrupt = test_mask,
        .unmask_interrupt = test_unmask,
        .context = &backend,
    };
    bsd_resource_interrupt_source_ops_t source_operations = {
        .enable = test_source_enable,
        .disable = test_source_disable,
        .context = &backend,
        .interrupt_flags = 1,
    };
    device_t device = (device_t)(uintptr_t)1;
    device_t parent_device = (device_t)(uintptr_t)2;
    device_t child_device = (device_t)(uintptr_t)3;
    struct resource *resource;
    struct resource *parent_resource;
    void *cookie;

    assert(bsd_allocator_initialize(&allocator_operations) == 0);
    assert(bsd_interrupt_initialize(&interrupt_operations) == 0);
    assert(bsd_device_add_resource(device, SYS_RES_IRQ, 0, 47, 1,
        RF_SHAREABLE, 0) == 0);
    assert(bsd_resource_set_interrupt_source(device, 0,
        &source_operations) == 0);
    resource = bus_alloc_resource(device, SYS_RES_IRQ, 0, 0,
        RM_MAX_END, 1, RF_ACTIVE | RF_SHAREABLE);
    assert(resource != 0);
    assert(bus_setup_intr(device, resource, INTR_TYPE_NET | INTR_MPSAFE,
        test_filter, test_handler, &driver, &cookie) == 0);
    assert(backend.interrupt == 47);
    assert(backend.interrupt_flags == 1);
    assert(rman_get_irq_cookie(resource) == cookie);
    assert(backend.source_enable_count == 1);
    assert(g_worker_create_count == 1);

    backend.callback(backend.argument);
    assert(driver.filter_count == 1);
    assert(driver.handler_count == 0);
    driver.schedule = 1;
    backend.callback(backend.argument);
    assert(driver.filter_count == 2);
    assert(driver.handler_count == 0);
    assert(backend.mask_count == 1);
    backend.callback(backend.argument);
    assert(driver.filter_count == 3);
    assert(backend.mask_count == 1);
    run_scheduled_task();
    assert(driver.handler_count == 1);
    assert(driver.handler_no_sleeping_count == 1);
    assert(g_no_sleeping == 0);
    assert(backend.unmask_count == 1);

    assert(bus_suspend_intr(device, resource) == 0);
    assert(backend.mask_count == 2);
    assert(backend.source_disable_count == 1);
    backend.callback(backend.argument);
    assert(driver.filter_count == 3);
    assert(bus_resume_intr(device, resource) == 0);
    assert(backend.unmask_count == 2);
    assert(backend.source_enable_count == 2);
    backend.callback(backend.argument);
    assert(driver.filter_count == 4);
    assert(driver.handler_count == 1);
    assert(backend.mask_count == 3);
    run_scheduled_task();
    assert(driver.handler_count == 2);
    assert(driver.handler_no_sleeping_count == 2);
    assert(g_no_sleeping == 0);
    assert(backend.unmask_count == 3);

    backend.fail_unregister = 1;
    assert(bus_teardown_intr(device, resource, cookie) == 5);
    assert(backend.source_disable_count == 2);
    assert(backend.source_enable_count == 3);
    assert(rman_get_irq_cookie(resource) == cookie);
    backend.callback(backend.argument);
    assert(driver.filter_count == 5);
    assert(backend.mask_count == 4);
    run_scheduled_task();
    assert(driver.handler_count == 3);
    assert(driver.handler_no_sleeping_count == 3);
    assert(g_no_sleeping == 0);
    assert(backend.unmask_count == 4);

    backend.fail_unregister = 0;
    assert(bus_teardown_intr(device, resource, cookie) == 0);
    assert(backend.source_disable_count == 3);
    assert(backend.unregister_count == 2);
    assert(rman_get_irq_cookie(resource) == 0);
    assert(g_worker_destroy_count == 1);
    assert(bus_release_resource(device, resource) == 0);
    bus_delete_resource(device, SYS_RES_IRQ, 0);

    g_parent_device = parent_device;
    g_child_device = child_device;
    assert(bsd_device_add_resource(parent_device, SYS_RES_IRQ, 0, 48, 1,
        RF_SHAREABLE, 0) == 0);
    assert(bsd_resource_set_interrupt_source(parent_device, 0,
        &source_operations) == 0);
    parent_resource = bus_alloc_resource(parent_device, SYS_RES_IRQ, 0, 0,
        RM_MAX_END, 1, RF_ACTIVE | RF_SHAREABLE);
    assert(parent_resource != 0);
    assert(bus_setup_intr(child_device, parent_resource,
        INTR_TYPE_TTY | INTR_MPSAFE, test_filter, test_handler, &driver,
        &cookie) == 0);
    assert(backend.interrupt == 48);
    assert(bus_teardown_intr(child_device, parent_resource, cookie) == 0);
    assert(bus_release_resource(parent_device, parent_resource) == 0);
    bus_delete_resource(parent_device, SYS_RES_IRQ, 0);
    return 0;
}
