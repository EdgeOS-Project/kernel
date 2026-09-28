/* SPDX-License-Identifier: MPL-2.0 */
/* Lifecycle tests for the shared BSD interrupt-domain runtime. */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/bus.h>
#include <sys/intr.h>
#include <sys/kthread.h>
#include <sys/malloc.h>
#include <sys/rman.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/resource.h"
#include "compat/freebsd/edgeos/taskqueue.h"
#include "msi_if.h"
#include "pic_if.h"

#define TEST_HEAP_SIZE (16U * 1024U * 1024U)
static void
test_assert_fail(int line)
{
    printf("intrng lifecycle assertion failed at line %d\n", line);
    abort();
}

#define TEST_ASSERT(condition) do {                                     \
    if (!(condition))                                                   \
        test_assert_fail(__LINE__);                                     \
} while (0)

typedef struct {
    struct kobj object;
    struct intr_irqsrc source;
    struct intr_irqsrc msi_sources[4];
    int activate_count;
    int deactivate_count;
    int setup_count;
    int teardown_count;
    int enable_count;
    int disable_count;
    int post_filter_count;
    int pre_thread_count;
    int post_thread_count;
    int fail_activate;
    int fail_setup;
    int msi_alloc_count;
    int msi_release_count;
    int msix_alloc_count;
    int msix_release_count;
    int msi_map_count;
    int iommu_init_count;
    int iommu_deinit_count;
} test_pic_t;

typedef struct {
    int filter_count;
    int handler_count;
} test_driver_t;

static uint8_t g_test_heap[TEST_HEAP_SIZE] __attribute__((aligned(4096)));
static size_t g_test_heap_used;
static struct task *g_scheduled_task;
static int g_schedule_error;
static int g_worker_create_count;
static int g_worker_destroy_count;
static struct thread g_test_thread;

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    size_t bytes;
    void *memory;

    (void)context;
    if (page_count > SIZE_MAX / 4096U)
        return 0;
    bytes = (size_t)page_count * 4096U;
    if (bytes > TEST_HEAP_SIZE - g_test_heap_used)
        return 0;
    memory = &g_test_heap[g_test_heap_used];
    g_test_heap_used += bytes;
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)base;
    (void)page_count;
    (void)context;
}

const char *
device_get_nameunit(device_t device)
{
    (void)device;
    return "intrng-test0";
}

struct thread *
bsd_kthread_current_public(void)
{
    return &g_test_thread;
}

void
bsd_kthread_critical_enter(void)
{
    g_test_thread.td_critnest++;
}

void
bsd_kthread_critical_exit(void)
{
    TEST_ASSERT(g_test_thread.td_critnest > 0);
    g_test_thread.td_critnest--;
}

int
bsd_taskqueue_runtime_is_initialized(void)
{
    return 1;
}

struct taskqueue *
bsd_taskqueue_worker_create(const char *name)
{
    TEST_ASSERT(name != 0);
    g_worker_create_count++;
    return (struct taskqueue *)(uintptr_t)1;
}

int
bsd_taskqueue_worker_schedule(struct taskqueue *queue, struct task *task)
{
    TEST_ASSERT(queue == (struct taskqueue *)(uintptr_t)1);
    TEST_ASSERT(g_scheduled_task == 0);
    if (g_schedule_error)
        return g_schedule_error;
    g_scheduled_task = task;
    return 0;
}

void
bsd_taskqueue_worker_drain(struct taskqueue *queue, struct task *task)
{
    TEST_ASSERT(queue == (struct taskqueue *)(uintptr_t)1);
    TEST_ASSERT(g_scheduled_task == 0 || g_scheduled_task == task);
}

void
bsd_taskqueue_worker_destroy(struct taskqueue *queue)
{
    TEST_ASSERT(queue == (struct taskqueue *)(uintptr_t)1);
    g_worker_destroy_count++;
}

void
bsd_taskqueue_task_init(struct task *task, uint8_t priority,
    bsd_taskqueue_task_fn_t *function, void *context)
{
    memset(task, 0, sizeof(*task));
    task->ta_priority = priority;
    task->ta_func = function;
    task->ta_context = context;
}

static void
test_run_scheduled_task(void)
{
    struct task *task = g_scheduled_task;

    TEST_ASSERT(task != 0);
    g_scheduled_task = 0;
    task->ta_func(task->ta_context, 1);
}

static int
test_pic_activate(device_t device, struct intr_irqsrc *source,
    struct resource *resource, struct intr_map_data *data)
{
    test_pic_t *pic = (test_pic_t *)device;

    TEST_ASSERT(source == &pic->source);
    TEST_ASSERT(resource != 0);
    TEST_ASSERT(data != 0);
    pic->activate_count++;
    return pic->fail_activate;
}

static int
test_pic_deactivate(device_t device, struct intr_irqsrc *source,
    struct resource *resource, struct intr_map_data *data)
{
    test_pic_t *pic = (test_pic_t *)device;

    TEST_ASSERT(source == &pic->source);
    TEST_ASSERT(resource != 0);
    TEST_ASSERT(data != 0);
    pic->deactivate_count++;
    return 0;
}

static int
test_pic_map(device_t device, struct intr_map_data *data,
    struct intr_irqsrc **source_out)
{
    test_pic_t *pic = (test_pic_t *)device;

    TEST_ASSERT(data != 0);
    TEST_ASSERT(source_out != 0);
    *source_out = &pic->source;
    return 0;
}

static int
test_pic_setup(device_t device, struct intr_irqsrc *source,
    struct resource *resource, struct intr_map_data *data)
{
    test_pic_t *pic = (test_pic_t *)device;

    TEST_ASSERT(source == &pic->source);
    TEST_ASSERT(resource != 0);
    TEST_ASSERT(data != 0);
    pic->setup_count++;
    return pic->fail_setup;
}

static int
test_pic_teardown(device_t device, struct intr_irqsrc *source,
    struct resource *resource, struct intr_map_data *data)
{
    test_pic_t *pic = (test_pic_t *)device;

    TEST_ASSERT(source == &pic->source);
    TEST_ASSERT(resource != 0);
    TEST_ASSERT(data != 0);
    pic->teardown_count++;
    return 0;
}

static void
test_pic_enable(device_t device, struct intr_irqsrc *source)
{
    test_pic_t *pic = (test_pic_t *)device;

    TEST_ASSERT(source == &pic->source);
    pic->enable_count++;
}

static void
test_pic_disable(device_t device, struct intr_irqsrc *source)
{
    test_pic_t *pic = (test_pic_t *)device;

    TEST_ASSERT(source == &pic->source);
    pic->disable_count++;
}

static void
test_pic_post_filter(device_t device, struct intr_irqsrc *source)
{
    test_pic_t *pic = (test_pic_t *)device;

    TEST_ASSERT(source == &pic->source);
    pic->post_filter_count++;
}

static void
test_pic_pre_thread(device_t device, struct intr_irqsrc *source)
{
    test_pic_t *pic = (test_pic_t *)device;

    TEST_ASSERT(source == &pic->source);
    pic->pre_thread_count++;
}

static void
test_pic_post_thread(device_t device, struct intr_irqsrc *source)
{
    test_pic_t *pic = (test_pic_t *)device;

    TEST_ASSERT(source == &pic->source);
    pic->post_thread_count++;
}

static int
test_msi_alloc(device_t device, device_t child, int count, int maxcount,
    device_t *controller, struct intr_irqsrc **sources)
{
    test_pic_t *pic = (test_pic_t *)device;

    TEST_ASSERT(child != 0);
    TEST_ASSERT(count > 0 && count <= maxcount);
    TEST_ASSERT(count <= (int)(sizeof(pic->msi_sources) /
        sizeof(pic->msi_sources[0])));
    TEST_ASSERT(controller != 0);
    TEST_ASSERT(sources != 0);
    pic->msi_alloc_count++;
    *controller = device;
    for (int index = 0; index < count; ++index)
        sources[index] = &pic->msi_sources[index];
    return 0;
}

static int
test_msi_release(device_t device, device_t child, int count,
    struct intr_irqsrc **sources)
{
    test_pic_t *pic = (test_pic_t *)device;

    TEST_ASSERT(child != 0);
    TEST_ASSERT(count > 0);
    for (int index = 0; index < count; ++index)
        TEST_ASSERT(sources[index] == &pic->msi_sources[index]);
    pic->msi_release_count++;
    return 0;
}

static int
test_msix_alloc(device_t device, device_t child, device_t *controller,
    struct intr_irqsrc **source)
{
    test_pic_t *pic = (test_pic_t *)device;

    TEST_ASSERT(child != 0);
    TEST_ASSERT(controller != 0);
    TEST_ASSERT(source != 0);
    pic->msix_alloc_count++;
    *controller = device;
    *source = &pic->msi_sources[3];
    return 0;
}

static int
test_msix_release(device_t device, device_t child,
    struct intr_irqsrc *source)
{
    test_pic_t *pic = (test_pic_t *)device;

    TEST_ASSERT(child != 0);
    TEST_ASSERT(source == &pic->msi_sources[3]);
    pic->msix_release_count++;
    return 0;
}

static int
test_msi_map(device_t device, device_t child, struct intr_irqsrc *source,
    uint64_t *address, uint32_t *data)
{
    test_pic_t *pic = (test_pic_t *)device;
    size_t index;

    TEST_ASSERT(child != 0);
    TEST_ASSERT(address != 0);
    TEST_ASSERT(data != 0);
    for (index = 0; index < sizeof(pic->msi_sources) /
        sizeof(pic->msi_sources[0]); ++index) {
        if (source == &pic->msi_sources[index])
            break;
    }
    TEST_ASSERT(index < sizeof(pic->msi_sources) /
        sizeof(pic->msi_sources[0]));
    pic->msi_map_count++;
    *address = UINT64_C(0xfee00000);
    *data = UINT32_C(0x40) + (uint32_t)index;
    return 0;
}

static int
test_msi_iommu_init(device_t device, device_t child,
    struct iommu_domain **domain)
{
    test_pic_t *pic = (test_pic_t *)device;

    TEST_ASSERT(child != 0);
    TEST_ASSERT(domain != 0);
    pic->iommu_init_count++;
    *domain = (struct iommu_domain *)(uintptr_t)UINT64_C(0x12340000);
    return 0;
}

static void
test_msi_iommu_deinit(device_t device, device_t child)
{
    test_pic_t *pic = (test_pic_t *)device;

    TEST_ASSERT(child != 0);
    pic->iommu_deinit_count++;
}

static int
test_filter(void *argument)
{
    test_driver_t *driver = argument;

    driver->filter_count++;
    return FILTER_SCHEDULE_THREAD;
}

static void
test_handler(void *argument)
{
    test_driver_t *driver = argument;

    driver->handler_count++;
}

static const struct kobj_method test_pic_methods[] = {
    KOBJMETHOD(pic_activate_intr, test_pic_activate),
    KOBJMETHOD(pic_deactivate_intr, test_pic_deactivate),
    KOBJMETHOD(pic_map_intr, test_pic_map),
    KOBJMETHOD(pic_setup_intr, test_pic_setup),
    KOBJMETHOD(pic_teardown_intr, test_pic_teardown),
    KOBJMETHOD(pic_enable_intr, test_pic_enable),
    KOBJMETHOD(pic_disable_intr, test_pic_disable),
    KOBJMETHOD(pic_post_filter, test_pic_post_filter),
    KOBJMETHOD(pic_pre_ithread, test_pic_pre_thread),
    KOBJMETHOD(pic_post_ithread, test_pic_post_thread),
    KOBJMETHOD(msi_alloc_msi, test_msi_alloc),
    KOBJMETHOD(msi_release_msi, test_msi_release),
    KOBJMETHOD(msi_alloc_msix, test_msix_alloc),
    KOBJMETHOD(msi_release_msix, test_msix_release),
    KOBJMETHOD(msi_map_msi, test_msi_map),
    KOBJMETHOD(msi_iommu_init, test_msi_iommu_init),
    KOBJMETHOD(msi_iommu_deinit, test_msi_iommu_deinit),
    KOBJMETHOD_END,
};

DEFINE_CLASS_0(intrng_test_pic, test_pic_class, test_pic_methods,
    sizeof(test_pic_t));

int
main(void)
{
    bsd_allocator_ops_t allocator_operations = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };
    device_t driver_device = (device_t)(uintptr_t)2;
    struct intr_map_data *map_data;
    struct resource *resource;
    test_driver_t driver = {0};
    test_pic_t *pic;
    void *cookie = 0;
    u_int clone_id;
    u_int map_id;
    int msi_irqs[2];
    int msix_irq;
    uint64_t msi_address;
    uint32_t msi_data;

    TEST_ASSERT(bsd_allocator_initialize(&allocator_operations) == 0);
    pic = (test_pic_t *)kobj_create(&test_pic_class, M_DEVBUF, M_WAITOK);
    TEST_ASSERT(pic != 0);
    TEST_ASSERT(intr_isrc_register(&pic->source, (device_t)pic, 0,
        "test-source") == 0);
    TEST_ASSERT(intr_pic_register((device_t)pic, 17) != 0);
    TEST_ASSERT(intr_msi_register((device_t)pic, 23) == 0);
    TEST_ASSERT(intr_msi_register((device_t)pic, 23) == 0);
    for (size_t index = 0; index < sizeof(pic->msi_sources) /
        sizeof(pic->msi_sources[0]); ++index) {
        TEST_ASSERT(intr_isrc_register(&pic->msi_sources[index],
            (device_t)pic, 0, "test-msi-%u", (u_int)index) == 0);
    }

    TEST_ASSERT(intr_alloc_msi(driver_device, driver_device, 23, 2, 4,
        msi_irqs) == 0);
    TEST_ASSERT(msi_irqs[0] != (int)INTR_IRQ_INVALID);
    TEST_ASSERT(msi_irqs[1] != (int)INTR_IRQ_INVALID);
    TEST_ASSERT(pic->msi_alloc_count == 1);
    TEST_ASSERT(pic->iommu_init_count == 1);
    TEST_ASSERT(pic->msi_sources[0].isrc_iommu != 0);
    TEST_ASSERT(pic->msi_sources[1].isrc_iommu != 0);
    TEST_ASSERT(intr_map_msi(driver_device, driver_device, 23,
        msi_irqs[1], &msi_address, &msi_data) == 0);
    TEST_ASSERT(msi_address == UINT64_C(0xfee00000));
    TEST_ASSERT(msi_data == UINT32_C(0x41));
    TEST_ASSERT(pic->msi_map_count == 1);
    TEST_ASSERT(intr_release_msi(driver_device, driver_device, 23, 2,
        msi_irqs) == 0);
    TEST_ASSERT(pic->msi_release_count == 1);
    TEST_ASSERT(pic->iommu_deinit_count == 1);
    TEST_ASSERT(msi_irqs[0] == (int)INTR_IRQ_INVALID);
    TEST_ASSERT(msi_irqs[1] == (int)INTR_IRQ_INVALID);
    TEST_ASSERT(pic->msi_sources[0].isrc_iommu == 0);
    TEST_ASSERT(pic->msi_sources[1].isrc_iommu == 0);

    TEST_ASSERT(intr_alloc_msix(driver_device, driver_device, 23,
        &msix_irq) == 0);
    TEST_ASSERT(msix_irq != (int)INTR_IRQ_INVALID);
    TEST_ASSERT(pic->msix_alloc_count == 1);
    TEST_ASSERT(pic->iommu_init_count == 2);
    TEST_ASSERT(intr_map_msi(driver_device, driver_device, 23, msix_irq,
        &msi_address, &msi_data) == 0);
    TEST_ASSERT(msi_data == UINT32_C(0x43));
    TEST_ASSERT(intr_release_msix(driver_device, driver_device, 23,
        msix_irq) == 0);
    TEST_ASSERT(pic->msix_release_count == 1);
    TEST_ASSERT(pic->iommu_deinit_count == 2);
    TEST_ASSERT(intr_alloc_msix(driver_device, driver_device, 99,
        &msix_irq) == 3);

    map_data = intr_alloc_map_data(INTR_MAP_DATA_FDT,
        sizeof(*map_data), M_WAITOK | M_ZERO);
    TEST_ASSERT(map_data != 0);
    map_id = intr_map_irq((device_t)pic, 17, map_data);
    TEST_ASSERT(map_id != INTR_IRQ_INVALID);
    clone_id = intr_map_clone_irq(map_id);
    TEST_ASSERT(clone_id != INTR_IRQ_INVALID);
    intr_unmap_irq(clone_id);

    TEST_ASSERT(bsd_device_add_resource(driver_device, SYS_RES_IRQ, 0,
        map_id, 1, 0, 0) == 0);
    resource = bus_alloc_resource(driver_device, SYS_RES_IRQ, 0,
        map_id, map_id, 1, RF_ACTIVE);
    TEST_ASSERT(resource != 0);
    TEST_ASSERT(pic->activate_count == 1);
    TEST_ASSERT(rman_get_virtual(resource) != 0);
    TEST_ASSERT(!intr_is_per_cpu(resource));

    pic->fail_setup = 5;
    TEST_ASSERT(intr_setup_irq(driver_device, resource, test_filter,
        test_handler, &driver, 0, &cookie) == 5);
    TEST_ASSERT(cookie == 0);
    TEST_ASSERT(pic->setup_count == 1);
    TEST_ASSERT(g_worker_create_count == 1);
    TEST_ASSERT(g_worker_destroy_count == 1);
    pic->fail_setup = 0;

    TEST_ASSERT(intr_setup_irq(driver_device, resource, test_filter,
        test_handler, &driver, 0, &cookie) == 0);
    TEST_ASSERT(cookie != 0);
    TEST_ASSERT(pic->setup_count == 2);
    TEST_ASSERT(pic->enable_count == 1);
    TEST_ASSERT(g_worker_create_count == 2);
    TEST_ASSERT(intr_describe_irq(driver_device, resource, cookie,
        "shared-domain-test") == 0);

    g_schedule_error = 5;
    TEST_ASSERT(intr_isrc_dispatch(&pic->source, 0) == 22);
    TEST_ASSERT(driver.filter_count == 1);
    TEST_ASSERT(driver.handler_count == 0);
    TEST_ASSERT(pic->pre_thread_count == 1);
    TEST_ASSERT(pic->post_thread_count == 1);
    g_schedule_error = 0;

    TEST_ASSERT(intr_isrc_dispatch(&pic->source, 0) == 0);
    TEST_ASSERT(driver.filter_count == 2);
    TEST_ASSERT(pic->pre_thread_count == 2);
    TEST_ASSERT(g_scheduled_task != 0);
    test_run_scheduled_task();
    TEST_ASSERT(driver.handler_count == 1);
    TEST_ASSERT(pic->post_thread_count == 2);

    TEST_ASSERT(bsd_intrng_suspend_irq(driver_device, resource) == 0);
    TEST_ASSERT(pic->disable_count == 1);
    TEST_ASSERT(bsd_intrng_resume_irq(driver_device, resource) == 0);
    TEST_ASSERT(pic->enable_count == 2);

    TEST_ASSERT(intr_teardown_irq(driver_device, resource, cookie) == 0);
    TEST_ASSERT(pic->disable_count == 2);
    TEST_ASSERT(pic->teardown_count == 1);
    TEST_ASSERT(g_worker_destroy_count == 2);
    TEST_ASSERT(bus_release_resource(driver_device, resource) == 0);
    TEST_ASSERT(pic->deactivate_count == 1);
    bus_delete_resource(driver_device, SYS_RES_IRQ, 0);
    intr_unmap_irq(map_id);
    TEST_ASSERT(intr_isrc_deregister(&pic->source) == 0);
    for (size_t index = 0; index < sizeof(pic->msi_sources) /
        sizeof(pic->msi_sources[0]); ++index) {
        TEST_ASSERT(intr_isrc_deregister(
            &pic->msi_sources[index]) == 0);
    }
    TEST_ASSERT(intr_pic_deregister((device_t)pic, 23) == 0);
    TEST_ASSERT(intr_pic_deregister((device_t)pic, 17) == 0);
    kobj_delete(&pic->object, M_DEVBUF);
    return 0;
}
