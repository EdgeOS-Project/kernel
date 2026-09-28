/* SPDX-License-Identifier: MPL-2.0 */
/* Host behavior tests for BSD Driver Bridge group taskqueues. */

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/module.h"
#include "compat/freebsd/sys/gtaskqueue.h"
#include "compat/freebsd/sys/smp.h"

#define TEST_PAGE_SIZE 4096u

static volatile uint32_t g_completed;

void
bsd_static_record_register(
    enum bsd_static_record_kind kind, const void *record)
{
    (void)kind;
    (void)record;
}

static void *
allocate_pages(uint64_t pages, void *context)
{
    void *memory = 0;

    (void)context;
    if (pages > SIZE_MAX / TEST_PAGE_SIZE ||
        posix_memalign(&memory, TEST_PAGE_SIZE,
        (size_t)pages * TEST_PAGE_SIZE) != 0)
        return 0;
    memset(memory, 0, (size_t)pages * TEST_PAGE_SIZE);
    return memory;
}

static void
release_pages(void *base, uint64_t pages, void *context)
{
    (void)pages;
    (void)context;
    free(base);
}

static void
complete_task(void *context)
{
    uint32_t amount = *(uint32_t *)context;

    __atomic_fetch_add(&g_completed, amount, __ATOMIC_RELEASE);
}

static void
wait_completed(uint32_t expected)
{
    struct timespec delay = {
        .tv_sec = 0,
        .tv_nsec = 1000000L,
    };

    for (uint32_t attempt = 0; attempt < 5000u; ++attempt) {
        if (__atomic_load_n(&g_completed, __ATOMIC_ACQUIRE) == expected)
            return;
        (void)nanosleep(&delay, 0);
    }
    assert(!"group taskqueue worker timed out");
}

int
main(void)
{
    bsd_allocator_ops_t allocator = {
        .allocate_pages = allocate_pages,
        .release_pages = release_pages,
    };
    struct taskqgroup *group;
    struct grouptask first = {0};
    struct grouptask second = {0};
    struct grouptask canceled = {0};
    struct grouptask pinned = {0};
    uint32_t one = 1;
    uint32_t ten = 10;
    int unique;

    assert(bsd_allocator_initialize(&allocator) == 0);
    assert(bsd_kthread_runtime_initialize() == 0);
    mp_ncpus = 2;
    CPU_ZERO(&all_cpus);
    CPU_SET(0, &all_cpus);
    CPU_SET(1, &all_cpus);

    group = taskqgroup_create("group-unit", 2, 1);
    assert(group != 0);
    GROUPTASK_INIT(&first, 0, complete_task, &one);
    GROUPTASK_INIT(&second, 0, complete_task, &ten);
    taskqgroup_attach(group, &first, &unique, 0, 0, "first");
    taskqgroup_attach(group, &second, &unique, 0, 0, "second");
    assert(first.gt_taskqueue != 0);
    assert(second.gt_taskqueue != 0);
    assert(first.gt_taskqueue != second.gt_taskqueue);
    assert(first.gt_cpu == -1);
    taskqgroup_attach(group, &first, &unique, 0, 0, "duplicate");
    assert(taskqgroup_attach_cpu(group, &first, &unique,
        0, 0, 0, "duplicate") == 16);

    gtaskqueue_block(first.gt_taskqueue);
    assert(GROUPTASK_ENQUEUE(&first) == 0);
    assert(GROUPTASK_ENQUEUE(&first) == 0);
    assert(__atomic_load_n(&g_completed, __ATOMIC_ACQUIRE) == 0);
    gtaskqueue_unblock(first.gt_taskqueue);
    assert(GROUPTASK_ENQUEUE(&second) == 0);
    wait_completed(11);
    taskqgroup_drain_all(group);

    GROUPTASK_INIT(&canceled, 0, complete_task, &ten);
    taskqgroup_attach(group, &canceled, &canceled, 0, 0, "canceled");
    gtaskqueue_block(canceled.gt_taskqueue);
    assert(GROUPTASK_ENQUEUE(&canceled) == 0);
    assert(gtaskqueue_cancel(
        canceled.gt_taskqueue, &canceled.gt_task) == 0);
    gtaskqueue_unblock(canceled.gt_taskqueue);
    assert(__atomic_load_n(&g_completed, __ATOMIC_ACQUIRE) == 11);

    grouptask_block(&canceled);
    assert(GROUPTASK_ENQUEUE(&canceled) == 11);
    grouptask_unblock(&canceled);
    assert(GROUPTASK_ENQUEUE(&canceled) == 0);
    wait_completed(21);
    gtaskqueue_drain(
        canceled.gt_taskqueue, &canceled.gt_task);

    GROUPTASK_INIT(&pinned, 0, complete_task, &one);
    assert(taskqgroup_attach_cpu(group, &pinned, &pinned,
        1, 0, 0, "pinned") == 0);
    assert(pinned.gt_cpu == 1);
    assert(GROUPTASK_ENQUEUE(&pinned) == 0);
    wait_completed(22);

    taskqgroup_detach(group, &pinned);
    taskqgroup_detach(group, &canceled);
    taskqgroup_detach(group, &second);
    assert(!pinned.gt_taskqueue);
    gtaskqueue_block(first.gt_taskqueue);
    assert(GROUPTASK_ENQUEUE(&first) == 0);
    taskqgroup_destroy(group);
    assert(!first.gt_taskqueue);
    assert(__atomic_load_n(&g_completed, __ATOMIC_ACQUIRE) == 23);

    printf("bsd_bridge_gtaskqueue_unit: PASS\n");
    return 0;
}
