/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for deferred FreeBSD configuration hooks. */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/module.h"
#include "compat/freebsd/edgeos/sync.h"
#include "compat/freebsd/sys/kernel.h"
#include "compat/freebsd/sys/taskqueue.h"

#define TEST_ASSERT(condition) test_assert((condition), __LINE__)

struct hook_test_context {
    struct intr_config_hook hook;
    int callback_count;
};

struct malloc_type M_DEVBUF[1];
static union {
    uintptr_t alignment;
    uint8_t bytes[512];
} g_allocation;
static int g_allocation_in_use;
static int g_oneshot_count;

struct taskqueue *taskqueue_thread = (struct taskqueue *)(uintptr_t)1;

static void
test_assert(int condition, int line)
{
    if (!condition) {
        dprintf(2, "config intrhook assertion failed at line %d\n", line);
        __builtin_trap();
    }
}

void
bsd_static_record_register(enum bsd_static_record_kind kind,
    const void *record)
{
    (void)kind;
    (void)record;
}

int
bsd_mutex_init(bsd_mutex_t *mutex, const char *name, uint32_t flags)
{
    mutex->guard = 0;
    mutex->owner = 0;
    mutex->name = name;
    mutex->recursion = 0;
    mutex->flags = flags;
    mutex->initialized = 1;
    return 0;
}

int
bsd_mutex_destroy(bsd_mutex_t *mutex)
{
    TEST_ASSERT(mutex != 0);
    TEST_ASSERT(mutex->guard == 0);
    mutex->initialized = 0;
    return 0;
}

void
bsd_mutex_lock(bsd_mutex_t *mutex)
{
    TEST_ASSERT(mutex != 0);
    TEST_ASSERT(mutex->initialized);
    TEST_ASSERT(mutex->guard == 0);
    mutex->guard = 1;
}

int
bsd_mutex_trylock(bsd_mutex_t *mutex)
{
    if (!mutex || !mutex->initialized || mutex->guard != 0)
        return 0;
    mutex->guard = 1;
    return 1;
}

void
bsd_mutex_unlock(bsd_mutex_t *mutex)
{
    TEST_ASSERT(mutex != 0);
    TEST_ASSERT(mutex->guard == 1);
    mutex->guard = 0;
}

int
bsd_mutex_owned(const bsd_mutex_t *mutex)
{
    return mutex && mutex->guard != 0;
}

int
bsd_mutex_recursed(const bsd_mutex_t *mutex)
{
    return mutex ? (int)mutex->recursion : 0;
}

int
bsd_mutex_assert(const bsd_mutex_t *mutex, int assertion)
{
    (void)mutex;
    (void)assertion;
    return 0;
}

void *
bsd_malloc(size_t size, struct malloc_type *type, int flags)
{
    (void)type;
    if (g_allocation_in_use || size > sizeof(g_allocation.bytes))
        return 0;
    g_allocation_in_use = 1;
    if ((flags & M_ZERO) != 0) {
        for (size_t index = 0; index < size; ++index)
            g_allocation.bytes[index] = 0;
    }
    return g_allocation.bytes;
}

void
bsd_free(void *allocation, struct malloc_type *type)
{
    (void)type;
    TEST_ASSERT(allocation == g_allocation.bytes);
    TEST_ASSERT(g_allocation_in_use);
    g_allocation_in_use = 0;
}

int
bsd_pause(const char *wait_message, int timeout_ticks)
{
    (void)wait_message;
    (void)timeout_ticks;
    return 0;
}

void
bsd_wakeup(const void *channel)
{
    (void)channel;
}

void
bsd_bridge_panic_stop(void)
{
    __builtin_trap();
}

int
taskqueue_enqueue(struct taskqueue *queue, struct task *task)
{
    TEST_ASSERT(queue == taskqueue_thread);
    TEST_ASSERT(task != 0);
    TEST_ASSERT(task->ta_func != 0);
    task->ta_func(task->ta_context, 1);
    return 0;
}

#include "../../src/compat/freebsd/kern/config_intrhook.c"

static void
test_hook_callback(void *argument)
{
    struct hook_test_context *context = argument;

    context->callback_count++;
    config_intrhook_disestablish(&context->hook);
}

static void
test_oneshot_callback(void *argument)
{
    int *count = argument;

    (*count)++;
}

int
main(void)
{
    struct hook_test_context canceled = { 0 };
    struct hook_test_context boot_queued = { 0 };
    struct hook_test_context runtime_queued = { 0 };

    bsd_mtx_sysinit(&intr_config_hook_args);

    canceled.hook.ich_func = test_hook_callback;
    canceled.hook.ich_arg = &canceled;
    TEST_ASSERT(config_intrhook_establish(&canceled.hook) == 0);
    TEST_ASSERT(config_intrhook_establish(&canceled.hook) == 22);
    TEST_ASSERT(config_intrhook_drain(&canceled.hook) == ICHS_QUEUED);
    TEST_ASSERT(canceled.hook.ich_state == ICHS_DONE);
    TEST_ASSERT(canceled.callback_count == 0);

    boot_queued.hook.ich_func = test_hook_callback;
    boot_queued.hook.ich_arg = &boot_queued;
    TEST_ASSERT(config_intrhook_establish(&boot_queued.hook) == 0);
    config_intrhook_boot(0);
    TEST_ASSERT(boot_queued.hook.ich_state == ICHS_DONE);
    TEST_ASSERT(boot_queued.callback_count == 1);
    TEST_ASSERT(config_intrhook_drain(&boot_queued.hook) == ICHS_DONE);

    runtime_queued.hook.ich_func = test_hook_callback;
    runtime_queued.hook.ich_arg = &runtime_queued;
    TEST_ASSERT(config_intrhook_establish(&runtime_queued.hook) == 0);
    TEST_ASSERT(runtime_queued.hook.ich_state == ICHS_DONE);
    TEST_ASSERT(runtime_queued.callback_count == 1);

    config_intrhook_oneshot(test_oneshot_callback, &g_oneshot_count);
    TEST_ASSERT(g_oneshot_count == 1);
    TEST_ASSERT(!g_allocation_in_use);
    TEST_ASSERT(config_intrhook_establish(0) == 22);
    TEST_ASSERT(config_intrhook_drain(0) == 22);

    bsd_mtx_sysuninit(&g_intrhook_lock);
    printf("BSD bridge config intrhook unit test passed\n");
    return 0;
}
