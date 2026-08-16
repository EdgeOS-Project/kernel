/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS timer-callout backend for BSD driver compatibility.
 *
 * Imported drivers keep the FreeBSD callout API and state model. Expiration
 * callbacks run on one shared kernel worker, use the lock operations carried
 * by struct lock_object, and may safely stop, drain, or reschedule themselves.
 */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/callout.h"
#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/sleep.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/callout.h"
#include "compat/freebsd/sys/kthread.h"
#include "compat/freebsd/sys/lock.h"
#include "compat/freebsd/sys/mutex.h"
#include "kernel/timer_policy.h"
#include "sys/boottime.h"

#define BSD_CALLOUT_EINVAL 22
#define BSD_CALLOUT_ENOMEM 12
#define BSD_CALLOUT_RUNNING 0x1000
#define BSD_CALLOUT_CANCELLED 0x2000
#define BSD_CALLOUT_DRAINING 0x4000
#define BSD_CALLOUT_SOURCE_HZ EDGE_KERNEL_TIMER_HZ

extern int hz;
extern volatile int ticks;
extern volatile long ticksl;

sbintime_t tick_sbt = SBT_1S / 1000;

static volatile uint32_t g_callout_guard;
static struct callout *g_callout_head;
static struct thread *g_callout_worker;
static void *g_callout_worker_token;
static struct mtx g_callout_giant;
static volatile uint32_t g_callout_runtime_state;
static uint8_t g_callout_wait_channel;

static uint64_t
callout_interrupt_save_disable(void)
{
#ifdef BSD_BRIDGE_HOST_TEST
    return 0;
#elif defined(__x86_64__)
    uint64_t state;

    __asm__ __volatile__(
        "pushfq; popq %0; cli" : "=r"(state) :: "memory");
    return state;
#elif defined(__aarch64__) || defined(_M_ARM64)
    uint64_t state;

    __asm__ __volatile__(
        "mrs %0, daif; msr daifset, #0xf"
        : "=r"(state) :: "memory");
    return state;
#else
#error "BSD Driver Bridge callouts need an interrupt backend"
#endif
}

static void
callout_interrupt_restore(uint64_t state)
{
#ifdef BSD_BRIDGE_HOST_TEST
    (void)state;
#elif defined(__x86_64__)
    if ((state & (1ull << 9)) != 0)
        __asm__ __volatile__("sti" ::: "memory");
#elif defined(__aarch64__) || defined(_M_ARM64)
    __asm__ __volatile__("msr daif, %0" :: "r"(state) : "memory");
#endif
}

static void
callout_relax(void)
{
#ifdef BSD_BRIDGE_HOST_TEST
    __asm__ __volatile__("" ::: "memory");
#elif defined(__x86_64__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__) || defined(_M_ARM64)
    __asm__ __volatile__("yield");
#endif
}

static uint64_t
callout_lock(void)
{
    uint64_t interrupt_state = callout_interrupt_save_disable();

    while (__atomic_test_and_set(&g_callout_guard, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&g_callout_guard, __ATOMIC_RELAXED))
            callout_relax();
    }
    return interrupt_state;
}

static void
callout_unlock(uint64_t interrupt_state)
{
    __atomic_clear(&g_callout_guard, __ATOMIC_RELEASE);
    callout_interrupt_restore(interrupt_state);
}

static sbintime_t
callout_now(void)
{
    uint64_t microseconds = boottime_monotonic_us();
    uint64_t seconds = microseconds / UINT64_C(1000000);
    uint64_t remainder = microseconds % UINT64_C(1000000);
    uint64_t fraction;

    if (seconds >= (uint64_t)(SBT_MAX >> 32))
        return SBT_MAX;
    fraction = (remainder << 32) / UINT64_C(1000000);
    return (sbintime_t)((seconds << 32) + fraction);
}

static void
callout_list_remove_locked(struct callout *callout)
{
    struct callout **previous;
    struct callout *next;

    if ((callout->c_iflags & CALLOUT_PENDING) == 0)
        return;
    previous = callout->c_links.le.le_prev;
    next = callout->c_links.le.le_next;
    if (previous)
        *previous = next;
    if (next)
        next->c_links.le.le_prev = previous;
    callout->c_links.le.le_next = 0;
    callout->c_links.le.le_prev = 0;
    callout->c_iflags &= (short)~CALLOUT_PENDING;
}

static void
callout_list_insert_locked(struct callout *callout)
{
    struct callout **position = &g_callout_head;

    while (*position && (*position)->c_time <= callout->c_time)
        position = &(*position)->c_links.le.le_next;
    callout->c_links.le.le_next = *position;
    callout->c_links.le.le_prev = position;
    if (*position)
        (*position)->c_links.le.le_prev =
            &callout->c_links.le.le_next;
    *position = callout;
    callout->c_iflags |= CALLOUT_PENDING;
}

static int
callout_lock_is_owned(const struct lock_object *lock)
{
    return lock && lock->lo_owned && lock->lo_owned(lock->lo_data);
}

static int
callout_try_acquire_lock(struct lock_object *lock, short flags)
{
    if (!lock)
        return 1;
    if ((flags & CALLOUT_TRYLOCK) != 0) {
        if (!lock->lo_trylock)
            return 0;
        return lock->lo_trylock(lock->lo_data);
    }
    if (!lock->lo_lock)
        return 0;
    lock->lo_lock(lock->lo_data);
    return 1;
}

static void
callout_release_lock(struct lock_object *lock)
{
    if (lock && lock->lo_unlock)
        lock->lo_unlock(lock->lo_data);
}

static void
callout_retry_after_failed_trylock(struct callout *callout)
{
    sbintime_t delay;
    sbintime_t now;
    uint64_t state = callout_lock();

    if ((callout->c_iflags &
        (BSD_CALLOUT_CANCELLED | BSD_CALLOUT_DRAINING)) == 0 &&
        (callout->c_iflags & CALLOUT_PENDING) == 0) {
        delay = callout->c_precision / 2;
        if (delay < tick_sbt)
            delay = tick_sbt;
        now = callout_now();
        if (SBT_MAX - now < delay)
            callout->c_time = SBT_MAX;
        else
            callout->c_time = now + delay;
        callout_list_insert_locked(callout);
        callout->c_flags |= CALLOUT_ACTIVE;
    }
    callout->c_iflags &=
        (short)~(BSD_CALLOUT_RUNNING | BSD_CALLOUT_CANCELLED);
    callout_unlock(state);
    bsd_wakeup(callout);
}

static void
callout_finish(struct callout *callout)
{
    uint64_t state = callout_lock();

    if ((callout->c_iflags & BSD_CALLOUT_DRAINING) != 0 &&
        (callout->c_iflags & CALLOUT_PENDING) != 0)
        callout_list_remove_locked(callout);
    callout->c_iflags &=
        (short)~(BSD_CALLOUT_RUNNING | BSD_CALLOUT_CANCELLED);
    callout_unlock(state);
    bsd_wakeup(callout);
}

static void
callout_execute(struct callout *callout, callout_func_t *function,
    void *argument, struct lock_object *external_lock, short saved_flags)
{
    int acquired;
    int execute;
    uint64_t state;

    acquired = callout_try_acquire_lock(external_lock, saved_flags);
    if (!acquired) {
        if ((saved_flags & CALLOUT_TRYLOCK) != 0) {
            callout_retry_after_failed_trylock(callout);
            return;
        }
        callout_finish(callout);
        return;
    }

    state = callout_lock();
    execute = (callout->c_iflags &
        (BSD_CALLOUT_CANCELLED | BSD_CALLOUT_DRAINING)) == 0;
    callout_unlock(state);

    if (execute)
        function(argument);
    if (external_lock &&
        (!execute || (saved_flags & CALLOUT_RETURNUNLOCKED) == 0))
        callout_release_lock(external_lock);
    callout_finish(callout);
}

static struct callout *
callout_take_due_locked(sbintime_t now, int direct)
{
    struct callout *callout = g_callout_head;

    while (callout && callout->c_time <= now) {
        int is_direct =
            (callout->c_iflags & CALLOUT_DIRECT) != 0;

        if (is_direct == direct) {
            callout_list_remove_locked(callout);
            callout->c_iflags |= BSD_CALLOUT_RUNNING;
            return callout;
        }
        callout = callout->c_links.le.le_next;
    }
    return 0;
}

static void
callout_worker_loop(void *argument)
{
    (void)argument;
    g_callout_worker_token = bsd_kthread_current_token();
    for (;;) {
        struct callout *callout = 0;
        callout_func_t *function = 0;
        struct lock_object *external_lock = 0;
        void *function_argument = 0;
        short saved_flags = 0;
        sbintime_t now = callout_now();
        uint64_t state = callout_lock();

        callout = callout_take_due_locked(now, 0);
        if (callout) {
            function = callout->c_func;
            function_argument = callout->c_arg;
            external_lock = callout->c_lock;
            saved_flags = callout->c_iflags;
        }
        callout_unlock(state);

        if (callout && function) {
            callout_execute(callout, function, function_argument,
                external_lock, saved_flags);
            continue;
        }
        (void)bsd_msleep(&g_callout_wait_channel, 0, 0,
            "callout", 1);
    }
}

void
callout_when(sbintime_t sbt, sbintime_t precision, int flags,
    sbintime_t *result, sbintime_t *precision_result)
{
    sbintime_t base;
    sbintime_t calculated_precision;
    int precision_shift;

    if (!result || !precision_result)
        return;
    if ((flags & (C_ABSOLUTE | C_PRECALC)) != 0) {
        *result = sbt;
        *precision_result = precision;
        return;
    }
    if ((flags & C_HARDCLOCK) != 0 && sbt < tick_sbt)
        sbt = tick_sbt;
    if (sbt < 0)
        sbt = 0;
    base = callout_now();
    *result = SBT_MAX - base < sbt ? SBT_MAX : base + sbt;
    precision_shift = C_PRELGET(flags);
    if (precision_shift < 0)
        calculated_precision = sbt >> 8;
    else if (precision_shift >= 63)
        calculated_precision = 0;
    else
        calculated_precision = sbt >> precision_shift;
    *precision_result = calculated_precision > precision ?
        calculated_precision : precision;
}

int
callout_reset_sbt_on(struct callout *callout, sbintime_t sbt,
    sbintime_t precision, callout_func_t *function, void *argument,
    int cpu, int flags)
{
    sbintime_t deadline;
    sbintime_t effective_precision;
    int cancelled = 0;
    uint64_t state;

    if (!callout || !function || cpu < -1 ||
        (flags & ~(C_DIRECT_EXEC | C_HARDCLOCK | C_ABSOLUTE |
        C_PRECALC | C_CATCH | (C_PRELRANGE << 1))) != 0)
        return BSD_CALLOUT_EINVAL;
    if ((flags & C_DIRECT_EXEC) != 0 && callout->c_lock &&
        (callout->c_lock->lo_flags & BSD_LOCK_OBJECT_SPIN) == 0)
        return BSD_CALLOUT_EINVAL;
    if (!bsd_callout_runtime_is_initialized() &&
        bsd_callout_runtime_initialize() != 0)
        return BSD_CALLOUT_ENOMEM;
    callout_when(sbt, precision, flags, &deadline,
        &effective_precision);

    state = callout_lock();
    if ((callout->c_iflags & BSD_CALLOUT_DRAINING) != 0) {
        cancelled = (callout->c_iflags &
            (CALLOUT_PENDING | BSD_CALLOUT_RUNNING)) != 0;
        callout_unlock(state);
        return cancelled;
    }
    if ((callout->c_iflags & CALLOUT_PENDING) != 0) {
        callout_list_remove_locked(callout);
        cancelled = 1;
    }
    if ((callout->c_iflags & BSD_CALLOUT_RUNNING) != 0 &&
        callout_lock_is_owned(callout->c_lock)) {
        callout->c_iflags |= BSD_CALLOUT_CANCELLED;
        cancelled = 1;
    }
    callout->c_time = deadline;
    callout->c_precision = effective_precision;
    callout->c_func = function;
    callout->c_arg = argument;
    callout->c_cpu = cpu < 0 ? 0 : cpu;
    if ((flags & C_DIRECT_EXEC) != 0)
        callout->c_iflags |= CALLOUT_DIRECT;
    else
        callout->c_iflags &= (short)~CALLOUT_DIRECT;
    callout->c_flags |= CALLOUT_ACTIVE;
    callout_list_insert_locked(callout);
    callout_unlock(state);
    bsd_wakeup_one(&g_callout_wait_channel);
    return cancelled;
}

int
callout_schedule_on(struct callout *callout, int timeout_ticks, int cpu)
{
    if (!callout || !callout->c_func)
        return BSD_CALLOUT_EINVAL;
    return callout_reset_sbt_on(callout,
        tick_sbt * timeout_ticks, 0, callout->c_func, callout->c_arg,
        cpu, C_HARDCLOCK);
}

int
callout_schedule(struct callout *callout, int timeout_ticks)
{
    return callout_schedule_on(callout, timeout_ticks,
        callout ? callout->c_cpu : -1);
}

int
_callout_stop_safe(struct callout *callout, int flags)
{
    int cancelled = 0;
    int running;
    uint64_t state;

    if (!callout || (flags & ~CS_DRAIN) != 0)
        return BSD_CALLOUT_EINVAL;
    state = callout_lock();
    if ((callout->c_iflags & CALLOUT_PENDING) != 0) {
        callout_list_remove_locked(callout);
        callout->c_flags &= (short)~CALLOUT_ACTIVE;
        cancelled = 1;
    }
    running = (callout->c_iflags & BSD_CALLOUT_RUNNING) != 0;
    if (!running) {
        if ((flags & CS_DRAIN) != 0)
            callout->c_iflags &= (short)~BSD_CALLOUT_DRAINING;
        callout_unlock(state);
        if (cancelled)
            bsd_wakeup_one(&g_callout_wait_channel);
        return cancelled ? 1 : -1;
    }

    callout->c_flags &= (short)~CALLOUT_ACTIVE;
    if ((flags & CS_DRAIN) == 0) {
        if (callout_lock_is_owned(callout->c_lock)) {
            callout->c_iflags |= BSD_CALLOUT_CANCELLED;
            cancelled = 1;
        }
        callout_unlock(state);
        return cancelled;
    }

    if (bsd_kthread_current_token() == g_callout_worker_token) {
        callout_unlock(state);
        return 0;
    }
    callout->c_iflags |= BSD_CALLOUT_DRAINING;
    callout_unlock(state);

    for (;;) {
        (void)bsd_msleep(callout, 0, 0, "codrain", 1);
        state = callout_lock();
        running =
            (callout->c_iflags & BSD_CALLOUT_RUNNING) != 0;
        if (!running)
            break;
        callout_unlock(state);
    }
    if ((callout->c_iflags & CALLOUT_PENDING) != 0) {
        callout_list_remove_locked(callout);
        cancelled = 1;
    }
    callout->c_flags &= (short)~CALLOUT_ACTIVE;
    callout->c_iflags &=
        (short)~(BSD_CALLOUT_DRAINING | BSD_CALLOUT_CANCELLED);
    callout_unlock(state);
    bsd_wakeup_one(&g_callout_wait_channel);
    return cancelled;
}

void
callout_process(sbintime_t now)
{
    int worker_due = 0;

    for (;;) {
        struct callout *callout;
        callout_func_t *function;
        struct lock_object *external_lock;
        void *argument;
        short saved_flags;
        uint64_t state = callout_lock();

        callout = callout_take_due_locked(now, 1);
        if (!callout) {
            struct callout *entry = g_callout_head;

            while (entry && entry->c_time <= now) {
                if ((entry->c_iflags & CALLOUT_DIRECT) == 0) {
                    worker_due = 1;
                    break;
                }
                entry = entry->c_links.le.le_next;
            }
            callout_unlock(state);
            break;
        }
        function = callout->c_func;
        argument = callout->c_arg;
        external_lock = callout->c_lock;
        saved_flags = callout->c_iflags;
        callout_unlock(state);
        if (function)
            callout_execute(callout, function, argument,
                external_lock, saved_flags);
        else
            callout_finish(callout);
    }
    if (worker_due)
        bsd_wakeup_one(&g_callout_wait_channel);
}

void
bsd_callout_process_timer_tick(void)
{
    int advance = hz / BSD_CALLOUT_SOURCE_HZ;
    int current;

    if (advance < 1)
        advance = 1;
    current = __atomic_add_fetch(&ticks, advance, __ATOMIC_RELAXED);
    __atomic_store_n(&ticksl, (long)current, __ATOMIC_RELAXED);
    if (bsd_callout_runtime_is_initialized())
        callout_process(callout_now());
}

void
callout_init(struct callout *callout, int mpsafe)
{
    if (!callout)
        return;
    if (!bsd_callout_runtime_is_initialized())
        (void)bsd_callout_runtime_initialize();
    bsd_memset(callout, 0, sizeof(*callout));
    if (mpsafe) {
        callout->c_lock = 0;
        callout->c_iflags = CALLOUT_RETURNUNLOCKED;
    } else {
        callout->c_lock = &g_callout_giant.lock_object;
    }
}

void
_callout_init_lock(struct callout *callout, struct lock_object *lock,
    int flags)
{
    if (!callout || !lock ||
        (flags & ~(CALLOUT_RETURNUNLOCKED | CALLOUT_SHAREDLOCK |
        CALLOUT_TRYLOCK)) != 0)
        return;
    bsd_memset(callout, 0, sizeof(*callout));
    callout->c_lock = lock;
    callout->c_iflags = (short)flags;
}

int
bsd_callout_runtime_initialize(void)
{
    uint32_t expected = 0;

    if (__atomic_load_n(
        &g_callout_runtime_state, __ATOMIC_ACQUIRE) == 2)
        return 0;
    if (!__atomic_compare_exchange_n(&g_callout_runtime_state,
        &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(
            &g_callout_runtime_state, __ATOMIC_ACQUIRE) == 1)
            callout_relax();
        return __atomic_load_n(
            &g_callout_runtime_state, __ATOMIC_ACQUIRE) == 2 ?
            0 : BSD_CALLOUT_ENOMEM;
    }
    if (!bsd_kthread_runtime_is_initialized() &&
        bsd_kthread_runtime_initialize() != 0)
        goto fail;
    tick_sbt = hz > 0 ?
        (SBT_1S + (sbintime_t)hz - 1) / (sbintime_t)hz :
        SBT_1S / 1000;
    mtx_init(&g_callout_giant, "Giant", 0, MTX_DEF);
    if (!mtx_initialized(&g_callout_giant))
        goto fail;
    if (kthread_add(callout_worker_loop, 0, 0,
        &g_callout_worker, 0, 0, "bsd-callout") != 0)
        goto fail;
    __atomic_store_n(
        &g_callout_runtime_state, 2, __ATOMIC_RELEASE);
    return 0;

fail:
    if (mtx_initialized(&g_callout_giant))
        mtx_destroy(&g_callout_giant);
    __atomic_store_n(
        &g_callout_runtime_state, 0, __ATOMIC_RELEASE);
    return BSD_CALLOUT_ENOMEM;
}

int
bsd_callout_runtime_is_initialized(void)
{
    return __atomic_load_n(
        &g_callout_runtime_state, __ATOMIC_ACQUIRE) == 2;
}
