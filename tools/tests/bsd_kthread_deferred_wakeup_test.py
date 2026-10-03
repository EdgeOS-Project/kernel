#!/usr/bin/env python3
"""Exercise production deferred-wakeup helpers with controlled races and threads."""

import argparse
import os
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cc", default=os.environ.get("HOST_CC", "clang"))
    parser.add_argument("--sanitizer", default="address,undefined")
    args = parser.parse_args()
    source = (ROOT / "src/compat/freebsd/kern/kthread.c").read_text()
    start = source.rindex("static bsd_kthread_channel_t *\nkthread_channel_locked(")
    end = source.index("static __attribute__((noreturn))", start)
    helpers = source[start:end]
    constants = "\n".join(
        re.search(rf"^#define {name} .+$", source, re.MULTILINE).group(0)
        for name in ("BSD_KTHREAD_MAX", "BSD_KTHREAD_CHANNEL_MAX")
    )
    harness = r'''
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
'''
    harness += constants
    harness += r'''
enum { BSD_KTHREAD_WAITING, BSD_KTHREAD_RUNNABLE };
typedef struct { const void *channel; uint64_t generation; }
    bsd_kthread_channel_t;
typedef struct {
    int state;
    const void *wait_channel;
    uint64_t deadline_us;
} bsd_kthread_record_t;
static bsd_kthread_channel_t g_channels[BSD_KTHREAD_CHANNEL_MAX];
static bsd_kthread_record_t g_kthreads[BSD_KTHREAD_MAX];
static volatile uintptr_t g_deferred_wakeup_channels[BSD_KTHREAD_CHANNEL_MAX];
static volatile uint8_t g_deferred_wakeup_overflow;
static int tokens[BSD_KTHREAD_CHANNEL_MAX + 1u];
static unsigned slot_exchanges, overflow_exchanges;
static int inject_after_zero_load, inject_after_exchange;
static _Thread_local int draining;
static void kthread_defer_wakeup(const void *channel);

static uintptr_t slot_load(volatile uintptr_t *slot, int order) {
    uintptr_t result = __atomic_load_n(slot, order);
    if (draining && slot == g_deferred_wakeup_channels &&
        result == 0 && inject_after_zero_load) {
        inject_after_zero_load = 0;
        kthread_defer_wakeup(&tokens[0]);
    }
    return result;
}

static uintptr_t slot_exchange(volatile uintptr_t *slot, uintptr_t value,
                               int order) {
    uintptr_t result = __atomic_exchange_n(slot, value, order);
    __atomic_fetch_add(&slot_exchanges, 1u, __ATOMIC_RELAXED);
    if (draining && slot == g_deferred_wakeup_channels &&
        inject_after_exchange) {
        inject_after_exchange = 0;
        kthread_defer_wakeup(&tokens[1]);
    }
    return result;
}

static uint8_t overflow_exchange(volatile uint8_t *slot, uint8_t value,
                                 int order) {
    __atomic_fetch_add(&overflow_exchanges, 1u, __ATOMIC_RELAXED);
    return __atomic_exchange_n(slot, value, order);
}

/* Wrap atomic observation points without copying the queue algorithm. */
#define __atomic_load_n(slot, order) slot_load(slot, order)
#define __atomic_exchange_n(slot, value, order) \
    _Generic((slot), volatile uintptr_t *: slot_exchange, \
             volatile uint8_t *: overflow_exchange)(slot, value, order)
'''
    harness += helpers
    harness += r'''
#undef __atomic_load_n
#undef __atomic_exchange_n

static void reset_state(void) {
    memset(g_channels, 0, sizeof(g_channels));
    memset(g_kthreads, 0, sizeof(g_kthreads));
    memset((void *)g_deferred_wakeup_channels, 0,
           sizeof(g_deferred_wakeup_channels));
    g_deferred_wakeup_overflow = 0;
    slot_exchanges = overflow_exchanges = 0;
    inject_after_zero_load = inject_after_exchange = 0;
}

static void wait_on(unsigned record, unsigned token) {
    assert(kthread_channel_locked(&tokens[token], 1));
    g_kthreads[record].state = BSD_KTHREAD_WAITING;
    g_kthreads[record].wait_channel = &tokens[token];
    g_kthreads[record].deadline_us = UINT64_MAX;
}

static void drain(void) {
    draining = 1;
    kthread_drain_deferred_wakeups_locked();
    draining = 0;
}

static void test_interleavings(void) {
    reset_state();
    drain();
    assert(slot_exchanges == 0u);
    assert(overflow_exchanges == 1u);

    wait_on(0, 0);
    inject_after_zero_load = 1;
    drain();
    assert(!inject_after_zero_load);
    assert(g_kthreads[0].state == BSD_KTHREAD_WAITING);
    assert(g_deferred_wakeup_channels[0] == (uintptr_t)&tokens[0]);
    drain();
    assert(g_kthreads[0].state == BSD_KTHREAD_RUNNABLE);
    assert(g_kthreads[0].wait_channel == 0 && !g_kthreads[0].deadline_us);

    reset_state();
    wait_on(0, 0);
    wait_on(1, 1);
    kthread_defer_wakeup(&tokens[0]);
    inject_after_exchange = 1;
    drain();
    assert(!inject_after_exchange);
    assert(g_kthreads[0].state == BSD_KTHREAD_RUNNABLE);
    assert(g_kthreads[1].state == BSD_KTHREAD_WAITING);
    assert(g_deferred_wakeup_channels[0] == (uintptr_t)&tokens[1]);
    drain();
    assert(g_kthreads[1].state == BSD_KTHREAD_RUNNABLE);

    reset_state();
    wait_on(0, 0);
    wait_on(1, 0);
    uint64_t generation = g_channels[0].generation;
    for (unsigned i = 0; i < 32u; ++i) kthread_defer_wakeup(&tokens[0]);
    drain();
    assert(slot_exchanges == 1u);
    assert(g_channels[0].generation == generation + 1u);
    assert(g_kthreads[0].state == BSD_KTHREAD_RUNNABLE);
    assert(g_kthreads[1].state == BSD_KTHREAD_RUNNABLE);

    reset_state();
    wait_on(0, BSD_KTHREAD_CHANNEL_MAX);
    for (unsigned i = 0; i <= BSD_KTHREAD_CHANNEL_MAX; ++i)
        kthread_defer_wakeup(&tokens[i]);
    assert(g_deferred_wakeup_overflow == 1u);
    drain();
    assert(!g_deferred_wakeup_overflow);
    assert(g_kthreads[0].state == BSD_KTHREAD_RUNNABLE);
}

#define PRODUCERS 4u
#define ROUNDS 2000u
static pthread_mutex_t consumer_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned acknowledgements[PRODUCERS];
static unsigned payload[PRODUCERS];
static unsigned producers_done;

static void *producer(void *argument) {
    unsigned id = (unsigned)(uintptr_t)argument;
    for (unsigned round = 1; round <= ROUNDS; ++round) {
        assert(!pthread_mutex_lock(&consumer_lock));
        wait_on(id, id);
        assert(!pthread_mutex_unlock(&consumer_lock));
        /* Publication must make this ordinary write visible to the consumer. */
        payload[id] = round;
        kthread_defer_wakeup(&tokens[id]);
        while (__atomic_load_n(&acknowledgements[id], __ATOMIC_ACQUIRE) != round)
            sched_yield();
    }
    __atomic_fetch_add(&producers_done, 1u, __ATOMIC_RELEASE);
    return 0;
}

static void *consumer(void *argument) {
    (void)argument;
    while (__atomic_load_n(&producers_done, __ATOMIC_ACQUIRE) != PRODUCERS) {
        /* Production serializes drain and wait-state changes with its guard. */
        assert(!pthread_mutex_lock(&consumer_lock));
        drain();
        for (unsigned id = 0; id < PRODUCERS; ++id) {
            unsigned acknowledged = __atomic_load_n(
                &acknowledgements[id], __ATOMIC_RELAXED);
            if (g_kthreads[id].state == BSD_KTHREAD_RUNNABLE &&
                acknowledged < ROUNDS && payload[id] == acknowledged + 1u) {
                __atomic_store_n(&acknowledgements[id], acknowledged + 1u,
                                 __ATOMIC_RELEASE);
            }
        }
        assert(!pthread_mutex_unlock(&consumer_lock));
        sched_yield();
    }
    return 0;
}

int main(void) {
    pthread_t publishers[PRODUCERS], drainers[2];
    test_interleavings();
    reset_state();
    for (unsigned id = 0; id < 2u; ++id)
        assert(!pthread_create(&drainers[id], 0, consumer, 0));
    for (unsigned id = 0; id < PRODUCERS; ++id)
        assert(!pthread_create(&publishers[id], 0, producer,
                               (void *)(uintptr_t)id));
    for (unsigned id = 0; id < PRODUCERS; ++id)
        assert(!pthread_join(publishers[id], 0));
    for (unsigned id = 0; id < 2u; ++id)
        assert(!pthread_join(drainers[id], 0));
    drain();
    for (unsigned id = 0; id < PRODUCERS; ++id)
        assert(acknowledgements[id] == ROUNDS && payload[id] == ROUNDS);
    for (unsigned i = 0; i < BSD_KTHREAD_CHANNEL_MAX; ++i)
        assert(!g_deferred_wakeup_channels[i]);
    assert(!g_deferred_wakeup_overflow);
    puts("bsd_kthread_deferred_wakeup_test: PASS (8000 publications, 2 drainers)");
    return 0;
}
'''
    args.output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [args.cc, "-x", "c", "-", "-std=c11", "-O1", "-g", "-pthread",
         "-Wall", "-Wextra", "-Werror", f"-fsanitize={args.sanitizer}",
         "-o", str(args.output)],
        input=harness, text=True, check=True,
    )
    subprocess.run([str(args.output.resolve())], check=True, timeout=30)


if __name__ == "__main__":
    main()
