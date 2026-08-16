/* SPDX-License-Identifier: MPL-2.0 */
/* Shared FreeBSD random-source registry backed by EdgeOS consumers. */

#ifdef BSD_BRIDGE_HOST_TEST
#include <stddef.h>
#include <stdint.h>
#include "compat/freebsd/sys/random.h"
#include "compat/freebsd/dev/random/randomdev.h"
#else
#include <sys/param.h>
#include <sys/types.h>
#include <sys/random.h>
#include <dev/random/randomdev.h>
#endif

#include "compat/freebsd/edgeos/random.h"
#ifndef BSD_BRIDGE_HOST_TEST
#include "kernel/random.h"
#endif

bool random_bypass_before_seeding;
bool read_random_bypassed_before_seeding;
bool arc4random_bypassed_before_seeding;
bool random_bypass_disable_warnings;
unsigned int hc_source_mask = UINT32_MAX;

static const struct random_source *g_random_source;
static uint64_t g_arc4_fallback_state = 0x243f6a8885a308d3ULL;

static void
bsd_random_mix(const void *entropy, unsigned int size)
{
    if (!entropy || size == 0)
        return;
#ifdef BSD_BRIDGE_HOST_TEST
    const uint8_t *bytes = entropy;
    uint64_t state = __atomic_load_n(
        &g_arc4_fallback_state, __ATOMIC_RELAXED);

    for (unsigned int index = 0; index < size; ++index) {
        state ^= (uint64_t)bytes[index] << ((index & 7u) * 8u);
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
    }
    __atomic_store_n(&g_arc4_fallback_state, state, __ATOMIC_RELEASE);
#else
    edge_random_mix(entropy, size);
#endif
}

void
random_harvest_queue_(const void *entropy, unsigned int size,
    enum random_entropy_source origin)
{
    (void)origin;
    bsd_random_mix(entropy, size);
}

void
random_harvest_fast_(const void *entropy, unsigned int size)
{
    bsd_random_mix(entropy, size);
}

void
random_harvest_direct_(const void *entropy, unsigned int size,
    enum random_entropy_source origin)
{
    (void)origin;
    bsd_random_mix(entropy, size);
}

void
random_source_register(const struct random_source *source)
{
    if (!source || !source->rs_read)
        return;
    __atomic_store_n(&g_random_source, source, __ATOMIC_RELEASE);
}

void
random_source_deregister(const struct random_source *source)
{
    const struct random_source *expected = source;

    if (!source)
        return;
    (void)__atomic_compare_exchange_n(&g_random_source, &expected, 0, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

size_t
bsd_random_fill(void *buffer, size_t length)
{
    const struct random_source *source;
    size_t completed = 0;

    if (!buffer)
        return 0;
    source = __atomic_load_n(&g_random_source, __ATOMIC_ACQUIRE);
    while (source && completed < length) {
        size_t remaining = length - completed;
        unsigned int request = remaining > UINT32_MAX ?
            UINT32_MAX : (unsigned int)remaining;
        unsigned int received = source->rs_read(
            (uint8_t *)buffer + completed, request);

        if (received == 0)
            break;
        if (received > request)
            received = request;
        completed += received;
    }
    return completed;
}

void
arc4rand(void *buffer, unsigned int length, int reseed)
{
    uint8_t *bytes = buffer;
    size_t completed;
    uint64_t state;

    (void)reseed;
    if (!bytes || length == 0)
        return;
    completed = bsd_random_fill(buffer, length);
    state = __atomic_fetch_add(&g_arc4_fallback_state,
        0x9e3779b97f4a7c15ULL, __ATOMIC_ACQ_REL);
    state ^= (uint64_t)(uintptr_t)buffer;
    state ^= (uint64_t)length << 32;
    while (completed < length) {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state *= 0x2545f4914f6cdd1dULL;
        for (unsigned int index = 0;
            index < 8 && completed < length; ++index)
            bytes[completed++] = (uint8_t)(state >> (index * 8u));
    }
    (void)__atomic_fetch_xor(&g_arc4_fallback_state, state,
        __ATOMIC_RELEASE);
}

void
read_random(void *buffer, unsigned int length)
{
    arc4rand(buffer, length, 0);
}

uint32_t
arc4random(void)
{
    uint32_t value;

    arc4rand(&value, sizeof(value), 0);
    return value;
}

unsigned long
random(void)
{
    /*
     * The FreeBSD kernel random(9) interface returns a nonnegative
     * 31-bit value.  Source it from the bridge CSPRNG so imported
     * probability and backoff users receive the complete contract.
     */
    return (unsigned long)(arc4random() & UINT32_C(0x7fffffff));
}

void
arc4random_buf(void *buffer, size_t length)
{
    uint8_t *bytes = buffer;

    while (bytes && length != 0) {
        unsigned int request = length > UINT32_MAX ?
            UINT32_MAX : (unsigned int)length;

        arc4rand(bytes, request, 0);
        bytes += request;
        length -= request;
    }
}
