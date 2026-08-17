/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS kernel random generator.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/random.h"

#include "string.h"
#include "sys/boottime.h"
#if defined(__x86_64__)
#include "keyboard.h"
#endif
#ifdef CONFIG_VIRTIO_RNG
#include "drivers/virtio_rng.h"
#endif
#ifdef CONFIG_BSD_DRIVER_BRIDGE
#include "compat/freebsd/edgeos/random.h"
#endif

typedef struct {
    volatile uint32_t lock;
    uint8_t initialized;
    uint32_t key[8];
    uint32_t nonce[2];
    uint64_t counter;
    uint64_t generated;
} edge_random_state_t;

static edge_random_state_t g_random;

static uint64_t random_cycle_counter(void) {
#if defined(__x86_64__)
    uint32_t low;
    uint32_t high;
    __asm__ __volatile__("rdtsc" : "=a"(low), "=d"(high));
    return ((uint64_t)high << 32) | low;
#elif defined(__aarch64__)
    uint64_t value;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(value));
    return value;
#else
#error "EdgeOS random generator needs an architecture counter"
#endif
}

static uint64_t splitmix64(uint64_t *state) {
    uint64_t value = (*state += 0x9e3779b97f4a7c15ull);
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ull;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebull;
    return value ^ (value >> 31);
}

static uint32_t rotate_left(uint32_t value, uint32_t shift) {
    return (value << shift) | (value >> (32u - shift));
}

static void chacha_quarter_round(uint32_t *a, uint32_t *b,
                                 uint32_t *c, uint32_t *d) {
    *a += *b;
    *d ^= *a;
    *d = rotate_left(*d, 16);
    *c += *d;
    *b ^= *c;
    *b = rotate_left(*b, 12);
    *a += *b;
    *d ^= *a;
    *d = rotate_left(*d, 8);
    *c += *d;
    *b ^= *c;
    *b = rotate_left(*b, 7);
}

static void chacha_block(uint8_t output[64]) {
    static const uint32_t constants[4] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
    };
    uint32_t initial[16];
    uint32_t working[16];
    memcpy(initial, constants, sizeof(constants));
    memcpy(&initial[4], g_random.key, sizeof(g_random.key));
    initial[12] = (uint32_t)g_random.counter;
    initial[13] = (uint32_t)(g_random.counter >> 32);
    initial[14] = g_random.nonce[0];
    initial[15] = g_random.nonce[1];
    memcpy(working, initial, sizeof(working));
    for (uint32_t round = 0; round < 10u; ++round) {
        chacha_quarter_round(&working[0], &working[4], &working[8], &working[12]);
        chacha_quarter_round(&working[1], &working[5], &working[9], &working[13]);
        chacha_quarter_round(&working[2], &working[6], &working[10], &working[14]);
        chacha_quarter_round(&working[3], &working[7], &working[11], &working[15]);
        chacha_quarter_round(&working[0], &working[5], &working[10], &working[15]);
        chacha_quarter_round(&working[1], &working[6], &working[11], &working[12]);
        chacha_quarter_round(&working[2], &working[7], &working[8], &working[13]);
        chacha_quarter_round(&working[3], &working[4], &working[9], &working[14]);
    }
    for (uint32_t index = 0; index < 16u; ++index) {
        uint32_t value = working[index] + initial[index];
        output[index * 4u] = (uint8_t)value;
        output[index * 4u + 1u] = (uint8_t)(value >> 8);
        output[index * 4u + 2u] = (uint8_t)(value >> 16);
        output[index * 4u + 3u] = (uint8_t)(value >> 24);
    }
    ++g_random.counter;
}

static void random_lock(void) {
    while (__sync_lock_test_and_set(&g_random.lock, 1u)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause" ::: "memory");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield" ::: "memory");
#endif
    }
}

static void random_unlock(void) {
    __sync_lock_release(&g_random.lock);
}

static void random_initialize(void) {
    uint64_t seed;
    if (g_random.initialized) return;
    seed = random_cycle_counter() ^ boottime_realtime_us();
#if defined(__x86_64__)
    seed ^= keyboard_entropy_last_tsc();
    seed ^= keyboard_entropy_irq_count() << 17;
#endif
    seed ^= (uint64_t)(uintptr_t)&g_random;
    for (uint32_t index = 0; index < 8u; index += 2u) {
        uint64_t value = splitmix64(&seed);
        g_random.key[index] = (uint32_t)value;
        g_random.key[index + 1u] = (uint32_t)(value >> 32);
    }
    {
        uint64_t value = splitmix64(&seed);
        g_random.nonce[0] = (uint32_t)value;
        g_random.nonce[1] = (uint32_t)(value >> 32);
    }
    g_random.counter = splitmix64(&seed);
    g_random.initialized = 1;
}

static void random_rekey(const uint8_t material[64]) {
    for (uint32_t index = 0; index < 8u; ++index) {
        uint32_t value = (uint32_t)material[index * 4u] |
                         ((uint32_t)material[index * 4u + 1u] << 8) |
                         ((uint32_t)material[index * 4u + 2u] << 16) |
                         ((uint32_t)material[index * 4u + 3u] << 24);
        g_random.key[index] ^= value;
    }
    g_random.nonce[0] ^= (uint32_t)random_cycle_counter();
    g_random.nonce[1] ^= (uint32_t)boottime_monotonic_us();
}

void edge_random_mix(const void *buffer, uint32_t length) {
    const uint8_t *bytes = (const uint8_t *)buffer;
    uint8_t material[64];
    if (!bytes && length) return;
    random_lock();
    random_initialize();
    for (uint32_t index = 0; index < length; ++index) {
        uint32_t slot = index & 7u;
        uint32_t shift = (index & 3u) * 8u;
        g_random.key[slot] ^= (uint32_t)bytes[index] << shift;
        g_random.key[(slot + 3u) & 7u] =
            rotate_left(g_random.key[(slot + 3u) & 7u] + bytes[index], 5);
    }
    chacha_block(material);
    random_rekey(material);
    memset(material, 0, sizeof(material));
    random_unlock();
}

void edge_random_fill(void *buffer, uint32_t length) {
    uint8_t *output = (uint8_t *)buffer;
    uint8_t block[64];
    uint32_t done = 0;
    if (!output || !length) return;
    random_lock();
    random_initialize();
#ifdef CONFIG_VIRTIO_RNG
    {
        int received = virtio_rng_fill(output, length);
        if (received > 0) {
            done = (uint32_t)received;
            if (done > length) done = length;
            for (uint32_t index = 0; index < done; ++index)
                g_random.key[index & 7u] ^=
                    (uint32_t)output[index] << ((index & 3u) * 8u);
        }
    }
#endif
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    if (done < length) {
        size_t received = bsd_random_fill(output + done, length - done);

        if (received > length - done)
            received = length - done;
        for (size_t index = 0; index < received; ++index)
            g_random.key[index & 7u] ^=
                (uint32_t)output[done + index] <<
                ((index & 3u) * 8u);
        done += (uint32_t)received;
    }
#endif
    while (done < length) {
        uint32_t count = length - done;
        if (count > sizeof(block)) count = sizeof(block);
        chacha_block(block);
        memcpy(output + done, block, count);
        done += count;
    }
    chacha_block(block);
    random_rekey(block);
    g_random.generated += length;
    memset(block, 0, sizeof(block));
    random_unlock();
}
