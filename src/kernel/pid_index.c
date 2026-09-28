/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent PID index.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/pid_index.h"
#include "string.h"

#define EDGE_PID_INDEX_EMPTY 0ULL
#define EDGE_PID_INDEX_TOMBSTONE UINT64_MAX

static uint32_t edge_pid_index_hash(int32_t pid) {
    uint32_t value = (uint32_t)pid;

    value ^= value >> 16;
    value *= 0x7feb352du;
    value ^= value >> 15;
    value *= 0x846ca68bu;
    value ^= value >> 16;
    return value & (EDGE_PID_INDEX_BUCKET_COUNT - 1u);
}

static uint64_t edge_pid_index_record(int32_t pid, uint32_t slot) {
    return ((uint64_t)(uint32_t)pid << 32) | ((uint64_t)slot + 1u);
}

static int32_t edge_pid_index_record_pid(uint64_t record) {
    return (int32_t)(uint32_t)(record >> 32);
}

static int edge_pid_index_record_slot(uint64_t record) {
    uint32_t slot_plus_one = (uint32_t)record;

    return slot_plus_one ? (int)(slot_plus_one - 1u) : -1;
}

void edge_pid_index_init(edge_pid_index_t *index) {
    if (!index) return;
    memset(index, 0, sizeof(*index));
}

int edge_pid_index_insert(edge_pid_index_t *index, int32_t pid,
                          uint32_t slot) {
    uint64_t desired;
    uint32_t first_tombstone = EDGE_PID_INDEX_BUCKET_COUNT;
    uint32_t bucket;

    if (!index || pid <= 0 || slot == UINT32_MAX) return -1;
    desired = edge_pid_index_record(pid, slot);
    bucket = edge_pid_index_hash(pid);
    for (uint32_t probe = 0; probe < EDGE_PID_INDEX_BUCKET_COUNT; ++probe) {
        uint32_t position =
            (bucket + probe) & (EDGE_PID_INDEX_BUCKET_COUNT - 1u);
        uint64_t current = __atomic_load_n(
            &index->buckets[position], __ATOMIC_ACQUIRE);

        if (current == desired) return 0;
        if (current == EDGE_PID_INDEX_TOMBSTONE) {
            if (first_tombstone == EDGE_PID_INDEX_BUCKET_COUNT)
                first_tombstone = position;
            continue;
        }
        if (current != EDGE_PID_INDEX_EMPTY) {
            if (edge_pid_index_record_pid(current) == pid) return -1;
            continue;
        }
        if (first_tombstone != EDGE_PID_INDEX_BUCKET_COUNT)
            position = first_tombstone;
        current = __atomic_load_n(
            &index->buckets[position], __ATOMIC_ACQUIRE);
        if (current != EDGE_PID_INDEX_EMPTY &&
            current != EDGE_PID_INDEX_TOMBSTONE) {
            probe = 0;
            first_tombstone = EDGE_PID_INDEX_BUCKET_COUNT;
            bucket = edge_pid_index_hash(pid);
            continue;
        }
        if (__atomic_compare_exchange_n(
                &index->buckets[position], &current, desired, 0,
                __ATOMIC_RELEASE, __ATOMIC_ACQUIRE))
            return 0;
        probe = 0;
        first_tombstone = EDGE_PID_INDEX_BUCKET_COUNT;
        bucket = edge_pid_index_hash(pid);
    }
    if (first_tombstone != EDGE_PID_INDEX_BUCKET_COUNT) {
        uint64_t expected = EDGE_PID_INDEX_TOMBSTONE;
        if (__atomic_compare_exchange_n(
                &index->buckets[first_tombstone], &expected, desired, 0,
                __ATOMIC_RELEASE, __ATOMIC_ACQUIRE))
            return 0;
    }
    return -1;
}

int edge_pid_index_lookup(const edge_pid_index_t *index, int32_t pid) {
    uint32_t bucket;

    if (!index || pid <= 0) return -1;
    bucket = edge_pid_index_hash(pid);
    for (uint32_t probe = 0; probe < EDGE_PID_INDEX_BUCKET_COUNT; ++probe) {
        uint32_t position =
            (bucket + probe) & (EDGE_PID_INDEX_BUCKET_COUNT - 1u);
        uint64_t current = __atomic_load_n(
            &index->buckets[position], __ATOMIC_ACQUIRE);

        if (current == EDGE_PID_INDEX_EMPTY) return -1;
        if (current != EDGE_PID_INDEX_TOMBSTONE &&
            edge_pid_index_record_pid(current) == pid)
            return edge_pid_index_record_slot(current);
    }
    return -1;
}

void edge_pid_index_remove(edge_pid_index_t *index, int32_t pid,
                           uint32_t slot) {
    uint64_t desired;
    uint32_t bucket;

    if (!index || pid <= 0 || slot == UINT32_MAX) return;
    desired = edge_pid_index_record(pid, slot);
    bucket = edge_pid_index_hash(pid);
    for (uint32_t probe = 0; probe < EDGE_PID_INDEX_BUCKET_COUNT; ++probe) {
        uint32_t position =
            (bucket + probe) & (EDGE_PID_INDEX_BUCKET_COUNT - 1u);
        uint64_t current = __atomic_load_n(
            &index->buckets[position], __ATOMIC_ACQUIRE);

        if (current == EDGE_PID_INDEX_EMPTY) return;
        if (current != desired) continue;
        (void)__atomic_compare_exchange_n(
            &index->buckets[position], &current, EDGE_PID_INDEX_TOMBSTONE, 0,
            __ATOMIC_RELEASE, __ATOMIC_ACQUIRE);
        return;
    }
}
