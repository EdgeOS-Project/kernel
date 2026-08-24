/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kernel/bpf_runtime.h"
#include "kernel/linux_errno.h"

typedef struct test_page_region {
    uint8_t *base;
    uint32_t pages;
    uint32_t released;
} test_page_region_t;

static test_page_region_t g_page_regions[256];

void *arch_vm_alloc_pages(uint64_t page_count) {
    uint8_t *pages;

    if (!page_count || page_count > UINT32_MAX ||
        page_count > SIZE_MAX / 4096u)
        return 0;
    pages = calloc((size_t)page_count, 4096u);
    if (!pages) return 0;
    for (uint32_t index = 0;
         index < sizeof(g_page_regions) / sizeof(g_page_regions[0]);
         ++index) {
        if (g_page_regions[index].base) continue;
        g_page_regions[index].base = pages;
        g_page_regions[index].pages = (uint32_t)page_count;
        return pages;
    }
    free(pages);
    return 0;
}

void *arch_vm_alloc_page(void) {
    return arch_vm_alloc_pages(1u);
}

void arch_vm_free_page(void *page) {
    uint8_t *address = page;

    for (uint32_t index = 0;
         index < sizeof(g_page_regions) / sizeof(g_page_regions[0]);
         ++index) {
        test_page_region_t *region = &g_page_regions[index];
        uint64_t length;

        if (!region->base) continue;
        length = (uint64_t)region->pages * 4096u;
        uintptr_t address_value = (uintptr_t)address;
        uintptr_t base_value = (uintptr_t)region->base;
        if (address_value < base_value ||
            address_value - base_value >= length ||
            ((address_value - base_value) & 4095u))
            continue;
        assert(region->released < region->pages);
        if (++region->released == region->pages) {
            free(region->base);
            memset(region, 0, sizeof(*region));
        }
        return;
    }
    assert(!"unknown page release");
}

uint32_t edge_smp_nr_cpu_ids(void) {
    return 4u;
}

static uint32_t g_test_current_cpu;
static uint32_t g_perf_event_references[8];
static uint32_t g_ringbuf_notifications;
static uint64_t g_monotonic_time_us;

uint64_t boottime_monotonic_us(void) {
    return ++g_monotonic_time_us;
}

void kernel_bpf_ringbuf_state_changed(void) {
    ++g_ringbuf_notifications;
}

uint32_t edge_smp_current_cpu(void) {
    return g_test_current_cpu;
}

int kernel_perf_event_retain(int event_id) {
    if (event_id < 0 || event_id >=
            (int)(sizeof(g_perf_event_references) /
                  sizeof(g_perf_event_references[0])) ||
        !g_perf_event_references[event_id])
        return -EDGE_LINUX_EBADF;
    ++g_perf_event_references[event_id];
    return 0;
}

void kernel_perf_event_release(int event_id) {
    assert(event_id >= 0 && event_id <
           (int)(sizeof(g_perf_event_references) /
                 sizeof(g_perf_event_references[0])));
    assert(g_perf_event_references[event_id] > 0u);
    --g_perf_event_references[event_id];
}

static int create_map(uint32_t type, uint32_t key_size,
                      uint32_t value_size, uint32_t max_entries,
                      const char *name) {
    kernel_bpf_map_create_request_t request = {
        .type = type,
        .key_size = key_size,
        .value_size = value_size,
        .max_entries = max_entries,
    };
    strncpy(request.name, name, sizeof(request.name) - 1u);
    return kernel_bpf_map_create(&request);
}

static void test_array_map(void) {
    kernel_bpf_map_info_t info;
    uint32_t key = 2u;
    uint32_t next = UINT32_MAX;
    uint64_t value = 0x1122334455667788ULL;
    uint64_t output = 0;
    int object = create_map(
        KERNEL_BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value), 4u,
        "array_map");

    assert(object >= 0);
    assert(kernel_bpf_map_info(object, &info) == 0);
    assert(info.type == KERNEL_BPF_MAP_TYPE_ARRAY);
    assert(info.key_size == sizeof(key));
    assert(info.value_size == sizeof(value));
    assert(info.max_entries == 4u);
    assert(strcmp(info.name, "array_map") == 0);
    assert(kernel_bpf_map_lookup(object, &key, &output) == 0);
    assert(output == 0u);
    assert(kernel_bpf_map_update(
               object, &key, &value, KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_lookup(object, &key, &output) == 0);
    assert(output == value);
    assert(kernel_bpf_map_update(
               object, &key, &value, KERNEL_BPF_NOEXIST) < 0);
    assert(kernel_bpf_map_delete(object, &key) < 0);
    assert(kernel_bpf_map_next_key(object, &key, &next) == 0);
    assert(next == 3u);
    key = 3u;
    assert(kernel_bpf_map_next_key(object, &key, &next) < 0);
    kernel_bpf_object_release(object);
    assert(kernel_bpf_map_info(object, &info) < 0);
}

static void test_map_access_flags(void) {
    kernel_bpf_map_create_request_t request = {
        .type = KERNEL_BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(uint64_t),
        .max_entries = 1u,
        .flags = KERNEL_BPF_MAP_RDONLY,
    };
    kernel_bpf_map_info_t info;
    int object;

    strncpy(request.name, "access_map", sizeof(request.name) - 1u);
    object = kernel_bpf_map_create(&request);
    assert(object >= 0);
    assert(kernel_bpf_map_info(object, &info) == 0);
    assert(info.flags == 0u);
    kernel_bpf_object_release(object);

    request.flags = KERNEL_BPF_MAP_WRONLY;
    object = kernel_bpf_map_create(&request);
    assert(object >= 0);
    assert(kernel_bpf_map_info(object, &info) == 0);
    assert(info.flags == 0u);
    kernel_bpf_object_release(object);

    request.flags = KERNEL_BPF_MAP_RDONLY | KERNEL_BPF_MAP_WRONLY;
    assert(kernel_bpf_map_create(&request) == -EDGE_LINUX_EINVAL);
}

static void test_hash_map(void) {
    kernel_bpf_map_info_t info;
    uint32_t key1 = 10u;
    uint32_t key2 = 20u;
    uint32_t missing = 30u;
    uint32_t next = 0u;
    uint64_t value1 = 100u;
    uint64_t value2 = 200u;
    uint64_t output = 0;
    int object = create_map(
        KERNEL_BPF_MAP_TYPE_HASH, sizeof(key1), sizeof(value1), 2u,
        "hash_map");

    assert(object >= 0);
    assert(kernel_bpf_map_update(
               object, &key1, &value1, KERNEL_BPF_NOEXIST) == 0);
    assert(kernel_bpf_map_update(
               object, &key1, &value1, KERNEL_BPF_NOEXIST) < 0);
    assert(kernel_bpf_map_update(
               object, &key2, &value2, KERNEL_BPF_EXIST) < 0);
    assert(kernel_bpf_map_update(
               object, &key2, &value2, KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_update(
               object, &missing, &value2, KERNEL_BPF_ANY) < 0);
    assert(kernel_bpf_map_lookup(object, &key1, &output) == 0);
    assert(output == value1);
    assert(kernel_bpf_map_lookup_and_delete(
               object, &key1, &output) == 0);
    assert(output == value1);
    assert(kernel_bpf_map_lookup(object, &key1, &output) < 0);
    assert(kernel_bpf_map_update(
               object, &key1, &value1, KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_next_key(object, 0, &next) == 0);
    assert(next == key1);
    assert(kernel_bpf_map_delete(object, &key1) == 0);
    assert(kernel_bpf_map_lookup(object, &key1, &output) < 0);
    assert(kernel_bpf_map_next_key(object, &missing, &next) == 0);
    assert(next == key2);
    assert(kernel_bpf_map_info(object, &info) == 0);
    assert(kernel_bpf_object_retain(object) == 0);
    kernel_bpf_object_release(object);
    kernel_bpf_object_release(object);
    assert(kernel_bpf_map_info(object, &info) < 0);
}

static void test_lru_hash_map(void) {
    kernel_bpf_map_create_request_t invalid = {
        .type = KERNEL_BPF_MAP_TYPE_LRU_HASH,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(uint64_t),
        .max_entries = 2u,
        .flags = KERNEL_BPF_MAP_NO_PREALLOC,
    };
    kernel_bpf_map_info_t info;
    uint32_t keys[] = { 1u, 2u, 3u, 4u };
    uint64_t values[] = { 11u, 22u, 33u, 44u };
    uint64_t output = 0u;
    int object = create_map(
        KERNEL_BPF_MAP_TYPE_LRU_HASH, sizeof(keys[0]),
        sizeof(values[0]), 2u, "lru_hash");

    assert(object >= 0);
    assert(kernel_bpf_map_info(object, &info) == 0);
    assert(info.type == KERNEL_BPF_MAP_TYPE_LRU_HASH);
    assert(kernel_bpf_map_update(
               object, &keys[0], &values[0], KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_update(
               object, &keys[1], &values[1], KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_lookup(object, &keys[0], &output) == 0);
    assert(output == values[0]);

    assert(kernel_bpf_map_update(
               object, &keys[2], &values[2], KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_lookup(object, &keys[1], &output) ==
           -EDGE_LINUX_ENOENT);
    assert(kernel_bpf_map_lookup(object, &keys[0], &output) == 0);
    assert(kernel_bpf_map_lookup(object, &keys[2], &output) == 0);

    assert(kernel_bpf_map_update(
               object, &keys[3], &values[3], KERNEL_BPF_EXIST) ==
           -EDGE_LINUX_ENOENT);
    assert(kernel_bpf_map_update(
               object, &keys[3], &values[3], KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_lookup(object, &keys[0], &output) ==
           -EDGE_LINUX_ENOENT);
    assert(kernel_bpf_map_lookup_and_delete(
               object, &keys[2], &output) == 0);
    assert(output == values[2]);
    assert(kernel_bpf_map_update(
               object, &keys[0], &values[0], KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_update(
               object, &keys[1], &values[1], KERNEL_BPF_ANY) == 0);
    {
        uint32_t cursor = 0u;
        uint32_t key = 0u;
        int has_more = 0;

        assert(kernel_bpf_map_batch_next(
                   object, &cursor, &key, &output, 1, &has_more) == 0);
        assert(key == keys[0] || key == keys[1]);
    }
    kernel_bpf_object_release(object);

    strcpy(invalid.name, "bad_lru");
    assert(kernel_bpf_map_create(&invalid) ==
           -EDGE_LINUX_ENOTSUPP);
}

static void test_queue_stack_maps(void) {
    kernel_bpf_map_create_request_t invalid = {
        .type = KERNEL_BPF_MAP_TYPE_QUEUE,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(uint64_t),
        .max_entries = 2u,
    };
    kernel_bpf_map_info_t info;
    uint32_t cursor = 0u;
    uint32_t key = 1u;
    uint64_t first = 11u;
    uint64_t second = 22u;
    uint64_t third = 33u;
    uint64_t output = UINT64_MAX;
    int has_more = 0;
    int queue = create_map(
        KERNEL_BPF_MAP_TYPE_QUEUE, 0u, sizeof(first), 2u, "queue_map");
    int stack;

    assert(queue >= 0);
    assert(kernel_bpf_map_info(queue, &info) == 0);
    assert(info.type == KERNEL_BPF_MAP_TYPE_QUEUE);
    assert(info.key_size == 0u);
    assert(kernel_bpf_map_lookup(queue, 0, &output) ==
           -EDGE_LINUX_ENOENT);
    assert(output == 0u);
    assert(kernel_bpf_map_update(
               queue, 0, &first, KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_update(
               queue, 0, &second, KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_update(
               queue, 0, &third, KERNEL_BPF_ANY) ==
           -EDGE_LINUX_E2BIG);
    assert(kernel_bpf_map_update(
               queue, &key, &third, KERNEL_BPF_ANY) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_bpf_map_update(
               queue, 0, &third, KERNEL_BPF_NOEXIST) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_bpf_map_update(
               queue, 0, &third, KERNEL_BPF_EXIST) == 0);
    assert(kernel_bpf_map_lookup(queue, 0, &output) == 0);
    assert(output == second);
    assert(kernel_bpf_map_lookup_and_delete(queue, 0, &output) == 0);
    assert(output == second);
    assert(kernel_bpf_map_lookup_and_delete(queue, 0, &output) == 0);
    assert(output == third);
    assert(kernel_bpf_map_lookup_and_delete(queue, 0, &output) ==
           -EDGE_LINUX_ENOENT);
    assert(output == 0u);
    assert(kernel_bpf_map_delete(queue, 0) == -EDGE_LINUX_EINVAL);
    assert(kernel_bpf_map_next_key(queue, 0, &key) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_bpf_map_batch_next(
               queue, &cursor, &key, &output, 0, &has_more) ==
           -EDGE_LINUX_ENOTSUPP);
    kernel_bpf_object_release(queue);

    stack = create_map(
        KERNEL_BPF_MAP_TYPE_STACK, 0u, sizeof(first), 2u, "stack_map");
    assert(stack >= 0);
    assert(kernel_bpf_map_update(
               stack, 0, &first, KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_update(
               stack, 0, &second, KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_lookup(stack, 0, &output) == 0);
    assert(output == second);
    assert(kernel_bpf_map_update(
               stack, 0, &third, KERNEL_BPF_EXIST) == 0);
    assert(kernel_bpf_map_lookup_and_delete(stack, 0, &output) == 0);
    assert(output == third);
    assert(kernel_bpf_map_lookup_and_delete(stack, 0, &output) == 0);
    assert(output == second);
    assert(kernel_bpf_map_update(
               stack, 0, &first, KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_freeze(stack) == 0);
    assert(kernel_bpf_map_lookup(stack, 0, &output) == 0);
    assert(output == first);
    assert(kernel_bpf_map_update(
               stack, 0, &second, KERNEL_BPF_ANY) ==
           -EDGE_LINUX_EPERM);
    assert(kernel_bpf_map_lookup_and_delete(stack, 0, &output) ==
           -EDGE_LINUX_EPERM);
    kernel_bpf_object_release(stack);

    strcpy(invalid.name, "bad_queue");
    assert(kernel_bpf_map_create(&invalid) == -EDGE_LINUX_EINVAL);
    invalid.key_size = 0u;
    invalid.flags = KERNEL_BPF_MAP_NO_PREALLOC;
    assert(kernel_bpf_map_create(&invalid) == -EDGE_LINUX_EINVAL);
}

static void test_lpm_trie_map(void) {
    struct lpm_key {
        uint32_t prefix_length;
        uint8_t address[4];
    } keys[] = {
        { .prefix_length = 0u, .address = { 0u, 0u, 0u, 0u } },
        { .prefix_length = 8u, .address = { 10u, 0u, 0u, 0u } },
        { .prefix_length = 24u, .address = { 10u, 1u, 2u, 0u } },
    };
    kernel_bpf_map_create_request_t request = {
        .type = KERNEL_BPF_MAP_TYPE_LPM_TRIE,
        .key_size = sizeof(keys[0]),
        .value_size = sizeof(uint32_t),
        .max_entries = 3u,
        .flags = KERNEL_BPF_MAP_NO_PREALLOC,
    };
    struct lpm_key query = {
        .prefix_length = 32u,
        .address = { 10u, 1u, 2u, 3u },
    };
    struct lpm_key replacement = {
        .prefix_length = 8u,
        .address = { 10u, 99u, 88u, 77u },
    };
    struct lpm_key next;
    uint32_t values[] = { 1u, 8u, 24u, 88u };
    uint32_t output = 0u;
    int object;

    strcpy(request.name, "routes");
    object = kernel_bpf_map_create(&request);
    assert(object >= 0);
    for (uint32_t index = 0; index < 3u; ++index)
        assert(kernel_bpf_map_update(
                   object, &keys[index], &values[index],
                   KERNEL_BPF_NOEXIST) == 0);
    assert(kernel_bpf_map_lookup(object, &query, &output) == 0);
    assert(output == values[2]);
    query.address[1] = 2u;
    assert(kernel_bpf_map_lookup(object, &query, &output) == 0);
    assert(output == values[1]);
    query.address[0] = 192u;
    assert(kernel_bpf_map_lookup(object, &query, &output) == 0);
    assert(output == values[0]);
    assert(kernel_bpf_map_update(
               object, &replacement, &values[3],
               KERNEL_BPF_NOEXIST) == -EDGE_LINUX_EEXIST);
    assert(kernel_bpf_map_update(
               object, &replacement, &values[3],
               KERNEL_BPF_EXIST) == 0);
    query.address[0] = 10u;
    assert(kernel_bpf_map_lookup(object, &query, &output) == 0);
    assert(output == values[3]);
    assert(kernel_bpf_map_delete(object, &keys[2]) == 0);
    query.address[1] = 1u;
    assert(kernel_bpf_map_lookup(object, &query, &output) == 0);
    assert(output == values[3]);
    assert(kernel_bpf_map_update(
               object, &keys[2], &values[2], KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_next_key(object, 0, &next) == 0);
    assert(next.prefix_length == 24u);
    assert(kernel_bpf_map_next_key(object, &next, &next) == 0);
    assert(next.prefix_length == 8u);
    assert(kernel_bpf_map_next_key(object, &next, &next) == 0);
    assert(next.prefix_length == 0u);
    assert(kernel_bpf_map_next_key(object, &next, &next) ==
           -EDGE_LINUX_ENOENT);
    query.prefix_length = 33u;
    assert(kernel_bpf_map_lookup(object, &query, &output) ==
           -EDGE_LINUX_ENOENT);
    assert(kernel_bpf_map_delete(object, &query) ==
           -EDGE_LINUX_EINVAL);
    kernel_bpf_object_release(object);

    request.flags = 0u;
    assert(kernel_bpf_map_create(&request) == -EDGE_LINUX_EINVAL);
}

static void test_bloom_filter_map(void) {
    kernel_bpf_map_create_request_t request = {
        .type = KERNEL_BPF_MAP_TYPE_BLOOM_FILTER,
        .value_size = sizeof(uint32_t),
        .max_entries = 100u,
        .flags = KERNEL_BPF_MAP_ZERO_SEED,
        .map_extra = 3u,
    };
    kernel_bpf_map_info_t info;
    uint32_t present = 0x11223344u;
    uint32_t missing = 0x55667788u;
    uint32_t next = 0u;
    int object;

    strcpy(request.name, "bloom");
    object = kernel_bpf_map_create(&request);
    assert(object >= 0);
    assert(kernel_bpf_map_info(object, &info) == 0);
    assert(info.type == KERNEL_BPF_MAP_TYPE_BLOOM_FILTER);
    assert(info.map_extra == 3u);
    assert(kernel_bpf_map_lookup(object, 0, &missing) ==
           -EDGE_LINUX_ENOENT);
    assert(kernel_bpf_map_update(
               object, 0, &present, KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_lookup(object, 0, &present) == 0);
    assert(kernel_bpf_map_update(
               object, 0, &present, KERNEL_BPF_EXIST) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_bpf_map_delete(object, 0) ==
           -EDGE_LINUX_EOPNOTSUPP);
    assert(kernel_bpf_map_next_key(object, 0, &next) ==
           -EDGE_LINUX_EOPNOTSUPP);
    assert(kernel_bpf_map_lookup_and_delete(
               object, 0, &present) == -EDGE_LINUX_EOPNOTSUPP);
    kernel_bpf_object_release(object);

    request.key_size = sizeof(uint32_t);
    assert(kernel_bpf_map_create(&request) == -EDGE_LINUX_EINVAL);
    request.key_size = 0u;
    request.map_extra = 16u;
    assert(kernel_bpf_map_create(&request) == -EDGE_LINUX_EINVAL);
}

static void test_percpu_maps(void) {
    uint8_t array_values[4][8];
    uint8_t array_output[4][8];
    uint8_t scalar_array_value[3] = { 91u, 92u, 93u };
    uint8_t scalar_array_output[3] = { 0u, 0u, 0u };
    uint64_t hash_values[4] = { 101u, 202u, 303u, 404u };
    uint64_t hash_output[4] = { 0u, 0u, 0u, 0u };
    uint64_t scalar_hash_value = 909u;
    uint64_t scalar_hash_output = 0u;
    uint32_t array_key = 1u;
    uint32_t hash_key = 7u;
    uint32_t batch_key = 0u;
    uint32_t cursor = 0u;
    uint32_t buffer_size = 0u;
    uint64_t cpu_one_flags = KERNEL_BPF_F_CPU | (1ULL << 32u);
    uint64_t cpu_two_flags = KERNEL_BPF_F_CPU | (2ULL << 32u);
    int has_more = 0;
    int array;
    int hash;

    memset(array_values, 0xa5, sizeof(array_values));
    memset(array_output, 0xcc, sizeof(array_output));
    for (uint32_t cpu = 0; cpu < 4u; ++cpu) {
        array_values[cpu][0] = (uint8_t)(cpu + 1u);
        array_values[cpu][1] = (uint8_t)(cpu + 11u);
        array_values[cpu][2] = (uint8_t)(cpu + 21u);
    }

    array = create_map(
        KERNEL_BPF_MAP_TYPE_PERCPU_ARRAY, sizeof(array_key), 3u, 2u,
        "percpu_array");
    assert(array >= 0);
    assert(kernel_bpf_map_value_buffer_size(
               array, 0u, &buffer_size) == 0);
    assert(buffer_size == sizeof(array_values));
    assert(kernel_bpf_map_lookup(array, &array_key, array_output) == 0);
    for (uint32_t cpu = 0; cpu < 4u; ++cpu)
        for (uint32_t byte = 0; byte < 8u; ++byte)
            assert(array_output[cpu][byte] == 0u);
    assert(kernel_bpf_map_update(
               array, &array_key, array_values, KERNEL_BPF_ANY) == 0);
    memset(array_output, 0xcc, sizeof(array_output));
    assert(kernel_bpf_map_lookup(array, &array_key, array_output) == 0);
    for (uint32_t cpu = 0; cpu < 4u; ++cpu) {
        assert(memcmp(array_output[cpu], array_values[cpu], 3u) == 0);
        for (uint32_t byte = 3u; byte < 8u; ++byte)
            assert(array_output[cpu][byte] == 0u);
    }
    assert(kernel_bpf_map_update(
               array, &array_key, array_values, KERNEL_BPF_NOEXIST) ==
           -EDGE_LINUX_EEXIST);
    assert(kernel_bpf_map_value_buffer_size(
               array, cpu_two_flags, &buffer_size) == 0);
    assert(buffer_size == sizeof(scalar_array_value));
    assert(kernel_bpf_map_update(
               array, &array_key, scalar_array_value, cpu_two_flags) == 0);
    assert(kernel_bpf_map_lookup_flags(
               array, &array_key, scalar_array_output, cpu_two_flags) == 0);
    assert(memcmp(scalar_array_output, scalar_array_value,
                  sizeof(scalar_array_value)) == 0);
    memset(array_output, 0, sizeof(array_output));
    assert(kernel_bpf_map_update(
               array, &array_key, scalar_array_value,
               KERNEL_BPF_F_ALL_CPUS) == 0);
    assert(kernel_bpf_map_lookup(array, &array_key, array_output) == 0);
    for (uint32_t cpu = 0; cpu < 4u; ++cpu)
        assert(memcmp(array_output[cpu], scalar_array_value,
                      sizeof(scalar_array_value)) == 0);
    assert(kernel_bpf_map_lookup_flags(
               array, &array_key, scalar_array_output,
               KERNEL_BPF_F_ALL_CPUS) == -EDGE_LINUX_EINVAL);
    assert(kernel_bpf_map_value_buffer_size(
               array, KERNEL_BPF_F_CPU | (4ULL << 32u),
               &buffer_size) == -EDGE_LINUX_ERANGE);
    assert(kernel_bpf_map_delete(array, &array_key) ==
           -EDGE_LINUX_EINVAL);
    kernel_bpf_object_release(array);

    hash = create_map(
        KERNEL_BPF_MAP_TYPE_PERCPU_HASH, sizeof(hash_key),
        sizeof(hash_values[0]), 2u, "percpu_hash");
    assert(hash >= 0);
    assert(kernel_bpf_map_value_buffer_size(
               hash, 0u, &buffer_size) == 0);
    assert(buffer_size == sizeof(hash_values));
    assert(kernel_bpf_map_update(
               hash, &hash_key, hash_values, KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_lookup(hash, &hash_key, hash_output) == 0);
    assert(memcmp(hash_output, hash_values, sizeof(hash_values)) == 0);
    assert(kernel_bpf_map_update(
               hash, &hash_key, &scalar_hash_value, cpu_one_flags) == 0);
    assert(kernel_bpf_map_lookup_flags(
               hash, &hash_key, &scalar_hash_output, cpu_one_flags) == 0);
    assert(scalar_hash_output == scalar_hash_value);
    memset(hash_output, 0, sizeof(hash_output));
    assert(kernel_bpf_map_batch_next_flags(
               hash, &cursor, &batch_key, &scalar_hash_output,
               cpu_one_flags, 0, &has_more) == 0);
    assert(batch_key == hash_key);
    assert(scalar_hash_output == scalar_hash_value);
    assert(has_more == 0);
    assert(kernel_bpf_map_update(
               hash, &hash_key, &scalar_hash_value,
               KERNEL_BPF_F_ALL_CPUS) == 0);
    for (uint32_t cpu = 0; cpu < 4u; ++cpu)
        hash_values[cpu] = scalar_hash_value;
    memset(hash_output, 0, sizeof(hash_output));
    assert(kernel_bpf_map_lookup_and_delete(
               hash, &hash_key, hash_output) == 0);
    assert(memcmp(hash_output, hash_values, sizeof(hash_values)) == 0);
    assert(kernel_bpf_map_lookup(hash, &hash_key, hash_output) ==
           -EDGE_LINUX_ENOENT);
    kernel_bpf_object_release(hash);
}

static void test_lru_percpu_hash_map(void) {
    uint64_t values[3][4] = {
        { 101u, 102u, 103u, 104u },
        { 201u, 202u, 203u, 204u },
        { 301u, 302u, 303u, 304u },
    };
    uint64_t output[4] = { 0u, 0u, 0u, 0u };
    uint32_t keys[3] = { 41u, 42u, 43u };
    kernel_bpf_map_create_request_t invalid = {
        .type = KERNEL_BPF_MAP_TYPE_LRU_PERCPU_HASH,
        .key_size = sizeof(keys[0]),
        .value_size = sizeof(values[0][0]),
        .max_entries = 2u,
        .flags = KERNEL_BPF_MAP_NO_PREALLOC,
    };
    int object = create_map(
        KERNEL_BPF_MAP_TYPE_LRU_PERCPU_HASH, sizeof(keys[0]),
        sizeof(values[0][0]), 2u, "lru_percpu");

    assert(object >= 0);
    assert(kernel_bpf_map_update(
               object, &keys[0], values[0], KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_update(
               object, &keys[1], values[1], KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_lookup(object, &keys[0], output) == 0);
    assert(memcmp(output, values[0], sizeof(output)) == 0);
    assert(kernel_bpf_map_update(
               object, &keys[2], values[2], KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_lookup(object, &keys[0], output) ==
           -EDGE_LINUX_ENOENT);
    assert(kernel_bpf_map_lookup(object, &keys[1], output) == 0);
    assert(memcmp(output, values[1], sizeof(output)) == 0);
    assert(kernel_bpf_map_lookup(object, &keys[2], output) == 0);
    assert(memcmp(output, values[2], sizeof(output)) == 0);
    kernel_bpf_object_release(object);

    strcpy(invalid.name, "bad_lru_percpu");
    assert(kernel_bpf_map_create(&invalid) == -EDGE_LINUX_ENOTSUPP);
}

static void test_no_common_lru(void) {
    kernel_bpf_map_create_request_t request = {
        .type = KERNEL_BPF_MAP_TYPE_LRU_HASH,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(uint64_t),
        .max_entries = 5u,
        .flags = KERNEL_BPF_MAP_NO_COMMON_LRU,
    };
    kernel_bpf_map_info_t info;
    uint32_t keys[] = { 51u, 52u, 53u, 54u };
    uint64_t values[] = { 510u, 520u, 530u, 540u };
    uint64_t output = 0u;
    int object;

    strcpy(request.name, "private_lru");
    object = kernel_bpf_map_create(&request);
    assert(object >= 0);
    assert(kernel_bpf_map_info(object, &info) == 0);
    assert(info.max_entries == 8u);
    assert(info.flags == KERNEL_BPF_MAP_NO_COMMON_LRU);

    g_test_current_cpu = 0u;
    assert(kernel_bpf_map_update(
               object, &keys[0], &values[0], KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_update(
               object, &keys[1], &values[1], KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_lookup(object, &keys[0], &output) == 0);
    assert(kernel_bpf_map_update(
               object, &keys[2], &values[2], KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_lookup(object, &keys[1], &output) ==
           -EDGE_LINUX_ENOENT);
    assert(kernel_bpf_map_lookup(object, &keys[0], &output) == 0);

    g_test_current_cpu = 1u;
    assert(kernel_bpf_map_update(
               object, &keys[3], &values[3], KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_lookup(object, &keys[3], &output) == 0);
    g_test_current_cpu = 0u;
    assert(kernel_bpf_map_lookup(object, &keys[0], &output) == 0);
    assert(kernel_bpf_map_lookup(object, &keys[2], &output) == 0);
    kernel_bpf_object_release(object);
}

static void test_map_in_map(void) {
    kernel_bpf_map_create_request_t outer_request = {
        .type = KERNEL_BPF_MAP_TYPE_ARRAY_OF_MAPS,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(uint32_t),
        .max_entries = 2u,
    };
    uint32_t key = 0u;
    uint32_t second_key = 1u;
    uint32_t inner_id = 0u;
    uint32_t replacement_id = 0u;
    uint32_t output_id = 0u;
    uint32_t cursor = 0u;
    uint32_t output_key = UINT32_MAX;
    int has_more = 0;
    uint64_t value = 11u;
    int inner = create_map(
        KERNEL_BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value), 2u,
        "inner_one");
    int replacement = create_map(
        KERNEL_BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value), 4u,
        "inner_two");
    int incompatible = create_map(
        KERNEL_BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(uint32_t), 2u,
        "inner_bad");
    int outer;
    int hash_outer;

    assert(inner >= 0 && replacement >= 0 && incompatible >= 0);
    assert(kernel_bpf_object_user_id(inner, &inner_id) == 0);
    outer_request.inner_map_object_id = inner;
    strcpy(outer_request.name, "array_of_maps");
    outer = kernel_bpf_map_create(&outer_request);
    assert(outer >= 0);
    assert(kernel_bpf_map_lookup(outer, &key, &output_id) ==
           -EDGE_LINUX_ENOENT);
    assert(kernel_bpf_map_update(
               outer, &key, &inner, KERNEL_BPF_ANY) == 0);
    kernel_bpf_object_release(inner);
    assert(kernel_bpf_map_lookup(outer, &key, &output_id) == 0);
    assert(output_id == inner_id);
    assert(kernel_bpf_map_update(
               outer, &key, &incompatible, KERNEL_BPF_ANY) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_bpf_map_update(
               outer, &key, &replacement, KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_object_user_id(replacement, &replacement_id) == 0);
    assert(kernel_bpf_map_update(
               outer, &second_key, &replacement, KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_batch_next(
               outer, &cursor, &output_key, &output_id, 0,
               &has_more) == 0);
    assert(output_key == key && output_id == replacement_id && has_more);
    assert(kernel_bpf_map_info(inner, &(kernel_bpf_map_info_t){0}) ==
           -EDGE_LINUX_EBADF);
    assert(kernel_bpf_map_delete(outer, &key) == 0);
    assert(kernel_bpf_map_delete(outer, &key) == -EDGE_LINUX_ENOENT);
    cursor = 0u;
    assert(kernel_bpf_map_batch_next(
               outer, &cursor, &output_key, &output_id, 0,
               &has_more) == 0);
    assert(output_key == second_key && output_id == replacement_id &&
           !has_more);
    kernel_bpf_object_release(outer);

    outer_request.type = KERNEL_BPF_MAP_TYPE_HASH_OF_MAPS;
    outer_request.inner_map_object_id = replacement;
    strcpy(outer_request.name, "hash_of_maps");
    hash_outer = kernel_bpf_map_create(&outer_request);
    assert(hash_outer >= 0);
    assert(kernel_bpf_map_update(
               hash_outer, &key, &replacement, KERNEL_BPF_NOEXIST) == 0);
    assert(kernel_bpf_map_update(
               hash_outer, &key, &replacement, KERNEL_BPF_NOEXIST) ==
           -EDGE_LINUX_EEXIST);
    cursor = 0u;
    assert(kernel_bpf_map_batch_next(
               hash_outer, &cursor, &output_key, &output_id, 1,
               &has_more) == 0);
    assert(output_key == key && output_id == replacement_id && !has_more);
    assert(kernel_bpf_map_lookup(hash_outer, &key, &output_id) ==
           -EDGE_LINUX_ENOENT);
    kernel_bpf_object_release(hash_outer);
    kernel_bpf_object_release(replacement);
    kernel_bpf_object_release(incompatible);
}

static void test_batch_and_freeze(void) {
    uint32_t keys[] = { 1u, 2u, 3u };
    uint64_t values[] = { 11u, 22u, 33u };
    uint32_t cursor = 0;
    uint32_t key = 0;
    uint64_t value = 0;
    int has_more = 0;
    int object = create_map(
        KERNEL_BPF_MAP_TYPE_HASH, sizeof(key), sizeof(value), 4u,
        "batch_map");

    assert(object >= 0);
    for (uint32_t index = 0; index < 3u; ++index)
        assert(kernel_bpf_map_update(
                   object, &keys[index], &values[index],
                   KERNEL_BPF_ANY) == 0);
    for (uint32_t index = 0; index < 3u; ++index) {
        assert(kernel_bpf_map_batch_next(
                   object, &cursor, &key, &value, 0, &has_more) == 0);
        assert(key == keys[index]);
        assert(value == values[index]);
        assert(has_more == (index + 1u < 3u));
    }
    assert(kernel_bpf_map_batch_next(
               object, &cursor, &key, &value, 0, &has_more) < 0);
    cursor = 0;
    for (uint32_t index = 0; index < 3u; ++index)
        assert(kernel_bpf_map_batch_next(
                   object, &cursor, &key, &value, 1, &has_more) == 0);
    cursor = 0;
    assert(kernel_bpf_map_batch_next(
               object, &cursor, &key, &value, 0, &has_more) < 0);
    assert(kernel_bpf_map_update(
               object, &keys[0], &values[0], KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_freeze(object) == 0);
    assert(kernel_bpf_map_freeze(object) < 0);
    assert(kernel_bpf_map_lookup(object, &keys[0], &value) == 0);
    assert(value == values[0]);
    assert(kernel_bpf_map_update(
               object, &keys[0], &values[1], KERNEL_BPF_ANY) < 0);
    assert(kernel_bpf_map_delete(object, &keys[0]) < 0);
    assert(kernel_bpf_map_lookup_and_delete(
               object, &keys[0], &value) < 0);
    cursor = 0;
    assert(kernel_bpf_map_batch_next(
               object, &cursor, &key, &value, 1, &has_more) < 0);
    kernel_bpf_object_release(object);
}

static void test_program(void) {
    static const uint8_t expected_tag[8] = {
        0xb1u, 0x14u, 0x59u, 0xa0u, 0xe1u, 0x1cu, 0xa1u, 0x4cu,
    };
    const kernel_bpf_instruction_t instructions[] = {
        { .code = 0xb7u, .registers = 0u, .offset = 0, .immediate = 1 },
        { .code = 0x95u, .registers = 0u, .offset = 0, .immediate = 0 },
    };
    kernel_bpf_program_create_request_t request = {
        .type = KERNEL_BPF_PROG_TYPE_CGROUP_DEVICE,
        .instruction_count = 2u,
        .expected_attach_type = KERNEL_BPF_CGROUP_DEVICE,
        .created_by_uid = 1000u,
    };
    kernel_bpf_program_info_t info;
    kernel_bpf_cgroup_device_context_t context = {
        .access_type = 1u,
        .major = 1u,
        .minor = 3u,
    };
    uint32_t result = 0;
    uint32_t count = 0;
    uint32_t flags[4];
    int objects[4];
    int links[4];
    int object;
    int deny_object;
    int replacement_object;
    int link_object;

    strcpy(request.name, "allow_dev");
    object = kernel_bpf_program_create(&request, instructions);
    assert(object >= 0);
    assert(kernel_bpf_program_info(object, &info) == 0);
    assert(info.type == KERNEL_BPF_PROG_TYPE_CGROUP_DEVICE);
    assert(info.instruction_count == 2u);
    assert(info.created_by_uid == 1000u);
    assert(memcmp(info.tag, expected_tag, sizeof(expected_tag)) == 0);
    assert(kernel_bpf_program_run_cgroup_device(
               object, &context, &result) == 0);
    assert(result == 1u);
    assert(kernel_bpf_cgroup_attach(3u, object, 0u, -1) == 0);
    assert(kernel_bpf_cgroup_attach(3u, object, 0u, -1) < 0);
    assert(kernel_bpf_cgroup_query(
               3u, objects, flags, 4u, &count, 0) == 0);
    assert(count == 1u && objects[0] == object && flags[0] == 0u);
    result = 0u;
    assert(kernel_bpf_cgroup_device_run(
               3u, &context, &result) == 0 && result == 1u);
    assert(kernel_bpf_cgroup_detach(3u, object) == 0);

    request.expected_attach_type = KERNEL_BPF_CGROUP_DEVICE;
    strcpy(request.name, "deny_dev");
    {
        const kernel_bpf_instruction_t deny_instructions[] = {
            { .code = 0xb7u, .registers = 0u,
              .offset = 0, .immediate = 0 },
            { .code = 0x95u, .registers = 0u,
              .offset = 0, .immediate = 0 },
        };
        deny_object = kernel_bpf_program_create(
            &request, deny_instructions);
    }
    assert(deny_object >= 0);
    strcpy(request.name, "replacement");
    replacement_object = kernel_bpf_program_create(
        &request, instructions);
    assert(replacement_object >= 0);
    assert(kernel_bpf_cgroup_attach(
               3u, object, KERNEL_BPF_F_ALLOW_MULTI, -1) == 0);
    assert(kernel_bpf_cgroup_attach(
               3u, deny_object, KERNEL_BPF_F_ALLOW_MULTI, -1) == 0);
    result = 1u;
    assert(kernel_bpf_cgroup_device_run(
               3u, &context, &result) == 0 && result == 0u);
    assert(kernel_bpf_cgroup_attach(
               3u, replacement_object,
               KERNEL_BPF_F_ALLOW_MULTI | KERNEL_BPF_F_REPLACE,
               deny_object) == 0);
    result = 0u;
    assert(kernel_bpf_cgroup_device_run(
               3u, &context, &result) == 0 && result == 1u);
    count = 0u;
    assert(kernel_bpf_cgroup_query(
               3u, 0, 0, 0u, &count, 0) < 0 && count == 2u);
    kernel_bpf_cgroup_release(3u);
    count = 1u;
    assert(kernel_bpf_cgroup_query(
               3u, objects, flags, 4u, &count, 0) == 0 && count == 0u);
    assert(kernel_bpf_cgroup_attach(
               4u, object, KERNEL_BPF_F_ALLOW_MULTI, -1) == 0);
    assert(kernel_bpf_cgroup_attach(
               4u, deny_object, KERNEL_BPF_F_ALLOW_MULTI, -1) == 0);
    assert(kernel_bpf_cgroup_detach(4u, object) == 0);
    assert(kernel_bpf_cgroup_attach(
               4u, replacement_object, KERNEL_BPF_F_ALLOW_MULTI, -1) == 0);
    count = 0u;
    assert(kernel_bpf_cgroup_query(
               4u, objects, flags, 4u, &count, 0) == 0);
    assert(count == 2u && objects[0] == deny_object &&
           objects[1] == replacement_object);
    kernel_bpf_cgroup_release(4u);

    link_object = kernel_bpf_cgroup_link_create(
        5u, object, KERNEL_BPF_CGROUP_DEVICE, 0u);
    assert(link_object >= 0);
    {
        kernel_bpf_link_info_t link_info;
        uint32_t link_user_id = 0u;

        assert(kernel_bpf_link_info(link_object, &link_info) == 0);
        assert(link_info.type == 3u && !link_info.detached &&
               link_info.program_id == info.id &&
               link_info.cgroup_id == 5u);
        assert(kernel_bpf_object_user_id(
                   link_object, &link_user_id) == 0);
        count = 0u;
        assert(kernel_bpf_cgroup_query_links(
                   5u, objects, flags, links, 4u, &count, 0) == 0);
        assert(count == 1u && objects[0] == object &&
               links[0] == link_object &&
               flags[0] == KERNEL_BPF_F_ALLOW_MULTI);
        assert(kernel_bpf_link_update(
                   link_object, deny_object, 0u, -1) == 0);
        result = 1u;
        assert(kernel_bpf_cgroup_device_run(
                   5u, &context, &result) == 0 && result == 0u);
        assert(kernel_bpf_link_detach(link_object) == 0);
        assert(kernel_bpf_link_detach(link_object) ==
               -EDGE_LINUX_ENOENT);
        assert(kernel_bpf_link_info(link_object, &link_info) == 0 &&
               link_info.detached && link_info.program_id != 0u);
        kernel_bpf_object_release(link_object);
        assert(kernel_bpf_object_from_user_id(
                   KERNEL_BPF_OBJECT_LINK, link_user_id) ==
               -EDGE_LINUX_ENOENT);
    }
    link_object = kernel_bpf_cgroup_link_create(
        5u, replacement_object, KERNEL_BPF_CGROUP_DEVICE, 0u);
    assert(link_object >= 0);
    kernel_bpf_object_release(link_object);
    count = 1u;
    assert(kernel_bpf_cgroup_query_links(
               5u, objects, flags, links, 4u, &count, 0) == 0 &&
           count == 0u);
    kernel_bpf_object_release(deny_object);
    kernel_bpf_object_release(replacement_object);
    kernel_bpf_object_release(object);
}

static void test_program_bind_map(void) {
    const kernel_bpf_instruction_t instructions[] = {
        { .code = 0xb7u, .registers = 0u,
          .offset = 0, .immediate = 1 },
        { .code = 0x95u, .registers = 0u,
          .offset = 0, .immediate = 0 },
    };
    kernel_bpf_program_create_request_t request = {
        .type = KERNEL_BPF_PROG_TYPE_CGROUP_DEVICE,
        .instruction_count = 2u,
        .expected_attach_type = KERNEL_BPF_CGROUP_DEVICE,
        .created_by_uid = 1000u,
    };
    kernel_bpf_map_info_t map_info;
    uint32_t map_ids[2] = {0u, 0u};
    uint32_t first_id = 0u;
    uint32_t second_id = 0u;
    uint32_t count = 0u;
    int program;
    int first_map;
    int second_map;

    strcpy(request.name, "bound_maps");
    program = kernel_bpf_program_create(&request, instructions);
    first_map = create_map(KERNEL_BPF_MAP_TYPE_ARRAY,
                           sizeof(uint32_t), sizeof(uint64_t), 1u,
                           "bound_a");
    second_map = create_map(KERNEL_BPF_MAP_TYPE_HASH,
                            sizeof(uint32_t), sizeof(uint64_t), 1u,
                            "bound_b");
    assert(program >= 0 && first_map >= 0 && second_map >= 0);
    assert(kernel_bpf_object_user_id(first_map, &first_id) == 0);
    assert(kernel_bpf_object_user_id(second_map, &second_id) == 0);
    assert(kernel_bpf_program_bind_map(program, first_map) == 0);
    assert(kernel_bpf_program_bind_map(program, first_map) == 0);
    assert(kernel_bpf_program_bind_map(program, second_map) == 0);
    assert(kernel_bpf_program_map_ids(
               program, map_ids, 1u, &count) == 0);
    assert(count == 2u && map_ids[0] == first_id);
    assert(kernel_bpf_program_map_ids(
               program, map_ids, 2u, &count) == 0);
    assert(count == 2u && map_ids[0] == first_id &&
           map_ids[1] == second_id);
    kernel_bpf_object_release(first_map);
    kernel_bpf_object_release(second_map);
    assert(kernel_bpf_map_info(first_map, &map_info) == 0);
    assert(kernel_bpf_map_info(second_map, &map_info) == 0);
    kernel_bpf_object_release(program);
    assert(kernel_bpf_map_info(first_map, &map_info) < 0);
    assert(kernel_bpf_map_info(second_map, &map_info) < 0);

    {
        kernel_bpf_instruction_t referenced_instructions[] = {
            { .code = 0x18u, .registers = 0x12u,
              .offset = 0, .immediate = 0 },
            { .code = 0u, .registers = 0u,
              .offset = 0, .immediate = 0 },
            { .code = 0xb7u, .registers = 0u,
              .offset = 0, .immediate = 1 },
            { .code = 0x95u, .registers = 0u,
              .offset = 0, .immediate = 0 },
        };

        first_map = create_map(KERNEL_BPF_MAP_TYPE_PROG_ARRAY,
                               sizeof(uint32_t), sizeof(uint32_t), 1u,
                               "referenced");
        assert(first_map >= 0);
        assert(kernel_bpf_object_user_id(first_map, &first_id) == 0);
        referenced_instructions[0].immediate = first_map;
        request.instruction_count =
            sizeof(referenced_instructions) /
            sizeof(referenced_instructions[0]);
        request.map_references_resolved = 1u;
        strcpy(request.name, "map_reference");
        program = kernel_bpf_program_create(
            &request, referenced_instructions);
        assert(program >= 0);
        assert(kernel_bpf_program_bind_map(program, first_map) == 0);
        count = 0u;
        assert(kernel_bpf_program_map_ids(
                   program, map_ids, 2u, &count) == 0);
        assert(count == 1u && map_ids[0] == first_id);
        kernel_bpf_object_release(first_map);
        assert(kernel_bpf_map_info(first_map, &map_info) == 0);
        kernel_bpf_object_release(program);
        assert(kernel_bpf_map_info(first_map, &map_info) < 0);
    }
}

static void test_program_runtime_stats(void) {
    const kernel_bpf_instruction_t instructions[] = {
        { .code = 0xb7u, .registers = 0u,
          .offset = 0, .immediate = 1 },
        { .code = 0x95u, .registers = 0u,
          .offset = 0, .immediate = 0 },
    };
    kernel_bpf_program_create_request_t request = {
        .type = KERNEL_BPF_PROG_TYPE_CGROUP_DEVICE,
        .instruction_count = 2u,
        .expected_attach_type = KERNEL_BPF_CGROUP_DEVICE,
        .created_by_uid = 1000u,
    };
    kernel_bpf_cgroup_device_context_t context = {
        .access_type = 1u,
        .major = 1u,
        .minor = 3u,
    };
    kernel_bpf_program_info_t info;
    uint32_t result = 0u;
    uint64_t recorded_time;
    uint64_t recorded_count;
    int program;
    int stats;

    strcpy(request.name, "runtime_stats");
    program = kernel_bpf_program_create(&request, instructions);
    assert(program >= 0);
    assert(kernel_bpf_program_run_cgroup_device(
               program, &context, &result) == 0);
    assert(kernel_bpf_program_info(program, &info) == 0);
    assert(info.run_count == 0u && info.run_time_ns == 0u);
    stats = kernel_bpf_runtime_stats_enable();
    assert(stats >= 0);
    assert(kernel_bpf_program_run_cgroup_device(
               program, &context, &result) == 0);
    assert(kernel_bpf_program_info(program, &info) == 0);
    assert(info.run_count == 1u && info.run_time_ns >= 1000u);
    recorded_count = info.run_count;
    recorded_time = info.run_time_ns;
    kernel_bpf_object_release(stats);
    assert(kernel_bpf_program_run_cgroup_device(
               program, &context, &result) == 0);
    assert(kernel_bpf_program_info(program, &info) == 0);
    assert(info.run_count == recorded_count &&
           info.run_time_ns == recorded_time);
    kernel_bpf_object_release(program);
}

static void test_program_array_tail_call(void) {
    const kernel_bpf_instruction_t callee_instructions[] = {
        { .code = 0xb7u, .registers = 0u,
          .offset = 0, .immediate = 7 },
        { .code = 0x95u, .registers = 0u,
          .offset = 0, .immediate = 0 },
    };
    kernel_bpf_instruction_t caller_instructions[] = {
        { .code = 0x18u, .registers = 0x12u,
          .offset = 0, .immediate = 0 },
        { .code = 0u, .registers = 0u,
          .offset = 0, .immediate = 0 },
        { .code = 0xb7u, .registers = 3u,
          .offset = 0, .immediate = 0 },
        { .code = 0x85u, .registers = 0u,
          .offset = 0, .immediate = 12 },
        { .code = 0xb7u, .registers = 0u,
          .offset = 0, .immediate = 1 },
        { .code = 0x95u, .registers = 0u,
          .offset = 0, .immediate = 0 },
    };
    kernel_bpf_program_create_request_t request = {
        .type = KERNEL_BPF_PROG_TYPE_CGROUP_DEVICE,
        .instruction_count = 2u,
        .expected_attach_type = KERNEL_BPF_CGROUP_DEVICE,
        .created_by_uid = 1000u,
        .map_references_resolved = 1u,
    };
    kernel_bpf_cgroup_device_context_t context = {
        .access_type = 1u,
        .major = 1u,
        .minor = 3u,
    };
    kernel_bpf_map_info_t map_info;
    kernel_bpf_program_info_t program_info;
    uint32_t key = 0u;
    uint32_t user_id = 0u;
    uint32_t result = 0u;
    int map;
    int callee;
    int caller;

    map = create_map(KERNEL_BPF_MAP_TYPE_PROG_ARRAY,
                     sizeof(uint32_t), sizeof(uint32_t), 2u,
                     "jump_table");
    assert(map >= 0);
    strcpy(request.name, "tail_target");
    callee = kernel_bpf_program_create(&request, callee_instructions);
    assert(callee >= 0);
    assert(kernel_bpf_object_user_id(callee, &user_id) == 0);
    assert(kernel_bpf_map_update(
               map, &key, &callee, KERNEL_BPF_ANY) == 0);
    assert(kernel_bpf_map_lookup(map, &key, &result) == 0);
    assert(result == user_id);

    request.instruction_count =
        sizeof(caller_instructions) / sizeof(caller_instructions[0]);
    strcpy(request.name, "tail_caller");
    caller_instructions[0].immediate = map;
    caller = kernel_bpf_program_create(&request, caller_instructions);
    assert(caller >= 0);
    assert(kernel_bpf_map_update(
               map, &key, &caller, KERNEL_BPF_ANY) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_bpf_map_update(
               map, &key, &callee, KERNEL_BPF_ANY) == 0);

    kernel_bpf_object_release(map);
    kernel_bpf_object_release(callee);
    assert(kernel_bpf_program_run_cgroup_device(
               caller, &context, &result) == 0);
    assert(result == 7u);
    assert(kernel_bpf_map_delete(map, &key) == 0);
    result = 0u;
    assert(kernel_bpf_program_run_cgroup_device(
               caller, &context, &result) == 0);
    assert(result == 1u);
    assert(kernel_bpf_program_info(callee, &program_info) < 0);
    kernel_bpf_object_release(caller);
    assert(kernel_bpf_map_info(map, &map_info) < 0);

    {
        int first_map = create_map(
            KERNEL_BPF_MAP_TYPE_PROG_ARRAY, sizeof(uint32_t),
            sizeof(uint32_t), 1u, "cycle_a");
        int second_map = create_map(
            KERNEL_BPF_MAP_TYPE_PROG_ARRAY, sizeof(uint32_t),
            sizeof(uint32_t), 1u, "cycle_b");
        int first_program;
        int second_program;

        assert(first_map >= 0 && second_map >= 0);
        caller_instructions[0].immediate = first_map;
        strcpy(request.name, "cycle_prog_a");
        first_program = kernel_bpf_program_create(
            &request, caller_instructions);
        assert(first_program >= 0);
        caller_instructions[0].immediate = second_map;
        strcpy(request.name, "cycle_prog_b");
        second_program = kernel_bpf_program_create(
            &request, caller_instructions);
        assert(second_program >= 0);
        assert(kernel_bpf_map_update(
                   second_map, &key, &first_program,
                   KERNEL_BPF_ANY) == 0);
        assert(kernel_bpf_map_update(
                   first_map, &key, &second_program,
                   KERNEL_BPF_ANY) == -EDGE_LINUX_EINVAL);
        assert(kernel_bpf_map_delete(second_map, &key) == 0);
        kernel_bpf_object_release(first_program);
        kernel_bpf_object_release(second_program);
        kernel_bpf_object_release(first_map);
        kernel_bpf_object_release(second_map);
    }
}

static void test_perf_event_array(void) {
    kernel_bpf_map_create_request_t request = {
        .type = KERNEL_BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(uint32_t),
        .max_entries = 3u,
        .flags = KERNEL_BPF_MAP_PRESERVE_ELEMS,
    };
    kernel_bpf_map_info_t info;
    uint32_t key = 1u;
    uint32_t next = UINT32_MAX;
    uint32_t output = 0u;
    int object;

    strcpy(request.name, "perf_array");
    object = kernel_bpf_map_create(&request);
    assert(object >= 0);
    assert(kernel_bpf_map_info(object, &info) == 0);
    assert(info.type == KERNEL_BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    assert(info.flags == KERNEL_BPF_MAP_PRESERVE_ELEMS);
    assert(kernel_bpf_map_lookup(object, &key, &output) ==
           -EDGE_LINUX_ENOTSUPP);
    assert(kernel_bpf_map_update(
               object, &key, &output, KERNEL_BPF_ANY) ==
           -EDGE_LINUX_ENOTSUPP);
    assert(kernel_bpf_map_next_key(object, 0, &next) == 0);
    assert(next == 0u);
    assert(kernel_bpf_map_delete(object, &key) ==
           -EDGE_LINUX_ENOENT);

    g_perf_event_references[1] = 1u;
    g_perf_event_references[2] = 1u;
    assert(kernel_bpf_perf_event_array_update(
               object, &key, 7, KERNEL_BPF_ANY) ==
           -EDGE_LINUX_EBADF);
    assert(kernel_bpf_perf_event_array_update(
               object, &key, 1, KERNEL_BPF_NOEXIST) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_bpf_perf_event_array_update(
               object, &key, 1, KERNEL_BPF_ANY) == 0);
    assert(g_perf_event_references[1] == 2u);
    assert(kernel_bpf_perf_event_array_update(
               object, &key, 2, KERNEL_BPF_ANY) == 0);
    assert(g_perf_event_references[1] == 1u);
    assert(g_perf_event_references[2] == 2u);
    assert(kernel_bpf_map_delete(object, &key) == 0);
    assert(g_perf_event_references[2] == 1u);
    assert(kernel_bpf_map_delete(object, &key) ==
           -EDGE_LINUX_ENOENT);

    assert(kernel_bpf_map_freeze(object) == 0);
    assert(kernel_bpf_perf_event_array_update(
               object, &key, 1, KERNEL_BPF_ANY) ==
           -EDGE_LINUX_EPERM);
    assert(g_perf_event_references[1] == 1u);
    kernel_bpf_object_release(object);

    request.flags = KERNEL_BPF_MAP_NO_PREALLOC;
    assert(kernel_bpf_map_create(&request) == -EDGE_LINUX_EINVAL);

    request.flags = 0u;
    object = kernel_bpf_map_create(&request);
    assert(object >= 0);
    g_perf_event_references[3] = 1u;
    assert(kernel_bpf_perf_event_array_update(
               object, &key, 3, KERNEL_BPF_ANY) == 0);
    assert(g_perf_event_references[3] == 2u);
    kernel_bpf_object_release(object);
    assert(g_perf_event_references[3] == 1u);
}

static void test_ring_buffer_maps(void) {
    kernel_bpf_map_create_request_t request = {
        .type = KERNEL_BPF_MAP_TYPE_RINGBUF,
        .max_entries = 4096u,
    };
    kernel_bpf_map_info_t info;
    void *consumer = 0;
    void *producer = 0;
    void *data = 0;
    void *data_alias = 0;
    uint32_t page_count = 0;
    uint32_t result = 0u;
    uint32_t record_header[2];
    uint64_t position;
    int readable;
    int writable;
    int object;
    int program;

    strcpy(request.name, "kernel_ring");
    object = kernel_bpf_map_create(&request);
    assert(object >= 0);
    assert(kernel_bpf_map_info(object, &info) == 0);
    assert(info.key_size == 0u && info.value_size == 0u);
    assert(info.max_entries == 4096u);
    assert(kernel_bpf_map_mmap_info(
               object, 0u, 4096u, 1, &page_count) == 0);
    assert(page_count == 1u);
    assert(kernel_bpf_map_mmap_info(
               object, 4096u, 3u * 4096u, 0, &page_count) == 0);
    assert(page_count == 3u);
    assert(kernel_bpf_map_mmap_info(
               object, 4096u, 4096u, 1, &page_count) ==
           -EDGE_LINUX_EPERM);
    assert(kernel_bpf_map_mmap_info(
               object, 0u, 8192u, 1, &page_count) ==
           -EDGE_LINUX_EPERM);
    assert(kernel_bpf_map_mmap_page(object, 0u, 0u, &consumer) == 0);
    assert(kernel_bpf_map_mmap_page(object, 4096u, 0u, &producer) == 0);
    assert(kernel_bpf_map_mmap_page(object, 4096u, 1u, &data) == 0);
    assert(kernel_bpf_map_mmap_page(
               object, 4096u, 2u, &data_alias) == 0);
    assert(consumer != producer && producer != data && data == data_alias);
    assert(kernel_bpf_ringbuf_poll_state(
               object, &readable, &writable) == 0);
    assert(!readable && !writable);
    {
        const kernel_bpf_cgroup_device_context_t context = {
            .access_type = 3u,
            .major = 8u,
            .minor = 1u,
        };
        kernel_bpf_instruction_t instructions[] = {
            { .code = 0x61u, .registers = 0x16u, .offset = 0 },
            { .code = 0x61u, .registers = 0x17u, .offset = 4 },
            { .code = 0x61u, .registers = 0x18u, .offset = 8 },
            { .code = 0x63u, .registers = 0x6au, .offset = -12 },
            { .code = 0x63u, .registers = 0x7au, .offset = -8 },
            { .code = 0x63u, .registers = 0x8au, .offset = -4 },
            { .code = 0xbfu, .registers = 0xa2u },
            { .code = 0x07u, .registers = 2u, .immediate = -12 },
            { .code = 0x18u, .registers = 0x11u,
              .immediate = object },
            { .code = 0u },
            { .code = 0xb7u, .registers = 3u,
              .immediate = sizeof(context) },
            { .code = 0xb7u, .registers = 4u, .immediate = 0 },
            { .code = 0x85u, .immediate = 130 },
            { .code = 0xb7u, .registers = 0u, .immediate = 1 },
            { .code = 0x95u },
        };
        kernel_bpf_program_create_request_t program_request = {
            .type = KERNEL_BPF_PROG_TYPE_CGROUP_DEVICE,
            .instruction_count =
                sizeof(instructions) / sizeof(instructions[0]),
            .expected_attach_type = KERNEL_BPF_CGROUP_DEVICE,
            .created_by_uid = 1000u,
            .map_references_resolved = 1u,
        };

        strcpy(program_request.name, "ring_output");
        program = kernel_bpf_program_create(
            &program_request, instructions);
        assert(program >= 0);
        g_ringbuf_notifications = 0u;
        assert(kernel_bpf_program_run_cgroup_device(
                   program, &context, &result) == 0);
        assert(result == 1u);
        assert(g_ringbuf_notifications == 1u);
        memcpy(record_header, data, sizeof(record_header));
        assert(record_header[0] == sizeof(context));
        assert(record_header[1] == 3u);
        assert(memcmp((uint8_t *)data + 8u,
                      &context, sizeof(context)) == 0);
        memcpy(&position, producer, sizeof(position));
        assert(position == 24u);
        kernel_bpf_object_release(program);
    }
    assert(kernel_bpf_ringbuf_poll_state(
               object, &readable, &writable) == 0);
    assert(readable && !writable);
    position = 24u;
    memcpy(consumer, &position, sizeof(position));
    assert(kernel_bpf_ringbuf_poll_state(
               object, &readable, &writable) == 0);
    assert(!readable && !writable);
    assert(kernel_bpf_map_lookup(object, 0, &position) ==
           -EDGE_LINUX_ENOTSUPP);
    kernel_bpf_object_release(object);

    request.type = KERNEL_BPF_MAP_TYPE_USER_RINGBUF;
    strcpy(request.name, "user_ring");
    object = kernel_bpf_map_create(&request);
    assert(object >= 0);
    assert(kernel_bpf_map_mmap_info(
               object, 0u, 4096u, 1, &page_count) ==
           -EDGE_LINUX_EPERM);
    assert(kernel_bpf_map_mmap_info(
               object, 4096u, 3u * 4096u, 1, &page_count) == 0);
    assert(kernel_bpf_map_mmap_page(object, 0u, 0u, &consumer) == 0);
    assert(kernel_bpf_map_mmap_page(object, 4096u, 0u, &producer) == 0);
    assert(kernel_bpf_ringbuf_poll_state(
               object, &readable, &writable) == 0);
    assert(!readable && writable);
    position = 4096u;
    memcpy(producer, &position, sizeof(position));
    assert(kernel_bpf_ringbuf_poll_state(
               object, &readable, &writable) == 0);
    assert(!readable && !writable);
    position = 8u;
    memcpy(consumer, &position, sizeof(position));
    assert(kernel_bpf_ringbuf_poll_state(
               object, &readable, &writable) == 0);
    assert(!readable && writable);
    kernel_bpf_object_release(object);

    request.type = KERNEL_BPF_MAP_TYPE_RINGBUF;
    request.max_entries = 4095u;
    assert(kernel_bpf_map_create(&request) == -EDGE_LINUX_EINVAL);
    request.max_entries = 8192u + 4096u;
    assert(kernel_bpf_map_create(&request) == -EDGE_LINUX_EINVAL);
    request.max_entries = 4096u;
    request.flags = KERNEL_BPF_MAP_NO_PREALLOC;
    assert(kernel_bpf_map_create(&request) == -EDGE_LINUX_EINVAL);
    request.type = KERNEL_BPF_MAP_TYPE_USER_RINGBUF;
    request.flags = KERNEL_BPF_MAP_RB_OVERWRITE;
    assert(kernel_bpf_map_create(&request) == -EDGE_LINUX_EINVAL);
}

static void test_btf_objects(void) {
    struct test_btf_blob {
        uint16_t magic;
        uint8_t version;
        uint8_t flags;
        uint32_t header_length;
        uint32_t type_offset;
        uint32_t type_length;
        uint32_t string_offset;
        uint32_t string_length;
        uint8_t strings[1];
    } __attribute__((packed)) blob = {
        .magic = 0xeb9fu,
        .version = 1u,
        .header_length = 24u,
        .string_length = 1u,
    };
    kernel_bpf_btf_info_t btf_info;
    kernel_bpf_map_info_t map_info;
    kernel_bpf_map_create_request_t request = {
        .type = KERNEL_BPF_MAP_TYPE_HASH,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(uint64_t),
        .max_entries = 2u,
        .btf_key_type_id = 1u,
        .btf_value_type_id = 2u,
        .btf_present = 1u,
    };
    uint8_t copied[sizeof(blob)];
    uint32_t actual_size = 0u;
    uint32_t next_id = 0u;
    int btf;
    int retained;
    int map;

    btf = kernel_bpf_btf_create(&blob, sizeof(blob));
    assert(btf >= 0);
    assert(kernel_bpf_btf_info(btf, &btf_info) == 0);
    assert(btf_info.id != 0u && btf_info.size == sizeof(blob));
    assert(kernel_bpf_btf_copy(
               btf, copied, sizeof(copied), &actual_size) == 0);
    assert(actual_size == sizeof(blob));
    assert(memcmp(copied, &blob, sizeof(blob)) == 0);
    assert(kernel_bpf_object_next_user_id(
               KERNEL_BPF_OBJECT_BTF, btf_info.id - 1u,
               &next_id) == 0);
    assert(next_id == btf_info.id);
    retained = kernel_bpf_object_from_user_id(
        KERNEL_BPF_OBJECT_BTF, btf_info.id);
    assert(retained == btf);
    kernel_bpf_object_release(retained);

    request.btf_object_id = btf;
    strcpy(request.name, "typed_hash");
    map = kernel_bpf_map_create(&request);
    assert(map >= 0);
    assert(kernel_bpf_map_info(map, &map_info) == 0);
    assert(map_info.btf_id == btf_info.id);
    assert(map_info.btf_key_type_id == 1u);
    assert(map_info.btf_value_type_id == 2u);
    kernel_bpf_object_release(btf);
    assert(kernel_bpf_btf_info(request.btf_object_id, &btf_info) == 0);
    kernel_bpf_object_release(map);
    assert(kernel_bpf_btf_info(request.btf_object_id, &btf_info) < 0);

    blob.magic = 0u;
    assert(kernel_bpf_btf_create(&blob, sizeof(blob)) ==
           -EDGE_LINUX_EINVAL);
    blob.magic = 0xeb9fu;
    blob.string_length = 0u;
    assert(kernel_bpf_btf_create(&blob, sizeof(blob)) ==
           -EDGE_LINUX_EINVAL);
}

static void test_ids(void) {
    uint32_t first_id;
    uint32_t next_id;
    int first = create_map(
        KERNEL_BPF_MAP_TYPE_ARRAY, 4u, 4u, 1u, "first");
    int second = create_map(
        KERNEL_BPF_MAP_TYPE_ARRAY, 4u, 4u, 1u, "second");
    int retained;

    assert(first >= 0 && second >= 0);
    assert(kernel_bpf_object_user_id(first, &first_id) == 0);
    assert(kernel_bpf_object_next_user_id(
               KERNEL_BPF_OBJECT_MAP, first_id, &next_id) == 0);
    assert(next_id > first_id);
    retained = kernel_bpf_object_from_user_id(
        KERNEL_BPF_OBJECT_MAP, next_id);
    assert(retained == second);
    kernel_bpf_object_release(retained);
    kernel_bpf_object_release(first);
    kernel_bpf_object_release(second);
}

static void test_pinned_object_lifetime(void) {
    static const uint32_t first_filesystem;
    static const uint32_t second_filesystem;
    kernel_bpf_map_info_t info;
    kernel_bpf_object_kind_t kind = 0;
    uint8_t btf_blob[25] = {
        0x9f, 0xeb, 1u, 0u,
        24u, 0u, 0u, 0u,
    };
    int first = create_map(
        KERNEL_BPF_MAP_TYPE_ARRAY, 4u, 4u, 1u, "pinned");
    int second = create_map(
        KERNEL_BPF_MAP_TYPE_ARRAY, 4u, 4u, 1u, "mounted");
    int retained;
    int btf;

    assert(first >= 0 && second >= 0);
    btf_blob[16] = 0u;
    btf_blob[20] = 1u;
    btf = kernel_bpf_btf_create(btf_blob, sizeof(btf_blob));
    assert(btf >= 0);
    assert(kernel_bpf_pin_create(
               &first_filesystem, 11u, 3u, btf) ==
           -EDGE_LINUX_EINVAL);
    kernel_bpf_object_release(btf);

    assert(kernel_bpf_pin_create(
               &first_filesystem, 11u, 3u, first) == 0);
    assert(kernel_bpf_pin_create(
               &first_filesystem, 11u, 3u, first) ==
           -EDGE_LINUX_EEXIST);
    kernel_bpf_object_release(first);
    retained = kernel_bpf_pin_get(
        &first_filesystem, 11u, 3u, &kind);
    assert(retained == first && kind == KERNEL_BPF_OBJECT_MAP);
    kernel_bpf_object_release(retained);
    kernel_bpf_pin_remove(&first_filesystem, 11u, 2u);
    assert(kernel_bpf_map_info(first, &info) == 0);
    kernel_bpf_pin_remove(&first_filesystem, 11u, 3u);
    assert(kernel_bpf_map_info(first, &info) < 0);
    assert(kernel_bpf_pin_get(
               &first_filesystem, 11u, 3u, &kind) ==
           -EDGE_LINUX_ENOENT);

    assert(kernel_bpf_pin_create(
               &second_filesystem, 8u, 1u, second) == 0);
    kernel_bpf_object_release(second);
    kernel_bpf_pin_filesystem_release(&first_filesystem);
    assert(kernel_bpf_map_info(second, &info) == 0);
    kernel_bpf_pin_filesystem_release(&second_filesystem);
    assert(kernel_bpf_map_info(second, &info) < 0);
}

int main(void) {
    test_array_map();
    test_map_access_flags();
    test_hash_map();
    test_lru_hash_map();
    test_queue_stack_maps();
    test_lpm_trie_map();
    test_bloom_filter_map();
    test_percpu_maps();
    test_lru_percpu_hash_map();
    test_no_common_lru();
    test_map_in_map();
    test_batch_and_freeze();
    test_program();
    test_program_bind_map();
    test_program_runtime_stats();
    test_program_array_tail_call();
    test_perf_event_array();
    test_ring_buffer_maps();
    test_btf_objects();
    test_ids();
    test_pinned_object_lifetime();
    puts("bpf_runtime_unit: PASS");
    return 0;
}
