/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kernel/bpf_runtime.h"
#include "kernel/linux_errno.h"

void *arch_vm_alloc_page(void) {
    return calloc(1u, 4096u);
}

void *arch_vm_alloc_pages(uint64_t page_count) {
    return calloc((size_t)page_count, 4096u);
}

void arch_vm_free_page(void *page) {
    free(page);
}

uint32_t edge_smp_nr_cpu_ids(void) {
    return 4u;
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
    int object;
    int deny_object;
    int replacement_object;

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
    kernel_bpf_object_release(deny_object);
    kernel_bpf_object_release(replacement_object);
    kernel_bpf_object_release(object);
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

int main(void) {
    test_array_map();
    test_hash_map();
    test_lru_hash_map();
    test_queue_stack_maps();
    test_percpu_maps();
    test_batch_and_freeze();
    test_program();
    test_ids();
    puts("bpf_runtime_unit: PASS");
    return 0;
}
