/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kernel/bpf_runtime.h"

void *arch_vm_alloc_page(void) {
    return calloc(1u, 4096u);
}

void *arch_vm_alloc_pages(uint64_t page_count) {
    return calloc((size_t)page_count, 4096u);
}

void arch_vm_free_page(void *page) {
    free(page);
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
    int object;

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
    test_batch_and_freeze();
    test_program();
    test_ids();
    puts("bpf_runtime_unit: PASS");
    return 0;
}
