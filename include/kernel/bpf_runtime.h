/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux BPF object runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_BPF_RUNTIME_H
#define EDGEOS_KERNEL_BPF_RUNTIME_H

#include <stdint.h>

#include "kernel/runtime_limits.h"

#define KERNEL_BPF_OBJECT_NAME_LENGTH 16u
#define KERNEL_BPF_MAX_KEY_SIZE 4096u
#define KERNEL_BPF_MAX_VALUE_SIZE 4096u
#define KERNEL_BPF_MAX_INSTRUCTIONS 4096u
#define KERNEL_BPF_MAX_ATTACHMENTS EDGE_RUNTIME_MAX_BPF_ATTACHMENTS

#define KERNEL_BPF_MAP_TYPE_HASH  1u
#define KERNEL_BPF_MAP_TYPE_ARRAY 2u
#define KERNEL_BPF_MAP_TYPE_PERCPU_HASH 5u
#define KERNEL_BPF_MAP_TYPE_PERCPU_ARRAY 6u
#define KERNEL_BPF_MAP_TYPE_LRU_HASH 9u
#define KERNEL_BPF_MAP_TYPE_QUEUE 22u
#define KERNEL_BPF_MAP_TYPE_STACK 23u

#define KERNEL_BPF_MAP_NO_PREALLOC (1u << 0)

#define KERNEL_BPF_ANY     0u
#define KERNEL_BPF_NOEXIST 1u
#define KERNEL_BPF_EXIST   2u
#define KERNEL_BPF_F_LOCK  4u
#define KERNEL_BPF_F_CPU   8u
#define KERNEL_BPF_F_ALL_CPUS 16u

#define KERNEL_BPF_PROG_TYPE_CGROUP_DEVICE 15u
#define KERNEL_BPF_CGROUP_DEVICE 6u

#define KERNEL_BPF_F_ALLOW_OVERRIDE (1u << 0)
#define KERNEL_BPF_F_ALLOW_MULTI    (1u << 1)
#define KERNEL_BPF_F_REPLACE        (1u << 2)

#define KERNEL_BPF_DEVCG_ACC_MKNOD (1u << 0)
#define KERNEL_BPF_DEVCG_ACC_READ  (1u << 1)
#define KERNEL_BPF_DEVCG_ACC_WRITE (1u << 2)
#define KERNEL_BPF_DEVCG_DEV_BLOCK (1u << 0)
#define KERNEL_BPF_DEVCG_DEV_CHAR  (1u << 1)

typedef enum kernel_bpf_object_kind {
    KERNEL_BPF_OBJECT_MAP = 1,
    KERNEL_BPF_OBJECT_PROGRAM = 2,
} kernel_bpf_object_kind_t;

typedef struct kernel_bpf_instruction {
    uint8_t code;
    uint8_t registers;
    int16_t offset;
    int32_t immediate;
} kernel_bpf_instruction_t;

typedef struct kernel_bpf_map_create_request {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t flags;
    char name[KERNEL_BPF_OBJECT_NAME_LENGTH];
} kernel_bpf_map_create_request_t;

typedef struct kernel_bpf_program_create_request {
    uint32_t type;
    uint32_t instruction_count;
    uint32_t flags;
    uint32_t expected_attach_type;
    uint32_t created_by_uid;
    uint32_t gpl_compatible;
    char name[KERNEL_BPF_OBJECT_NAME_LENGTH];
} kernel_bpf_program_create_request_t;

typedef struct kernel_bpf_map_info {
    uint32_t type;
    uint32_t id;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t flags;
    char name[KERNEL_BPF_OBJECT_NAME_LENGTH];
} kernel_bpf_map_info_t;

typedef struct kernel_bpf_program_info {
    uint32_t type;
    uint32_t id;
    uint32_t instruction_count;
    uint32_t created_by_uid;
    uint32_t verified_instructions;
    uint32_t gpl_compatible;
    uint64_t run_time_ns;
    uint64_t run_count;
    uint8_t tag[8];
    char name[KERNEL_BPF_OBJECT_NAME_LENGTH];
} kernel_bpf_program_info_t;

typedef struct kernel_bpf_cgroup_device_context {
    uint32_t access_type;
    uint32_t major;
    uint32_t minor;
} kernel_bpf_cgroup_device_context_t;

uint32_t kernel_bpf_possible_cpu_count(void);
int kernel_bpf_map_create(const kernel_bpf_map_create_request_t *request);
int kernel_bpf_program_create(
    const kernel_bpf_program_create_request_t *request,
    const kernel_bpf_instruction_t *instructions);
int kernel_bpf_object_retain(int object_id);
void kernel_bpf_object_release(int object_id);
int kernel_bpf_object_kind(int object_id, kernel_bpf_object_kind_t *kind);
int kernel_bpf_object_user_id(int object_id, uint32_t *user_id);
int kernel_bpf_object_from_user_id(kernel_bpf_object_kind_t kind,
                                   uint32_t user_id);
int kernel_bpf_object_next_user_id(kernel_bpf_object_kind_t kind,
                                   uint32_t start_id,
                                   uint32_t *next_id);

int kernel_bpf_map_info(int object_id, kernel_bpf_map_info_t *info);
int kernel_bpf_map_value_buffer_size(int object_id, uint64_t flags,
                                     uint32_t *size_out);
int kernel_bpf_program_info(int object_id, kernel_bpf_program_info_t *info);
int kernel_bpf_program_copy_instructions(int object_id, void *buffer,
                                         uint32_t capacity,
                                         uint32_t *actual_size);
int kernel_bpf_map_lookup_flags(int object_id, const void *key, void *value,
                                uint64_t flags);
int kernel_bpf_map_lookup(int object_id, const void *key, void *value);
int kernel_bpf_map_update(int object_id, const void *key, const void *value,
                          uint64_t flags);
int kernel_bpf_map_delete(int object_id, const void *key);
int kernel_bpf_map_lookup_and_delete(int object_id, const void *key,
                                     void *value);
int kernel_bpf_map_next_key(int object_id, const void *key, void *next_key);
int kernel_bpf_map_batch_next(int object_id, uint32_t *cursor,
                              void *key, void *value,
                              int delete_element, int *has_more);
int kernel_bpf_map_batch_next_flags(int object_id, uint32_t *cursor,
                                    void *key, void *value,
                                    uint64_t flags, int delete_element,
                                    int *has_more);
int kernel_bpf_map_freeze(int object_id);

int kernel_bpf_program_run_cgroup_device(
    int object_id, const kernel_bpf_cgroup_device_context_t *context,
    uint32_t *result);
int kernel_bpf_cgroup_attach(uint32_t cgroup_id, int object_id,
                             uint32_t flags, int replace_object_id);
int kernel_bpf_cgroup_detach(uint32_t cgroup_id, int object_id);
int kernel_bpf_cgroup_query(uint32_t cgroup_id, int *object_ids,
                            uint32_t *attach_flags, uint32_t capacity,
                            uint32_t *count, uint64_t *revision);
int kernel_bpf_cgroup_device_run(
    uint32_t cgroup_id,
    const kernel_bpf_cgroup_device_context_t *context,
    uint32_t *result);
void kernel_bpf_cgroup_release(uint32_t cgroup_id);

int kernel_bpf_create_descriptor(int object_id);
int kernel_bpf_descriptor_object(int32_t descriptor,
                                 kernel_bpf_object_kind_t expected_kind);

#endif
