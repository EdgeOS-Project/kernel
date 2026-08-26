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
#define KERNEL_BPF_MAX_KEY_SIZE 4194255u
#define KERNEL_BPF_MAX_VALUE_SIZE 4194255u
#define KERNEL_BPF_MAX_HASH_KEY_VALUE_SIZE 4194255u
#define KERNEL_BPF_MAX_INSTRUCTIONS 4096u
#define KERNEL_BPF_MAX_ATTACHMENTS EDGE_RUNTIME_MAX_BPF_ATTACHMENTS

#define KERNEL_BPF_MAP_TYPE_HASH  1u
#define KERNEL_BPF_MAP_TYPE_ARRAY 2u
#define KERNEL_BPF_MAP_TYPE_PROG_ARRAY 3u
#define KERNEL_BPF_MAP_TYPE_PERF_EVENT_ARRAY 4u
#define KERNEL_BPF_MAP_TYPE_PERCPU_HASH 5u
#define KERNEL_BPF_MAP_TYPE_PERCPU_ARRAY 6u
#define KERNEL_BPF_MAP_TYPE_STACK_TRACE 7u
#define KERNEL_BPF_MAP_TYPE_CGROUP_ARRAY 8u
#define KERNEL_BPF_MAP_TYPE_LRU_HASH 9u
#define KERNEL_BPF_MAP_TYPE_LRU_PERCPU_HASH 10u
#define KERNEL_BPF_MAP_TYPE_LPM_TRIE 11u
#define KERNEL_BPF_MAP_TYPE_ARRAY_OF_MAPS 12u
#define KERNEL_BPF_MAP_TYPE_HASH_OF_MAPS 13u
#define KERNEL_BPF_MAP_TYPE_DEVMAP 14u
#define KERNEL_BPF_MAP_TYPE_SOCKMAP 15u
#define KERNEL_BPF_MAP_TYPE_CPUMAP 16u
#define KERNEL_BPF_MAP_TYPE_XSKMAP 17u
#define KERNEL_BPF_MAP_TYPE_SOCKHASH 18u
#define KERNEL_BPF_MAP_TYPE_CGROUP_STORAGE 19u
#define KERNEL_BPF_MAP_TYPE_REUSEPORT_SOCKARRAY 20u
#define KERNEL_BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE 21u
#define KERNEL_BPF_MAP_TYPE_QUEUE 22u
#define KERNEL_BPF_MAP_TYPE_STACK 23u
#define KERNEL_BPF_MAP_TYPE_SK_STORAGE 24u
#define KERNEL_BPF_MAP_TYPE_DEVMAP_HASH 25u
#define KERNEL_BPF_MAP_TYPE_RINGBUF 27u
#define KERNEL_BPF_MAP_TYPE_INODE_STORAGE 28u
#define KERNEL_BPF_MAP_TYPE_TASK_STORAGE 29u
#define KERNEL_BPF_MAP_TYPE_BLOOM_FILTER 30u
#define KERNEL_BPF_MAP_TYPE_USER_RINGBUF 31u
#define KERNEL_BPF_MAP_TYPE_CGRP_STORAGE 32u
#define KERNEL_BPF_MAP_TYPE_ARENA 33u
#define KERNEL_BPF_MAP_TYPE_INSN_ARRAY 34u
#define KERNEL_BPF_MAP_TYPE_RHASH 35u

#define KERNEL_BPF_MAP_NO_PREALLOC (1u << 0)
#define KERNEL_BPF_MAP_NO_COMMON_LRU (1u << 1)
#define KERNEL_BPF_MAP_NUMA_NODE (1u << 2)
#define KERNEL_BPF_MAP_RDONLY (1u << 3)
#define KERNEL_BPF_MAP_WRONLY (1u << 4)
#define KERNEL_BPF_MAP_STACK_BUILD_ID (1u << 5)
#define KERNEL_BPF_MAP_ZERO_SEED (1u << 6)
#define KERNEL_BPF_MAP_CLONE (1u << 9)
#define KERNEL_BPF_MAP_RDONLY_PROGRAM (1u << 7)
#define KERNEL_BPF_MAP_MMAPABLE (1u << 10)
#define KERNEL_BPF_MAP_SEGV_ON_FAULT (1u << 17)
#define KERNEL_BPF_MAP_NO_USER_CONV (1u << 18)
#define KERNEL_BPF_MAP_PRESERVE_ELEMS (1u << 11)
#define KERNEL_BPF_MAP_RB_OVERWRITE (1u << 19)

#define KERNEL_BPF_ANY     0u
#define KERNEL_BPF_NOEXIST 1u
#define KERNEL_BPF_EXIST   2u
#define KERNEL_BPF_F_LOCK  4u
#define KERNEL_BPF_F_CPU   8u
#define KERNEL_BPF_F_ALL_CPUS 16u

#define KERNEL_BPF_PROG_TYPE_SOCKET_FILTER 1u
#define KERNEL_BPF_PROG_TYPE_CGROUP_DEVICE 15u
#define KERNEL_BPF_PROG_TYPE_RAW_TRACEPOINT 17u
#define KERNEL_BPF_CGROUP_DEVICE 6u

#define KERNEL_BPF_F_ALLOW_OVERRIDE (1u << 0)
#define KERNEL_BPF_F_ALLOW_MULTI    (1u << 1)
#define KERNEL_BPF_F_REPLACE        (1u << 2)
#define KERNEL_BPF_F_BEFORE         (1u << 3)
#define KERNEL_BPF_F_AFTER          (1u << 4)
#define KERNEL_BPF_F_ID             (1u << 5)
#define KERNEL_BPF_F_PREORDER       (1u << 6)
#define KERNEL_BPF_F_LINK           (1u << 13)

#define KERNEL_BPF_DEVCG_ACC_MKNOD (1u << 0)
#define KERNEL_BPF_DEVCG_ACC_READ  (1u << 1)
#define KERNEL_BPF_DEVCG_ACC_WRITE (1u << 2)
#define KERNEL_BPF_DEVCG_DEV_BLOCK (1u << 0)
#define KERNEL_BPF_DEVCG_DEV_CHAR  (1u << 1)

typedef enum kernel_bpf_object_kind {
    KERNEL_BPF_OBJECT_MAP = 1,
    KERNEL_BPF_OBJECT_PROGRAM = 2,
    KERNEL_BPF_OBJECT_BTF = 3,
    KERNEL_BPF_OBJECT_LINK = 4,
    KERNEL_BPF_OBJECT_STATS = 5,
} kernel_bpf_object_kind_t;

typedef struct kernel_bpf_instruction {
    uint8_t code;
    uint8_t registers;
    int16_t offset;
    int32_t immediate;
} kernel_bpf_instruction_t;

typedef struct kernel_bpf_socket_filter_context {
    uint32_t length;
    uint32_t packet_type;
    uint32_t mark;
    uint32_t socket_uid;
    uint64_t socket_cookie;
    uint64_t network_namespace_cookie;
} kernel_bpf_socket_filter_context_t;

typedef struct kernel_bpf_map_create_request {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t flags;
    int32_t inner_map_object_id;
    int32_t btf_object_id;
    uint32_t btf_key_type_id;
    uint32_t btf_value_type_id;
    uint64_t map_extra;
    uint8_t btf_present;
    char name[KERNEL_BPF_OBJECT_NAME_LENGTH];
} kernel_bpf_map_create_request_t;

typedef struct kernel_bpf_program_create_request {
    uint32_t type;
    uint32_t instruction_count;
    uint32_t flags;
    uint32_t expected_attach_type;
    uint32_t created_by_uid;
    uint32_t gpl_compatible;
    uint8_t map_references_resolved;
    char name[KERNEL_BPF_OBJECT_NAME_LENGTH];
} kernel_bpf_program_create_request_t;

typedef struct kernel_bpf_map_info {
    uint32_t type;
    uint32_t id;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t flags;
    uint32_t btf_id;
    uint32_t btf_key_type_id;
    uint32_t btf_value_type_id;
    uint64_t map_extra;
    char name[KERNEL_BPF_OBJECT_NAME_LENGTH];
} kernel_bpf_map_info_t;

typedef struct kernel_bpf_btf_info {
    uint32_t id;
    uint32_t size;
    uint32_t kernel_btf;
} kernel_bpf_btf_info_t;

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

typedef struct kernel_bpf_link_info {
    uint32_t type;
    uint32_t id;
    uint32_t program_id;
    uint32_t attach_type;
    uint64_t cgroup_id;
    uint32_t attach_flags;
    uint32_t detached;
} kernel_bpf_link_info_t;

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
int kernel_bpf_btf_create(const void *data, uint32_t size);
int kernel_bpf_object_retain(int object_id);
void kernel_bpf_object_release(int object_id);
int kernel_bpf_object_kind(int object_id, kernel_bpf_object_kind_t *kind);
int kernel_bpf_object_user_id(int object_id, uint32_t *user_id);
int kernel_bpf_object_from_user_id(kernel_bpf_object_kind_t kind,
                                   uint32_t user_id);
int kernel_bpf_object_next_user_id(kernel_bpf_object_kind_t kind,
                                   uint32_t start_id,
                                   uint32_t *next_id);
int kernel_bpf_pin_create(const void *filesystem_identity,
                          uint32_t inode_number,
                          uint32_t inode_generation,
                          int object_id);
int kernel_bpf_pin_get(const void *filesystem_identity,
                       uint32_t inode_number,
                       uint32_t inode_generation,
                       kernel_bpf_object_kind_t *kind);
void kernel_bpf_pin_remove(const void *filesystem_identity,
                           uint32_t inode_number,
                           uint32_t inode_generation);
void kernel_bpf_pin_filesystem_release(const void *filesystem_identity);

int kernel_bpf_map_info(int object_id, kernel_bpf_map_info_t *info);
int kernel_bpf_map_value_buffer_size(int object_id, uint64_t flags,
                                     uint32_t *size_out);
int kernel_bpf_program_info(int object_id, kernel_bpf_program_info_t *info);
int kernel_bpf_program_bind_map(int program_object_id, int map_object_id);
int kernel_bpf_program_map_ids(int program_object_id, uint32_t *map_ids,
                               uint32_t capacity, uint32_t *actual_count);
int kernel_bpf_runtime_stats_enable(void);
int kernel_bpf_program_copy_instructions(int object_id, void *buffer,
                                         uint32_t capacity,
                                         uint32_t *actual_size);
int kernel_bpf_btf_info(int object_id, kernel_bpf_btf_info_t *info);
int kernel_bpf_btf_copy(int object_id, void *buffer, uint32_t capacity,
                        uint32_t *actual_size);
int kernel_bpf_link_info(int object_id, kernel_bpf_link_info_t *info);
int kernel_bpf_map_lookup_flags(int object_id, const void *key, void *value,
                                uint64_t flags);
int kernel_bpf_map_lookup(int object_id, const void *key, void *value);
int kernel_bpf_map_update(int object_id, const void *key, const void *value,
                          uint64_t flags);
int kernel_bpf_devmap_update(int object_id, const void *key,
                             const void *value, uint64_t flags,
                             int ifindex_valid, int program_status);
int kernel_bpf_xskmap_update(int object_id, const void *key,
                             const void *value, uint64_t flags,
                             int socket_status);
int kernel_bpf_socket_map_update(int object_id, const void *key,
                                 int32_t socket_descriptor,
                                 uint64_t flags);
int kernel_bpf_reuseport_array_update(int object_id, const void *key,
                                      uint64_t socket_descriptor,
                                      uint64_t flags);
void kernel_bpf_reuseport_socket_detach(uint64_t description_identity);
int kernel_bpf_perf_event_array_update(int object_id, const void *key,
                                       int32_t event_id, uint64_t flags);
int kernel_bpf_cgroup_array_update(int object_id, const void *key,
                                   uint64_t cgroup_reference,
                                   uint64_t flags);
int kernel_bpf_cgrp_storage_lookup(int object_id,
                                   uint64_t cgroup_reference,
                                   void *value, uint64_t flags);
int kernel_bpf_cgrp_storage_update(int object_id,
                                   uint64_t cgroup_reference,
                                   const void *value, uint64_t flags);
int kernel_bpf_cgrp_storage_delete(int object_id,
                                   uint64_t cgroup_reference);
int kernel_bpf_sk_storage_lookup(int object_id,
                                 uint64_t socket_identity,
                                 void *value, uint64_t flags);
int kernel_bpf_sk_storage_exists(int object_id,
                                 uint64_t socket_identity);
int kernel_bpf_sk_storage_update(int object_id,
                                 uint64_t socket_identity,
                                 const void *value, uint64_t flags);
int kernel_bpf_sk_storage_delete(int object_id,
                                 uint64_t socket_identity);
int kernel_bpf_sk_storage_clone(uint64_t source_socket_identity,
                                uint64_t target_socket_identity);
int kernel_bpf_inode_storage_lookup(int object_id,
                                    uint64_t filesystem_identity,
                                    uint32_t inode_number,
                                    uint32_t inode_generation,
                                    void *value, uint64_t flags);
int kernel_bpf_inode_storage_update(int object_id,
                                    uint64_t filesystem_identity,
                                    uint32_t inode_number,
                                    uint32_t inode_generation,
                                    const void *value, uint64_t flags);
int kernel_bpf_inode_storage_delete(int object_id,
                                    uint64_t filesystem_identity,
                                    uint32_t inode_number,
                                    uint32_t inode_generation);
uint32_t kernel_bpf_inode_storage_owner_release(
    uint64_t filesystem_identity, uint32_t inode_number,
    uint32_t inode_generation);
int kernel_bpf_task_storage_lookup(int object_id, int32_t tid,
                                   uint64_t start_time_ticks,
                                   void *value, uint64_t flags);
int kernel_bpf_task_storage_update(int object_id, int32_t tid,
                                   uint64_t start_time_ticks,
                                   const void *value, uint64_t flags);
int kernel_bpf_task_storage_delete(int object_id, int32_t tid,
                                   uint64_t start_time_ticks);
void kernel_bpf_task_storage_task_exit(int32_t tid,
                                       uint64_t start_time_ticks);
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
int kernel_bpf_map_mmap_info(int object_id, uint64_t offset,
                             uint64_t length, int writable,
                             uint32_t *page_count);
int kernel_bpf_map_mmap_page(int object_id, uint64_t offset,
                             uint32_t page_index, void **page_address);
int kernel_bpf_ringbuf_poll_state(int object_id, int *readable,
                                  int *writable);

int kernel_bpf_program_run_cgroup_device(
    int object_id, const kernel_bpf_cgroup_device_context_t *context,
    uint32_t *result);
int kernel_bpf_program_run_cgroup_device_at(
    int object_id, uint32_t cgroup_id,
    const kernel_bpf_cgroup_device_context_t *context,
    uint32_t *result);
int kernel_bpf_program_run_socket_filter(
    int object_id, const kernel_bpf_socket_filter_context_t *context,
    uint32_t *result);
int kernel_bpf_program_run_raw_tracepoint(
    int object_id, const uint64_t *arguments, uint32_t argument_count,
    uint32_t *result);
int kernel_bpf_raw_tracepoint_open(const char *name, int object_id);
void kernel_bpf_raw_tracepoint_sys_enter(void *user_registers,
                                         uint64_t system_call_number);
int kernel_bpf_cgroup_attach(uint32_t cgroup_id, int object_id,
                             uint32_t flags, int replace_object_id,
                             int relative_object_id,
                             uint64_t expected_revision);
int kernel_bpf_cgroup_detach(uint32_t cgroup_id, int object_id,
                             uint64_t expected_revision);
int kernel_bpf_cgroup_query(uint32_t cgroup_id, int *object_ids,
                            uint32_t *attach_flags, uint32_t capacity,
                            uint32_t *count, uint64_t *revision);
int kernel_bpf_cgroup_query_links(uint32_t cgroup_id, int *object_ids,
                                  uint32_t *attach_flags,
                                  int *link_object_ids,
                                  uint32_t capacity, uint32_t *count,
                                  uint64_t *revision);
int kernel_bpf_cgroup_link_create(uint32_t cgroup_id, int object_id,
                                  uint32_t attach_type, uint32_t flags,
                                  int relative_object_id,
                                  uint64_t expected_revision);
int kernel_bpf_link_update(int link_object_id, int new_object_id,
                           uint32_t flags, int old_object_id);
int kernel_bpf_link_detach(int link_object_id);
int kernel_bpf_cgroup_device_run(
    uint32_t cgroup_id,
    const kernel_bpf_cgroup_device_context_t *context,
    uint32_t *result);
void kernel_bpf_cgroup_release(uint32_t cgroup_id);
uint32_t kernel_bpf_cgroup_storage_owner_release(
    uint64_t cgroup_reference);

int kernel_bpf_create_descriptor(int object_id);
int kernel_bpf_create_descriptor_flags(int object_id, uint32_t status_flags);
int kernel_bpf_descriptor_object(int32_t descriptor,
                                 kernel_bpf_object_kind_t expected_kind);
int kernel_bpf_descriptor_object_any(int32_t descriptor,
                                     kernel_bpf_object_kind_t *kind);

#endif
