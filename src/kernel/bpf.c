/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux BPF object runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "fs/cgroupfs.h"
#include "kernel/anonymous_fd.h"
#include "kernel/bpf_runtime.h"
#include "kernel/fd_runtime.h"
#include "kernel/file_description_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/perf_event.h"
#include "kernel/runtime_limits.h"
#include "kernel/smp.h"
#include "kernel/socket_runtime.h"
#include "mm/arch_vm.h"
#include "sys/boottime.h"
#include "string.h"

#define BPF_OBJECT_CAPACITY EDGE_RUNTIME_MAX_BPF_OBJECTS
#define BPF_PAGE_SIZE 4096u
#define BPF_STACK_MAX_DEPTH 127u
#define BPF_OBJECT_ALLOCATION_LIMIT (16u * 1024u * 1024u)
#define BPF_CGRP_STORAGE_ENTRIES 256u
#define BPF_LOCAL_STORAGE_VALUE_LIMIT 65504u
#ifdef CONFIG_NR_CPUS
#define BPF_CPUMAP_MAX_ENTRIES CONFIG_NR_CPUS
#else
#define BPF_CPUMAP_MAX_ENTRIES EDGE_SMP_MAX_CPUS
#endif

#define BPF_CLASS(code) ((code) & 0x07u)
#define BPF_SIZE(code)  ((code) & 0x18u)
#define BPF_MODE(code)  ((code) & 0xe0u)
#define BPF_OP(code)    ((code) & 0xf0u)
#define BPF_SRC(code)   ((code) & 0x08u)

#define BPF_LD    0x00u
#define BPF_LDX   0x01u
#define BPF_STX   0x03u
#define BPF_ALU64 0x07u
#define BPF_JMP   0x05u
#define BPF_W     0x00u
#define BPF_DW    0x18u
#define BPF_IMM   0x00u
#define BPF_MEM   0x60u
#define BPF_K     0x00u
#define BPF_X     0x08u
#define BPF_ADD   0x00u
#define BPF_SUB   0x10u
#define BPF_MUL   0x20u
#define BPF_DIV   0x30u
#define BPF_OR    0x40u
#define BPF_AND   0x50u
#define BPF_LSH   0x60u
#define BPF_RSH   0x70u
#define BPF_NEG   0x80u
#define BPF_MOD   0x90u
#define BPF_XOR   0xa0u
#define BPF_MOV   0xb0u
#define BPF_ARSH  0xc0u
#define BPF_JA    0x00u
#define BPF_JEQ   0x10u
#define BPF_JGT   0x20u
#define BPF_JGE   0x30u
#define BPF_JSET  0x40u
#define BPF_JNE   0x50u
#define BPF_JSGT  0x60u
#define BPF_JSGE  0x70u
#define BPF_JLT   0xa0u
#define BPF_JLE   0xb0u
#define BPF_JSLT  0xc0u
#define BPF_JSLE  0xd0u
#define BPF_CALL  0x80u
#define BPF_EXIT  0x90u
#define BPF_PSEUDO_MAP_FD 1u
#define BPF_FUNC_TAIL_CALL 12u
#define BPF_FUNC_GET_STACKID 27u
#define BPF_FUNC_GET_LOCAL_STORAGE 81u
#define BPF_FUNC_RINGBUF_OUTPUT 130u
#define BPF_MAX_TAIL_CALLS 33u
#define BPF_RB_NO_WAKEUP (1ull << 0)
#define BPF_RB_FORCE_WAKEUP (1ull << 1)
#define BPF_RINGBUF_BUSY_BIT (1u << 31)
#define BPF_RINGBUF_DISCARD_BIT (1u << 30)
#define BPF_RINGBUF_HEADER_SIZE 8u
#define BPF_F_SKIP_FIELD_MASK 0xffu
#define BPF_F_USER_STACK (1u << 8)
#define BPF_F_FAST_STACK_CMP (1u << 9)
#define BPF_F_REUSE_STACKID (1u << 10)
#define BPF_RAW_TRACEPOINT_SYS_ENTER 1u

typedef struct kernel_bpf_map {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t storage_entries;
    uint32_t flags;
    uint32_t entry_stride;
    uint32_t entry_count;
    uint32_t storage_pages;
    uint32_t queue_head;
    uint32_t queue_tail;
    uint32_t value_stride;
    uint32_t possible_cpu_count;
    uint32_t inner_type;
    uint32_t inner_key_size;
    uint32_t inner_value_size;
    uint32_t inner_flags;
    int32_t btf_object_id;
    uint32_t btf_key_type_id;
    uint32_t btf_value_type_id;
    uint64_t map_extra;
    uint64_t access_sequence;
    uint32_t bloom_bit_mask;
    uint32_t bloom_hash_count;
    uint32_t bloom_seed;
    uint8_t frozen;
    uint8_t *storage;
    char name[KERNEL_BPF_OBJECT_NAME_LENGTH];
} kernel_bpf_map_t;

typedef struct bpf_local_storage_owner {
    uint64_t primary;
    uint64_t secondary;
} bpf_local_storage_owner_t;

typedef struct kernel_bpf_program {
    uint32_t type;
    uint32_t instruction_count;
    uint32_t flags;
    uint32_t expected_attach_type;
    uint32_t created_by_uid;
    uint32_t gpl_compatible;
    uint32_t storage_pages;
    uint32_t map_reference_count;
    uint32_t bound_map_count;
    uint64_t run_time_ns;
    uint64_t run_count;
    uint8_t tag[8];
    kernel_bpf_instruction_t *instructions;
    int32_t bound_map_ids[BPF_OBJECT_CAPACITY];
    char name[KERNEL_BPF_OBJECT_NAME_LENGTH];
} kernel_bpf_program_t;

typedef struct kernel_bpf_btf {
    uint32_t size;
    uint32_t storage_pages;
    uint8_t *data;
} kernel_bpf_btf_t;

typedef struct kernel_bpf_link {
    int32_t program_object_id;
    uint32_t cgroup_id;
    uint32_t attach_type;
    uint32_t attach_flags;
    uint8_t detached;
    uint8_t padding[3];
} kernel_bpf_link_t;

typedef struct kernel_bpf_object {
    uint8_t used;
    uint8_t kind;
    uint16_t padding;
    uint32_t references;
    uint32_t user_id;
    union {
        kernel_bpf_map_t map;
        kernel_bpf_program_t program;
        kernel_bpf_btf_t btf;
        kernel_bpf_link_t link;
    } value;
} kernel_bpf_object_t;

typedef struct kernel_btf_header {
    uint16_t magic;
    uint8_t version;
    uint8_t flags;
    uint32_t header_length;
    uint32_t type_offset;
    uint32_t type_length;
    uint32_t string_offset;
    uint32_t string_length;
} kernel_btf_header_t;

typedef struct kernel_btf_type {
    uint32_t name_offset;
    uint32_t info;
    uint32_t size_or_type;
} kernel_btf_type_t;

#define KERNEL_BTF_MAGIC 0xeb9fu
#define KERNEL_BTF_VERSION 1u
#define KERNEL_BTF_KIND_INT 1u
#define KERNEL_BTF_KIND_PTR 2u
#define KERNEL_BTF_KIND_ARRAY 3u
#define KERNEL_BTF_KIND_STRUCT 4u
#define KERNEL_BTF_KIND_UNION 5u
#define KERNEL_BTF_KIND_ENUM 6u
#define KERNEL_BTF_KIND_FWD 7u
#define KERNEL_BTF_KIND_TYPEDEF 8u
#define KERNEL_BTF_KIND_VOLATILE 9u
#define KERNEL_BTF_KIND_CONST 10u
#define KERNEL_BTF_KIND_RESTRICT 11u
#define KERNEL_BTF_KIND_FUNC 12u
#define KERNEL_BTF_KIND_FUNC_PROTO 13u
#define KERNEL_BTF_KIND_VAR 14u
#define KERNEL_BTF_KIND_DATASEC 15u
#define KERNEL_BTF_KIND_FLOAT 16u
#define KERNEL_BTF_KIND_DECL_TAG 17u
#define KERNEL_BTF_KIND_TYPE_TAG 18u
#define KERNEL_BTF_KIND_ENUM64 19u
#define KERNEL_BTF_KIND_MAX KERNEL_BTF_KIND_ENUM64
#define KERNEL_BTF_INFO_KIND(info) (((info) >> 24u) & 0x1fu)
#define KERNEL_BTF_INFO_VLEN(info) ((info) & 0xffffu)
#define KERNEL_BTF_INFO_KIND_FLAG(info) ((info) >> 31u)

typedef struct kernel_bpf_attachment {
    uint8_t used;
    uint8_t padding[3];
    uint32_t cgroup_id;
    int32_t object_id;
    int32_t link_object_id;
    uint32_t flags;
    uint32_t attach_type;
    uint64_t sequence;
} kernel_bpf_attachment_t;

typedef struct kernel_bpf_raw_tracepoint_attachment {
    uint8_t used;
    uint8_t tracepoint;
    uint16_t padding;
    int32_t object_id;
    int32_t link_object_id;
} kernel_bpf_raw_tracepoint_attachment_t;

typedef struct kernel_bpf_pin {
    uint8_t used;
    uint8_t padding[3];
    const void *filesystem_identity;
    uint32_t inode_number;
    uint32_t inode_generation;
    int32_t object_id;
} kernel_bpf_pin_t;

#define BPF_PIN_CAPACITY (BPF_OBJECT_CAPACITY * 4u)

static kernel_bpf_object_t g_bpf_objects[BPF_OBJECT_CAPACITY];
static uint32_t g_bpf_runtime_stats_users;
static kernel_bpf_attachment_t
    g_bpf_attachments[EDGE_RUNTIME_MAX_BPF_ATTACHMENTS];
static kernel_bpf_raw_tracepoint_attachment_t
    g_bpf_raw_tracepoints[EDGE_RUNTIME_MAX_BPF_ATTACHMENTS];
static volatile uint32_t g_bpf_raw_tracepoint_users;
static kernel_bpf_pin_t g_bpf_pins[BPF_PIN_CAPACITY];
static uint64_t g_bpf_cgroup_revisions[256];
static volatile uint32_t g_bpf_lock;
static uint32_t g_bpf_next_user_id = 1u;
static uint64_t g_bpf_attachment_sequence;

static void bpf_socket_description_closed(uint64_t identity);
static int bpf_legacy_cgroup_storage_link_map_locked(
    kernel_bpf_map_t *map, uint32_t cgroup_id,
    uint32_t attach_type);
static void bpf_legacy_cgroup_storage_unlink_map_locked(
    kernel_bpf_map_t *map, uint32_t cgroup_id,
    uint32_t attach_type);
static int bpf_program_legacy_storage_link_locked(
    const kernel_bpf_program_t *program, uint32_t cgroup_id,
    uint32_t attach_type);
static int bpf_btf_map_types_validate(int object_id,
                                      uint32_t key_type_id,
                                      uint32_t value_type_id,
                                      uint32_t key_size,
                                      uint32_t value_size);

_Static_assert(sizeof(kernel_bpf_instruction_t) == 8u,
               "BPF instruction layout must match Linux UAPI");

static void bpf_lock(void) {
    while (__sync_lock_test_and_set(&g_bpf_lock, 1u)) { }
}

static void bpf_unlock(void) {
    __sync_lock_release(&g_bpf_lock);
}

static uint32_t bpf_align8(uint32_t value) {
    return (value + 7u) & ~7u;
}

static int bpf_map_is_hash(const kernel_bpf_map_t *map) {
    return map &&
        (map->type == KERNEL_BPF_MAP_TYPE_HASH ||
         map->type == KERNEL_BPF_MAP_TYPE_PERCPU_HASH ||
         map->type == KERNEL_BPF_MAP_TYPE_LRU_HASH ||
         map->type == KERNEL_BPF_MAP_TYPE_LRU_PERCPU_HASH ||
         map->type == KERNEL_BPF_MAP_TYPE_HASH_OF_MAPS ||
         map->type == KERNEL_BPF_MAP_TYPE_RHASH);
}

static int bpf_map_is_array(const kernel_bpf_map_t *map) {
    return map &&
        (map->type == KERNEL_BPF_MAP_TYPE_ARRAY ||
         map->type == KERNEL_BPF_MAP_TYPE_PERCPU_ARRAY ||
         map->type == KERNEL_BPF_MAP_TYPE_PROG_ARRAY ||
         map->type == KERNEL_BPF_MAP_TYPE_PERF_EVENT_ARRAY ||
         map->type == KERNEL_BPF_MAP_TYPE_CGROUP_ARRAY ||
         map->type == KERNEL_BPF_MAP_TYPE_ARRAY_OF_MAPS);
}

static int bpf_map_type_is_object_array(uint32_t type) {
    return type == KERNEL_BPF_MAP_TYPE_PROG_ARRAY ||
           type == KERNEL_BPF_MAP_TYPE_ARRAY_OF_MAPS;
}

static int bpf_map_is_object_array(const kernel_bpf_map_t *map) {
    return map && bpf_map_type_is_object_array(map->type);
}

static int bpf_map_is_perf_event_array(const kernel_bpf_map_t *map) {
    return map && map->type == KERNEL_BPF_MAP_TYPE_PERF_EVENT_ARRAY;
}

static int bpf_map_is_cgroup_array(const kernel_bpf_map_t *map) {
    return map && map->type == KERNEL_BPF_MAP_TYPE_CGROUP_ARRAY;
}

static int bpf_map_type_has_descriptor_slots(uint32_t type) {
    return bpf_map_type_is_object_array(type) ||
           type == KERNEL_BPF_MAP_TYPE_PERF_EVENT_ARRAY;
}

static int bpf_map_type_is_map_in_map(uint32_t type) {
    return type == KERNEL_BPF_MAP_TYPE_ARRAY_OF_MAPS ||
           type == KERNEL_BPF_MAP_TYPE_HASH_OF_MAPS;
}

static int bpf_map_is_map_in_map(const kernel_bpf_map_t *map) {
    return map && bpf_map_type_is_map_in_map(map->type);
}

static int bpf_map_type_is_percpu(uint32_t type) {
    return type == KERNEL_BPF_MAP_TYPE_PERCPU_HASH ||
           type == KERNEL_BPF_MAP_TYPE_PERCPU_ARRAY ||
           type == KERNEL_BPF_MAP_TYPE_LRU_PERCPU_HASH ||
           type == KERNEL_BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE;
}

static int bpf_map_is_percpu(const kernel_bpf_map_t *map) {
    return map && bpf_map_type_is_percpu(map->type);
}

static int bpf_map_is_lru_hash(const kernel_bpf_map_t *map) {
    return map &&
        (map->type == KERNEL_BPF_MAP_TYPE_LRU_HASH ||
         map->type == KERNEL_BPF_MAP_TYPE_LRU_PERCPU_HASH);
}

static int bpf_map_type_is_lru_hash(uint32_t type) {
    return type == KERNEL_BPF_MAP_TYPE_LRU_HASH ||
           type == KERNEL_BPF_MAP_TYPE_LRU_PERCPU_HASH;
}

static int bpf_map_has_percpu_lru(const kernel_bpf_map_t *map) {
    return map && bpf_map_is_lru_hash(map) &&
           (map->flags & KERNEL_BPF_MAP_NO_COMMON_LRU);
}

static int bpf_map_type_is_queue_stack(uint32_t type) {
    return type == KERNEL_BPF_MAP_TYPE_QUEUE ||
           type == KERNEL_BPF_MAP_TYPE_STACK;
}

static int bpf_map_is_lpm_trie(const kernel_bpf_map_t *map) {
    return map && map->type == KERNEL_BPF_MAP_TYPE_LPM_TRIE;
}

static int bpf_map_is_bloom_filter(const kernel_bpf_map_t *map) {
    return map && map->type == KERNEL_BPF_MAP_TYPE_BLOOM_FILTER;
}

static int bpf_map_is_stack_trace(const kernel_bpf_map_t *map) {
    return map && map->type == KERNEL_BPF_MAP_TYPE_STACK_TRACE;
}

static int bpf_map_is_cpumap(const kernel_bpf_map_t *map) {
    return map && map->type == KERNEL_BPF_MAP_TYPE_CPUMAP;
}

static int bpf_map_is_devmap_array(const kernel_bpf_map_t *map) {
    return map && map->type == KERNEL_BPF_MAP_TYPE_DEVMAP;
}

static int bpf_map_is_devmap_hash(const kernel_bpf_map_t *map) {
    return map && map->type == KERNEL_BPF_MAP_TYPE_DEVMAP_HASH;
}

static int bpf_map_is_devmap(const kernel_bpf_map_t *map) {
    return bpf_map_is_devmap_array(map) || bpf_map_is_devmap_hash(map);
}

static int bpf_map_is_xskmap(const kernel_bpf_map_t *map) {
    return map && map->type == KERNEL_BPF_MAP_TYPE_XSKMAP;
}

static int bpf_map_is_sockmap(const kernel_bpf_map_t *map) {
    return map && map->type == KERNEL_BPF_MAP_TYPE_SOCKMAP;
}

static int bpf_map_is_sockhash(const kernel_bpf_map_t *map) {
    return map && map->type == KERNEL_BPF_MAP_TYPE_SOCKHASH;
}

static int bpf_map_is_socket_map(const kernel_bpf_map_t *map) {
    return bpf_map_is_sockmap(map) || bpf_map_is_sockhash(map);
}

static int bpf_map_is_reuseport_array(const kernel_bpf_map_t *map) {
    return map &&
        map->type == KERNEL_BPF_MAP_TYPE_REUSEPORT_SOCKARRAY;
}

static int bpf_map_is_cgrp_storage(const kernel_bpf_map_t *map) {
    return map && map->type == KERNEL_BPF_MAP_TYPE_CGRP_STORAGE;
}

static int bpf_map_is_legacy_cgroup_storage(
        const kernel_bpf_map_t *map) {
    return map &&
        (map->type == KERNEL_BPF_MAP_TYPE_CGROUP_STORAGE ||
         map->type == KERNEL_BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
}

static int bpf_map_type_is_legacy_cgroup_storage(uint32_t type) {
    return type == KERNEL_BPF_MAP_TYPE_CGROUP_STORAGE ||
           type == KERNEL_BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE;
}

static int bpf_map_is_sk_storage(const kernel_bpf_map_t *map) {
    return map && map->type == KERNEL_BPF_MAP_TYPE_SK_STORAGE;
}

static int bpf_map_is_inode_storage(const kernel_bpf_map_t *map) {
    return map && map->type == KERNEL_BPF_MAP_TYPE_INODE_STORAGE;
}

static int bpf_map_is_task_storage(const kernel_bpf_map_t *map) {
    return map && map->type == KERNEL_BPF_MAP_TYPE_TASK_STORAGE;
}

static int bpf_map_is_local_storage(const kernel_bpf_map_t *map) {
    return bpf_map_is_cgrp_storage(map) || bpf_map_is_sk_storage(map) ||
           bpf_map_is_inode_storage(map) || bpf_map_is_task_storage(map);
}

static int bpf_map_type_is_local_storage(uint32_t type) {
    return type == KERNEL_BPF_MAP_TYPE_CGRP_STORAGE ||
           type == KERNEL_BPF_MAP_TYPE_SK_STORAGE ||
           type == KERNEL_BPF_MAP_TYPE_INODE_STORAGE ||
           type == KERNEL_BPF_MAP_TYPE_TASK_STORAGE;
}

static size_t bpf_local_storage_owner_size(const kernel_bpf_map_t *map) {
    return bpf_map_is_inode_storage(map) || bpf_map_is_task_storage(map) ?
        sizeof(bpf_local_storage_owner_t) : sizeof(uint64_t);
}

static int bpf_map_is_insn_array(const kernel_bpf_map_t *map) {
    return map && map->type == KERNEL_BPF_MAP_TYPE_INSN_ARRAY;
}

static uint32_t bpf_round_power_of_two(uint32_t value) {
    uint32_t rounded = 1u;

    while (rounded < value && rounded < (1u << 31u)) rounded <<= 1u;
    return rounded;
}

static int bpf_map_type_is_ringbuf(uint32_t type) {
    return type == KERNEL_BPF_MAP_TYPE_RINGBUF ||
           type == KERNEL_BPF_MAP_TYPE_USER_RINGBUF;
}

static int bpf_map_is_ringbuf(const kernel_bpf_map_t *map) {
    return map && bpf_map_type_is_ringbuf(map->type);
}

static int bpf_map_is_queue_stack(const kernel_bpf_map_t *map) {
    return map && bpf_map_type_is_queue_stack(map->type);
}

uint32_t kernel_bpf_possible_cpu_count(void) {
    uint32_t count = edge_smp_nr_cpu_ids();

    return count ? count : 1u;
}

static uint32_t bpf_map_value_buffer_size_locked(
        const kernel_bpf_map_t *map) {
    if (!map) return 0u;
    if (bpf_map_is_percpu(map))
        return map->value_stride * map->possible_cpu_count;
    return map->value_size;
}

static int bpf_map_check_percpu_flags_locked(
        const kernel_bpf_map_t *map, uint64_t flags) {
    uint32_t operation_flags = (uint32_t)flags;
    uint32_t cpu = (uint32_t)(flags >> 32u);

    if (operation_flags & KERNEL_BPF_F_LOCK)
        return -EDGE_LINUX_EINVAL;
    if (!bpf_map_is_percpu(map)) {
        if ((operation_flags &
             (KERNEL_BPF_F_CPU | KERNEL_BPF_F_ALL_CPUS)) || cpu)
            return -EDGE_LINUX_EINVAL;
        if (flags != KERNEL_BPF_ANY && flags != KERNEL_BPF_NOEXIST &&
            flags != KERNEL_BPF_EXIST)
            return -EDGE_LINUX_EINVAL;
        return 0;
    }
    if (operation_flags > KERNEL_BPF_F_ALL_CPUS)
        return -EDGE_LINUX_EINVAL;
    if (!(operation_flags & KERNEL_BPF_F_CPU) && cpu)
        return -EDGE_LINUX_EINVAL;
    if ((operation_flags & KERNEL_BPF_F_CPU) &&
        (operation_flags & KERNEL_BPF_F_ALL_CPUS))
        return -EDGE_LINUX_EINVAL;
    if ((operation_flags & KERNEL_BPF_F_CPU) &&
        cpu >= map->possible_cpu_count)
        return -EDGE_LINUX_ERANGE;
    return 0;
}

static int bpf_name_valid(const char *name) {
    uint32_t index;

    if (!name || name[KERNEL_BPF_OBJECT_NAME_LENGTH - 1u]) return 0;
    for (index = 0; index < KERNEL_BPF_OBJECT_NAME_LENGTH && name[index];
         ++index) {
        char character = name[index];
        if (!((character >= 'a' && character <= 'z') ||
              (character >= 'A' && character <= 'Z') ||
              (character >= '0' && character <= '9') || character == '_'))
            return 0;
    }
    return 1;
}

static int bpf_allocation_size(uint64_t bytes, uint32_t *pages_out) {
    uint64_t pages;

    if (!bytes || bytes > BPF_OBJECT_ALLOCATION_LIMIT || !pages_out)
        return -EDGE_LINUX_E2BIG;
    pages = (bytes + BPF_PAGE_SIZE - 1u) / BPF_PAGE_SIZE;
    if (!pages || pages > UINT32_MAX) return -EDGE_LINUX_E2BIG;
    *pages_out = (uint32_t)pages;
    return 0;
}

static void bpf_free_pages(void *storage, uint32_t pages) {
    uint8_t *base = (uint8_t *)storage;
    uint32_t page;

    if (!base) return;
    for (page = 0; page < pages; ++page)
        arch_vm_free_page(base + (uint64_t)page * BPF_PAGE_SIZE);
}

static kernel_bpf_object_t *bpf_object_locked(int object_id) {
    if (object_id < 0 || (uint32_t)object_id >= BPF_OBJECT_CAPACITY ||
        !g_bpf_objects[object_id].used)
        return 0;
    return &g_bpf_objects[object_id];
}

static uint64_t *bpf_cgroup_revision_locked(uint32_t cgroup_id);

static int bpf_allocate_object_locked(kernel_bpf_object_kind_t kind,
                                      kernel_bpf_object_t **object_out) {
    uint32_t index;

    for (index = 0; index < BPF_OBJECT_CAPACITY; ++index) {
        kernel_bpf_object_t *object = &g_bpf_objects[index];
        if (object->used) continue;
        memset(object, 0, sizeof(*object));
        object->used = 1;
        object->kind = (uint8_t)kind;
        object->references = 1;
        object->user_id = g_bpf_next_user_id++;
        if (!object->user_id) object->user_id = g_bpf_next_user_id++;
        *object_out = object;
        return (int)index;
    }
    return -EDGE_LINUX_ENFILE;
}

int kernel_bpf_map_create(const kernel_bpf_map_create_request_t *request) {
    kernel_bpf_object_t *object;
    uint32_t pages;
    uint32_t stride;
    uint32_t validation_flags;
    uint32_t stored_flags;
    uint32_t value_stride;
    uint32_t possible_cpu_count;
    uint32_t actual_max_entries;
    uint32_t storage_entries;
    uint32_t bloom_bit_count = 0u;
    uint32_t bloom_hash_count = 0u;
    uint64_t bytes;
    uint8_t *storage;
    kernel_bpf_map_info_t inner_info;
    int object_id;
    int status;
    int btf_retained = 0;

    if (!request || !bpf_name_valid(request->name) ||
        request->key_size > KERNEL_BPF_MAX_KEY_SIZE ||
        (!request->value_size &&
         !bpf_map_type_is_ringbuf(request->type) &&
         request->type != KERNEL_BPF_MAP_TYPE_ARENA) ||
        (request->value_size > KERNEL_BPF_MAX_VALUE_SIZE &&
         !bpf_map_type_is_local_storage(request->type) &&
         !bpf_map_type_is_legacy_cgroup_storage(request->type)) ||
        (!request->max_entries &&
         !bpf_map_type_is_local_storage(request->type) &&
         !bpf_map_type_is_legacy_cgroup_storage(request->type)))
        return -EDGE_LINUX_EINVAL;
    if ((request->flags &
         (KERNEL_BPF_MAP_RDONLY | KERNEL_BPF_MAP_WRONLY)) ==
        (KERNEL_BPF_MAP_RDONLY | KERNEL_BPF_MAP_WRONLY))
        return -EDGE_LINUX_EINVAL;
    validation_flags = request->flags &
        ~(KERNEL_BPF_MAP_RDONLY | KERNEL_BPF_MAP_WRONLY);
    stored_flags = validation_flags;
    if (!request->btf_present &&
        (request->btf_key_type_id || request->btf_value_type_id))
        return -EDGE_LINUX_EINVAL;
    if (request->btf_present) {
        kernel_bpf_object_kind_t kind;

        if (!request->btf_value_type_id ||
            (!!request->key_size != !!request->btf_key_type_id) ||
            kernel_bpf_object_kind(request->btf_object_id, &kind) < 0 ||
            kind != KERNEL_BPF_OBJECT_BTF)
            return -EDGE_LINUX_EINVAL;
        status = kernel_bpf_object_retain(request->btf_object_id);
        if (status < 0) return status;
        btf_retained = 1;
        status = bpf_btf_map_types_validate(
            request->btf_object_id, request->btf_key_type_id,
            request->btf_value_type_id, request->key_size,
            request->value_size);
        if (status < 0) goto fail_btf;
    }
    if (bpf_map_type_is_queue_stack(request->type) ||
        bpf_map_type_is_ringbuf(request->type) ||
        request->type == KERNEL_BPF_MAP_TYPE_BLOOM_FILTER ||
        request->type == KERNEL_BPF_MAP_TYPE_ARENA) {
        if (request->key_size) {
            status = -EDGE_LINUX_EINVAL;
            goto fail_btf;
        }
    } else if (!request->key_size) {
        status = -EDGE_LINUX_EINVAL;
        goto fail_btf;
    }
    value_stride = bpf_align8(request->value_size);
    possible_cpu_count =
        (bpf_map_type_is_percpu(request->type) ||
         (bpf_map_type_is_lru_hash(request->type) &&
          (validation_flags & KERNEL_BPF_MAP_NO_COMMON_LRU))) ?
        kernel_bpf_possible_cpu_count() : 1u;
    if (!possible_cpu_count) possible_cpu_count = 1u;
    actual_max_entries = request->max_entries;
    storage_entries = actual_max_entries;
    memset(&inner_info, 0, sizeof(inner_info));
    if (bpf_map_type_is_map_in_map(request->type)) {
        status = kernel_bpf_map_info(
            request->inner_map_object_id, &inner_info);
        if (status < 0) goto fail_btf;
        if (bpf_map_type_is_map_in_map(inner_info.type))
            goto invalid_btf;
        if (request->value_size != sizeof(uint32_t))
            goto invalid_btf;
    }
    if (request->type == KERNEL_BPF_MAP_TYPE_ARRAY ||
        request->type == KERNEL_BPF_MAP_TYPE_PERCPU_ARRAY) {
        if (request->key_size != sizeof(uint32_t) || validation_flags)
            goto invalid_btf;
        stride = request->type == KERNEL_BPF_MAP_TYPE_PERCPU_ARRAY ?
            value_stride * possible_cpu_count : value_stride;
    } else if (request->type == KERNEL_BPF_MAP_TYPE_PROG_ARRAY) {
        if (request->key_size != sizeof(uint32_t) ||
            request->value_size != sizeof(uint32_t) ||
            validation_flags || request->map_extra ||
            request->btf_present)
            goto invalid_btf;
        stride = sizeof(int32_t);
    } else if (request->type == KERNEL_BPF_MAP_TYPE_PERF_EVENT_ARRAY) {
        if (request->key_size != sizeof(uint32_t) ||
            request->value_size != sizeof(uint32_t) ||
            (validation_flags & ~KERNEL_BPF_MAP_PRESERVE_ELEMS) ||
            request->map_extra || request->btf_present)
            goto invalid_btf;
        stride = sizeof(int32_t);
    } else if (request->type == KERNEL_BPF_MAP_TYPE_CGROUP_ARRAY) {
        if (request->key_size != sizeof(uint32_t) ||
            request->value_size != sizeof(uint32_t) ||
            validation_flags || request->map_extra ||
            request->btf_present)
            goto invalid_btf;
        stride = sizeof(uint64_t);
    } else if (request->type == KERNEL_BPF_MAP_TYPE_STACK_TRACE) {
        uint32_t element_size =
            validation_flags & KERNEL_BPF_MAP_STACK_BUILD_ID ? 32u : 8u;

        if (request->max_entries > (1u << 31u)) {
            status = -EDGE_LINUX_E2BIG;
            goto fail_btf;
        }
        if (request->key_size != sizeof(uint32_t) ||
            request->value_size < element_size ||
            request->value_size % element_size ||
            request->value_size / element_size > BPF_STACK_MAX_DEPTH ||
            (validation_flags &
             ~(KERNEL_BPF_MAP_NUMA_NODE |
               KERNEL_BPF_MAP_STACK_BUILD_ID)) ||
            request->btf_present || request->map_extra)
            goto invalid_btf;
        storage_entries = bpf_round_power_of_two(request->max_entries);
        stride = bpf_align8(1u + request->value_size);
    } else if (request->type == KERNEL_BPF_MAP_TYPE_CPUMAP) {
        if (request->max_entries > BPF_CPUMAP_MAX_ENTRIES) {
            status = -EDGE_LINUX_E2BIG;
            goto fail_btf;
        }
        if (request->key_size != sizeof(uint32_t) ||
            (request->value_size != sizeof(uint32_t) &&
             request->value_size != 2u * sizeof(uint32_t)) ||
            (validation_flags & ~KERNEL_BPF_MAP_NUMA_NODE) ||
            request->btf_present || request->map_extra)
            goto invalid_btf;
        stride = bpf_align8(1u + request->value_size);
    } else if (request->type == KERNEL_BPF_MAP_TYPE_DEVMAP ||
               request->type == KERNEL_BPF_MAP_TYPE_DEVMAP_HASH) {
        if (request->type == KERNEL_BPF_MAP_TYPE_DEVMAP_HASH &&
            request->max_entries > (1u << 31u))
            goto invalid_btf;
        if (request->key_size != sizeof(uint32_t) ||
            (request->value_size != sizeof(uint32_t) &&
             request->value_size != 2u * sizeof(uint32_t)) ||
            (validation_flags & ~KERNEL_BPF_MAP_NUMA_NODE) ||
            request->btf_present || request->map_extra)
            goto invalid_btf;
        stride = request->type == KERNEL_BPF_MAP_TYPE_DEVMAP ?
            bpf_align8(1u + request->value_size) :
            bpf_align8(1u + request->key_size + request->value_size);
        stored_flags |= KERNEL_BPF_MAP_RDONLY_PROGRAM;
    } else if (request->type == KERNEL_BPF_MAP_TYPE_XSKMAP) {
        if (request->key_size != sizeof(uint32_t) ||
            request->value_size != sizeof(uint32_t) ||
            (validation_flags & ~KERNEL_BPF_MAP_NUMA_NODE) ||
            request->btf_present || request->map_extra)
            goto invalid_btf;
        stride = bpf_align8(1u + request->value_size);
    } else if (request->type == KERNEL_BPF_MAP_TYPE_SOCKMAP ||
               request->type == KERNEL_BPF_MAP_TYPE_SOCKHASH) {
        if (request->type == KERNEL_BPF_MAP_TYPE_SOCKHASH &&
            request->key_size > 512u) {
            status = -EDGE_LINUX_E2BIG;
            goto fail_btf;
        }
        if ((request->type == KERNEL_BPF_MAP_TYPE_SOCKMAP &&
             request->key_size != sizeof(uint32_t)) ||
            (request->value_size != sizeof(uint32_t) &&
             request->value_size != sizeof(uint64_t)) ||
            (validation_flags & ~KERNEL_BPF_MAP_NUMA_NODE) ||
            request->btf_present || request->map_extra)
            goto invalid_btf;
        stride = request->type == KERNEL_BPF_MAP_TYPE_SOCKMAP ?
            bpf_align8(1u + sizeof(uint64_t)) :
            bpf_align8(1u + request->key_size + sizeof(uint64_t));
    } else if (request->type ==
               KERNEL_BPF_MAP_TYPE_REUSEPORT_SOCKARRAY) {
        if (request->key_size != sizeof(uint32_t) ||
            (request->value_size != sizeof(uint32_t) &&
             request->value_size != sizeof(uint64_t)) ||
            (validation_flags & ~KERNEL_BPF_MAP_NUMA_NODE) ||
            request->btf_present || request->map_extra)
            goto invalid_btf;
        stride = bpf_align8(1u + sizeof(uint64_t));
    } else if (bpf_map_type_is_legacy_cgroup_storage(request->type)) {
        if (request->value_size > BPF_LOCAL_STORAGE_VALUE_LIMIT) {
            status = -EDGE_LINUX_E2BIG;
            goto fail_btf;
        }
        if (request->max_entries ||
            (request->key_size != sizeof(uint64_t) &&
             request->key_size != 2u * sizeof(uint64_t)) ||
            !request->value_size ||
            (validation_flags & ~KERNEL_BPF_MAP_NUMA_NODE) ||
            request->map_extra)
            goto invalid_btf;
        storage_entries = BPF_CGRP_STORAGE_ENTRIES;
        stride = request->type ==
                KERNEL_BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE ?
            bpf_align8(1u + request->key_size) +
                value_stride * possible_cpu_count :
            bpf_align8(1u + request->key_size + request->value_size);
    } else if (bpf_map_type_is_local_storage(request->type)) {
        if (request->value_size > BPF_LOCAL_STORAGE_VALUE_LIMIT) {
            status = -EDGE_LINUX_E2BIG;
            goto fail_btf;
        }
        if (request->max_entries ||
            request->key_size != sizeof(int32_t) ||
            !request->value_size ||
            !(validation_flags & KERNEL_BPF_MAP_NO_PREALLOC) ||
            (validation_flags & ~(KERNEL_BPF_MAP_NO_PREALLOC |
                                  KERNEL_BPF_MAP_CLONE)) ||
            !request->btf_present || !request->btf_key_type_id ||
            !request->btf_value_type_id || request->map_extra)
            goto invalid_btf;
        storage_entries = BPF_CGRP_STORAGE_ENTRIES;
        stride = bpf_align8(
            1u + ((request->type == KERNEL_BPF_MAP_TYPE_INODE_STORAGE ||
                   request->type == KERNEL_BPF_MAP_TYPE_TASK_STORAGE) ?
                  sizeof(bpf_local_storage_owner_t) : sizeof(uint64_t)) +
            request->value_size);
    } else if (request->type == KERNEL_BPF_MAP_TYPE_INSN_ARRAY) {
        if (request->key_size != sizeof(uint32_t) ||
            request->value_size != 4u * sizeof(uint32_t) ||
            request->flags || request->map_extra)
            goto invalid_btf;
        stride = bpf_align8(request->value_size);
        stored_flags |= KERNEL_BPF_MAP_RDONLY_PROGRAM;
    } else if (request->type == KERNEL_BPF_MAP_TYPE_HASH ||
               request->type == KERNEL_BPF_MAP_TYPE_PERCPU_HASH) {
        if (validation_flags & ~KERNEL_BPF_MAP_NO_PREALLOC)
            goto invalid_btf;
        stride = request->type == KERNEL_BPF_MAP_TYPE_PERCPU_HASH ?
            bpf_align8(1u + request->key_size) +
                value_stride * possible_cpu_count :
            bpf_align8(1u + request->key_size + request->value_size);
    } else if (request->type == KERNEL_BPF_MAP_TYPE_RHASH) {
        if (request->max_entries > (1u << 31u)) {
            status = -EDGE_LINUX_E2BIG;
            goto fail_btf;
        }
        if (!(validation_flags & KERNEL_BPF_MAP_NO_PREALLOC) ||
            (validation_flags & KERNEL_BPF_MAP_ZERO_SEED) ||
            (validation_flags & ~(KERNEL_BPF_MAP_NO_PREALLOC |
                                  KERNEL_BPF_MAP_NUMA_NODE)))
            goto invalid_btf;
        if (request->map_extra >> 32u)
            goto invalid_btf;
        if ((uint32_t)request->map_extra > UINT16_MAX) {
            status = -EDGE_LINUX_E2BIG;
            goto fail_btf;
        }
        if ((uint32_t)request->map_extra > request->max_entries)
            goto invalid_btf;
        storage_entries = (uint32_t)request->map_extra;
        if (!storage_entries)
            storage_entries = request->max_entries < 4u ?
                request->max_entries : 4u;
        stride = bpf_align8(
            1u + request->key_size + request->value_size);
    } else if (request->type == KERNEL_BPF_MAP_TYPE_LRU_HASH ||
               request->type == KERNEL_BPF_MAP_TYPE_LRU_PERCPU_HASH) {
        if (validation_flags & KERNEL_BPF_MAP_NO_PREALLOC)
            goto unsupported_btf;
        if (validation_flags & ~KERNEL_BPF_MAP_NO_COMMON_LRU)
            goto invalid_btf;
        if (validation_flags & KERNEL_BPF_MAP_NO_COMMON_LRU) {
            uint64_t rounded =
                ((uint64_t)actual_max_entries + possible_cpu_count - 1u) /
                possible_cpu_count * possible_cpu_count;

            if (rounded > UINT32_MAX)
                rounded = actual_max_entries -
                    actual_max_entries % possible_cpu_count;
            if (!rounded) {
                status = -EDGE_LINUX_E2BIG;
                goto fail_btf;
            }
            actual_max_entries = (uint32_t)rounded;
        }
        stride = request->type == KERNEL_BPF_MAP_TYPE_LRU_PERCPU_HASH ?
            bpf_align8(1u + request->key_size) +
                value_stride * possible_cpu_count + sizeof(uint64_t) :
            bpf_align8(1u + request->key_size + request->value_size) +
                sizeof(uint64_t);
    } else if (request->type == KERNEL_BPF_MAP_TYPE_ARRAY_OF_MAPS) {
        if (request->key_size != sizeof(uint32_t) || validation_flags)
            goto invalid_btf;
        stride = sizeof(int32_t);
    } else if (request->type == KERNEL_BPF_MAP_TYPE_HASH_OF_MAPS) {
        if (validation_flags & ~KERNEL_BPF_MAP_NO_PREALLOC)
            goto invalid_btf;
        stride = bpf_align8(
            1u + request->key_size + sizeof(int32_t));
    } else if (bpf_map_type_is_queue_stack(request->type)) {
        if (validation_flags) goto invalid_btf;
        stride = bpf_align8(request->value_size);
    } else if (request->type == KERNEL_BPF_MAP_TYPE_LPM_TRIE) {
        if (request->key_size < sizeof(uint32_t) + 1u ||
            request->key_size > sizeof(uint32_t) + 256u ||
            validation_flags != KERNEL_BPF_MAP_NO_PREALLOC ||
            request->map_extra)
            goto invalid_btf;
        stride = bpf_align8(
            1u + request->key_size + request->value_size);
    } else if (bpf_map_type_is_ringbuf(request->type)) {
        if (request->value_size || request->btf_present ||
            request->map_extra ||
            (request->max_entries & (BPF_PAGE_SIZE - 1u)) ||
            (request->max_entries & (request->max_entries - 1u)) ||
            (validation_flags & ~(KERNEL_BPF_MAP_NUMA_NODE |
                                  KERNEL_BPF_MAP_RB_OVERWRITE)) ||
            (request->type == KERNEL_BPF_MAP_TYPE_USER_RINGBUF &&
             (validation_flags & KERNEL_BPF_MAP_RB_OVERWRITE)))
            goto invalid_btf;
        stride = 1u;
    } else if (request->type == KERNEL_BPF_MAP_TYPE_ARENA) {
        uint64_t virtual_size =
            (uint64_t)request->max_entries * BPF_PAGE_SIZE;

        if (request->key_size || request->value_size ||
            request->btf_present ||
            !(validation_flags & KERNEL_BPF_MAP_MMAPABLE) ||
            (validation_flags &
             ~(KERNEL_BPF_MAP_MMAPABLE |
               KERNEL_BPF_MAP_SEGV_ON_FAULT |
               KERNEL_BPF_MAP_NO_USER_CONV)) ||
            (request->map_extra & (BPF_PAGE_SIZE - 1u)))
            goto invalid_btf;
        if (virtual_size > UINT32_MAX + 1ull) {
            status = -EDGE_LINUX_E2BIG;
            goto fail_btf;
        }
        if (request->map_extra &&
            (request->map_extra >> 32u) !=
            ((request->map_extra + virtual_size - 1u) >> 32u)) {
            status = -EDGE_LINUX_ERANGE;
            goto fail_btf;
        }
        stride = BPF_PAGE_SIZE;
    } else if (request->type == KERNEL_BPF_MAP_TYPE_BLOOM_FILTER) {
        uint64_t estimated_bits;
        uint64_t rounded_bits = 64u;

        if (request->key_size ||
            (validation_flags & ~KERNEL_BPF_MAP_ZERO_SEED) ||
            (request->map_extra & ~0xfull))
            goto invalid_btf;
        bloom_hash_count = (uint32_t)(request->map_extra & 0xfull);
        if (!bloom_hash_count) bloom_hash_count = 5u;
        estimated_bits =
            (uint64_t)request->max_entries * bloom_hash_count;
        estimated_bits = estimated_bits / 5u * 7u;
        while (rounded_bits < estimated_bits &&
               rounded_bits < (1ull << 31u))
            rounded_bits <<= 1u;
        if (rounded_bits > UINT32_MAX) goto invalid_btf;
        bloom_bit_count = (uint32_t)rounded_bits;
        stride = (bloom_bit_count + 7u) / 8u;
    } else {
        goto invalid_btf;
    }
    if (request->type == KERNEL_BPF_MAP_TYPE_SOCKMAP ||
        request->type == KERNEL_BPF_MAP_TYPE_SOCKHASH ||
        request->type == KERNEL_BPF_MAP_TYPE_REUSEPORT_SOCKARRAY ||
        request->type == KERNEL_BPF_MAP_TYPE_SK_STORAGE) {
        status = kernel_file_description_close_observer_register(
            bpf_socket_description_closed);
        if (status < 0) goto fail_btf;
    }
    bytes = request->type == KERNEL_BPF_MAP_TYPE_BLOOM_FILTER ?
        stride : bpf_map_type_is_ringbuf(request->type) ?
        (uint64_t)actual_max_entries + 2u * BPF_PAGE_SIZE :
        (uint64_t)stride * storage_entries;
    status = bpf_allocation_size(bytes, &pages);
    if (status < 0) goto fail_btf;
    storage = (uint8_t *)arch_vm_alloc_pages(pages);
    if (!storage) {
        status = -EDGE_LINUX_ENOMEM;
        goto fail_btf;
    }
    memset(storage, 0, (uint64_t)pages * BPF_PAGE_SIZE);
    if (bpf_map_type_has_descriptor_slots(request->type)) {
        for (uint32_t index = 0; index < actual_max_entries; ++index) {
            int32_t empty = -1;
            memcpy(storage + (uint64_t)index * stride,
                   &empty, sizeof(empty));
        }
    }

    bpf_lock();
    object_id = bpf_allocate_object_locked(KERNEL_BPF_OBJECT_MAP, &object);
    if (object_id >= 0) {
        object->value.map.type = request->type;
        object->value.map.key_size = request->key_size;
        object->value.map.value_size = request->value_size;
        object->value.map.max_entries = actual_max_entries;
        object->value.map.storage_entries = storage_entries;
        object->value.map.flags = stored_flags;
        object->value.map.entry_stride = stride;
        object->value.map.value_stride = value_stride;
        object->value.map.possible_cpu_count = possible_cpu_count;
        object->value.map.inner_type = inner_info.type;
        object->value.map.inner_key_size = inner_info.key_size;
        object->value.map.inner_value_size = inner_info.value_size;
        object->value.map.inner_flags = inner_info.flags;
        object->value.map.btf_object_id = request->btf_present ?
            request->btf_object_id : -1;
        object->value.map.btf_key_type_id = request->btf_key_type_id;
        object->value.map.btf_value_type_id = request->btf_value_type_id;
        object->value.map.map_extra = request->map_extra;
        object->value.map.bloom_bit_mask = bloom_bit_count ?
            bloom_bit_count - 1u : 0u;
        object->value.map.bloom_hash_count = bloom_hash_count;
        object->value.map.bloom_seed =
            validation_flags & KERNEL_BPF_MAP_ZERO_SEED ?
                0u : object->user_id * 0x9e3779b9u;
        object->value.map.storage_pages = pages;
        object->value.map.storage = storage;
        memcpy(object->value.map.name, request->name,
               KERNEL_BPF_OBJECT_NAME_LENGTH);
    }
    bpf_unlock();
    if (object_id < 0) {
        bpf_free_pages(storage, pages);
        if (btf_retained) kernel_bpf_object_release(request->btf_object_id);
    }
    return object_id;

unsupported_btf:
    status = -EDGE_LINUX_ENOTSUPP;
    goto fail_btf;
invalid_btf:
    status = -EDGE_LINUX_EINVAL;
fail_btf:
    if (btf_retained) kernel_bpf_object_release(request->btf_object_id);
    return status;
}

static int bpf_btf_string_valid(const uint8_t *strings,
                                uint32_t string_length,
                                uint32_t offset) {
    if (!strings || offset >= string_length) return 0;
    while (offset < string_length) {
        if (!strings[offset]) return 1;
        ++offset;
    }
    return 0;
}

static int bpf_btf_kind_layout(uint32_t kind, uint32_t value_count,
                               uint32_t kind_flag,
                               uint64_t *extra_size) {
    uint64_t element_size = 0u;

    if (!extra_size || !kind || kind > KERNEL_BTF_KIND_MAX)
        return -EDGE_LINUX_EINVAL;
    switch (kind) {
    case KERNEL_BTF_KIND_INT:
        if (value_count || kind_flag) return -EDGE_LINUX_EINVAL;
        *extra_size = sizeof(uint32_t);
        return 0;
    case KERNEL_BTF_KIND_PTR:
    case KERNEL_BTF_KIND_TYPEDEF:
    case KERNEL_BTF_KIND_VOLATILE:
    case KERNEL_BTF_KIND_CONST:
    case KERNEL_BTF_KIND_RESTRICT:
    case KERNEL_BTF_KIND_TYPE_TAG:
        if (value_count || kind_flag) return -EDGE_LINUX_EINVAL;
        *extra_size = 0u;
        return 0;
    case KERNEL_BTF_KIND_ARRAY:
        if (value_count || kind_flag) return -EDGE_LINUX_EINVAL;
        *extra_size = 3u * sizeof(uint32_t);
        return 0;
    case KERNEL_BTF_KIND_STRUCT:
    case KERNEL_BTF_KIND_UNION:
        element_size = 3u * sizeof(uint32_t);
        break;
    case KERNEL_BTF_KIND_ENUM:
        element_size = 2u * sizeof(uint32_t);
        break;
    case KERNEL_BTF_KIND_FWD:
        if (value_count) return -EDGE_LINUX_EINVAL;
        *extra_size = 0u;
        return 0;
    case KERNEL_BTF_KIND_FUNC:
        if (kind_flag || value_count > 2u)
            return -EDGE_LINUX_EINVAL;
        *extra_size = 0u;
        return 0;
    case KERNEL_BTF_KIND_FUNC_PROTO:
        if (kind_flag) return -EDGE_LINUX_EINVAL;
        element_size = 2u * sizeof(uint32_t);
        break;
    case KERNEL_BTF_KIND_VAR:
        if (kind_flag || value_count)
            return -EDGE_LINUX_EINVAL;
        *extra_size = sizeof(uint32_t);
        return 0;
    case KERNEL_BTF_KIND_DATASEC:
        if (kind_flag) return -EDGE_LINUX_EINVAL;
        element_size = 3u * sizeof(uint32_t);
        break;
    case KERNEL_BTF_KIND_FLOAT:
        if (kind_flag || value_count)
            return -EDGE_LINUX_EINVAL;
        *extra_size = 0u;
        return 0;
    case KERNEL_BTF_KIND_DECL_TAG:
        if (kind_flag || value_count)
            return -EDGE_LINUX_EINVAL;
        *extra_size = sizeof(uint32_t);
        return 0;
    case KERNEL_BTF_KIND_ENUM64:
        if (kind_flag > 1u) return -EDGE_LINUX_EINVAL;
        element_size = 3u * sizeof(uint32_t);
        break;
    default:
        return -EDGE_LINUX_EINVAL;
    }
    if ((uint64_t)value_count > UINT64_MAX / element_size)
        return -EDGE_LINUX_EINVAL;
    *extra_size = (uint64_t)value_count * element_size;
    return 0;
}

static int bpf_btf_type_at(const uint8_t *types, uint32_t type_length,
                           uint32_t requested_id,
                           kernel_btf_type_t *type_out,
                           const uint8_t **extra_out) {
    uint64_t cursor = 0u;
    uint32_t type_id = 1u;

    if (!types || !requested_id || !type_out) return -EDGE_LINUX_EINVAL;
    while (cursor < type_length) {
        kernel_btf_type_t type;
        uint64_t extra_size;
        uint32_t kind;

        if ((uint64_t)type_length - cursor < sizeof(type))
            return -EDGE_LINUX_EINVAL;
        memcpy(&type, types + cursor, sizeof(type));
        kind = KERNEL_BTF_INFO_KIND(type.info);
        if (bpf_btf_kind_layout(
                kind, KERNEL_BTF_INFO_VLEN(type.info),
                KERNEL_BTF_INFO_KIND_FLAG(type.info),
                &extra_size) < 0 ||
            extra_size > (uint64_t)type_length - cursor - sizeof(type))
            return -EDGE_LINUX_EINVAL;
        if (type_id == requested_id) {
            *type_out = type;
            if (extra_out) *extra_out = types + cursor + sizeof(type);
            return 0;
        }
        cursor += sizeof(type) + extra_size;
        ++type_id;
    }
    return -EDGE_LINUX_EINVAL;
}

static int bpf_btf_reference_valid(uint32_t type_id,
                                   uint32_t type_count,
                                   int allow_void) {
    if (!type_id) return allow_void;
    return type_id <= type_count;
}

static int bpf_btf_validate(const uint8_t *data, uint32_t size) {
    kernel_btf_header_t header;
    const uint8_t *types;
    const uint8_t *strings;
    uint64_t payload_size;
    uint64_t type_end;
    uint64_t string_end;
    uint64_t cursor;
    uint32_t type_count = 0u;

    if (!data || size < sizeof(header)) return -EDGE_LINUX_EINVAL;
    memcpy(&header, data, sizeof(header));
    if (header.magic != KERNEL_BTF_MAGIC ||
        header.version != KERNEL_BTF_VERSION || header.flags ||
        header.header_length < sizeof(header) ||
        header.header_length > size ||
        (header.type_offset & 3u) || (header.type_length & 3u))
        return -EDGE_LINUX_EINVAL;
    payload_size = size - header.header_length;
    type_end = (uint64_t)header.type_offset + header.type_length;
    string_end = (uint64_t)header.string_offset + header.string_length;
    if (type_end > payload_size || string_end > payload_size ||
        header.string_offset < type_end || !header.string_length)
        return -EDGE_LINUX_EINVAL;
    types = data + header.header_length + header.type_offset;
    strings = data + header.header_length + header.string_offset;
    if (strings[0] || strings[header.string_length - 1u])
        return -EDGE_LINUX_EINVAL;

    for (cursor = 0u; cursor < header.type_length;) {
        kernel_btf_type_t type;
        const uint8_t *extra;
        uint64_t extra_size;
        uint32_t kind;
        uint32_t value_count;
        uint32_t name_index;

        if ((uint64_t)header.type_length - cursor < sizeof(type))
            return -EDGE_LINUX_EINVAL;
        memcpy(&type, types + cursor, sizeof(type));
        kind = KERNEL_BTF_INFO_KIND(type.info);
        value_count = KERNEL_BTF_INFO_VLEN(type.info);
        if (bpf_btf_kind_layout(
                kind, value_count,
                KERNEL_BTF_INFO_KIND_FLAG(type.info),
                &extra_size) < 0 ||
            extra_size > (uint64_t)header.type_length - cursor -
                             sizeof(type) ||
            !bpf_btf_string_valid(strings, header.string_length,
                                  type.name_offset))
            return -EDGE_LINUX_EINVAL;
        extra = types + cursor + sizeof(type);
        if (kind == KERNEL_BTF_KIND_PTR ||
            kind == KERNEL_BTF_KIND_ARRAY ||
            kind == KERNEL_BTF_KIND_VOLATILE ||
            kind == KERNEL_BTF_KIND_CONST ||
            kind == KERNEL_BTF_KIND_RESTRICT ||
            kind == KERNEL_BTF_KIND_FUNC_PROTO ||
            kind == KERNEL_BTF_KIND_TYPE_TAG) {
            if (type.name_offset) return -EDGE_LINUX_EINVAL;
        }
        if ((kind == KERNEL_BTF_KIND_STRUCT ||
             kind == KERNEL_BTF_KIND_UNION) && !type.size_or_type &&
            value_count)
            return -EDGE_LINUX_EINVAL;
        if (kind == KERNEL_BTF_KIND_INT) {
            uint32_t integer;
            uint32_t bits;
            uint32_t bit_offset;

            memcpy(&integer, extra, sizeof(integer));
            bits = integer & 0xffu;
            bit_offset = (integer >> 16u) & 0xffu;
            if (!type.size_or_type || type.size_or_type > 16u ||
                !bits || bits > 128u ||
                bit_offset + bits > type.size_or_type * 8u ||
                ((integer >> 24u) & ~7u))
                return -EDGE_LINUX_EINVAL;
        } else if (kind == KERNEL_BTF_KIND_FLOAT) {
            if (type.size_or_type != 2u && type.size_or_type != 4u &&
                type.size_or_type != 8u && type.size_or_type != 12u &&
                type.size_or_type != 16u)
                return -EDGE_LINUX_EINVAL;
        } else if (kind == KERNEL_BTF_KIND_ENUM ||
                   kind == KERNEL_BTF_KIND_ENUM64) {
            if (type.size_or_type != 1u && type.size_or_type != 2u &&
                type.size_or_type != 4u && type.size_or_type != 8u)
                return -EDGE_LINUX_EINVAL;
        } else if (kind == KERNEL_BTF_KIND_FWD &&
                   type.size_or_type) {
            return -EDGE_LINUX_EINVAL;
        } else if (kind == KERNEL_BTF_KIND_VAR) {
            uint32_t linkage;
            memcpy(&linkage, extra, sizeof(linkage));
            if (linkage > 2u) return -EDGE_LINUX_EINVAL;
        }
        if (kind == KERNEL_BTF_KIND_STRUCT ||
            kind == KERNEL_BTF_KIND_UNION ||
            kind == KERNEL_BTF_KIND_ENUM ||
            kind == KERNEL_BTF_KIND_ENUM64 ||
            kind == KERNEL_BTF_KIND_FUNC_PROTO) {
            uint32_t stride =
                (kind == KERNEL_BTF_KIND_ENUM) ? 8u :
                (kind == KERNEL_BTF_KIND_ENUM64) ? 12u :
                (kind == KERNEL_BTF_KIND_FUNC_PROTO) ? 8u : 12u;
            for (name_index = 0u; name_index < value_count;
                 ++name_index) {
                uint32_t name_offset;
                memcpy(&name_offset, extra +
                       (uint64_t)name_index * stride,
                       sizeof(name_offset));
                if (!bpf_btf_string_valid(
                        strings, header.string_length, name_offset))
                    return -EDGE_LINUX_EINVAL;
            }
        }
        cursor += sizeof(type) + extra_size;
        if (++type_count == UINT32_MAX)
            return -EDGE_LINUX_E2BIG;
    }
    if (cursor != header.type_length) return -EDGE_LINUX_EINVAL;

    for (cursor = 0u; cursor < header.type_length;) {
        kernel_btf_type_t type;
        const uint8_t *extra;
        uint64_t extra_size;
        uint32_t kind;
        uint32_t value_count;

        memcpy(&type, types + cursor, sizeof(type));
        kind = KERNEL_BTF_INFO_KIND(type.info);
        value_count = KERNEL_BTF_INFO_VLEN(type.info);
        if (bpf_btf_kind_layout(
                kind, value_count,
                KERNEL_BTF_INFO_KIND_FLAG(type.info),
                &extra_size) < 0)
            return -EDGE_LINUX_EINVAL;
        extra = types + cursor + sizeof(type);
        if (kind == KERNEL_BTF_KIND_PTR) {
            if (!bpf_btf_reference_valid(
                    type.size_or_type, type_count, 1))
                return -EDGE_LINUX_EINVAL;
        } else if (kind == KERNEL_BTF_KIND_ARRAY) {
            uint32_t element_type;
            uint32_t index_type;
            kernel_btf_type_t index;

            memcpy(&element_type, extra, sizeof(element_type));
            memcpy(&index_type, extra + sizeof(uint32_t),
                   sizeof(index_type));
            if (!bpf_btf_reference_valid(element_type, type_count, 0) ||
                !bpf_btf_reference_valid(index_type, type_count, 0) ||
                bpf_btf_type_at(types, header.type_length,
                                index_type, &index, 0) < 0 ||
                KERNEL_BTF_INFO_KIND(index.info) != KERNEL_BTF_KIND_INT)
                return -EDGE_LINUX_EINVAL;
        } else if (kind == KERNEL_BTF_KIND_STRUCT ||
                   kind == KERNEL_BTF_KIND_UNION) {
            for (uint32_t index = 0u; index < value_count; ++index) {
                uint32_t member_type;
                memcpy(&member_type, extra +
                       (uint64_t)index * 12u + sizeof(uint32_t),
                       sizeof(member_type));
                if (!bpf_btf_reference_valid(
                        member_type, type_count, 0))
                    return -EDGE_LINUX_EINVAL;
            }
        } else if (kind == KERNEL_BTF_KIND_TYPEDEF ||
                   kind == KERNEL_BTF_KIND_VOLATILE ||
                   kind == KERNEL_BTF_KIND_CONST ||
                   kind == KERNEL_BTF_KIND_RESTRICT ||
                   kind == KERNEL_BTF_KIND_FUNC ||
                   kind == KERNEL_BTF_KIND_VAR ||
                   kind == KERNEL_BTF_KIND_DECL_TAG ||
                   kind == KERNEL_BTF_KIND_TYPE_TAG) {
            kernel_btf_type_t target;
            if (!bpf_btf_reference_valid(
                    type.size_or_type, type_count, 0) ||
                (kind == KERNEL_BTF_KIND_FUNC &&
                 bpf_btf_type_at(types, header.type_length,
                                 type.size_or_type,
                                 &target, 0) < 0))
                return -EDGE_LINUX_EINVAL;
            if (kind == KERNEL_BTF_KIND_FUNC &&
                KERNEL_BTF_INFO_KIND(target.info) !=
                    KERNEL_BTF_KIND_FUNC_PROTO)
                return -EDGE_LINUX_EINVAL;
        } else if (kind == KERNEL_BTF_KIND_FUNC_PROTO) {
            if (!bpf_btf_reference_valid(
                    type.size_or_type, type_count, 1))
                return -EDGE_LINUX_EINVAL;
            for (uint32_t index = 0u; index < value_count; ++index) {
                uint32_t name_offset;
                uint32_t parameter_type;
                memcpy(&name_offset, extra + (uint64_t)index * 8u,
                       sizeof(name_offset));
                memcpy(&parameter_type,
                       extra + (uint64_t)index * 8u + 4u,
                       sizeof(parameter_type));
                if (!parameter_type) {
                    if (name_offset || index + 1u != value_count)
                        return -EDGE_LINUX_EINVAL;
                } else if (!bpf_btf_reference_valid(
                               parameter_type, type_count, 0)) {
                    return -EDGE_LINUX_EINVAL;
                }
            }
        } else if (kind == KERNEL_BTF_KIND_DATASEC) {
            for (uint32_t index = 0u; index < value_count; ++index) {
                uint32_t variable_type;
                uint32_t offset;
                uint32_t length;
                kernel_btf_type_t variable;
                memcpy(&variable_type, extra + (uint64_t)index * 12u,
                       sizeof(variable_type));
                memcpy(&offset, extra + (uint64_t)index * 12u + 4u,
                       sizeof(offset));
                memcpy(&length, extra + (uint64_t)index * 12u + 8u,
                       sizeof(length));
                if (!bpf_btf_reference_valid(
                        variable_type, type_count, 0) ||
                    bpf_btf_type_at(types, header.type_length,
                                    variable_type, &variable, 0) < 0 ||
                    KERNEL_BTF_INFO_KIND(variable.info) !=
                        KERNEL_BTF_KIND_VAR ||
                    offset > type.size_or_type ||
                    length > type.size_or_type - offset)
                    return -EDGE_LINUX_EINVAL;
            }
        }
        cursor += sizeof(type) + extra_size;
    }
    return 0;
}

static int bpf_btf_type_size_data(const uint8_t *data, uint32_t size,
                                  uint32_t type_id, uint32_t depth,
                                  uint64_t *resolved_size) {
    kernel_btf_header_t header;
    kernel_btf_type_t type;
    const uint8_t *types;
    const uint8_t *extra;
    uint32_t kind;

    if (!data || !resolved_size || !type_id || depth > 64u ||
        size < sizeof(header))
        return -EDGE_LINUX_EINVAL;
    memcpy(&header, data, sizeof(header));
    types = data + header.header_length + header.type_offset;
    if (bpf_btf_type_at(types, header.type_length, type_id,
                        &type, &extra) < 0)
        return -EDGE_LINUX_EINVAL;
    kind = KERNEL_BTF_INFO_KIND(type.info);
    if (kind == KERNEL_BTF_KIND_INT ||
        kind == KERNEL_BTF_KIND_ENUM ||
        kind == KERNEL_BTF_KIND_FLOAT ||
        kind == KERNEL_BTF_KIND_ENUM64) {
        *resolved_size = type.size_or_type;
        return 0;
    }
    if (kind == KERNEL_BTF_KIND_PTR) {
        *resolved_size = sizeof(uint64_t);
        return 0;
    }
    if (kind == KERNEL_BTF_KIND_ARRAY) {
        uint32_t element_type;
        uint32_t element_count;
        uint64_t element_size;

        memcpy(&element_type, extra, sizeof(element_type));
        memcpy(&element_count, extra + 2u * sizeof(uint32_t),
               sizeof(element_count));
        if (bpf_btf_type_size_data(
                data, size, element_type, depth + 1u,
                &element_size) < 0 ||
            (element_count && element_size > UINT64_MAX / element_count))
            return -EDGE_LINUX_EINVAL;
        *resolved_size = element_size * element_count;
        return 0;
    }
    if (kind == KERNEL_BTF_KIND_STRUCT ||
        kind == KERNEL_BTF_KIND_UNION) {
        uint32_t value_count = KERNEL_BTF_INFO_VLEN(type.info);
        uint64_t aggregate_bits = (uint64_t)type.size_or_type * 8u;

        for (uint32_t index = 0u; index < value_count; ++index) {
            uint32_t member_type;
            uint32_t member_offset;
            uint32_t bitfield_size = 0u;
            uint64_t member_size;
            uint64_t member_bits;

            memcpy(&member_type, extra + (uint64_t)index * 12u + 4u,
                   sizeof(member_type));
            memcpy(&member_offset, extra + (uint64_t)index * 12u + 8u,
                   sizeof(member_offset));
            if (KERNEL_BTF_INFO_KIND_FLAG(type.info)) {
                bitfield_size = member_offset >> 24u;
                member_offset &= 0x00ffffffu;
            }
            if (bpf_btf_type_size_data(
                    data, size, member_type, depth + 1u,
                    &member_size) < 0)
                return -EDGE_LINUX_EINVAL;
            if (bitfield_size > member_size * 8u)
                return -EDGE_LINUX_EINVAL;
            member_bits = bitfield_size ? bitfield_size : member_size * 8u;
            if (kind == KERNEL_BTF_KIND_UNION && member_offset)
                return -EDGE_LINUX_EINVAL;
            if (member_offset > aggregate_bits ||
                member_bits > aggregate_bits - member_offset)
                return -EDGE_LINUX_EINVAL;
        }
        *resolved_size = type.size_or_type;
        return 0;
    }
    if (kind == KERNEL_BTF_KIND_TYPEDEF ||
        kind == KERNEL_BTF_KIND_VOLATILE ||
        kind == KERNEL_BTF_KIND_CONST ||
        kind == KERNEL_BTF_KIND_RESTRICT ||
        kind == KERNEL_BTF_KIND_TYPE_TAG)
        return bpf_btf_type_size_data(
            data, size, type.size_or_type, depth + 1u,
            resolved_size);
    return -EDGE_LINUX_EINVAL;
}

static int bpf_btf_graph_validate(const uint8_t *data, uint32_t size) {
    kernel_btf_header_t header;
    const uint8_t *types;
    uint64_t cursor = 0u;
    uint32_t type_id = 1u;

    if (!data || size < sizeof(header)) return -EDGE_LINUX_EINVAL;
    memcpy(&header, data, sizeof(header));
    types = data + header.header_length + header.type_offset;
    while (cursor < header.type_length) {
        kernel_btf_type_t type;
        uint64_t extra_size;
        uint64_t resolved_size;
        uint32_t kind;

        memcpy(&type, types + cursor, sizeof(type));
        kind = KERNEL_BTF_INFO_KIND(type.info);
        if (bpf_btf_kind_layout(
                kind, KERNEL_BTF_INFO_VLEN(type.info),
                KERNEL_BTF_INFO_KIND_FLAG(type.info),
                &extra_size) < 0)
            return -EDGE_LINUX_EINVAL;
        if (kind == KERNEL_BTF_KIND_INT ||
            kind == KERNEL_BTF_KIND_PTR ||
            kind == KERNEL_BTF_KIND_ARRAY ||
            kind == KERNEL_BTF_KIND_STRUCT ||
            kind == KERNEL_BTF_KIND_UNION ||
            kind == KERNEL_BTF_KIND_ENUM ||
            kind == KERNEL_BTF_KIND_TYPEDEF ||
            kind == KERNEL_BTF_KIND_VOLATILE ||
            kind == KERNEL_BTF_KIND_CONST ||
            kind == KERNEL_BTF_KIND_RESTRICT ||
            kind == KERNEL_BTF_KIND_FLOAT ||
            kind == KERNEL_BTF_KIND_TYPE_TAG ||
            kind == KERNEL_BTF_KIND_ENUM64) {
            if (bpf_btf_type_size_data(
                    data, size, type_id, 0u, &resolved_size) < 0)
                return -EDGE_LINUX_EINVAL;
        }
        cursor += sizeof(type) + extra_size;
        ++type_id;
    }
    return 0;
}

static int bpf_btf_map_types_validate(int object_id,
                                      uint32_t key_type_id,
                                      uint32_t value_type_id,
                                      uint32_t key_size,
                                      uint32_t value_size) {
    kernel_bpf_object_t *object;
    uint64_t key_type_size = 0u;
    uint64_t value_type_size;
    int status;

    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_BTF) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    if (key_size) {
        status = bpf_btf_type_size_data(
            object->value.btf.data, object->value.btf.size,
            key_type_id, 0u, &key_type_size);
        if (status < 0 || key_type_size != key_size) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
    }
    status = bpf_btf_type_size_data(
        object->value.btf.data, object->value.btf.size,
        value_type_id, 0u, &value_type_size);
    if (status < 0 || value_type_size != value_size)
        status = -EDGE_LINUX_EINVAL;
    else
        status = 0;
out:
    bpf_unlock();
    return status;
}

int kernel_bpf_btf_create(const void *data, uint32_t size) {
    kernel_bpf_object_t *object;
    uint8_t *storage;
    uint32_t pages;
    int object_id;
    int status;

    status = bpf_btf_validate((const uint8_t *)data, size);
    if (status < 0) return status;
    status = bpf_btf_graph_validate((const uint8_t *)data, size);
    if (status < 0) return status;
    status = bpf_allocation_size(size, &pages);
    if (status < 0) return status;
    storage = (uint8_t *)arch_vm_alloc_pages(pages);
    if (!storage) return -EDGE_LINUX_ENOMEM;
    memset(storage, 0, (uint64_t)pages * BPF_PAGE_SIZE);
    memcpy(storage, data, size);
    bpf_lock();
    object_id = bpf_allocate_object_locked(KERNEL_BPF_OBJECT_BTF, &object);
    if (object_id >= 0) {
        object->value.btf.size = size;
        object->value.btf.storage_pages = pages;
        object->value.btf.data = storage;
    }
    bpf_unlock();
    if (object_id < 0) bpf_free_pages(storage, pages);
    return object_id;
}

static uint32_t bpf_program_destination(
    const kernel_bpf_instruction_t *instruction) {
    return instruction->registers & 0x0fu;
}

static uint32_t bpf_program_source(
    const kernel_bpf_instruction_t *instruction) {
    return instruction->registers >> 4;
}

static uint32_t bpf_sha256_rotate_right(uint32_t value, uint32_t count) {
    return (value >> count) | (value << (32u - count));
}

static uint32_t bpf_sha256_load_be32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static void bpf_sha256_transform(uint32_t state[8],
                                 const uint8_t block[64]) {
    static const uint32_t constants[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
    };
    uint32_t words[64];
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (uint32_t index = 0; index < 16u; ++index)
        words[index] = bpf_sha256_load_be32(block + index * 4u);
    for (uint32_t index = 16u; index < 64u; ++index) {
        uint32_t s0 = bpf_sha256_rotate_right(words[index - 15u], 7u) ^
                      bpf_sha256_rotate_right(words[index - 15u], 18u) ^
                      (words[index - 15u] >> 3);
        uint32_t s1 = bpf_sha256_rotate_right(words[index - 2u], 17u) ^
                      bpf_sha256_rotate_right(words[index - 2u], 19u) ^
                      (words[index - 2u] >> 10);
        words[index] = words[index - 16u] + s0 + words[index - 7u] + s1;
    }
    for (uint32_t index = 0; index < 64u; ++index) {
        uint32_t s1 = bpf_sha256_rotate_right(e, 6u) ^
                      bpf_sha256_rotate_right(e, 11u) ^
                      bpf_sha256_rotate_right(e, 25u);
        uint32_t choice = (e & f) ^ (~e & g);
        uint32_t temporary1 = h + s1 + choice + constants[index] +
                              words[index];
        uint32_t s0 = bpf_sha256_rotate_right(a, 2u) ^
                      bpf_sha256_rotate_right(a, 13u) ^
                      bpf_sha256_rotate_right(a, 22u);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temporary2 = s0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + temporary1;
        d = c;
        c = b;
        b = a;
        a = temporary1 + temporary2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

static void bpf_program_tag_copy(
        const kernel_bpf_instruction_t *instructions, uint32_t count,
        uint64_t offset, uint8_t *destination, uint32_t length) {
    const uint8_t *source = (const uint8_t *)instructions;

    memcpy(destination, source + offset, length);
    for (uint32_t index = 0; index + 1u < count; ++index) {
        uint64_t immediate =
            (uint64_t)index * sizeof(*instructions) + 4u;
        uint64_t high_immediate = immediate + sizeof(*instructions);

        if (instructions[index].code != (BPF_LD | BPF_DW | BPF_IMM) ||
            bpf_program_source(&instructions[index]) !=
                BPF_PSEUDO_MAP_FD)
            continue;
        for (uint32_t byte = 0; byte < sizeof(int32_t); ++byte) {
            uint64_t position = immediate + byte;
            if (position >= offset && position < offset + length)
                destination[position - offset] = 0;
            position = high_immediate + byte;
            if (position >= offset && position < offset + length)
                destination[position - offset] = 0;
        }
        ++index;
    }
}

static void bpf_program_tag(const kernel_bpf_instruction_t *instructions,
                            uint32_t count, uint8_t tag[8]) {
    uint32_t state[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
    };
    uint64_t length = (uint64_t)count * sizeof(*instructions);
    uint64_t offset = 0;
    uint8_t block[64];
    uint8_t final_blocks[128];
    uint32_t final_size;

    while (length - offset >= 64u) {
        bpf_program_tag_copy(
            instructions, count, offset, block, sizeof(block));
        bpf_sha256_transform(state, block);
        offset += 64u;
    }
    final_size = (uint32_t)(length - offset);
    memset(final_blocks, 0, sizeof(final_blocks));
    if (final_size)
        bpf_program_tag_copy(
            instructions, count, offset, final_blocks, final_size);
    final_blocks[final_size] = 0x80u;
    final_size = final_size < 56u ? 64u : 128u;
    for (uint32_t index = 0; index < 8u; ++index)
        final_blocks[final_size - 1u - index] =
            (uint8_t)((length * 8u) >> (index * 8u));
    bpf_sha256_transform(state, final_blocks);
    if (final_size == 128u)
        bpf_sha256_transform(state, final_blocks + 64u);
    for (uint32_t index = 0; index < 8u; ++index)
        tag[index] = (uint8_t)(state[index / 4u] >>
                               (24u - (index % 4u) * 8u));
}

static int bpf_program_validate(
    const kernel_bpf_program_create_request_t *request,
    const kernel_bpf_instruction_t *instructions) {
    uint16_t initialized = (1u << 1) | (1u << 10);
    uint16_t map_registers = 0u;
    uint16_t program_array_registers = 0u;
    uint16_t ringbuf_registers = 0u;
    uint16_t stack_trace_registers = 0u;
    uint16_t cgroup_storage_registers = 0u;
    uint16_t storage_value_registers = 0u;
    uint16_t context_registers = 1u << 1;
    uint16_t stack_registers = 1u << 10;
    int32_t legacy_shared_map = -1;
    int32_t legacy_percpu_map = -1;
    uint32_t pc;

    if (!request || !instructions ||
        (request->type != KERNEL_BPF_PROG_TYPE_SOCKET_FILTER &&
         request->type != KERNEL_BPF_PROG_TYPE_CGROUP_DEVICE &&
         request->type != KERNEL_BPF_PROG_TYPE_RAW_TRACEPOINT) ||
        !request->instruction_count ||
        request->instruction_count > KERNEL_BPF_MAX_INSTRUCTIONS ||
        request->flags ||
        (request->type == KERNEL_BPF_PROG_TYPE_CGROUP_DEVICE &&
         request->expected_attach_type &&
         request->expected_attach_type != KERNEL_BPF_CGROUP_DEVICE) ||
        (request->type == KERNEL_BPF_PROG_TYPE_RAW_TRACEPOINT &&
         request->expected_attach_type) ||
        (request->type == KERNEL_BPF_PROG_TYPE_SOCKET_FILTER &&
         request->expected_attach_type) ||
        !bpf_name_valid(request->name))
        return -EDGE_LINUX_EINVAL;

    for (pc = 0; pc < request->instruction_count; ++pc) {
        const kernel_bpf_instruction_t *instruction = &instructions[pc];
        uint32_t destination = bpf_program_destination(instruction);
        uint32_t source = bpf_program_source(instruction);
        uint32_t class = BPF_CLASS(instruction->code);
        uint32_t operation = BPF_OP(instruction->code);

        if (destination >= 11u || source >= 11u ||
            (destination == 10u && class != BPF_STX))
            return -EDGE_LINUX_EINVAL;
        if (class == BPF_LD && instruction->code ==
                (BPF_LD | BPF_DW | BPF_IMM)) {
            kernel_bpf_object_kind_t kind;
            kernel_bpf_map_info_t info;

            if (source != BPF_PSEUDO_MAP_FD ||
                !request->map_references_resolved ||
                pc + 1u >= request->instruction_count ||
                instructions[pc + 1u].code ||
                instructions[pc + 1u].registers ||
                instructions[pc + 1u].offset ||
                instructions[pc + 1u].immediate ||
                kernel_bpf_object_kind(
                    instruction->immediate, &kind) < 0 ||
                kind != KERNEL_BPF_OBJECT_MAP ||
                kernel_bpf_map_info(
                    instruction->immediate, &info) < 0 ||
                (info.type != KERNEL_BPF_MAP_TYPE_PROG_ARRAY &&
                 info.type != KERNEL_BPF_MAP_TYPE_RINGBUF &&
                 !(request->type ==
                       KERNEL_BPF_PROG_TYPE_RAW_TRACEPOINT &&
                   info.type == KERNEL_BPF_MAP_TYPE_STACK_TRACE) &&
                 !bpf_map_type_is_legacy_cgroup_storage(info.type)))
                return -EDGE_LINUX_EINVAL;
            if (info.type == KERNEL_BPF_MAP_TYPE_CGROUP_STORAGE) {
                if (legacy_shared_map >= 0 &&
                    legacy_shared_map != instruction->immediate)
                    return -EDGE_LINUX_EBUSY;
                legacy_shared_map = instruction->immediate;
            } else if (info.type ==
                       KERNEL_BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE) {
                if (legacy_percpu_map >= 0 &&
                    legacy_percpu_map != instruction->immediate)
                    return -EDGE_LINUX_EBUSY;
                legacy_percpu_map = instruction->immediate;
            }
            initialized |= (uint16_t)(1u << destination);
            map_registers |= (uint16_t)(1u << destination);
            stack_trace_registers &=
                (uint16_t)~(1u << destination);
            if (info.type == KERNEL_BPF_MAP_TYPE_PROG_ARRAY) {
                program_array_registers |=
                    (uint16_t)(1u << destination);
                ringbuf_registers &=
                    (uint16_t)~(1u << destination);
                cgroup_storage_registers &=
                    (uint16_t)~(1u << destination);
            } else if (info.type == KERNEL_BPF_MAP_TYPE_RINGBUF) {
                ringbuf_registers |= (uint16_t)(1u << destination);
                program_array_registers &=
                    (uint16_t)~(1u << destination);
                cgroup_storage_registers &=
                    (uint16_t)~(1u << destination);
            } else if (info.type == KERNEL_BPF_MAP_TYPE_STACK_TRACE) {
                stack_trace_registers |=
                    (uint16_t)(1u << destination);
                program_array_registers &=
                    (uint16_t)~(1u << destination);
                ringbuf_registers &=
                    (uint16_t)~(1u << destination);
                cgroup_storage_registers &=
                    (uint16_t)~(1u << destination);
            } else {
                cgroup_storage_registers |=
                    (uint16_t)(1u << destination);
                program_array_registers &=
                    (uint16_t)~(1u << destination);
                ringbuf_registers &=
                    (uint16_t)~(1u << destination);
            }
            storage_value_registers &=
                (uint16_t)~(1u << destination);
            context_registers &= (uint16_t)~(1u << destination);
            stack_registers &= (uint16_t)~(1u << destination);
            ++pc;
            continue;
        }
        if (class == BPF_ALU64) {
            if (operation == BPF_MOV) {
                if (BPF_SRC(instruction->code) == BPF_X &&
                    !(initialized & (1u << source)))
                    return -EDGE_LINUX_EINVAL;
                if (BPF_SRC(instruction->code) == BPF_X &&
                    (map_registers & (1u << source)))
                    map_registers |= (uint16_t)(1u << destination);
                else
                    map_registers &= (uint16_t)~(1u << destination);
                if (BPF_SRC(instruction->code) == BPF_X &&
                    (program_array_registers & (1u << source)))
                    program_array_registers |=
                        (uint16_t)(1u << destination);
                else
                    program_array_registers &=
                        (uint16_t)~(1u << destination);
                if (BPF_SRC(instruction->code) == BPF_X &&
                    (ringbuf_registers & (1u << source)))
                    ringbuf_registers |=
                        (uint16_t)(1u << destination);
                else
                    ringbuf_registers &=
                        (uint16_t)~(1u << destination);
                if (BPF_SRC(instruction->code) == BPF_X &&
                    (stack_trace_registers & (1u << source)))
                    stack_trace_registers |=
                        (uint16_t)(1u << destination);
                else
                    stack_trace_registers &=
                        (uint16_t)~(1u << destination);
                if (BPF_SRC(instruction->code) == BPF_X &&
                    (cgroup_storage_registers & (1u << source)))
                    cgroup_storage_registers |=
                        (uint16_t)(1u << destination);
                else
                    cgroup_storage_registers &=
                        (uint16_t)~(1u << destination);
                if (BPF_SRC(instruction->code) == BPF_X &&
                    (storage_value_registers & (1u << source)))
                    storage_value_registers |=
                        (uint16_t)(1u << destination);
                else
                    storage_value_registers &=
                        (uint16_t)~(1u << destination);
                if (BPF_SRC(instruction->code) == BPF_X &&
                    (context_registers & (1u << source)))
                    context_registers |=
                        (uint16_t)(1u << destination);
                else
                    context_registers &=
                        (uint16_t)~(1u << destination);
                if (BPF_SRC(instruction->code) == BPF_X &&
                    (stack_registers & (1u << source)))
                    stack_registers |=
                        (uint16_t)(1u << destination);
                else
                    stack_registers &=
                        (uint16_t)~(1u << destination);
            } else {
                if (!(initialized & (1u << destination)) ||
                    (BPF_SRC(instruction->code) == BPF_X &&
                     !(initialized & (1u << source))) ||
                    (map_registers & (1u << destination)) ||
                    (BPF_SRC(instruction->code) == BPF_X &&
                     (map_registers & (1u << source))) ||
                    ((stack_registers & (1u << destination)) &&
                     (operation != BPF_ADD ||
                      BPF_SRC(instruction->code) != BPF_K)) ||
                    (BPF_SRC(instruction->code) == BPF_X &&
                     (stack_registers & (1u << source))) ||
                    (operation != BPF_ADD && operation != BPF_SUB &&
                     operation != BPF_MUL && operation != BPF_DIV &&
                     operation != BPF_OR && operation != BPF_AND &&
                     operation != BPF_LSH && operation != BPF_RSH &&
                     operation != BPF_NEG && operation != BPF_MOD &&
                     operation != BPF_XOR && operation != BPF_ARSH) ||
                    ((operation == BPF_DIV || operation == BPF_MOD) &&
                     BPF_SRC(instruction->code) == BPF_K &&
                     instruction->immediate == 0))
                    return -EDGE_LINUX_EINVAL;
                map_registers &= (uint16_t)~(1u << destination);
                program_array_registers &=
                    (uint16_t)~(1u << destination);
                ringbuf_registers &= (uint16_t)~(1u << destination);
                stack_trace_registers &=
                    (uint16_t)~(1u << destination);
                cgroup_storage_registers &=
                    (uint16_t)~(1u << destination);
                storage_value_registers &=
                    (uint16_t)~(1u << destination);
                context_registers &= (uint16_t)~(1u << destination);
                if (!(stack_registers & (1u << destination)))
                    stack_registers &=
                        (uint16_t)~(1u << destination);
            }
            initialized |= (uint16_t)(1u << destination);
            continue;
        }
        if (class == BPF_LDX && BPF_MODE(instruction->code) == BPF_MEM &&
            BPF_SIZE(instruction->code) == BPF_W &&
            (initialized & (1u << source)) &&
            ((source == 1u && instruction->offset >= 0 &&
              instruction->offset <= 8) ||
             ((storage_value_registers & (1u << source)) &&
              instruction->offset >= 0)) &&
            !(instruction->offset & 3)) {
            initialized |= (uint16_t)(1u << destination);
            map_registers &= (uint16_t)~(1u << destination);
            program_array_registers &=
                (uint16_t)~(1u << destination);
            ringbuf_registers &= (uint16_t)~(1u << destination);
            stack_trace_registers &=
                (uint16_t)~(1u << destination);
            cgroup_storage_registers &=
                (uint16_t)~(1u << destination);
            storage_value_registers &=
                (uint16_t)~(1u << destination);
            context_registers &= (uint16_t)~(1u << destination);
            stack_registers &= (uint16_t)~(1u << destination);
            continue;
        }
        if (class == BPF_STX &&
            instruction->code == (BPF_STX | BPF_W | BPF_MEM) &&
            ((stack_registers & (1u << destination)) ||
             (storage_value_registers & (1u << destination))) &&
            (initialized & (1u << source)) &&
            !(map_registers & (1u << source)) &&
            !(context_registers & (1u << source)) &&
            !(stack_registers & (1u << source)) &&
            ((stack_registers & (1u << destination)) ?
                 (instruction->offset >= -512 &&
                  instruction->offset <= -4) :
                 instruction->offset >= 0) &&
            !(instruction->offset & 3)) {
            continue;
        }
        if (class == BPF_JMP && operation == BPF_EXIT) {
            if (instruction->code != (BPF_JMP | BPF_EXIT) ||
                !(initialized & 1u) ||
                pc + 1u != request->instruction_count)
                return -EDGE_LINUX_EINVAL;
            return 0;
        }
        if (class == BPF_JMP && operation == BPF_CALL) {
            uint16_t required;

            if (instruction->code != (BPF_JMP | BPF_CALL) ||
                instruction->offset)
                return -EDGE_LINUX_EINVAL;
            if (instruction->immediate ==
                    (int32_t)BPF_FUNC_TAIL_CALL) {
                required = (1u << 1) | (1u << 2) | (1u << 3);
                if ((initialized & required) != required ||
                    !(context_registers & (1u << 1)) ||
                    !(program_array_registers & (1u << 2)))
                    return -EDGE_LINUX_EINVAL;
            } else if (instruction->immediate ==
                           (int32_t)BPF_FUNC_RINGBUF_OUTPUT) {
                required = (1u << 1) | (1u << 2) |
                           (1u << 3) | (1u << 4);
                if ((initialized & required) != required ||
                    !(ringbuf_registers & (1u << 1)) ||
                    !(stack_registers & (1u << 2)) ||
                    (map_registers & ((1u << 2) | (1u << 3) |
                                      (1u << 4))))
                    return -EDGE_LINUX_EINVAL;
            } else if (instruction->immediate ==
                           (int32_t)BPF_FUNC_GET_LOCAL_STORAGE) {
                required = (1u << 1) | (1u << 2);
                if ((initialized & required) != required ||
                    !(cgroup_storage_registers & (1u << 1)) ||
                    (map_registers & (1u << 2)))
                    return -EDGE_LINUX_EINVAL;
            } else if (instruction->immediate ==
                           (int32_t)BPF_FUNC_GET_STACKID) {
                required = (1u << 1) | (1u << 2) | (1u << 3);
                if (request->type !=
                        KERNEL_BPF_PROG_TYPE_RAW_TRACEPOINT ||
                    !request->gpl_compatible ||
                    (initialized & required) != required ||
                    !(context_registers & (1u << 1)) ||
                    !(stack_trace_registers & (1u << 2)) ||
                    (map_registers & (1u << 3)))
                    return -EDGE_LINUX_EINVAL;
            } else {
                return -EDGE_LINUX_EINVAL;
            }
            initialized &= (uint16_t)~0x3eu;
            initialized |= 1u;
            map_registers &= (uint16_t)~0x3fu;
            program_array_registers &= (uint16_t)~0x3fu;
            ringbuf_registers &= (uint16_t)~0x3fu;
            stack_trace_registers &= (uint16_t)~0x3fu;
            cgroup_storage_registers &= (uint16_t)~0x3fu;
            storage_value_registers &= (uint16_t)~0x3fu;
            if (instruction->immediate ==
                    (int32_t)BPF_FUNC_GET_LOCAL_STORAGE)
                storage_value_registers |= 1u;
            context_registers &= (uint16_t)~0x3fu;
            stack_registers &= (uint16_t)~0x3fu;
            continue;
        }
        if (class == BPF_JMP) {
            uint32_t target;
            if (BPF_SRC(instruction->code) == BPF_X &&
                !(initialized & (1u << source)))
                return -EDGE_LINUX_EINVAL;
            if (operation != BPF_JA && operation != BPF_JEQ &&
                operation != BPF_JGT && operation != BPF_JGE &&
                operation != BPF_JSET && operation != BPF_JNE &&
                operation != BPF_JSGT && operation != BPF_JSGE &&
                operation != BPF_JLT && operation != BPF_JLE &&
                operation != BPF_JSLT && operation != BPF_JSLE)
                return -EDGE_LINUX_EINVAL;
            if (operation != BPF_JA && !(initialized & (1u << destination)))
                return -EDGE_LINUX_EINVAL;
            if (instruction->offset < 0) return -EDGE_LINUX_EINVAL;
            target = pc + 1u + (uint32_t)instruction->offset;
            if (target >= request->instruction_count)
                return -EDGE_LINUX_EINVAL;
            continue;
        }
        return -EDGE_LINUX_EINVAL;
    }
    return -EDGE_LINUX_EINVAL;
}

static void bpf_program_map_references_release(
        const kernel_bpf_instruction_t *instructions, uint32_t count,
        uint32_t reference_count) {
    for (uint32_t pc = 0;
         pc + 1u < count && reference_count; ++pc) {
        const kernel_bpf_instruction_t *instruction = &instructions[pc];

        if (instruction->code != (BPF_LD | BPF_DW | BPF_IMM) ||
            bpf_program_source(instruction) != BPF_PSEUDO_MAP_FD)
            continue;
        kernel_bpf_object_release(instruction->immediate);
        --reference_count;
        ++pc;
    }
}

int kernel_bpf_program_create(
    const kernel_bpf_program_create_request_t *request,
    const kernel_bpf_instruction_t *instructions) {
    kernel_bpf_object_t *object;
    kernel_bpf_instruction_t *storage;
    uint32_t pages;
    uint32_t retained_maps = 0u;
    int object_id;
    int status;

    status = bpf_program_validate(request, instructions);
    if (status < 0) return status;
    for (uint32_t pc = 0; pc + 1u < request->instruction_count; ++pc) {
        const kernel_bpf_instruction_t *instruction = &instructions[pc];

        if (instruction->code != (BPF_LD | BPF_DW | BPF_IMM) ||
            bpf_program_source(instruction) != BPF_PSEUDO_MAP_FD)
            continue;
        status = kernel_bpf_object_retain(instruction->immediate);
        if (status < 0) {
            bpf_program_map_references_release(
                instructions, request->instruction_count,
                retained_maps);
            return status;
        }
        ++retained_maps;
        ++pc;
    }
    status = bpf_allocation_size(
        (uint64_t)request->instruction_count * sizeof(*instructions), &pages);
    if (status < 0) {
        bpf_program_map_references_release(
            instructions, request->instruction_count, retained_maps);
        return status;
    }
    storage = (kernel_bpf_instruction_t *)arch_vm_alloc_pages(pages);
    if (!storage) {
        bpf_program_map_references_release(
            instructions, request->instruction_count, retained_maps);
        return -EDGE_LINUX_ENOMEM;
    }
    memset(storage, 0, (uint64_t)pages * BPF_PAGE_SIZE);
    memcpy(storage, instructions,
           (uint64_t)request->instruction_count * sizeof(*instructions));

    bpf_lock();
    object_id = bpf_allocate_object_locked(
        KERNEL_BPF_OBJECT_PROGRAM, &object);
    if (object_id >= 0) {
        object->value.program.type = request->type;
        object->value.program.instruction_count = request->instruction_count;
        object->value.program.flags = request->flags;
        object->value.program.expected_attach_type =
            request->expected_attach_type;
        object->value.program.created_by_uid = request->created_by_uid;
        object->value.program.gpl_compatible = request->gpl_compatible != 0;
        object->value.program.storage_pages = pages;
        object->value.program.map_reference_count = retained_maps;
        object->value.program.instructions = storage;
        bpf_program_tag(
            storage, request->instruction_count,
            object->value.program.tag);
        memcpy(object->value.program.name, request->name,
               KERNEL_BPF_OBJECT_NAME_LENGTH);
    }
    bpf_unlock();
    if (object_id < 0) {
        bpf_program_map_references_release(
            instructions, request->instruction_count, retained_maps);
        bpf_free_pages(storage, pages);
    }
    return object_id;
}

int kernel_bpf_object_retain(int object_id) {
    kernel_bpf_object_t *object;
    int result = -EDGE_LINUX_EBADF;

    bpf_lock();
    object = bpf_object_locked(object_id);
    if (object && object->references != UINT32_MAX) {
        ++object->references;
        result = 0;
    }
    bpf_unlock();
    return result;
}

void kernel_bpf_object_release(int object_id) {
    kernel_bpf_object_t *object;
    void *storage = 0;
    uint32_t pages = 0;
    uint32_t map_type = 0u;
    uint32_t map_entries = 0u;
    uint32_t map_storage_entries = 0u;
    uint32_t map_stride = 0u;
    uint32_t map_key_size = 0u;
    uint32_t program_instruction_count = 0u;
    uint32_t program_map_reference_count = 0u;
    uint32_t program_bound_map_count = 0u;
    int32_t program_bound_map_ids[BPF_OBJECT_CAPACITY];
    int32_t map_btf_object = -1;
    int32_t released_link_program = -1;

    bpf_lock();
    object = bpf_object_locked(object_id);
    if (object && object->references && !--object->references) {
        if (object->kind == KERNEL_BPF_OBJECT_MAP) {
            storage = object->value.map.storage;
            pages = object->value.map.storage_pages;
            map_type = object->value.map.type;
            map_entries = object->value.map.max_entries;
            map_storage_entries = object->value.map.storage_entries;
            map_stride = object->value.map.entry_stride;
            map_key_size = object->value.map.key_size;
            map_btf_object = object->value.map.btf_object_id;
        } else if (object->kind == KERNEL_BPF_OBJECT_PROGRAM) {
            storage = object->value.program.instructions;
            pages = object->value.program.storage_pages;
            program_instruction_count =
                object->value.program.instruction_count;
            program_map_reference_count =
                object->value.program.map_reference_count;
            program_bound_map_count =
                object->value.program.bound_map_count;
            memcpy(program_bound_map_ids,
                   object->value.program.bound_map_ids,
                   (uint64_t)program_bound_map_count *
                       sizeof(program_bound_map_ids[0]));
        } else if (object->kind == KERNEL_BPF_OBJECT_BTF) {
            storage = object->value.btf.data;
            pages = object->value.btf.storage_pages;
        } else if (object->kind == KERNEL_BPF_OBJECT_LINK) {
            released_link_program =
                object->value.link.program_object_id;
            if (!object->value.link.detached) {
                int detached = 0;

                for (uint32_t index = 0;
                     index < EDGE_RUNTIME_MAX_BPF_ATTACHMENTS; ++index) {
                    kernel_bpf_attachment_t *attachment =
                        &g_bpf_attachments[index];
                    if (!attachment->used ||
                        attachment->link_object_id != object_id)
                        continue;
                    if (bpf_cgroup_revision_locked(
                            attachment->cgroup_id))
                        ++*bpf_cgroup_revision_locked(
                            attachment->cgroup_id);
                    memset(attachment, 0, sizeof(*attachment));
                    detached = 1;
                    break;
                }
                if (!detached) {
                    for (uint32_t index = 0;
                         index < EDGE_RUNTIME_MAX_BPF_ATTACHMENTS; ++index) {
                        kernel_bpf_raw_tracepoint_attachment_t *attachment =
                            &g_bpf_raw_tracepoints[index];

                        if (!attachment->used ||
                            attachment->link_object_id != object_id)
                            continue;
                        memset(attachment, 0, sizeof(*attachment));
                        __atomic_sub_fetch(&g_bpf_raw_tracepoint_users, 1u,
                                           __ATOMIC_RELEASE);
                        break;
                    }
                }
            }
        } else if (object->kind == KERNEL_BPF_OBJECT_STATS &&
                   g_bpf_runtime_stats_users) {
            --g_bpf_runtime_stats_users;
        }
        memset(object, 0, sizeof(*object));
    }
    bpf_unlock();
    if (storage &&
        (bpf_map_type_is_map_in_map(map_type) ||
         map_type == KERNEL_BPF_MAP_TYPE_PROG_ARRAY)) {
        for (uint32_t index = 0; index < map_entries; ++index) {
            uint8_t *entry = (uint8_t *)storage +
                (uint64_t)index * map_stride;
            int32_t inner = -1;

            if (map_type == KERNEL_BPF_MAP_TYPE_HASH_OF_MAPS) {
                if (!entry[0]) continue;
                memcpy(&inner, entry + 1u + map_key_size, sizeof(inner));
            } else {
                memcpy(&inner, entry, sizeof(inner));
            }
            if (inner >= 0) kernel_bpf_object_release(inner);
        }
    }
    if (storage && map_type == KERNEL_BPF_MAP_TYPE_PERF_EVENT_ARRAY) {
        for (uint32_t index = 0; index < map_entries; ++index) {
            uint8_t *entry = (uint8_t *)storage +
                (uint64_t)index * map_stride;
            int32_t event_id = -1;

            memcpy(&event_id, entry, sizeof(event_id));
            if (event_id >= 0) kernel_perf_event_release(event_id);
        }
    }
    if (storage && map_type == KERNEL_BPF_MAP_TYPE_CGROUP_ARRAY) {
        for (uint32_t index = 0; index < map_entries; ++index) {
            uint8_t *entry = (uint8_t *)storage +
                (uint64_t)index * map_stride;
            uint64_t reference = 0u;

            memcpy(&reference, entry, sizeof(reference));
            if (reference) cgroupfs_reference_put(reference);
        }
    }
    if (storage && map_type == KERNEL_BPF_MAP_TYPE_CGRP_STORAGE) {
        for (uint32_t index = 0; index < map_storage_entries; ++index) {
            uint8_t *entry = (uint8_t *)storage +
                (uint64_t)index * map_stride;
            uint64_t reference = 0u;

            if (!entry[0]) continue;
            memcpy(&reference, entry + 1u, sizeof(reference));
            if (reference) cgroupfs_reference_put(reference);
        }
    }
    if (map_btf_object >= 0)
        kernel_bpf_object_release(map_btf_object);
    if (released_link_program >= 0)
        kernel_bpf_object_release(released_link_program);
    if (storage && program_instruction_count)
        bpf_program_map_references_release(
            (const kernel_bpf_instruction_t *)storage,
            program_instruction_count, program_map_reference_count);
    for (uint32_t index = 0; index < program_bound_map_count; ++index)
        kernel_bpf_object_release(program_bound_map_ids[index]);
    bpf_free_pages(storage, pages);
}

int kernel_bpf_object_kind(int object_id, kernel_bpf_object_kind_t *kind) {
    kernel_bpf_object_t *object;

    if (!kind) return -EDGE_LINUX_EINVAL;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object) {
        bpf_unlock();
        return -EDGE_LINUX_EBADF;
    }
    *kind = (kernel_bpf_object_kind_t)object->kind;
    bpf_unlock();
    return 0;
}

int kernel_bpf_object_user_id(int object_id, uint32_t *user_id) {
    kernel_bpf_object_t *object;

    if (!user_id) return -EDGE_LINUX_EINVAL;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object) {
        bpf_unlock();
        return -EDGE_LINUX_EBADF;
    }
    *user_id = object->user_id;
    bpf_unlock();
    return 0;
}

int kernel_bpf_object_from_user_id(kernel_bpf_object_kind_t kind,
                                   uint32_t user_id) {
    uint32_t index;
    int result = -EDGE_LINUX_ENOENT;

    if (!user_id) return -EDGE_LINUX_ENOENT;
    bpf_lock();
    for (index = 0; index < BPF_OBJECT_CAPACITY; ++index) {
        kernel_bpf_object_t *object = &g_bpf_objects[index];
        if (!object->used || object->kind != (uint8_t)kind ||
            object->user_id != user_id)
            continue;
        if (object->references == UINT32_MAX) {
            result = -EDGE_LINUX_EOVERFLOW;
        } else {
            ++object->references;
            result = (int)index;
        }
        break;
    }
    bpf_unlock();
    return result;
}

int kernel_bpf_object_next_user_id(kernel_bpf_object_kind_t kind,
                                   uint32_t start_id,
                                   uint32_t *next_id) {
    uint32_t candidate = UINT32_MAX;
    uint32_t index;

    if (!next_id) return -EDGE_LINUX_EINVAL;
    bpf_lock();
    for (index = 0; index < BPF_OBJECT_CAPACITY; ++index) {
        kernel_bpf_object_t *object = &g_bpf_objects[index];
        if (object->used && object->kind == (uint8_t)kind &&
            object->user_id > start_id && object->user_id < candidate)
            candidate = object->user_id;
    }
    bpf_unlock();
    if (candidate == UINT32_MAX) return -EDGE_LINUX_ENOENT;
    *next_id = candidate;
    return 0;
}

int kernel_bpf_pin_create(const void *filesystem_identity,
                          uint32_t inode_number,
                          uint32_t inode_generation,
                          int object_id) {
    kernel_bpf_object_t *object;
    kernel_bpf_pin_t *free_pin = 0;
    int result = -EDGE_LINUX_ENOSPC;

    if (!filesystem_identity || !inode_number)
        return -EDGE_LINUX_EINVAL;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object) {
        result = -EDGE_LINUX_EBADF;
        goto out;
    }
    if (object->kind == KERNEL_BPF_OBJECT_BTF) {
        result = -EDGE_LINUX_EINVAL;
        goto out;
    }
    for (uint32_t index = 0; index < BPF_PIN_CAPACITY; ++index) {
        kernel_bpf_pin_t *pin = &g_bpf_pins[index];
        if (!pin->used) {
            if (!free_pin) free_pin = pin;
            continue;
        }
        if (pin->filesystem_identity == filesystem_identity &&
            pin->inode_number == inode_number &&
            pin->inode_generation == inode_generation) {
            result = -EDGE_LINUX_EEXIST;
            goto out;
        }
    }
    if (!free_pin || object->references == UINT32_MAX) {
        result = object->references == UINT32_MAX ?
            -EDGE_LINUX_EOVERFLOW : -EDGE_LINUX_ENOSPC;
        goto out;
    }
    ++object->references;
    memset(free_pin, 0, sizeof(*free_pin));
    free_pin->used = 1u;
    free_pin->filesystem_identity = filesystem_identity;
    free_pin->inode_number = inode_number;
    free_pin->inode_generation = inode_generation;
    free_pin->object_id = object_id;
    result = 0;
out:
    bpf_unlock();
    return result;
}

int kernel_bpf_pin_get(const void *filesystem_identity,
                       uint32_t inode_number,
                       uint32_t inode_generation,
                       kernel_bpf_object_kind_t *kind) {
    int result = -EDGE_LINUX_ENOENT;

    if (!filesystem_identity || !inode_number || !kind)
        return -EDGE_LINUX_EINVAL;
    bpf_lock();
    for (uint32_t index = 0; index < BPF_PIN_CAPACITY; ++index) {
        kernel_bpf_pin_t *pin = &g_bpf_pins[index];
        kernel_bpf_object_t *object;
        if (!pin->used || pin->filesystem_identity != filesystem_identity ||
            pin->inode_number != inode_number ||
            pin->inode_generation != inode_generation)
            continue;
        object = bpf_object_locked(pin->object_id);
        if (!object) break;
        if (object->references == UINT32_MAX) {
            result = -EDGE_LINUX_EOVERFLOW;
            break;
        }
        ++object->references;
        *kind = (kernel_bpf_object_kind_t)object->kind;
        result = pin->object_id;
        break;
    }
    bpf_unlock();
    return result;
}

void kernel_bpf_pin_remove(const void *filesystem_identity,
                           uint32_t inode_number,
                           uint32_t inode_generation) {
    int object_id = -1;

    if (!filesystem_identity || !inode_number) return;
    bpf_lock();
    for (uint32_t index = 0; index < BPF_PIN_CAPACITY; ++index) {
        kernel_bpf_pin_t *pin = &g_bpf_pins[index];
        if (!pin->used || pin->filesystem_identity != filesystem_identity ||
            pin->inode_number != inode_number ||
            pin->inode_generation != inode_generation)
            continue;
        object_id = pin->object_id;
        memset(pin, 0, sizeof(*pin));
        break;
    }
    bpf_unlock();
    if (object_id >= 0) kernel_bpf_object_release(object_id);
}

void kernel_bpf_pin_filesystem_release(const void *filesystem_identity) {
    if (!filesystem_identity) return;
    for (;;) {
        int object_id = -1;
        bpf_lock();
        for (uint32_t index = 0; index < BPF_PIN_CAPACITY; ++index) {
            kernel_bpf_pin_t *pin = &g_bpf_pins[index];
            if (!pin->used ||
                pin->filesystem_identity != filesystem_identity)
                continue;
            object_id = pin->object_id;
            memset(pin, 0, sizeof(*pin));
            break;
        }
        bpf_unlock();
        if (object_id < 0) break;
        kernel_bpf_object_release(object_id);
    }
}

int kernel_bpf_map_info(int object_id, kernel_bpf_map_info_t *info) {
    kernel_bpf_object_t *object;

    if (!info) return -EDGE_LINUX_EINVAL;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        bpf_unlock();
        return -EDGE_LINUX_EBADF;
    }
    memset(info, 0, sizeof(*info));
    info->type = object->value.map.type;
    info->id = object->user_id;
    info->key_size = object->value.map.key_size;
    info->value_size = object->value.map.value_size;
    info->max_entries = object->value.map.max_entries;
    info->flags = object->value.map.flags;
    if (object->value.map.btf_object_id >= 0) {
        kernel_bpf_object_t *btf = bpf_object_locked(
            object->value.map.btf_object_id);
        if (btf && btf->kind == KERNEL_BPF_OBJECT_BTF)
            info->btf_id = btf->user_id;
    }
    info->btf_key_type_id = object->value.map.btf_key_type_id;
    info->btf_value_type_id = object->value.map.btf_value_type_id;
    info->map_extra = object->value.map.map_extra;
    memcpy(info->name, object->value.map.name, sizeof(info->name));
    bpf_unlock();
    return 0;
}

int kernel_bpf_map_mmap_info(int object_id, uint64_t offset,
                             uint64_t length, int writable,
                             uint32_t *page_count) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint64_t data_pages;
    uint64_t virtual_pages;
    uint64_t first_page;
    uint64_t requested_pages;
    int status = 0;

    if (!page_count || !length ||
        (offset & (BPF_PAGE_SIZE - 1u)) ||
        (length & (BPF_PAGE_SIZE - 1u)))
        return -EDGE_LINUX_EINVAL;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (!bpf_map_is_ringbuf(map) &&
        map->type != KERNEL_BPF_MAP_TYPE_ARENA) {
        status = -EDGE_LINUX_ENODEV;
        goto out;
    }
    if (map->type == KERNEL_BPF_MAP_TYPE_ARENA) {
        requested_pages = length / BPF_PAGE_SIZE;
        if (offset || requested_pages > map->max_entries) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        if (writable && map->frozen) {
            status = -EDGE_LINUX_EPERM;
            goto out;
        }
        if (writable &&
            (map->flags & KERNEL_BPF_MAP_RDONLY_PROGRAM)) {
            status = -EDGE_LINUX_EACCES;
            goto out;
        }
        *page_count = (uint32_t)requested_pages;
        goto out;
    }
    first_page = offset / BPF_PAGE_SIZE;
    requested_pages = length / BPF_PAGE_SIZE;
    data_pages = map->max_entries / BPF_PAGE_SIZE;
    virtual_pages = 2u + 2u * data_pages;
    if (first_page >= virtual_pages ||
        requested_pages > virtual_pages - first_page) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (writable) {
        if (map->type == KERNEL_BPF_MAP_TYPE_RINGBUF) {
            if (first_page != 0u || requested_pages != 1u)
                status = -EDGE_LINUX_EPERM;
        } else if (first_page == 0u) {
            status = -EDGE_LINUX_EPERM;
        }
    }
    if (status == 0) *page_count = (uint32_t)requested_pages;
out:
    bpf_unlock();
    return status;
}

int kernel_bpf_map_mmap_page(int object_id, uint64_t offset,
                             uint32_t page_index, void **page_address) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint64_t data_pages;
    uint64_t virtual_page;
    uint64_t storage_page;
    int status = 0;

    if (!page_address || (offset & (BPF_PAGE_SIZE - 1u)))
        return -EDGE_LINUX_EINVAL;
    *page_address = 0;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (!bpf_map_is_ringbuf(map) &&
        map->type != KERNEL_BPF_MAP_TYPE_ARENA) {
        status = -EDGE_LINUX_ENODEV;
        goto out;
    }
    if (map->type == KERNEL_BPF_MAP_TYPE_ARENA) {
        virtual_page = offset / BPF_PAGE_SIZE + page_index;
        if (offset || virtual_page >= map->max_entries ||
            virtual_page >= map->storage_pages) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        *page_address = map->storage + virtual_page * BPF_PAGE_SIZE;
        goto out;
    }
    data_pages = map->max_entries / BPF_PAGE_SIZE;
    virtual_page = offset / BPF_PAGE_SIZE + page_index;
    if (virtual_page >= 2u + 2u * data_pages) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    storage_page = virtual_page < 2u ? virtual_page :
        2u + (virtual_page - 2u) % data_pages;
    if (storage_page >= map->storage_pages) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    *page_address = map->storage + storage_page * BPF_PAGE_SIZE;
out:
    bpf_unlock();
    return status;
}

int kernel_bpf_ringbuf_poll_state(int object_id, int *readable,
                                  int *writable) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint64_t consumer;
    uint64_t producer;
    int status = 0;

    if (!readable || !writable) return -EDGE_LINUX_EINVAL;
    *readable = 0;
    *writable = 0;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    if (object->kind == KERNEL_BPF_OBJECT_STATS) {
        *readable = 1;
        *writable = 1;
        goto out;
    }
    if (object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (!bpf_map_is_ringbuf(map)) {
        status = -EDGE_LINUX_ENODEV;
        goto out;
    }
    consumer = __atomic_load_n(
        (uint64_t *)(void *)map->storage, __ATOMIC_ACQUIRE);
    producer = __atomic_load_n(
        (uint64_t *)(void *)(map->storage + BPF_PAGE_SIZE),
        __ATOMIC_ACQUIRE);
    if (map->type == KERNEL_BPF_MAP_TYPE_RINGBUF)
        *readable = producer != consumer;
    else
        *writable = producer - consumer < map->max_entries;
out:
    bpf_unlock();
    return status;
}

int kernel_bpf_map_value_buffer_size(int object_id, uint64_t flags,
                                     uint32_t *size_out) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    int status;

    if (!size_out) return -EDGE_LINUX_EINVAL;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        bpf_unlock();
        return -EDGE_LINUX_EBADF;
    }
    map = &object->value.map;
    status = (bpf_map_is_xskmap(map) || bpf_map_is_socket_map(map) ||
              bpf_map_is_reuseport_array(map)) ? 0 :
        bpf_map_check_percpu_flags_locked(map, flags);
    if (status < 0) {
        bpf_unlock();
        return status;
    }
    if (bpf_map_is_percpu(map) &&
        ((uint32_t)flags &
         (KERNEL_BPF_F_CPU | KERNEL_BPF_F_ALL_CPUS)))
        *size_out = map->value_size;
    else
        *size_out = bpf_map_value_buffer_size_locked(map);
    bpf_unlock();
    return 0;
}

int kernel_bpf_program_info(int object_id, kernel_bpf_program_info_t *info) {
    kernel_bpf_object_t *object;

    if (!info) return -EDGE_LINUX_EINVAL;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_PROGRAM) {
        bpf_unlock();
        return -EDGE_LINUX_EBADF;
    }
    memset(info, 0, sizeof(*info));
    info->type = object->value.program.type;
    info->id = object->user_id;
    info->instruction_count = object->value.program.instruction_count;
    info->created_by_uid = object->value.program.created_by_uid;
    info->verified_instructions = object->value.program.instruction_count;
    info->gpl_compatible = object->value.program.gpl_compatible;
    info->run_time_ns = object->value.program.run_time_ns;
    info->run_count = object->value.program.run_count;
    memcpy(info->tag, object->value.program.tag, sizeof(info->tag));
    memcpy(info->name, object->value.program.name, sizeof(info->name));
    bpf_unlock();
    return 0;
}

static int bpf_program_has_map_locked(const kernel_bpf_program_t *program,
                                      int map_object_id) {
    uint32_t pc;

    for (pc = 0; pc + 1u < program->instruction_count; ++pc) {
        const kernel_bpf_instruction_t *instruction =
            &program->instructions[pc];

        if (instruction->code != (BPF_LD | BPF_DW | BPF_IMM) ||
            bpf_program_source(instruction) != BPF_PSEUDO_MAP_FD)
            continue;
        if (instruction->immediate == map_object_id) return 1;
        ++pc;
    }
    for (uint32_t index = 0; index < program->bound_map_count; ++index)
        if (program->bound_map_ids[index] == map_object_id) return 1;
    return 0;
}

static int bpf_program_has_legacy_storage_type_locked(
        const kernel_bpf_program_t *program, uint32_t map_type,
        int except_object_id) {
    for (uint32_t index = 0; index < BPF_OBJECT_CAPACITY; ++index) {
        kernel_bpf_object_t *object = &g_bpf_objects[index];

        if ((int)index == except_object_id || !object->used ||
            object->kind != KERNEL_BPF_OBJECT_MAP ||
            object->value.map.type != map_type)
            continue;
        if (bpf_program_has_map_locked(program, (int)index)) return 1;
    }
    return 0;
}

static int bpf_program_legacy_storage_link_locked(
        const kernel_bpf_program_t *program, uint32_t cgroup_id,
        uint32_t attach_type) {
    int linked[BPF_OBJECT_CAPACITY];
    uint32_t linked_count = 0u;
    int status = 0;

    for (uint32_t index = 0; index < BPF_OBJECT_CAPACITY; ++index) {
        kernel_bpf_object_t *object = &g_bpf_objects[index];

        if (!object->used || object->kind != KERNEL_BPF_OBJECT_MAP ||
            !bpf_map_is_legacy_cgroup_storage(&object->value.map) ||
            !bpf_program_has_map_locked(program, (int)index))
            continue;
        status = bpf_legacy_cgroup_storage_link_map_locked(
            &object->value.map, cgroup_id, attach_type);
        if (status < 0) break;
        if (status > 0) linked[linked_count++] = (int)index;
    }
    if (status < 0) {
        while (linked_count) {
            kernel_bpf_object_t *object =
                &g_bpf_objects[linked[--linked_count]];
            bpf_legacy_cgroup_storage_unlink_map_locked(
                &object->value.map, cgroup_id, attach_type);
        }
    }
    return status < 0 ? status : 0;
}

int kernel_bpf_program_bind_map(int program_object_id, int map_object_id) {
    kernel_bpf_object_t *program_object;
    kernel_bpf_object_t *map_object;
    kernel_bpf_program_t *program;
    int status = 0;

    bpf_lock();
    program_object = bpf_object_locked(program_object_id);
    if (!program_object ||
        program_object->kind != KERNEL_BPF_OBJECT_PROGRAM) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map_object = bpf_object_locked(map_object_id);
    if (!map_object || map_object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    program = &program_object->value.program;
    if (bpf_program_has_map_locked(program, map_object_id)) goto out;
    if (bpf_map_is_legacy_cgroup_storage(&map_object->value.map) &&
        bpf_program_has_legacy_storage_type_locked(
            program, map_object->value.map.type, map_object_id)) {
        status = -EDGE_LINUX_EBUSY;
        goto out;
    }
    if (program->bound_map_count >= BPF_OBJECT_CAPACITY) {
        status = -EDGE_LINUX_E2BIG;
        goto out;
    }
    if (map_object->references == UINT32_MAX) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    ++map_object->references;
    program->bound_map_ids[program->bound_map_count++] = map_object_id;
out:
    bpf_unlock();
    return status;
}

int kernel_bpf_runtime_stats_enable(void) {
    kernel_bpf_object_t *object;
    int object_id;

    bpf_lock();
    if (g_bpf_runtime_stats_users > (uint32_t)INT32_MAX / 2u) {
        bpf_unlock();
        return -EDGE_LINUX_EBUSY;
    }
    object_id = bpf_allocate_object_locked(
        KERNEL_BPF_OBJECT_STATS, &object);
    if (object_id >= 0) ++g_bpf_runtime_stats_users;
    bpf_unlock();
    return object_id;
}

int kernel_bpf_program_map_ids(int program_object_id, uint32_t *map_ids,
                               uint32_t capacity, uint32_t *actual_count) {
    kernel_bpf_object_t *program_object;
    kernel_bpf_program_t *program;
    int32_t object_ids[BPF_OBJECT_CAPACITY];
    uint32_t count = 0u;
    int status = 0;

    if (!actual_count || (capacity && !map_ids))
        return -EDGE_LINUX_EINVAL;
    bpf_lock();
    program_object = bpf_object_locked(program_object_id);
    if (!program_object ||
        program_object->kind != KERNEL_BPF_OBJECT_PROGRAM) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    program = &program_object->value.program;
    for (uint32_t pc = 0; pc + 1u < program->instruction_count; ++pc) {
        const kernel_bpf_instruction_t *instruction =
            &program->instructions[pc];
        int duplicate = 0;

        if (instruction->code != (BPF_LD | BPF_DW | BPF_IMM) ||
            bpf_program_source(instruction) != BPF_PSEUDO_MAP_FD)
            continue;
        for (uint32_t index = 0; index < count; ++index)
            if (object_ids[index] == instruction->immediate)
                duplicate = 1;
        if (!duplicate && count < BPF_OBJECT_CAPACITY)
            object_ids[count++] = instruction->immediate;
        ++pc;
    }
    for (uint32_t bound = 0; bound < program->bound_map_count; ++bound) {
        int duplicate = 0;

        for (uint32_t index = 0; index < count; ++index)
            if (object_ids[index] == program->bound_map_ids[bound])
                duplicate = 1;
        if (!duplicate && count < BPF_OBJECT_CAPACITY)
            object_ids[count++] = program->bound_map_ids[bound];
    }
    for (uint32_t index = 0; index < count && index < capacity; ++index) {
        kernel_bpf_object_t *map = bpf_object_locked(object_ids[index]);

        if (!map || map->kind != KERNEL_BPF_OBJECT_MAP) {
            status = -EDGE_LINUX_EBADF;
            goto out;
        }
        map_ids[index] = map->user_id;
    }
    *actual_count = count;
out:
    bpf_unlock();
    return status;
}

int kernel_bpf_link_info(int object_id, kernel_bpf_link_info_t *info) {
    kernel_bpf_object_t *object;
    kernel_bpf_object_t *program;

    if (!info) return -EDGE_LINUX_EINVAL;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_LINK) {
        bpf_unlock();
        return -EDGE_LINUX_EBADF;
    }
    memset(info, 0, sizeof(*info));
    info->type = 3u;
    info->id = object->user_id;
    info->attach_type = object->value.link.attach_type;
    info->cgroup_id = object->value.link.cgroup_id;
    info->attach_flags = object->value.link.attach_flags;
    info->detached = object->value.link.detached;
    program = bpf_object_locked(object->value.link.program_object_id);
    if (program && program->kind == KERNEL_BPF_OBJECT_PROGRAM)
        info->program_id = program->user_id;
    bpf_unlock();
    return 0;
}

int kernel_bpf_program_copy_instructions(int object_id, void *buffer,
                                         uint32_t capacity,
                                         uint32_t *actual_size) {
    kernel_bpf_object_t *object;
    uint32_t size;

    if (!actual_size) return -EDGE_LINUX_EINVAL;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_PROGRAM) {
        bpf_unlock();
        return -EDGE_LINUX_EBADF;
    }
    size = object->value.program.instruction_count *
           sizeof(kernel_bpf_instruction_t);
    *actual_size = size;
    if (capacity && !buffer) {
        bpf_unlock();
        return -EDGE_LINUX_EFAULT;
    }
    if (capacity > size) capacity = size;
    if (capacity)
        memcpy(buffer, object->value.program.instructions, capacity);
    bpf_unlock();
    return 0;
}

int kernel_bpf_btf_info(int object_id, kernel_bpf_btf_info_t *info) {
    kernel_bpf_object_t *object;

    if (!info) return -EDGE_LINUX_EINVAL;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_BTF) {
        bpf_unlock();
        return -EDGE_LINUX_EBADF;
    }
    memset(info, 0, sizeof(*info));
    info->id = object->user_id;
    info->size = object->value.btf.size;
    bpf_unlock();
    return 0;
}

int kernel_bpf_btf_copy(int object_id, void *buffer, uint32_t capacity,
                        uint32_t *actual_size) {
    kernel_bpf_object_t *object;
    uint32_t copied;

    if (!actual_size) return -EDGE_LINUX_EINVAL;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_BTF) {
        bpf_unlock();
        return -EDGE_LINUX_EBADF;
    }
    *actual_size = object->value.btf.size;
    if (capacity && !buffer) {
        bpf_unlock();
        return -EDGE_LINUX_EFAULT;
    }
    copied = capacity < object->value.btf.size ?
        capacity : object->value.btf.size;
    if (copied) memcpy(buffer, object->value.btf.data, copied);
    bpf_unlock();
    return 0;
}

static uint8_t *bpf_map_entry(kernel_bpf_map_t *map, uint32_t index) {
    return map->storage + (uint64_t)index * map->entry_stride;
}

static uint8_t *bpf_map_value(kernel_bpf_map_t *map, uint32_t index) {
    uint8_t *entry = bpf_map_entry(map, index);

    if (bpf_map_is_array(map) || bpf_map_is_queue_stack(map)) return entry;
    if (bpf_map_is_percpu(map))
        return entry + bpf_align8(1u + map->key_size);
    return entry + 1u + map->key_size;
}

static uint64_t bpf_legacy_cgroup_inode_id(uint32_t cgroup_id) {
    return UINT64_C(0xc7000000) |
           ((uint64_t)(cgroup_id & 0xffffu) << 8u) | 1u;
}

static void bpf_legacy_cgroup_storage_key(
        const kernel_bpf_map_t *map, uint32_t cgroup_id,
        uint32_t attach_type, uint8_t key[16]) {
    uint64_t inode_id = bpf_legacy_cgroup_inode_id(cgroup_id);

    memset(key, 0, 16u);
    memcpy(key, &inode_id, sizeof(inode_id));
    if (map->key_size == 16u)
        memcpy(key + sizeof(inode_id), &attach_type,
               sizeof(attach_type));
}

static void bpf_legacy_cgroup_storage_find_locked(
        kernel_bpf_map_t *map, const void *key,
        uint32_t *index_out, uint32_t *free_out) {
    uint32_t found = UINT32_MAX;
    uint32_t free_slot = UINT32_MAX;

    for (uint32_t index = 0; index < map->storage_entries; ++index) {
        uint8_t *entry = bpf_map_entry(map, index);

        if (!entry[0]) {
            if (free_slot == UINT32_MAX) free_slot = index;
            continue;
        }
        if (!memcmp(entry + 1u, key, map->key_size)) {
            found = index;
            break;
        }
    }
    if (index_out) *index_out = found;
    if (free_out) *free_out = free_slot;
}

static int bpf_legacy_cgroup_storage_link_map_locked(
        kernel_bpf_map_t *map, uint32_t cgroup_id,
        uint32_t attach_type) {
    uint8_t key[16];
    uint32_t index;
    uint32_t free_slot;
    uint8_t *entry;

    bpf_legacy_cgroup_storage_key(
        map, cgroup_id, attach_type, key);
    bpf_legacy_cgroup_storage_find_locked(
        map, key, &index, &free_slot);
    if (index != UINT32_MAX) return 0;
    if (free_slot == UINT32_MAX) return -EDGE_LINUX_ENOSPC;
    entry = bpf_map_entry(map, free_slot);
    memset(entry, 0, map->entry_stride);
    entry[0] = 1u;
    memcpy(entry + 1u, key, map->key_size);
    ++map->entry_count;
    return 1;
}

static void bpf_legacy_cgroup_storage_unlink_map_locked(
        kernel_bpf_map_t *map, uint32_t cgroup_id,
        uint32_t attach_type) {
    uint8_t key[16];
    uint32_t index;

    bpf_legacy_cgroup_storage_key(
        map, cgroup_id, attach_type, key);
    bpf_legacy_cgroup_storage_find_locked(map, key, &index, 0);
    if (index == UINT32_MAX) return;
    memset(bpf_map_entry(map, index), 0, map->entry_stride);
    if (map->entry_count) --map->entry_count;
}

static void bpf_legacy_cgroup_storage_release_locked(
        uint32_t cgroup_id) {
    uint64_t inode_id = bpf_legacy_cgroup_inode_id(cgroup_id);

    for (uint32_t object_index = 0;
         object_index < BPF_OBJECT_CAPACITY; ++object_index) {
        kernel_bpf_object_t *object = &g_bpf_objects[object_index];
        kernel_bpf_map_t *map;

        if (!object->used || object->kind != KERNEL_BPF_OBJECT_MAP)
            continue;
        map = &object->value.map;
        if (!bpf_map_is_legacy_cgroup_storage(map)) continue;
        for (uint32_t entry_index = 0;
             entry_index < map->storage_entries; ++entry_index) {
            uint8_t *entry = bpf_map_entry(map, entry_index);
            uint64_t stored_inode = 0u;

            if (!entry[0]) continue;
            memcpy(&stored_inode, entry + 1u, sizeof(stored_inode));
            if (stored_inode != inode_id) continue;
            memset(entry, 0, map->entry_stride);
            if (map->entry_count) --map->entry_count;
        }
    }
}

static uint8_t *bpf_legacy_cgroup_storage_value_locked(
        kernel_bpf_map_t *map, uint32_t cgroup_id,
        uint32_t attach_type) {
    uint8_t key[16];
    uint32_t index;
    uint8_t *value;

    bpf_legacy_cgroup_storage_key(
        map, cgroup_id, attach_type, key);
    bpf_legacy_cgroup_storage_find_locked(map, key, &index, 0);
    if (index == UINT32_MAX) return 0;
    value = bpf_map_value(map, index);
    if (map->type == KERNEL_BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE) {
        uint32_t cpu = edge_smp_current_cpu();

        if (cpu >= map->possible_cpu_count) cpu = 0u;
        value += (uint64_t)cpu * map->value_stride;
    }
    return value;
}

static int bpf_legacy_storage_address_locked(
        uintptr_t address, uint32_t size) {
    if (!size || address > UINTPTR_MAX - size) return 0;
    for (uint32_t object_index = 0;
         object_index < BPF_OBJECT_CAPACITY; ++object_index) {
        kernel_bpf_object_t *object = &g_bpf_objects[object_index];
        kernel_bpf_map_t *map;

        if (!object->used || object->kind != KERNEL_BPF_OBJECT_MAP)
            continue;
        map = &object->value.map;
        if (!bpf_map_is_legacy_cgroup_storage(map)) continue;
        for (uint32_t index = 0; index < map->storage_entries; ++index) {
            uint8_t *entry = bpf_map_entry(map, index);
            uint32_t value_count;

            if (!entry[0]) continue;
            value_count = bpf_map_is_percpu(map) ?
                map->possible_cpu_count : 1u;
            for (uint32_t value_index = 0;
                 value_index < value_count; ++value_index) {
                uintptr_t value_start =
                    (uintptr_t)bpf_map_value(map, index) +
                    (uint64_t)value_index * map->value_stride;
                uintptr_t value_end = value_start + map->value_size;

                if (address >= value_start &&
                    address + size <= value_end)
                    return 1;
            }
        }
    }
    return 0;
}

static uint8_t *bpf_socket_map_cookie(kernel_bpf_map_t *map,
                                      uint32_t index) {
    uint8_t *entry = bpf_map_entry(map, index);

    return entry + 1u + (bpf_map_is_sockhash(map) ? map->key_size : 0u);
}

static void bpf_socket_description_remove(uint64_t identity,
                                          int reuseport_only) {
    if (!identity) return;
    bpf_lock();
    for (uint32_t object_index = 0;
         object_index < BPF_OBJECT_CAPACITY; ++object_index) {
        kernel_bpf_object_t *object = &g_bpf_objects[object_index];
        kernel_bpf_map_t *map;

        if (!object->used ||
            object->kind != KERNEL_BPF_OBJECT_MAP)
            continue;
        map = &object->value.map;
        if (reuseport_only) {
            if (!bpf_map_is_reuseport_array(map)) continue;
        } else if (!bpf_map_is_socket_map(map) &&
                   !bpf_map_is_reuseport_array(map) &&
                   !bpf_map_is_sk_storage(map)) {
            continue;
        }
        for (uint32_t entry_index = 0;
             entry_index < map->storage_entries; ++entry_index) {
            uint8_t *entry = bpf_map_entry(map, entry_index);
            uint64_t cookie = 0u;

            if (!entry[0]) continue;
            memcpy(&cookie, bpf_socket_map_cookie(map, entry_index),
                   sizeof(cookie));
            if (cookie != identity) continue;
            memset(entry, 0, map->entry_stride);
            if (map->entry_count) --map->entry_count;
        }
    }
    bpf_unlock();
}

static void bpf_socket_description_closed(uint64_t identity) {
    bpf_socket_description_remove(identity, 0);
}

void kernel_bpf_reuseport_socket_detach(uint64_t description_identity) {
    bpf_socket_description_remove(description_identity, 1);
}

static void bpf_map_copy_value_out(kernel_bpf_map_t *map, uint32_t index,
                                   void *value, uint64_t flags) {
    uint8_t *source = bpf_map_value(map, index);

    if (!bpf_map_is_percpu(map)) {
        memcpy(value, source, map->value_size);
        return;
    }
    if ((uint32_t)flags & KERNEL_BPF_F_CPU) {
        uint32_t cpu = (uint32_t)(flags >> 32u);

        memcpy(value, source + (uint64_t)cpu * map->value_stride,
               map->value_size);
        return;
    }
    for (uint32_t cpu = 0; cpu < map->possible_cpu_count; ++cpu) {
        uint8_t *destination = (uint8_t *)value +
            (uint64_t)cpu * map->value_stride;

        memset(destination, 0, map->value_stride);
        memcpy(destination, source + (uint64_t)cpu * map->value_stride,
               map->value_size);
    }
}

static void bpf_map_copy_value_in(kernel_bpf_map_t *map, uint32_t index,
                                  const void *value, uint64_t flags) {
    uint8_t *destination = bpf_map_value(map, index);

    if (!bpf_map_is_percpu(map)) {
        memcpy(destination, value, map->value_size);
        return;
    }
    if ((uint32_t)flags & KERNEL_BPF_F_CPU) {
        uint32_t cpu = (uint32_t)(flags >> 32u);

        destination += (uint64_t)cpu * map->value_stride;
        memset(destination, 0, map->value_stride);
        memcpy(destination, value, map->value_size);
        return;
    }
    for (uint32_t cpu = 0; cpu < map->possible_cpu_count; ++cpu) {
        const uint8_t *source = (const uint8_t *)value;

        if (!((uint32_t)flags & KERNEL_BPF_F_ALL_CPUS))
            source += (uint64_t)cpu * map->value_stride;

        memset(destination + (uint64_t)cpu * map->value_stride, 0,
               map->value_stride);
        memcpy(destination + (uint64_t)cpu * map->value_stride, source,
               map->value_size);
    }
}

static uint64_t *bpf_map_lru_sequence(
        kernel_bpf_map_t *map, uint32_t index) {
    uint32_t offset = bpf_map_is_percpu(map) ?
        bpf_align8(1u + map->key_size) +
            map->value_stride * map->possible_cpu_count :
        bpf_align8(1u + map->key_size + map->value_size);

    return (uint64_t *)(void *)(bpf_map_entry(map, index) + offset);
}

static void bpf_map_lru_touch(kernel_bpf_map_t *map, uint32_t index) {
    uint64_t minimum = UINT64_MAX;

    if (!bpf_map_is_lru_hash(map)) return;
    if (map->access_sequence == UINT64_MAX) {
        for (uint32_t slot = 0; slot < map->max_entries; ++slot) {
            uint8_t *entry = bpf_map_entry(map, slot);
            uint64_t sequence;

            if (!entry[0]) continue;
            sequence = *bpf_map_lru_sequence(map, slot);
            if (sequence < minimum) minimum = sequence;
        }
        if (minimum == UINT64_MAX) minimum = 1u;
        for (uint32_t slot = 0; slot < map->max_entries; ++slot) {
            uint8_t *entry = bpf_map_entry(map, slot);
            uint64_t *sequence;

            if (!entry[0]) continue;
            sequence = bpf_map_lru_sequence(map, slot);
            *sequence -= minimum - 1u;
        }
        map->access_sequence -= minimum - 1u;
    }
    *bpf_map_lru_sequence(map, index) = ++map->access_sequence;
}

static uint32_t bpf_map_lru_cpu(const kernel_bpf_map_t *map) {
    uint32_t cpu = edge_smp_current_cpu();

    return cpu < map->possible_cpu_count ? cpu : 0u;
}

static void bpf_map_lru_range(const kernel_bpf_map_t *map,
                              uint32_t *first, uint32_t *last) {
    if (bpf_map_has_percpu_lru(map)) {
        uint32_t entries_per_cpu =
            map->max_entries / map->possible_cpu_count;
        uint32_t cpu = bpf_map_lru_cpu(map);

        *first = cpu * entries_per_cpu;
        *last = *first + entries_per_cpu;
        return;
    }
    *first = 0u;
    *last = map->max_entries;
}

static uint32_t bpf_map_lru_free_slot(kernel_bpf_map_t *map) {
    uint32_t first;
    uint32_t last;

    bpf_map_lru_range(map, &first, &last);
    for (uint32_t index = first; index < last; ++index) {
        if (!bpf_map_entry(map, index)[0]) return index;
    }
    return UINT32_MAX;
}

static uint32_t bpf_map_lru_oldest(kernel_bpf_map_t *map) {
    uint32_t oldest = UINT32_MAX;
    uint64_t oldest_sequence = UINT64_MAX;
    uint32_t first;
    uint32_t last;

    bpf_map_lru_range(map, &first, &last);
    for (uint32_t index = first; index < last; ++index) {
        uint8_t *entry = bpf_map_entry(map, index);
        uint64_t sequence;

        if (!entry[0]) continue;
        sequence = *bpf_map_lru_sequence(map, index);
        if (sequence < oldest_sequence) {
            oldest_sequence = sequence;
            oldest = index;
        }
    }
    return oldest;
}

static int bpf_map_queue_stack_get(kernel_bpf_map_t *map, void *value,
                                   int delete_element) {
    uint32_t index;

    if (!map->entry_count) {
        memset(value, 0, map->value_size);
        return -EDGE_LINUX_ENOENT;
    }
    if (map->type == KERNEL_BPF_MAP_TYPE_QUEUE) {
        index = map->queue_tail;
        if (delete_element) {
            map->queue_tail = (map->queue_tail + 1u) % map->max_entries;
            --map->entry_count;
        }
    } else {
        index = map->queue_head ? map->queue_head - 1u :
                                 map->max_entries - 1u;
        if (delete_element) {
            map->queue_head = index;
            --map->entry_count;
        }
    }
    memcpy(value, bpf_map_entry(map, index), map->value_size);
    return 0;
}

static int bpf_map_array_index(const kernel_bpf_map_t *map, const void *key,
                               uint32_t *index) {
    uint32_t value;

    if (!map || !key || !index) return -EDGE_LINUX_EFAULT;
    memcpy(&value, key, sizeof(value));
    if (value >= map->max_entries) return -EDGE_LINUX_E2BIG;
    *index = value;
    return 0;
}

static int bpf_map_hash_find(kernel_bpf_map_t *map, const void *key,
                             uint32_t *found, uint32_t *free_slot) {
    uint32_t index;

    *found = UINT32_MAX;
    *free_slot = UINT32_MAX;
    for (index = 0; index < map->storage_entries; ++index) {
        uint8_t *entry = bpf_map_entry(map, index);
        if (!entry[0]) {
            if (*free_slot == UINT32_MAX) *free_slot = index;
            continue;
        }
        if (memcmp(entry + 1u, key, map->key_size) == 0) {
            *found = index;
            break;
        }
    }
    return 0;
}

static int bpf_rhash_grow_locked(kernel_bpf_map_t *map) {
    uint8_t *replacement;
    uint8_t *previous;
    uint32_t replacement_entries;
    uint32_t replacement_pages;
    uint32_t previous_pages;
    uint64_t replacement_bytes;

    if (!map || map->type != KERNEL_BPF_MAP_TYPE_RHASH)
        return -EDGE_LINUX_EINVAL;
    if (map->storage_entries >= map->max_entries)
        return -EDGE_LINUX_E2BIG;
    replacement_entries = map->storage_entries < 4u ?
        4u : map->storage_entries * 2u;
    if (replacement_entries < map->storage_entries ||
        replacement_entries > map->max_entries)
        replacement_entries = map->max_entries;
    replacement_bytes =
        (uint64_t)replacement_entries * map->entry_stride;
    if (bpf_allocation_size(replacement_bytes, &replacement_pages) < 0)
        return -EDGE_LINUX_E2BIG;
    replacement = (uint8_t *)arch_vm_alloc_pages(replacement_pages);
    if (!replacement) return -EDGE_LINUX_ENOMEM;
    memset(replacement, 0,
           (uint64_t)replacement_pages * BPF_PAGE_SIZE);
    memcpy(replacement, map->storage,
           (uint64_t)map->storage_entries * map->entry_stride);
    previous = map->storage;
    previous_pages = map->storage_pages;
    map->storage = replacement;
    map->storage_entries = replacement_entries;
    map->storage_pages = replacement_pages;
    bpf_free_pages(previous, previous_pages);
    return 0;
}

static uint32_t bpf_lpm_prefix_length(const void *key) {
    uint32_t prefix_length;

    memcpy(&prefix_length, key, sizeof(prefix_length));
    return prefix_length;
}

static int bpf_lpm_prefix_equal(const uint8_t *left,
                                const uint8_t *right,
                                uint32_t bit_count) {
    uint32_t full_bytes = bit_count / 8u;
    uint32_t remaining_bits = bit_count % 8u;

    if (full_bytes && memcmp(left, right, full_bytes) != 0) return 0;
    if (remaining_bits) {
        uint8_t mask = (uint8_t)(0xffu << (8u - remaining_bits));
        if ((left[full_bytes] & mask) != (right[full_bytes] & mask))
            return 0;
    }
    return 1;
}

static int bpf_lpm_key_order(const void *left, const void *right) {
    const uint8_t *left_data =
        (const uint8_t *)left + sizeof(uint32_t);
    const uint8_t *right_data =
        (const uint8_t *)right + sizeof(uint32_t);
    uint32_t left_prefix = bpf_lpm_prefix_length(left);
    uint32_t right_prefix = bpf_lpm_prefix_length(right);
    uint32_t common_prefix = left_prefix < right_prefix ?
        left_prefix : right_prefix;

    for (uint32_t bit = 0; bit < common_prefix; ++bit) {
        uint8_t mask = (uint8_t)(1u << (7u - bit % 8u));
        int left_set = (left_data[bit / 8u] & mask) != 0;
        int right_set = (right_data[bit / 8u] & mask) != 0;

        if (left_set != right_set) return left_set ? 1 : -1;
    }
    if (left_prefix == right_prefix) return 0;
    return left_prefix > right_prefix ? -1 : 1;
}

static uint32_t bpf_map_lpm_ordered_index(kernel_bpf_map_t *map,
                                          uint32_t ordinal) {
    uint32_t previous = UINT32_MAX;

    for (uint32_t position = 0; position <= ordinal; ++position) {
        uint32_t selected = UINT32_MAX;

        for (uint32_t index = 0; index < map->max_entries; ++index) {
            uint8_t *entry = bpf_map_entry(map, index);

            if (!entry[0] ||
                (previous != UINT32_MAX &&
                 bpf_lpm_key_order(
                     entry + 1u,
                     bpf_map_entry(map, previous) + 1u) <= 0))
                continue;
            if (selected == UINT32_MAX ||
                bpf_lpm_key_order(
                    entry + 1u,
                    bpf_map_entry(map, selected) + 1u) < 0)
                selected = index;
        }
        if (selected == UINT32_MAX) return UINT32_MAX;
        previous = selected;
    }
    return previous;
}

static int bpf_map_lpm_find_exact(kernel_bpf_map_t *map,
                                  const void *key,
                                  uint32_t *found,
                                  uint32_t *free_slot) {
    const uint8_t *data = (const uint8_t *)key + sizeof(uint32_t);
    uint32_t prefix_length = bpf_lpm_prefix_length(key);
    uint32_t max_prefix = (map->key_size - sizeof(uint32_t)) * 8u;

    if (prefix_length > max_prefix) return -EDGE_LINUX_EINVAL;

    *found = UINT32_MAX;
    *free_slot = UINT32_MAX;
    for (uint32_t index = 0; index < map->max_entries; ++index) {
        uint8_t *entry = bpf_map_entry(map, index);
        uint32_t stored_prefix;

        if (!entry[0]) {
            if (*free_slot == UINT32_MAX) *free_slot = index;
            continue;
        }
        stored_prefix = bpf_lpm_prefix_length(entry + 1u);
        if (stored_prefix == prefix_length &&
            bpf_lpm_prefix_equal(
                entry + 1u + sizeof(uint32_t), data,
                prefix_length)) {
            *found = index;
            break;
        }
    }
    return 0;
}

static int bpf_map_lpm_lookup(kernel_bpf_map_t *map, const void *key,
                              uint32_t *found) {
    const uint8_t *data = (const uint8_t *)key + sizeof(uint32_t);
    uint32_t query_prefix = bpf_lpm_prefix_length(key);
    uint32_t max_prefix = (map->key_size - sizeof(uint32_t)) * 8u;
    uint32_t best_prefix = 0u;
    int have_match = 0;

    if (query_prefix > max_prefix) return -EDGE_LINUX_ENOENT;
    *found = UINT32_MAX;
    for (uint32_t index = 0; index < map->max_entries; ++index) {
        uint8_t *entry = bpf_map_entry(map, index);
        uint32_t stored_prefix;

        if (!entry[0]) continue;
        stored_prefix = bpf_lpm_prefix_length(entry + 1u);
        if (stored_prefix > query_prefix ||
            !bpf_lpm_prefix_equal(
                entry + 1u + sizeof(uint32_t), data,
                stored_prefix))
            continue;
        if (!have_match || stored_prefix > best_prefix) {
            have_match = 1;
            best_prefix = stored_prefix;
            *found = index;
        }
    }
    return have_match ? 0 : -EDGE_LINUX_ENOENT;
}

static uint32_t bpf_bloom_hash(const kernel_bpf_map_t *map,
                               const void *value, uint32_t index) {
    const uint8_t *bytes = (const uint8_t *)value;
    uint32_t hash = 2166136261u ^ map->bloom_seed ^
        (index + 1u) * 0x9e3779b9u;

    for (uint32_t offset = 0; offset < map->value_size; ++offset) {
        hash ^= bytes[offset];
        hash *= 16777619u;
        hash ^= hash >> 13u;
    }
    hash ^= hash >> 16u;
    hash *= 0x85ebca6bu;
    hash ^= hash >> 13u;
    return hash & map->bloom_bit_mask;
}

static int bpf_map_bloom_lookup(kernel_bpf_map_t *map,
                                const void *value) {
    for (uint32_t index = 0; index < map->bloom_hash_count; ++index) {
        uint32_t bit = bpf_bloom_hash(map, value, index);
        if (!(map->storage[bit / 8u] & (uint8_t)(1u << (bit % 8u))))
            return -EDGE_LINUX_ENOENT;
    }
    return 0;
}

static void bpf_map_bloom_update(kernel_bpf_map_t *map,
                                 const void *value) {
    for (uint32_t index = 0; index < map->bloom_hash_count; ++index) {
        uint32_t bit = bpf_bloom_hash(map, value, index);
        map->storage[bit / 8u] |= (uint8_t)(1u << (bit % 8u));
    }
}

static int bpf_map_inner_compatible_locked(
        const kernel_bpf_map_t *outer, int inner_object_id) {
    kernel_bpf_object_t *inner = bpf_object_locked(inner_object_id);
    kernel_bpf_map_t *map;

    if (!inner || inner->kind != KERNEL_BPF_OBJECT_MAP)
        return -EDGE_LINUX_EBADF;
    map = &inner->value.map;
    if (bpf_map_is_map_in_map(map) || map->type != outer->inner_type ||
        map->key_size != outer->inner_key_size ||
        map->value_size != outer->inner_value_size ||
        map->flags != outer->inner_flags)
        return -EDGE_LINUX_EINVAL;
    return 0;
}

static int bpf_map_inner_user_id_locked(int inner_object_id,
                                        uint32_t *user_id) {
    kernel_bpf_object_t *inner = bpf_object_locked(inner_object_id);

    if (!inner || inner->kind != KERNEL_BPF_OBJECT_MAP)
        return -EDGE_LINUX_ENOENT;
    *user_id = inner->user_id;
    return 0;
}

static int bpf_program_reaches_map_locked(int program_object_id,
                                          int target_map_object_id) {
    uint8_t visited[BPF_OBJECT_CAPACITY] = {0};
    int32_t pending[BPF_OBJECT_CAPACITY];
    uint32_t pending_count = 0u;

    if (program_object_id < 0 ||
        (uint32_t)program_object_id >= BPF_OBJECT_CAPACITY)
        return 0;
    pending[pending_count++] = program_object_id;
    visited[program_object_id] = 1u;
    while (pending_count) {
        int32_t current_id = pending[--pending_count];
        kernel_bpf_object_t *program;

        if (current_id < 0 || (uint32_t)current_id >= BPF_OBJECT_CAPACITY ||
            visited[current_id] == 2u)
            continue;
        visited[current_id] = 2u;
        program = bpf_object_locked(current_id);
        if (!program || program->kind != KERNEL_BPF_OBJECT_PROGRAM)
            continue;
        for (uint32_t pc = 0;
             pc + 1u < program->value.program.instruction_count; ++pc) {
            const kernel_bpf_instruction_t *instruction =
                &program->value.program.instructions[pc];
            kernel_bpf_object_t *referenced_map;

            if (instruction->code != (BPF_LD | BPF_DW | BPF_IMM) ||
                bpf_program_source(instruction) != BPF_PSEUDO_MAP_FD)
                continue;
            if (instruction->immediate == target_map_object_id)
                return 1;
            referenced_map = bpf_object_locked(instruction->immediate);
            if (referenced_map &&
                referenced_map->kind == KERNEL_BPF_OBJECT_MAP &&
                referenced_map->value.map.type ==
                    KERNEL_BPF_MAP_TYPE_PROG_ARRAY) {
                kernel_bpf_map_t *map = &referenced_map->value.map;

                for (uint32_t index = 0;
                     index < map->max_entries; ++index) {
                    int32_t next_program = -1;

                    memcpy(&next_program, bpf_map_value(map, index),
                           sizeof(next_program));
                    if (next_program >= 0 &&
                        (uint32_t)next_program < BPF_OBJECT_CAPACITY &&
                        !visited[next_program] &&
                        pending_count < BPF_OBJECT_CAPACITY) {
                        visited[next_program] = 1u;
                        pending[pending_count++] = next_program;
                    }
                }
            }
            ++pc;
        }
    }
    return 0;
}

static int bpf_map_object_compatible_locked(
        int map_object_id, const kernel_bpf_map_t *map, int object_id) {
    kernel_bpf_object_t *object = bpf_object_locked(object_id);

    if (!map || !object) return -EDGE_LINUX_EBADF;
    if (map->type == KERNEL_BPF_MAP_TYPE_PROG_ARRAY) {
        if (object->kind != KERNEL_BPF_OBJECT_PROGRAM ||
            object->value.program.type !=
                KERNEL_BPF_PROG_TYPE_CGROUP_DEVICE)
            return -EDGE_LINUX_EINVAL;
        if (bpf_program_reaches_map_locked(object_id, map_object_id))
            return -EDGE_LINUX_EINVAL;
        for (uint32_t index = 0; index < map->max_entries; ++index) {
            int32_t existing_id = -1;
            kernel_bpf_object_t *existing;

            memcpy(&existing_id,
                   map->storage + (uint64_t)index * map->entry_stride,
                   sizeof(existing_id));
            if (existing_id < 0 || existing_id == object_id) continue;
            existing = bpf_object_locked(existing_id);
            if (!existing || existing->kind != KERNEL_BPF_OBJECT_PROGRAM ||
                existing->value.program.type != object->value.program.type ||
                existing->value.program.expected_attach_type !=
                    object->value.program.expected_attach_type)
                return -EDGE_LINUX_EINVAL;
            break;
        }
        return 0;
    }
    return bpf_map_inner_compatible_locked(map, object_id);
}

static int bpf_map_object_user_id_locked(
        const kernel_bpf_map_t *map, int object_id, uint32_t *user_id) {
    kernel_bpf_object_t *object = bpf_object_locked(object_id);

    if (!map || !user_id || !object) return -EDGE_LINUX_ENOENT;
    if (map->type == KERNEL_BPF_MAP_TYPE_PROG_ARRAY) {
        if (object->kind != KERNEL_BPF_OBJECT_PROGRAM)
            return -EDGE_LINUX_ENOENT;
    } else if (object->kind != KERNEL_BPF_OBJECT_MAP) {
        return -EDGE_LINUX_ENOENT;
    }
    *user_id = object->user_id;
    return 0;
}

int kernel_bpf_map_lookup_flags(int object_id, const void *key, void *value,
                                uint64_t flags) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint32_t index;
    uint32_t free_slot;
    int status = 0;

    if (!value) return -EDGE_LINUX_EFAULT;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (map->type == KERNEL_BPF_MAP_TYPE_ARENA) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (bpf_map_is_ringbuf(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (bpf_map_is_cgroup_array(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (bpf_map_is_perf_event_array(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (bpf_map_is_stack_trace(map)) {
        uint32_t bucket;
        uint8_t *entry;

        if (flags) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        if (!key) {
            status = -EDGE_LINUX_EFAULT;
            goto out;
        }
        memcpy(&bucket, key, sizeof(bucket));
        if (bucket >= map->storage_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        entry = bpf_map_entry(map, bucket);
        if (!entry[0]) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(value, entry + 1u, map->value_size);
        goto out;
    }
    if (bpf_map_is_cpumap(map)) {
        uint32_t cpu;
        uint8_t *entry;

        if (flags) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        if (!key) {
            status = -EDGE_LINUX_EFAULT;
            goto out;
        }
        memcpy(&cpu, key, sizeof(cpu));
        if (cpu >= map->max_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        entry = bpf_map_entry(map, cpu);
        if (!entry[0]) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(value, entry + 1u, map->value_size);
        goto out;
    }
    if (bpf_map_is_devmap_array(map)) {
        uint32_t array_index;
        uint8_t *entry;

        if (flags) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        if (!key) {
            status = -EDGE_LINUX_EFAULT;
            goto out;
        }
        memcpy(&array_index, key, sizeof(array_index));
        if (array_index >= map->max_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        entry = bpf_map_entry(map, array_index);
        if (!entry[0]) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(value, entry + 1u, map->value_size);
        goto out;
    }
    if (bpf_map_is_devmap_hash(map)) {
        if (flags) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        if (!key) {
            status = -EDGE_LINUX_EFAULT;
            goto out;
        }
        bpf_map_hash_find(map, key, &index, &free_slot);
        if (index == UINT32_MAX) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        bpf_map_copy_value_out(map, index, value, 0u);
        goto out;
    }
    if (bpf_map_is_xskmap(map)) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    if (bpf_map_is_socket_map(map) || bpf_map_is_reuseport_array(map)) {
        uint8_t *entry;

        if (flags) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        if (!key) {
            status = -EDGE_LINUX_EFAULT;
            goto out;
        }
        if (map->value_size != sizeof(uint64_t)) {
            status = -EDGE_LINUX_ENOSPC;
            goto out;
        }
        if (bpf_map_is_sockmap(map) ||
            bpf_map_is_reuseport_array(map)) {
            memcpy(&index, key, sizeof(index));
            if (index >= map->max_entries) {
                status = -EDGE_LINUX_ENOENT;
                goto out;
            }
        } else {
            bpf_map_hash_find(map, key, &index, &free_slot);
            if (index == UINT32_MAX) {
                status = -EDGE_LINUX_ENOENT;
                goto out;
            }
        }
        entry = bpf_map_entry(map, index);
        if (!entry[0]) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(value, bpf_socket_map_cookie(map, index),
               sizeof(uint64_t));
        goto out;
    }
    if (bpf_map_is_legacy_cgroup_storage(map)) {
        if (!key) {
            status = -EDGE_LINUX_EFAULT;
            goto out;
        }
        if (map->type == KERNEL_BPF_MAP_TYPE_CGROUP_STORAGE) {
            if (flags) {
                status = -EDGE_LINUX_EINVAL;
                goto out;
            }
        } else {
            status = bpf_map_check_percpu_flags_locked(map, flags);
            if (status < 0) goto out;
        }
        bpf_legacy_cgroup_storage_find_locked(
            map, key, &index, 0);
        if (index == UINT32_MAX) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        bpf_map_copy_value_out(map, index, value, flags);
        goto out;
    }
    if (bpf_map_is_local_storage(map)) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    if (bpf_map_is_insn_array(map)) {
        uint32_t index;

        if (flags) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        if (!key) {
            status = -EDGE_LINUX_EFAULT;
            goto out;
        }
        memcpy(&index, key, sizeof(index));
        if (index >= map->max_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(value, bpf_map_entry(map, index), map->value_size);
        goto out;
    }
    status = bpf_map_check_percpu_flags_locked(map, flags);
    if (status < 0 || ((uint32_t)flags & ~KERNEL_BPF_F_CPU)) {
        if (status == 0) status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (bpf_map_is_bloom_filter(map)) {
        if (key) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        status = bpf_map_bloom_lookup(map, value);
    } else if (bpf_map_is_queue_stack(map)) {
        if (key) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        status = bpf_map_queue_stack_get(map, value, 0);
    } else if (!key) {
        status = -EDGE_LINUX_EFAULT;
    } else if (bpf_map_is_array(map)) {
        status = bpf_map_array_index(map, key, &index);
        if (status < 0) goto out;
        if (bpf_map_is_object_array(map)) {
            int32_t inner;
            memcpy(&inner, bpf_map_value(map, index), sizeof(inner));
            if (inner < 0) {
                status = -EDGE_LINUX_ENOENT;
                goto out;
            }
            status = bpf_map_object_user_id_locked(
                map, inner, (uint32_t *)value);
        } else {
            bpf_map_copy_value_out(map, index, value, flags);
        }
    } else if (bpf_map_is_lpm_trie(map)) {
        status = bpf_map_lpm_lookup(map, key, &index);
        if (status < 0) goto out;
        bpf_map_copy_value_out(map, index, value, flags);
    } else {
        bpf_map_hash_find(map, key, &index, &free_slot);
        if (index == UINT32_MAX) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        if (bpf_map_is_map_in_map(map)) {
            int32_t inner;
            memcpy(&inner, bpf_map_value(map, index), sizeof(inner));
            status = bpf_map_inner_user_id_locked(
                inner, (uint32_t *)value);
            if (status < 0) goto out;
        } else {
            bpf_map_copy_value_out(map, index, value, flags);
        }
        if (!bpf_map_is_percpu(map)) bpf_map_lru_touch(map, index);
    }
out:
    bpf_unlock();
    return status;
}

int kernel_bpf_map_lookup(int object_id, const void *key, void *value) {
    return kernel_bpf_map_lookup_flags(object_id, key, value, 0u);
}

static int bpf_socket_descriptor_suitable(
        const kernel_socket_descriptor_info_t *info) {
    uint32_t socket_type;

    if (!info) return 0;
    socket_type = info->type & 0xfu;
    if (socket_type != EDGE_LINUX_SOCK_STREAM &&
        socket_type != EDGE_LINUX_SOCK_SEQPACKET)
        return 0;
    if (info->domain == EDGE_LINUX_AF_UNIX)
        return info->connected != 0u;
    if (info->domain == EDGE_LINUX_AF_INET ||
        info->domain == EDGE_LINUX_AF_INET6)
        return info->connected != 0u || info->listening != 0u;
    return 0;
}

int kernel_bpf_socket_map_update(int object_id, const void *key,
                                 int32_t socket_descriptor,
                                 uint64_t flags) {
    kernel_fd_operation_lease_t new_lease = {0};
    kernel_socket_operation_request_t describe_request = {
        .operation = KERNEL_SOCKET_OPERATION_DESCRIBE,
    };
    kernel_socket_operation_result_t describe_result;
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint64_t cookie;
    uint32_t index;
    uint32_t free_slot = UINT32_MAX;
    uint8_t *entry;
    int replacing;
    int status;

    if (!key) return -EDGE_LINUX_EFAULT;
    status = kernel_fd_operation_acquire(socket_descriptor, &new_lease);
    if (status < 0) return status;
    if (!kernel_fd_operation_socket_supported(&new_lease)) {
        status = -EDGE_LINUX_ENOTSOCK;
        goto release;
    }
    status = (int)kernel_fd_operation_socket(
        &new_lease, &describe_request, &describe_result);
    if (status < 0) goto release;
    if (!bpf_socket_descriptor_suitable(
            &describe_result.output.description)) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto release;
    }
    status = kernel_fd_operation_description_id(&new_lease, &cookie);
    if (status < 0) goto release;
    if (flags > KERNEL_BPF_EXIST) {
        status = -EDGE_LINUX_EINVAL;
        goto release;
    }

    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto unlock;
    }
    map = &object->value.map;
    if (!bpf_map_is_socket_map(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto unlock;
    }
    if (map->frozen) {
        status = -EDGE_LINUX_EPERM;
        goto unlock;
    }
    if (bpf_map_is_sockmap(map)) {
        memcpy(&index, key, sizeof(index));
        if (index >= map->max_entries) {
            status = -EDGE_LINUX_E2BIG;
            goto unlock;
        }
        replacing = bpf_map_entry(map, index)[0] != 0u;
    } else {
        bpf_map_hash_find(map, key, &index, &free_slot);
        replacing = index != UINT32_MAX;
        if (!replacing) {
            if (free_slot == UINT32_MAX) {
                status = -EDGE_LINUX_E2BIG;
                goto unlock;
            }
            index = free_slot;
        }
    }
    if (replacing && flags == KERNEL_BPF_NOEXIST) {
        status = -EDGE_LINUX_EEXIST;
        goto unlock;
    }
    if (!replacing && flags == KERNEL_BPF_EXIST) {
        status = -EDGE_LINUX_ENOENT;
        goto unlock;
    }
    entry = bpf_map_entry(map, index);
    memset(entry, 0, map->entry_stride);
    entry[0] = 1u;
    if (bpf_map_is_sockhash(map))
        memcpy(entry + 1u, key, map->key_size);
    memcpy(bpf_socket_map_cookie(map, index), &cookie, sizeof(cookie));
    if (!replacing) ++map->entry_count;
    status = 0;
unlock:
    bpf_unlock();
release:
    if (kernel_fd_operation_view(&new_lease))
        (void)kernel_fd_operation_release(&new_lease);
    return status;
}

static int bpf_reuseport_descriptor_validate(
        const kernel_socket_descriptor_info_t *info) {
    uint32_t protocol;
    uint32_t socket_type;

    if (!info) return -EDGE_LINUX_EINVAL;
    if (info->domain != EDGE_LINUX_AF_INET &&
        info->domain != EDGE_LINUX_AF_INET6)
        return -EDGE_LINUX_ENOTSUPP;
    socket_type = info->type & 0xfu;
    if (socket_type != EDGE_LINUX_SOCK_STREAM &&
        socket_type != EDGE_LINUX_SOCK_DGRAM)
        return -EDGE_LINUX_ENOTSUPP;
    protocol = info->protocol;
    if (!protocol)
        protocol = socket_type == EDGE_LINUX_SOCK_STREAM ?
            EDGE_LINUX_IPPROTO_TCP : EDGE_LINUX_IPPROTO_UDP;
    if (protocol != EDGE_LINUX_IPPROTO_TCP &&
        protocol != EDGE_LINUX_IPPROTO_UDP)
        return -EDGE_LINUX_ENOTSUPP;
    return info->bound && info->reuse_port ? 0 : -EDGE_LINUX_EINVAL;
}

static int bpf_reuseport_cookie_in_use_locked(uint64_t cookie) {
    for (uint32_t object_index = 0;
         object_index < BPF_OBJECT_CAPACITY; ++object_index) {
        kernel_bpf_object_t *object = &g_bpf_objects[object_index];
        kernel_bpf_map_t *map;

        if (!object->used || object->kind != KERNEL_BPF_OBJECT_MAP)
            continue;
        map = &object->value.map;
        if (!bpf_map_is_reuseport_array(map)) continue;
        for (uint32_t entry_index = 0;
             entry_index < map->storage_entries; ++entry_index) {
            uint8_t *entry = bpf_map_entry(map, entry_index);
            uint64_t stored_cookie = 0u;

            if (!entry[0]) continue;
            memcpy(&stored_cookie,
                   bpf_socket_map_cookie(map, entry_index),
                   sizeof(stored_cookie));
            if (stored_cookie == cookie) return 1;
        }
    }
    return 0;
}

int kernel_bpf_reuseport_array_update(int object_id, const void *key,
                                      uint64_t socket_descriptor,
                                      uint64_t flags) {
    kernel_fd_operation_lease_t new_lease = {0};
    kernel_socket_operation_request_t describe_request = {
        .operation = KERNEL_SOCKET_OPERATION_DESCRIBE,
    };
    kernel_socket_operation_result_t describe_result;
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint64_t cookie;
    uint32_t index;
    uint8_t *entry;
    int replacing;
    int status;

    if (!key) return -EDGE_LINUX_EFAULT;
    if (flags > KERNEL_BPF_EXIST) return -EDGE_LINUX_EINVAL;
    memcpy(&index, key, sizeof(index));

    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto unlock_initial;
    }
    map = &object->value.map;
    if (!bpf_map_is_reuseport_array(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto unlock_initial;
    }
    if (index >= map->max_entries) {
        status = -EDGE_LINUX_E2BIG;
        goto unlock_initial;
    }
    bpf_unlock();

    if (socket_descriptor > INT32_MAX) return -EDGE_LINUX_EINVAL;

    status = kernel_fd_operation_acquire(
        (int32_t)socket_descriptor, &new_lease);
    if (status < 0) return status;
    if (!kernel_fd_operation_socket_supported(&new_lease)) {
        status = -EDGE_LINUX_ENOTSOCK;
        goto release;
    }
    status = (int)kernel_fd_operation_socket(
        &new_lease, &describe_request, &describe_result);
    if (status < 0) goto release;
    status = bpf_reuseport_descriptor_validate(
        &describe_result.output.description);
    if (status < 0) goto release;
    status = kernel_fd_operation_description_id(&new_lease, &cookie);
    if (status < 0) goto release;

    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP ||
        !bpf_map_is_reuseport_array(&object->value.map)) {
        status = -EDGE_LINUX_EBADF;
        goto unlock_update;
    }
    map = &object->value.map;
    if (map->frozen) {
        status = -EDGE_LINUX_EPERM;
        goto unlock_update;
    }
    entry = bpf_map_entry(map, index);
    replacing = entry[0] != 0u;
    if (replacing && flags == KERNEL_BPF_NOEXIST) {
        status = -EDGE_LINUX_EEXIST;
        goto unlock_update;
    }
    if (!replacing && flags == KERNEL_BPF_EXIST) {
        status = -EDGE_LINUX_ENOENT;
        goto unlock_update;
    }
    if (bpf_reuseport_cookie_in_use_locked(cookie)) {
        status = -EDGE_LINUX_EBUSY;
        goto unlock_update;
    }
    memset(entry, 0, map->entry_stride);
    entry[0] = 1u;
    memcpy(bpf_socket_map_cookie(map, index), &cookie, sizeof(cookie));
    if (!replacing) ++map->entry_count;
    status = 0;
unlock_update:
    bpf_unlock();
release:
    if (kernel_fd_operation_view(&new_lease))
        (void)kernel_fd_operation_release(&new_lease);
    return status;
unlock_initial:
    bpf_unlock();
    return status;
}

static int bpf_devmap_update_locked(kernel_bpf_map_t *map,
                                    const void *key, const void *value,
                                    uint64_t flags, int ifindex_valid,
                                    int program_status) {
    uint32_t ifindex;
    uint32_t index;
    uint32_t free_slot;
    uint8_t *entry;
    int replacing;

    if (map->frozen) return -EDGE_LINUX_EPERM;
    if (!key) return -EDGE_LINUX_EFAULT;
    if (flags > KERNEL_BPF_EXIST) return -EDGE_LINUX_EINVAL;
    memcpy(&ifindex, value, sizeof(ifindex));
    if (bpf_map_is_devmap_array(map)) {
        memcpy(&index, key, sizeof(index));
        if (index >= map->max_entries) return -EDGE_LINUX_E2BIG;
        if (flags == KERNEL_BPF_NOEXIST) return -EDGE_LINUX_EEXIST;
        if (!ifindex) {
            int32_t program = -1;

            if (map->value_size == 2u * sizeof(uint32_t))
                memcpy(&program,
                       (const uint8_t *)value + sizeof(uint32_t),
                       sizeof(program));
            if (program > 0) return -EDGE_LINUX_EINVAL;
            entry = bpf_map_entry(map, index);
            if (entry[0] && map->entry_count) --map->entry_count;
            memset(entry, 0, map->entry_stride);
            return 0;
        }
        if (!ifindex_valid) return -EDGE_LINUX_EINVAL;
        if (program_status < 0) return program_status;
        entry = bpf_map_entry(map, index);
        if (!entry[0]) ++map->entry_count;
        memset(entry, 0, map->entry_stride);
        entry[0] = 1u;
        memcpy(entry + 1u, &ifindex, sizeof(ifindex));
        return 0;
    }
    if (!ifindex) return -EDGE_LINUX_EINVAL;
    if (!ifindex_valid) return -EDGE_LINUX_EINVAL;
    if (program_status < 0) return program_status;
    bpf_map_hash_find(map, key, &index, &free_slot);
    replacing = index != UINT32_MAX;
    if (replacing && flags == KERNEL_BPF_NOEXIST)
        return -EDGE_LINUX_EEXIST;
    if (!replacing) {
        if (free_slot == UINT32_MAX) return -EDGE_LINUX_E2BIG;
        index = free_slot;
        ++map->entry_count;
    }
    entry = bpf_map_entry(map, index);
    memset(entry, 0, map->entry_stride);
    entry[0] = 1u;
    memcpy(entry + 1u, key, map->key_size);
    memcpy(bpf_map_value(map, index), &ifindex, sizeof(ifindex));
    return 0;
}

static int bpf_xskmap_update_locked(kernel_bpf_map_t *map,
                                    const void *key, uint64_t flags,
                                    int socket_status) {
    uint32_t index;

    if (map->frozen) return -EDGE_LINUX_EPERM;
    if (!key) return -EDGE_LINUX_EFAULT;
    if (flags > KERNEL_BPF_EXIST) return -EDGE_LINUX_EINVAL;
    memcpy(&index, key, sizeof(index));
    if (index >= map->max_entries) return -EDGE_LINUX_E2BIG;
    return socket_status;
}

int kernel_bpf_map_update(int object_id, const void *key, const void *value,
                          uint64_t flags) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint8_t *entry;
    uint32_t index;
    uint32_t free_slot;
    int32_t released_inner = -1;
    int32_t new_inner = -1;
    int replacing = 0;
    int status = 0;

    if (!value) return -EDGE_LINUX_EFAULT;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (map->type == KERNEL_BPF_MAP_TYPE_ARENA) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    if (bpf_map_is_ringbuf(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (bpf_map_is_perf_event_array(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (bpf_map_is_cgroup_array(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (bpf_map_is_stack_trace(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (bpf_map_is_cpumap(map)) {
        uint32_t cpu;
        uint32_t qsize;
        uint8_t *cpu_entry;

        if (map->frozen) {
            status = -EDGE_LINUX_EPERM;
            goto out;
        }
        if (!key) {
            status = -EDGE_LINUX_EFAULT;
            goto out;
        }
        if (flags > KERNEL_BPF_EXIST) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        memcpy(&cpu, key, sizeof(cpu));
        if (cpu >= map->max_entries) {
            status = -EDGE_LINUX_E2BIG;
            goto out;
        }
        if (flags == KERNEL_BPF_NOEXIST) {
            status = -EDGE_LINUX_EEXIST;
            goto out;
        }
        memcpy(&qsize, value, sizeof(qsize));
        if (qsize > 16384u) {
            status = -EDGE_LINUX_EOVERFLOW;
            goto out;
        }
        if (cpu >= edge_smp_nr_cpu_ids()) {
            status = -EDGE_LINUX_ENODEV;
            goto out;
        }
        if (qsize && map->value_size == 2u * sizeof(uint32_t)) {
            int32_t program_object;

            memcpy(&program_object,
                   (const uint8_t *)value + sizeof(uint32_t),
                   sizeof(program_object));
            if (program_object > 0) {
                kernel_bpf_object_t *program =
                    bpf_object_locked(program_object);

                status = !program ? -EDGE_LINUX_EBADF :
                    -EDGE_LINUX_EINVAL;
                goto out;
            }
        }
        cpu_entry = bpf_map_entry(map, cpu);
        if (!qsize) {
            if (cpu_entry[0] && map->entry_count) --map->entry_count;
            memset(cpu_entry, 0, map->entry_stride);
            goto out;
        }
        if (!cpu_entry[0]) ++map->entry_count;
        memset(cpu_entry, 0, map->entry_stride);
        cpu_entry[0] = 1u;
        memcpy(cpu_entry + 1u, &qsize, sizeof(qsize));
        goto out;
    }
    if (bpf_map_is_devmap(map)) {
        int32_t program_object = -1;
        int program_status = 0;

        if (map->value_size == 2u * sizeof(uint32_t))
            memcpy(&program_object,
                   (const uint8_t *)value + sizeof(uint32_t),
                   sizeof(program_object));
        if (program_object > 0)
            program_status = -EDGE_LINUX_EINVAL;
        status = bpf_devmap_update_locked(
            map, key, value, flags, 1, program_status);
        goto out;
    }
    if (bpf_map_is_xskmap(map)) {
        status = bpf_xskmap_update_locked(
            map, key, flags, -EDGE_LINUX_EBADF);
        goto out;
    }
    if (bpf_map_is_socket_map(map)) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    if (bpf_map_is_reuseport_array(map)) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    if (bpf_map_is_legacy_cgroup_storage(map)) {
        if (map->frozen) {
            status = -EDGE_LINUX_EPERM;
            goto out;
        }
        if (!key) {
            status = -EDGE_LINUX_EFAULT;
            goto out;
        }
        if (map->type == KERNEL_BPF_MAP_TYPE_CGROUP_STORAGE) {
            if (flags != KERNEL_BPF_ANY &&
                flags != KERNEL_BPF_EXIST) {
                status = -EDGE_LINUX_EINVAL;
                goto out;
            }
        } else {
            status = bpf_map_check_percpu_flags_locked(map, flags);
            if (status < 0) goto out;
            if (((uint32_t)flags &
                 ~(KERNEL_BPF_EXIST | KERNEL_BPF_F_CPU |
                   KERNEL_BPF_F_ALL_CPUS)) != 0u) {
                status = -EDGE_LINUX_EINVAL;
                goto out;
            }
        }
        bpf_legacy_cgroup_storage_find_locked(
            map, key, &index, 0);
        if (index == UINT32_MAX) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        bpf_map_copy_value_in(map, index, value, flags);
        goto out;
    }
    if (bpf_map_is_local_storage(map)) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    if (bpf_map_is_insn_array(map)) {
        const uint32_t *fields = (const uint32_t *)value;
        uint32_t index;

        if (map->frozen) {
            status = -EDGE_LINUX_EPERM;
            goto out;
        }
        if (!key) {
            status = -EDGE_LINUX_EFAULT;
            goto out;
        }
        memcpy(&index, key, sizeof(index));
        if (index >= map->max_entries) {
            status = -EDGE_LINUX_E2BIG;
            goto out;
        }
        if (flags & KERNEL_BPF_NOEXIST) {
            status = -EDGE_LINUX_EEXIST;
            goto out;
        }
        if (fields[1] || fields[2]) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        memset(bpf_map_entry(map, index), 0, map->entry_stride);
        memcpy(bpf_map_entry(map, index), fields, sizeof(fields[0]));
        goto out;
    }
    if (bpf_map_is_map_in_map(map) ||
        map->type == KERNEL_BPF_MAP_TYPE_PROG_ARRAY) {
        memcpy(&new_inner, value, sizeof(new_inner));
        status = bpf_map_object_compatible_locked(
            object_id, map, new_inner);
        if (status < 0) goto out;
        if (g_bpf_objects[new_inner].references == UINT32_MAX) {
            status = -EDGE_LINUX_EOVERFLOW;
            goto out;
        }
    }
    status = bpf_map_check_percpu_flags_locked(map, flags);
    if (status < 0) goto out;
    if (!bpf_map_is_percpu(map) &&
        flags != KERNEL_BPF_ANY && flags != KERNEL_BPF_NOEXIST &&
        flags != KERNEL_BPF_EXIST) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (map->frozen) {
        status = -EDGE_LINUX_EPERM;
        goto out;
    }
    if (bpf_map_is_bloom_filter(map)) {
        if (key || flags != KERNEL_BPF_ANY) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        bpf_map_bloom_update(map, value);
    } else if (bpf_map_is_queue_stack(map)) {
        if (key || flags == KERNEL_BPF_NOEXIST ||
            flags > KERNEL_BPF_EXIST) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        if (map->entry_count == map->max_entries) {
            if (flags != KERNEL_BPF_EXIST) {
                status = -EDGE_LINUX_E2BIG;
                goto out;
            }
            map->queue_tail = (map->queue_tail + 1u) % map->max_entries;
        } else {
            ++map->entry_count;
        }
        memcpy(bpf_map_entry(map, map->queue_head), value,
               map->value_size);
        map->queue_head = (map->queue_head + 1u) % map->max_entries;
    } else if (!key) {
        status = -EDGE_LINUX_EFAULT;
    } else if (bpf_map_is_array(map)) {
        if (bpf_map_is_object_array(map) && flags != KERNEL_BPF_ANY) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        if (!bpf_map_is_object_array(map) &&
            flags == KERNEL_BPF_NOEXIST) {
            status = -EDGE_LINUX_EEXIST;
            goto out;
        }
        status = bpf_map_array_index(map, key, &index);
        if (status < 0) goto out;
        if (bpf_map_is_object_array(map)) {
            memcpy(&released_inner, bpf_map_value(map, index),
                   sizeof(released_inner));
            ++g_bpf_objects[new_inner].references;
            memcpy(bpf_map_value(map, index), &new_inner,
                   sizeof(new_inner));
        } else {
            bpf_map_copy_value_in(map, index, value, flags);
        }
    } else if (bpf_map_is_lpm_trie(map)) {
        uint32_t prefix_length = bpf_lpm_prefix_length(key);
        uint32_t max_prefix =
            (map->key_size - sizeof(uint32_t)) * 8u;

        if (prefix_length > max_prefix) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        bpf_map_lpm_find_exact(map, key, &index, &free_slot);
        replacing = index != UINT32_MAX;
        if (replacing && flags == KERNEL_BPF_NOEXIST) {
            status = -EDGE_LINUX_EEXIST;
            goto out;
        }
        if (!replacing && flags == KERNEL_BPF_EXIST) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        if (!replacing) {
            if (free_slot == UINT32_MAX) {
                status = -EDGE_LINUX_ENOSPC;
                goto out;
            }
            index = free_slot;
            ++map->entry_count;
        }
        entry = bpf_map_entry(map, index);
        entry[0] = 1u;
        memcpy(entry + 1u, key, map->key_size);
        bpf_map_copy_value_in(map, index, value, flags);
    } else {
        bpf_map_hash_find(map, key, &index, &free_slot);
        replacing = index != UINT32_MAX;
        if (index != UINT32_MAX && flags == KERNEL_BPF_NOEXIST) {
            status = -EDGE_LINUX_EEXIST;
            goto out;
        }
        if (index == UINT32_MAX && flags == KERNEL_BPF_EXIST) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        if (index == UINT32_MAX) {
            if (bpf_map_has_percpu_lru(map))
                free_slot = bpf_map_lru_free_slot(map);
            if (free_slot == UINT32_MAX &&
                map->type == KERNEL_BPF_MAP_TYPE_RHASH &&
                map->entry_count < map->max_entries) {
                status = bpf_rhash_grow_locked(map);
                if (status < 0) goto out;
                bpf_map_hash_find(map, key, &index, &free_slot);
            }
            if (free_slot == UINT32_MAX) {
                if (!bpf_map_is_lru_hash(map)) {
                    status = -EDGE_LINUX_E2BIG;
                    goto out;
                }
                free_slot = bpf_map_lru_oldest(map);
                if (free_slot == UINT32_MAX) {
                    status = -EDGE_LINUX_E2BIG;
                    goto out;
                }
            }
            index = free_slot;
            if (!bpf_map_entry(map, index)[0]) ++map->entry_count;
        }
        entry = bpf_map_entry(map, index);
        entry[0] = 1u;
        memcpy(entry + 1u, key, map->key_size);
        if (bpf_map_is_map_in_map(map)) {
            if (replacing)
                memcpy(&released_inner, bpf_map_value(map, index),
                       sizeof(released_inner));
            ++g_bpf_objects[new_inner].references;
            memcpy(bpf_map_value(map, index), &new_inner,
                   sizeof(new_inner));
        } else {
            bpf_map_copy_value_in(map, index, value, flags);
        }
        bpf_map_lru_touch(map, index);
    }
out:
    bpf_unlock();
    if (released_inner >= 0)
        kernel_bpf_object_release(released_inner);
    return status;
}

int kernel_bpf_devmap_update(int object_id, const void *key,
                             const void *value, uint64_t flags,
                             int ifindex_valid, int program_status) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    int status;

    if (!value) return -EDGE_LINUX_EFAULT;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (!bpf_map_is_devmap(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    status = bpf_devmap_update_locked(
        map, key, value, flags, ifindex_valid, program_status);
out:
    bpf_unlock();
    return status;
}

int kernel_bpf_xskmap_update(int object_id, const void *key,
                             const void *value, uint64_t flags,
                             int socket_status) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    int status;

    if (!value) return -EDGE_LINUX_EFAULT;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (!bpf_map_is_xskmap(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    status = bpf_xskmap_update_locked(
        map, key, flags, socket_status);
out:
    bpf_unlock();
    return status;
}

int kernel_bpf_perf_event_array_update(int object_id, const void *key,
                                       int32_t event_id, uint64_t flags) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint32_t index;
    int32_t released_event = -1;
    int status;

    if (!key) return -EDGE_LINUX_EFAULT;
    if (flags != KERNEL_BPF_ANY) return -EDGE_LINUX_EINVAL;
    status = kernel_perf_event_retain(event_id);
    if (status < 0) return status;

    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (!bpf_map_is_perf_event_array(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (map->frozen) {
        status = -EDGE_LINUX_EPERM;
        goto out;
    }
    status = bpf_map_array_index(map, key, &index);
    if (status < 0) goto out;
    memcpy(&released_event, bpf_map_value(map, index),
           sizeof(released_event));
    memcpy(bpf_map_value(map, index), &event_id, sizeof(event_id));
    status = 0;
out:
    bpf_unlock();
    if (status < 0)
        kernel_perf_event_release(event_id);
    else if (released_event >= 0)
        kernel_perf_event_release(released_event);
    return status;
}

int kernel_bpf_cgroup_array_update(int object_id, const void *key,
                                   uint64_t cgroup_reference,
                                   uint64_t flags) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint64_t released_reference = 0u;
    uint32_t index;
    int status;

    if (!key) return -EDGE_LINUX_EFAULT;
    if (!cgroup_reference) return -EDGE_LINUX_EBADF;
    if (flags != KERNEL_BPF_ANY) return -EDGE_LINUX_EINVAL;

    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (!bpf_map_is_cgroup_array(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (map->frozen) {
        status = -EDGE_LINUX_EPERM;
        goto out;
    }
    status = bpf_map_array_index(map, key, &index);
    if (status < 0) goto out;
    memcpy(&released_reference, bpf_map_value(map, index),
           sizeof(released_reference));
    memcpy(bpf_map_value(map, index), &cgroup_reference,
           sizeof(cgroup_reference));
    status = 0;
out:
    bpf_unlock();
    if (status == 0 && released_reference)
        cgroupfs_reference_put(released_reference);
    return status;
}

static uint8_t *bpf_local_storage_value(kernel_bpf_map_t *map,
                                        uint32_t index) {
    return bpf_map_entry(map, index) + 1u +
        bpf_local_storage_owner_size(map);
}

static void bpf_local_storage_find_locked(kernel_bpf_map_t *map,
                                          bpf_local_storage_owner_t owner,
                                          uint32_t *index_out,
                                          uint32_t *free_out) {
    uint32_t found = UINT32_MAX;
    uint32_t free_slot = UINT32_MAX;

    for (uint32_t index = 0; index < map->storage_entries; ++index) {
        uint8_t *entry = bpf_map_entry(map, index);
        bpf_local_storage_owner_t stored_owner = {0};
        size_t owner_size = bpf_local_storage_owner_size(map);

        if (!entry[0]) {
            if (free_slot == UINT32_MAX) free_slot = index;
            continue;
        }
        memcpy(&stored_owner, entry + 1u, owner_size);
        if (stored_owner.primary == owner.primary &&
            stored_owner.secondary == owner.secondary) {
            found = index;
            break;
        }
    }
    if (index_out) *index_out = found;
    if (free_out) *free_out = free_slot;
}

static int bpf_local_storage_lookup(int object_id, uint32_t map_type,
                                    bpf_local_storage_owner_t owner,
                                    void *value,
                                    uint64_t flags) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint32_t index;
    int status = 0;

    if (!value) return -EDGE_LINUX_EFAULT;
    if (!owner.primary) return -EDGE_LINUX_EBADF;
    if (flags) return -EDGE_LINUX_EINVAL;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (map->type != map_type || !bpf_map_is_local_storage(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    bpf_local_storage_find_locked(map, owner, &index, 0);
    if (index == UINT32_MAX) {
        status = -EDGE_LINUX_ENOENT;
        goto out;
    }
    memcpy(value, bpf_local_storage_value(map, index),
           map->value_size);
out:
    bpf_unlock();
    return status;
}

static int bpf_local_storage_update(int object_id, uint32_t map_type,
                                    bpf_local_storage_owner_t owner,
                                    const void *value,
                                    uint64_t flags) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint32_t index;
    uint32_t free_slot;
    int retained = 0;
    int replacing;
    int status;

    if (!value) return -EDGE_LINUX_EFAULT;
    if (!owner.primary) return -EDGE_LINUX_EBADF;
    if (flags > KERNEL_BPF_EXIST) return -EDGE_LINUX_EINVAL;
    if (map_type == KERNEL_BPF_MAP_TYPE_CGRP_STORAGE) {
        status = cgroupfs_reference_retain(owner.primary);
        if (status < 0) return status;
        retained = 1;
    }

    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (map->type != map_type || !bpf_map_is_local_storage(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (map->frozen) {
        status = -EDGE_LINUX_EPERM;
        goto out;
    }
    bpf_local_storage_find_locked(map, owner, &index, &free_slot);
    replacing = index != UINT32_MAX;
    if (replacing && flags == KERNEL_BPF_NOEXIST) {
        status = -EDGE_LINUX_EEXIST;
        goto out;
    }
    if (!replacing && flags == KERNEL_BPF_EXIST) {
        status = -EDGE_LINUX_ENOENT;
        goto out;
    }
    if (!replacing) {
        uint8_t *entry;

        if (free_slot == UINT32_MAX) {
            status = -EDGE_LINUX_ENOMEM;
            goto out;
        }
        index = free_slot;
        entry = bpf_map_entry(map, index);
        memset(entry, 0, map->entry_stride);
        entry[0] = 1u;
        memcpy(entry + 1u, &owner, bpf_local_storage_owner_size(map));
        ++map->entry_count;
        retained = 0;
    }
    memcpy(bpf_local_storage_value(map, index), value,
           map->value_size);
    status = 0;
out:
    bpf_unlock();
    if (retained) cgroupfs_reference_put(owner.primary);
    return status;
}

static int bpf_local_storage_delete(int object_id, uint32_t map_type,
                                    bpf_local_storage_owner_t owner) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    bpf_local_storage_owner_t released_owner = {0};
    uint32_t index;
    int status = 0;

    if (!owner.primary) return -EDGE_LINUX_EBADF;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (map->type != map_type || !bpf_map_is_local_storage(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (map->frozen) {
        status = -EDGE_LINUX_EPERM;
        goto out;
    }
    bpf_local_storage_find_locked(map, owner, &index, 0);
    if (index == UINT32_MAX) {
        status = -EDGE_LINUX_ENOENT;
        goto out;
    }
    memcpy(&released_owner, bpf_map_entry(map, index) + 1u,
           bpf_local_storage_owner_size(map));
    memset(bpf_map_entry(map, index), 0, map->entry_stride);
    if (map->entry_count) --map->entry_count;
out:
    bpf_unlock();
    if (released_owner.primary &&
        map_type == KERNEL_BPF_MAP_TYPE_CGRP_STORAGE)
        cgroupfs_reference_put(released_owner.primary);
    return status;
}

int kernel_bpf_cgrp_storage_lookup(int object_id,
                                   uint64_t cgroup_reference,
                                   void *value, uint64_t flags) {
    bpf_local_storage_owner_t owner = {cgroup_reference, 0u};

    return bpf_local_storage_lookup(
        object_id, KERNEL_BPF_MAP_TYPE_CGRP_STORAGE,
        owner, value, flags);
}

int kernel_bpf_cgrp_storage_update(int object_id,
                                   uint64_t cgroup_reference,
                                   const void *value, uint64_t flags) {
    bpf_local_storage_owner_t owner = {cgroup_reference, 0u};

    return bpf_local_storage_update(
        object_id, KERNEL_BPF_MAP_TYPE_CGRP_STORAGE,
        owner, value, flags);
}

int kernel_bpf_cgrp_storage_delete(int object_id,
                                   uint64_t cgroup_reference) {
    bpf_local_storage_owner_t owner = {cgroup_reference, 0u};

    return bpf_local_storage_delete(
        object_id, KERNEL_BPF_MAP_TYPE_CGRP_STORAGE, owner);
}

int kernel_bpf_sk_storage_lookup(int object_id,
                                 uint64_t socket_identity,
                                 void *value, uint64_t flags) {
    bpf_local_storage_owner_t owner = {socket_identity, 0u};

    return bpf_local_storage_lookup(
        object_id, KERNEL_BPF_MAP_TYPE_SK_STORAGE, owner, value, flags);
}

int kernel_bpf_sk_storage_update(int object_id,
                                 uint64_t socket_identity,
                                 const void *value, uint64_t flags) {
    bpf_local_storage_owner_t owner = {socket_identity, 0u};

    return bpf_local_storage_update(
        object_id, KERNEL_BPF_MAP_TYPE_SK_STORAGE, owner, value, flags);
}

int kernel_bpf_sk_storage_delete(int object_id,
                                 uint64_t socket_identity) {
    bpf_local_storage_owner_t owner = {socket_identity, 0u};

    return bpf_local_storage_delete(
        object_id, KERNEL_BPF_MAP_TYPE_SK_STORAGE, owner);
}

int kernel_bpf_sk_storage_clone(uint64_t source_socket_identity,
                                uint64_t target_socket_identity) {
    bpf_local_storage_owner_t source = {source_socket_identity, 0u};
    bpf_local_storage_owner_t target = {target_socket_identity, 0u};
    int status = 0;

    if (!source.primary || !target.primary)
        return -EDGE_LINUX_EBADF;
    bpf_lock();
    for (uint32_t object_index = 0;
         object_index < BPF_OBJECT_CAPACITY; ++object_index) {
        kernel_bpf_object_t *object = &g_bpf_objects[object_index];
        kernel_bpf_map_t *map;
        uint32_t source_index;
        uint32_t target_index;
        uint32_t free_slot;
        uint8_t *entry;

        if (!object->used ||
            object->kind != KERNEL_BPF_OBJECT_MAP)
            continue;
        map = &object->value.map;
        if (!bpf_map_is_sk_storage(map) ||
            !(map->flags & KERNEL_BPF_MAP_CLONE))
            continue;
        bpf_local_storage_find_locked(
            map, source, &source_index, 0);
        if (source_index == UINT32_MAX) continue;
        bpf_local_storage_find_locked(
            map, target, &target_index, &free_slot);
        if (target_index != UINT32_MAX) continue;
        if (free_slot == UINT32_MAX) {
            status = -EDGE_LINUX_ENOMEM;
            break;
        }
        entry = bpf_map_entry(map, free_slot);
        memset(entry, 0, map->entry_stride);
        entry[0] = 1u;
        memcpy(entry + 1u, &target,
               bpf_local_storage_owner_size(map));
        memcpy(bpf_local_storage_value(map, free_slot),
               bpf_local_storage_value(map, source_index),
               map->value_size);
        ++map->entry_count;
    }
    bpf_unlock();
    return status;
}

static bpf_local_storage_owner_t bpf_inode_storage_owner(
        uint64_t filesystem_identity, uint32_t inode_number,
        uint32_t inode_generation) {
    bpf_local_storage_owner_t owner;

    owner.primary = filesystem_identity;
    owner.secondary = ((uint64_t)inode_generation << 32u) |
                      inode_number;
    return owner;
}

int kernel_bpf_inode_storage_lookup(int object_id,
                                    uint64_t filesystem_identity,
                                    uint32_t inode_number,
                                    uint32_t inode_generation,
                                    void *value, uint64_t flags) {
    return bpf_local_storage_lookup(
        object_id, KERNEL_BPF_MAP_TYPE_INODE_STORAGE,
        bpf_inode_storage_owner(filesystem_identity, inode_number,
                                inode_generation),
        value, flags);
}

int kernel_bpf_inode_storage_update(int object_id,
                                    uint64_t filesystem_identity,
                                    uint32_t inode_number,
                                    uint32_t inode_generation,
                                    const void *value, uint64_t flags) {
    return bpf_local_storage_update(
        object_id, KERNEL_BPF_MAP_TYPE_INODE_STORAGE,
        bpf_inode_storage_owner(filesystem_identity, inode_number,
                                inode_generation),
        value, flags);
}

int kernel_bpf_inode_storage_delete(int object_id,
                                    uint64_t filesystem_identity,
                                    uint32_t inode_number,
                                    uint32_t inode_generation) {
    return bpf_local_storage_delete(
        object_id, KERNEL_BPF_MAP_TYPE_INODE_STORAGE,
        bpf_inode_storage_owner(filesystem_identity, inode_number,
                                inode_generation));
}

uint32_t kernel_bpf_inode_storage_owner_release(
        uint64_t filesystem_identity, uint32_t inode_number,
        uint32_t inode_generation) {
    bpf_local_storage_owner_t expected = bpf_inode_storage_owner(
        filesystem_identity, inode_number, inode_generation);
    uint32_t released = 0u;

    if (!filesystem_identity) return 0u;
    bpf_lock();
    for (uint32_t object_index = 0;
         object_index < BPF_OBJECT_CAPACITY; ++object_index) {
        kernel_bpf_object_t *object = &g_bpf_objects[object_index];
        kernel_bpf_map_t *map;

        if (!object->used || object->kind != KERNEL_BPF_OBJECT_MAP)
            continue;
        map = &object->value.map;
        if (map->type != KERNEL_BPF_MAP_TYPE_INODE_STORAGE)
            continue;
        for (uint32_t entry_index = 0;
             entry_index < map->storage_entries; ++entry_index) {
            uint8_t *entry = bpf_map_entry(map, entry_index);
            bpf_local_storage_owner_t owner = {0};

            if (!entry[0]) continue;
            memcpy(&owner, entry + 1u, sizeof(owner));
            if (owner.primary != expected.primary ||
                owner.secondary != expected.secondary)
                continue;
            memset(entry, 0, map->entry_stride);
            if (map->entry_count) --map->entry_count;
            ++released;
        }
    }
    bpf_unlock();
    return released;
}

static bpf_local_storage_owner_t bpf_task_storage_owner(
        int32_t tid, uint64_t start_time_ticks) {
    bpf_local_storage_owner_t owner;

    owner.primary = (uint64_t)(uint32_t)tid;
    owner.secondary = start_time_ticks;
    return owner;
}

int kernel_bpf_task_storage_lookup(int object_id, int32_t tid,
                                   uint64_t start_time_ticks,
                                   void *value, uint64_t flags) {
    return bpf_local_storage_lookup(
        object_id, KERNEL_BPF_MAP_TYPE_TASK_STORAGE,
        bpf_task_storage_owner(tid, start_time_ticks), value, flags);
}

int kernel_bpf_task_storage_update(int object_id, int32_t tid,
                                   uint64_t start_time_ticks,
                                   const void *value, uint64_t flags) {
    return bpf_local_storage_update(
        object_id, KERNEL_BPF_MAP_TYPE_TASK_STORAGE,
        bpf_task_storage_owner(tid, start_time_ticks), value, flags);
}

int kernel_bpf_task_storage_delete(int object_id, int32_t tid,
                                   uint64_t start_time_ticks) {
    return bpf_local_storage_delete(
        object_id, KERNEL_BPF_MAP_TYPE_TASK_STORAGE,
        bpf_task_storage_owner(tid, start_time_ticks));
}

void kernel_bpf_task_storage_task_exit(int32_t tid,
                                       uint64_t start_time_ticks) {
    bpf_local_storage_owner_t owner =
        bpf_task_storage_owner(tid, start_time_ticks);

    if (tid <= 0 || !start_time_ticks) return;
    bpf_lock();
    for (uint32_t object_index = 0;
         object_index < BPF_OBJECT_CAPACITY; ++object_index) {
        kernel_bpf_object_t *object = &g_bpf_objects[object_index];
        kernel_bpf_map_t *map;
        uint32_t index;

        if (!object->used || object->kind != KERNEL_BPF_OBJECT_MAP)
            continue;
        map = &object->value.map;
        if (!bpf_map_is_task_storage(map)) continue;
        bpf_local_storage_find_locked(map, owner, &index, 0);
        if (index == UINT32_MAX) continue;
        memset(bpf_map_entry(map, index), 0, map->entry_stride);
        if (map->entry_count) --map->entry_count;
    }
    bpf_unlock();
}

int kernel_bpf_map_lookup_and_delete(int object_id, const void *key,
                                     void *value) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint32_t index;
    uint32_t free_slot;
    int32_t released_inner = -1;
    int status = 0;

    if (!value) return -EDGE_LINUX_EFAULT;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (map->type == KERNEL_BPF_MAP_TYPE_ARENA) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    if (map->frozen) {
        status = -EDGE_LINUX_EPERM;
        goto out;
    }
    if (bpf_map_is_queue_stack(map)) {
        if (key) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        status = bpf_map_queue_stack_get(map, value, 1);
        goto out;
    }
    if (bpf_map_is_stack_trace(map)) {
        uint32_t bucket;
        uint8_t *entry;

        if (!key) {
            status = -EDGE_LINUX_EFAULT;
            goto out;
        }
        memcpy(&bucket, key, sizeof(bucket));
        if (bucket >= map->storage_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        entry = bpf_map_entry(map, bucket);
        if (!entry[0]) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(value, entry + 1u, map->value_size);
        memset(entry, 0, map->entry_stride);
        if (map->entry_count) --map->entry_count;
        goto out;
    }
    if (bpf_map_is_cpumap(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (bpf_map_is_devmap(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (bpf_map_is_xskmap(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (bpf_map_is_socket_map(map)) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    if (bpf_map_is_reuseport_array(map)) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    if (bpf_map_is_local_storage(map)) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    if (bpf_map_is_insn_array(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (bpf_map_is_bloom_filter(map) || bpf_map_is_lpm_trie(map)) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    if (!key) {
        status = -EDGE_LINUX_EFAULT;
        goto out;
    }
    if (!bpf_map_is_hash(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    bpf_map_hash_find(map, key, &index, &free_slot);
    if (index == UINT32_MAX) {
        status = -EDGE_LINUX_ENOENT;
        goto out;
    }
    if (bpf_map_is_map_in_map(map)) {
        memcpy(&released_inner, bpf_map_value(map, index),
               sizeof(released_inner));
        status = bpf_map_inner_user_id_locked(
            released_inner, (uint32_t *)value);
        if (status < 0) goto out;
    } else {
        bpf_map_copy_value_out(map, index, value, 0u);
    }
    memset(bpf_map_entry(map, index), 0, map->entry_stride);
    if (map->entry_count) --map->entry_count;
out:
    bpf_unlock();
    if (released_inner >= 0)
        kernel_bpf_object_release(released_inner);
    return status;
}

int kernel_bpf_map_delete(int object_id, const void *key) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint32_t index;
    uint32_t free_slot;
    int32_t released_inner = -1;
    int32_t released_event = -1;
    uint64_t released_cgroup = 0u;
    int status = 0;

    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (map->type == KERNEL_BPF_MAP_TYPE_ARENA) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    if (map->frozen) {
        status = -EDGE_LINUX_EPERM;
        goto out;
    }
    if (bpf_map_is_queue_stack(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (bpf_map_is_bloom_filter(map)) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    if (!key) {
        status = -EDGE_LINUX_EFAULT;
        goto out;
    }
    if (bpf_map_is_stack_trace(map)) {
        uint32_t bucket;
        uint8_t *entry;

        memcpy(&bucket, key, sizeof(bucket));
        if (bucket >= map->storage_entries) {
            status = -EDGE_LINUX_E2BIG;
            goto out;
        }
        entry = bpf_map_entry(map, bucket);
        if (!entry[0]) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memset(entry, 0, map->entry_stride);
        if (map->entry_count) --map->entry_count;
        goto out;
    }
    if (bpf_map_is_cpumap(map)) {
        uint32_t cpu;
        uint8_t *entry;

        memcpy(&cpu, key, sizeof(cpu));
        if (cpu >= map->max_entries) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        entry = bpf_map_entry(map, cpu);
        if (entry[0] && map->entry_count) --map->entry_count;
        memset(entry, 0, map->entry_stride);
        goto out;
    }
    if (bpf_map_is_devmap_array(map)) {
        uint32_t array_index;
        uint8_t *entry;

        memcpy(&array_index, key, sizeof(array_index));
        if (array_index >= map->max_entries) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        entry = bpf_map_entry(map, array_index);
        if (entry[0] && map->entry_count) --map->entry_count;
        memset(entry, 0, map->entry_stride);
        goto out;
    }
    if (bpf_map_is_devmap_hash(map)) {
        bpf_map_hash_find(map, key, &index, &free_slot);
        if (index == UINT32_MAX) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memset(bpf_map_entry(map, index), 0, map->entry_stride);
        if (map->entry_count) --map->entry_count;
        goto out;
    }
    if (bpf_map_is_xskmap(map)) {
        uint32_t index;
        uint8_t *entry;

        memcpy(&index, key, sizeof(index));
        if (index >= map->max_entries) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        entry = bpf_map_entry(map, index);
        if (entry[0] && map->entry_count) --map->entry_count;
        memset(entry, 0, map->entry_stride);
        goto out;
    }
    if (bpf_map_is_socket_map(map)) {
        uint8_t *entry;

        if (bpf_map_is_sockmap(map)) {
            memcpy(&index, key, sizeof(index));
            if (index >= map->max_entries) {
                status = -EDGE_LINUX_EINVAL;
                goto out;
            }
        } else {
            bpf_map_hash_find(map, key, &index, &free_slot);
            if (index == UINT32_MAX) {
                status = -EDGE_LINUX_ENOENT;
                goto out;
            }
        }
        entry = bpf_map_entry(map, index);
        if (!entry[0]) {
            status = bpf_map_is_sockmap(map) ?
                -EDGE_LINUX_EINVAL : -EDGE_LINUX_ENOENT;
            goto out;
        }
        memset(entry, 0, map->entry_stride);
        if (map->entry_count) --map->entry_count;
        status = 0;
        goto out;
    }
    if (bpf_map_is_reuseport_array(map)) {
        uint8_t *entry;

        memcpy(&index, key, sizeof(index));
        if (index >= map->max_entries) {
            status = -EDGE_LINUX_E2BIG;
            goto out;
        }
        entry = bpf_map_entry(map, index);
        if (!entry[0]) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memset(entry, 0, map->entry_stride);
        if (map->entry_count) --map->entry_count;
        status = 0;
        goto out;
    }
    if (bpf_map_is_legacy_cgroup_storage(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (bpf_map_is_local_storage(map)) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    if (bpf_map_is_insn_array(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (bpf_map_is_array(map) && !bpf_map_is_object_array(map) &&
        !bpf_map_is_perf_event_array(map) &&
        !bpf_map_is_cgroup_array(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (bpf_map_is_object_array(map)) {
        status = bpf_map_array_index(map, key, &index);
        if (status < 0) goto out;
        memcpy(&released_inner, bpf_map_value(map, index),
               sizeof(released_inner));
        if (released_inner < 0) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        {
            int32_t empty = -1;
            memcpy(bpf_map_value(map, index), &empty, sizeof(empty));
        }
        goto out;
    }
    if (bpf_map_is_perf_event_array(map)) {
        int32_t empty = -1;

        status = bpf_map_array_index(map, key, &index);
        if (status < 0) goto out;
        memcpy(&released_event, bpf_map_value(map, index),
               sizeof(released_event));
        if (released_event < 0) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(bpf_map_value(map, index), &empty, sizeof(empty));
        goto out;
    }
    if (bpf_map_is_cgroup_array(map)) {
        uint64_t empty = 0u;

        status = bpf_map_array_index(map, key, &index);
        if (status < 0) goto out;
        memcpy(&released_cgroup, bpf_map_value(map, index),
               sizeof(released_cgroup));
        if (!released_cgroup) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(bpf_map_value(map, index), &empty, sizeof(empty));
        goto out;
    }
    if (bpf_map_is_lpm_trie(map)) {
        status = bpf_map_lpm_find_exact(
            map, key, &index, &free_slot);
        if (status < 0) goto out;
    } else {
        bpf_map_hash_find(map, key, &index, &free_slot);
    }
    if (index == UINT32_MAX) {
        status = -EDGE_LINUX_ENOENT;
        goto out;
    }
    if (bpf_map_is_map_in_map(map))
        memcpy(&released_inner, bpf_map_value(map, index),
               sizeof(released_inner));
    memset(bpf_map_entry(map, index), 0, map->entry_stride);
    if (map->entry_count) --map->entry_count;
out:
    bpf_unlock();
    if (released_inner >= 0)
        kernel_bpf_object_release(released_inner);
    if (released_event >= 0)
        kernel_perf_event_release(released_event);
    if (released_cgroup)
        cgroupfs_reference_put(released_cgroup);
    return status;
}

int kernel_bpf_map_next_key(int object_id, const void *key, void *next_key) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint32_t index = UINT32_MAX;
    uint32_t free_slot;
    uint32_t next;
    int status = 0;

    if (!next_key) return -EDGE_LINUX_EFAULT;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (map->type == KERNEL_BPF_MAP_TYPE_ARENA) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    if (bpf_map_is_queue_stack(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (bpf_map_is_bloom_filter(map)) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    if (bpf_map_is_stack_trace(map)) {
        uint32_t bucket = 0u;

        if (key) {
            memcpy(&bucket, key, sizeof(bucket));
            if (bucket < map->storage_entries &&
                bpf_map_entry(map, bucket)[0])
                ++bucket;
            else
                bucket = 0u;
        }
        while (bucket < map->storage_entries &&
               !bpf_map_entry(map, bucket)[0])
            ++bucket;
        if (bucket >= map->storage_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(next_key, &bucket, sizeof(bucket));
        goto out;
    }
    if (bpf_map_is_cpumap(map)) {
        uint32_t cpu;

        if (key) {
            memcpy(&cpu, key, sizeof(cpu));
            cpu = cpu < map->max_entries ? cpu + 1u : 0u;
        } else {
            cpu = 0u;
        }
        if (cpu >= map->max_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(next_key, &cpu, sizeof(cpu));
        goto out;
    }
    if (bpf_map_is_devmap_array(map)) {
        uint32_t array_index;

        if (key) {
            memcpy(&array_index, key, sizeof(array_index));
            array_index = array_index < map->max_entries ?
                array_index + 1u : 0u;
        } else {
            array_index = 0u;
        }
        if (array_index >= map->max_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(next_key, &array_index, sizeof(array_index));
        goto out;
    }
    if (bpf_map_is_devmap_hash(map)) {
        if (key) bpf_map_hash_find(map, key, &index, &free_slot);
        next = index == UINT32_MAX ? 0u : index + 1u;
        while (next < map->max_entries &&
               !bpf_map_entry(map, next)[0])
            ++next;
        if (next >= map->max_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(next_key, bpf_map_entry(map, next) + 1u,
               map->key_size);
        goto out;
    }
    if (bpf_map_is_xskmap(map)) {
        uint32_t index;

        if (key) {
            memcpy(&index, key, sizeof(index));
            index = index < map->max_entries ? index + 1u : 0u;
        } else {
            index = 0u;
        }
        if (index >= map->max_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(next_key, &index, sizeof(index));
        goto out;
    }
    if (bpf_map_is_sockmap(map)) {
        uint32_t socket_index;

        if (key) {
            memcpy(&socket_index, key, sizeof(socket_index));
            socket_index = socket_index < map->max_entries ?
                socket_index + 1u : 0u;
        } else {
            socket_index = 0u;
        }
        if (socket_index >= map->max_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(next_key, &socket_index, sizeof(socket_index));
        goto out;
    }
    if (bpf_map_is_reuseport_array(map)) {
        uint32_t socket_index;

        if (key) {
            memcpy(&socket_index, key, sizeof(socket_index));
            socket_index = socket_index < map->max_entries ?
                socket_index + 1u : 0u;
        } else {
            socket_index = 0u;
        }
        if (socket_index >= map->max_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(next_key, &socket_index, sizeof(socket_index));
        goto out;
    }
    if (bpf_map_is_legacy_cgroup_storage(map)) {
        if (key) {
            bpf_legacy_cgroup_storage_find_locked(
                map, key, &index, 0);
            if (index == UINT32_MAX) {
                status = -EDGE_LINUX_ENOENT;
                goto out;
            }
            next = index + 1u;
        } else {
            next = 0u;
        }
        while (next < map->storage_entries &&
               !bpf_map_entry(map, next)[0])
            ++next;
        if (next >= map->storage_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(next_key, bpf_map_entry(map, next) + 1u,
               map->key_size);
        goto out;
    }
    if (bpf_map_is_local_storage(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (bpf_map_is_sockhash(map)) {
        if (key) bpf_map_hash_find(map, key, &index, &free_slot);
        next = index == UINT32_MAX ? 0u : index + 1u;
        while (next < map->max_entries &&
               !bpf_map_entry(map, next)[0])
            ++next;
        if (next >= map->max_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(next_key, bpf_map_entry(map, next) + 1u,
               map->key_size);
        goto out;
    }
    if (bpf_map_is_insn_array(map)) {
        uint32_t index;

        if (key) {
            memcpy(&index, key, sizeof(index));
            index = index < map->max_entries ? index + 1u : 0u;
        } else {
            index = 0u;
        }
        if (index >= map->max_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(next_key, &index, sizeof(index));
        goto out;
    }
    if (bpf_map_is_array(map)) {
        if (key) {
            memcpy(&index, key, sizeof(index));
            next = index < map->max_entries ? index + 1u : 0u;
        } else {
            next = 0u;
        }
        if (next >= map->max_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(next_key, &next, sizeof(next));
        goto out;
    }
    if (bpf_map_is_lpm_trie(map)) {
        uint32_t selected = UINT32_MAX;
        int exact = 0;

        if (key && bpf_map_lpm_find_exact(
                map, key, &index, &free_slot) == 0)
            exact = index != UINT32_MAX;
        for (uint32_t candidate = 0;
             candidate < map->max_entries; ++candidate) {
            uint8_t *entry = bpf_map_entry(map, candidate);

            if (!entry[0] ||
                (exact && bpf_lpm_key_order(entry + 1u, key) <= 0))
                continue;
            if (selected == UINT32_MAX ||
                bpf_lpm_key_order(
                    entry + 1u,
                    bpf_map_entry(map, selected) + 1u) < 0)
                selected = candidate;
        }
        if (selected == UINT32_MAX) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(next_key, bpf_map_entry(map, selected) + 1u,
               map->key_size);
        goto out;
    }
    if (key) {
        bpf_map_hash_find(map, key, &index, &free_slot);
    }
    next = index == UINT32_MAX ? 0u : index + 1u;
    while (next < map->storage_entries &&
           !bpf_map_entry(map, next)[0])
        ++next;
    if (next >= map->storage_entries) {
        status = -EDGE_LINUX_ENOENT;
        goto out;
    }
    memcpy(next_key, bpf_map_entry(map, next) + 1u, map->key_size);
out:
    bpf_unlock();
    return status;
}

int kernel_bpf_map_batch_next_flags(int object_id, uint32_t *cursor,
                                    void *key, void *value,
                                    uint64_t flags, int delete_element,
                                    int *has_more) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint32_t index;
    int32_t released_inner = -1;
    int status = 0;

    if (!cursor || !key || !value || !has_more)
        return -EDGE_LINUX_EFAULT;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (bpf_map_is_stack_trace(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (bpf_map_is_cpumap(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (bpf_map_is_devmap(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (bpf_map_is_xskmap(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (bpf_map_is_socket_map(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (bpf_map_is_reuseport_array(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (bpf_map_is_local_storage(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (bpf_map_is_insn_array(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    status = bpf_map_check_percpu_flags_locked(map, flags);
    if (status < 0 || ((uint32_t)flags & ~KERNEL_BPF_F_CPU)) {
        if (status == 0) status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (bpf_map_is_queue_stack(map)) {
        status = -EDGE_LINUX_ENOTSUPP;
        goto out;
    }
    if (delete_element && map->frozen) {
        status = -EDGE_LINUX_EPERM;
        goto out;
    }
    if (delete_element && !bpf_map_is_hash(map) &&
        !bpf_map_is_lpm_trie(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    index = *cursor;
    if (bpf_map_is_array(map)) {
        if (bpf_map_is_object_array(map)) {
            int32_t inner = -1;

            while (index < map->max_entries) {
                memcpy(&inner, bpf_map_value(map, index), sizeof(inner));
                if (inner >= 0) break;
                ++index;
            }
        }
        if (index >= map->max_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(key, &index, sizeof(index));
        if (bpf_map_is_object_array(map)) {
            int32_t inner;
            memcpy(&inner, bpf_map_value(map, index), sizeof(inner));
            status = bpf_map_object_user_id_locked(
                map, inner, (uint32_t *)value);
            if (status < 0) goto out;
        } else {
            bpf_map_copy_value_out(map, index, value, flags);
        }
    } else if (bpf_map_is_lpm_trie(map)) {
        index = bpf_map_lpm_ordered_index(map, *cursor);
        if (index == UINT32_MAX) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(key, bpf_map_entry(map, index) + 1u, map->key_size);
        bpf_map_copy_value_out(map, index, value, flags);
        if (delete_element) {
            memset(bpf_map_entry(map, index), 0, map->entry_stride);
            if (map->entry_count) --map->entry_count;
        } else {
            ++*cursor;
        }
        *has_more = map->entry_count > *cursor;
        goto out;
    } else {
        while (index < map->storage_entries &&
               !bpf_map_entry(map, index)[0])
            ++index;
        if (index >= map->storage_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(key, bpf_map_entry(map, index) + 1u, map->key_size);
        if (bpf_map_is_map_in_map(map)) {
            int32_t inner;
            memcpy(&inner, bpf_map_value(map, index), sizeof(inner));
            status = bpf_map_inner_user_id_locked(
                inner, (uint32_t *)value);
            if (status < 0) goto out;
            if (delete_element) released_inner = inner;
        } else {
            bpf_map_copy_value_out(map, index, value, flags);
        }
        if (!delete_element && !bpf_map_is_percpu(map))
            bpf_map_lru_touch(map, index);
        if (delete_element) {
            memset(bpf_map_entry(map, index), 0, map->entry_stride);
            if (map->entry_count) --map->entry_count;
        }
    }
    *cursor = index + 1u;
    *has_more = 0;
    if (bpf_map_is_array(map)) {
        index = *cursor;
        if (bpf_map_is_object_array(map)) {
            while (index < map->max_entries) {
                int32_t inner;
                memcpy(&inner, bpf_map_value(map, index), sizeof(inner));
                if (inner >= 0) break;
                ++index;
            }
        }
        *has_more = index < map->max_entries;
    } else {
        index = *cursor;
        while (index < map->storage_entries &&
               !bpf_map_entry(map, index)[0])
            ++index;
        *has_more = index < map->storage_entries;
    }
out:
    bpf_unlock();
    if (released_inner >= 0)
        kernel_bpf_object_release(released_inner);
    return status;
}

int kernel_bpf_map_batch_next(int object_id, uint32_t *cursor,
                              void *key, void *value,
                              int delete_element, int *has_more) {
    return kernel_bpf_map_batch_next_flags(
        object_id, cursor, key, value, 0u, delete_element, has_more);
}

int kernel_bpf_map_freeze(int object_id) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    int status = 0;

    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (map->frozen) {
        status = -EDGE_LINUX_EBUSY;
        goto out;
    }
    map->frozen = 1u;
out:
    bpf_unlock();
    return status;
}

static uint64_t bpf_alu_result(uint32_t operation, uint64_t left,
                               uint64_t right) {
    switch (operation) {
    case BPF_ADD: return left + right;
    case BPF_SUB: return left - right;
    case BPF_MUL: return left * right;
    case BPF_DIV: return right ? left / right : 0;
    case BPF_OR: return left | right;
    case BPF_AND: return left & right;
    case BPF_LSH: return left << (right & 63u);
    case BPF_RSH: return left >> (right & 63u);
    case BPF_NEG: return 0u - left;
    case BPF_MOD: return right ? left % right : 0;
    case BPF_XOR: return left ^ right;
    case BPF_MOV: return right;
    case BPF_ARSH: return (uint64_t)((int64_t)left >> (right & 63u));
    default: return 0;
    }
}

static int bpf_jump_taken(uint32_t operation, uint64_t left,
                          uint64_t right) {
    switch (operation) {
    case BPF_JA: return 1;
    case BPF_JEQ: return left == right;
    case BPF_JGT: return left > right;
    case BPF_JGE: return left >= right;
    case BPF_JSET: return (left & right) != 0;
    case BPF_JNE: return left != right;
    case BPF_JSGT: return (int64_t)left > (int64_t)right;
    case BPF_JSGE: return (int64_t)left >= (int64_t)right;
    case BPF_JLT: return left < right;
    case BPF_JLE: return left <= right;
    case BPF_JSLT: return (int64_t)left < (int64_t)right;
    case BPF_JSLE: return (int64_t)left <= (int64_t)right;
    default: return 0;
    }
}

static void bpf_ringbuf_copy(kernel_bpf_map_t *map, uint64_t position,
                             const void *source, uint32_t length) {
    uint8_t *data = map->storage + 2u * BPF_PAGE_SIZE;
    uint32_t offset = (uint32_t)(position & (map->max_entries - 1u));
    uint32_t first = map->max_entries - offset;

    if (first > length) first = length;
    if (first) memcpy(data + offset, source, first);
    if (length > first)
        memcpy(data, (const uint8_t *)source + first, length - first);
}

static void bpf_ringbuf_zero(kernel_bpf_map_t *map, uint64_t position,
                             uint32_t length) {
    static const uint8_t zeroes[8];

    while (length) {
        uint32_t chunk = length > sizeof(zeroes) ?
            (uint32_t)sizeof(zeroes) : length;
        bpf_ringbuf_copy(map, position, zeroes, chunk);
        position += chunk;
        length -= chunk;
    }
}

static uint32_t bpf_ringbuf_record_size_locked(
        const kernel_bpf_map_t *map, uint64_t position) {
    const uint8_t *data = map->storage + 2u * BPF_PAGE_SIZE;
    uint32_t offset = (uint32_t)(position & (map->max_entries - 1u));
    uint32_t length;

    memcpy(&length, data + offset, sizeof(length));
    length &= ~(BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT);
    if (length > map->max_entries - BPF_RINGBUF_HEADER_SIZE)
        return 0u;
    return bpf_align8(length + BPF_RINGBUF_HEADER_SIZE);
}

static int bpf_ringbuf_output_locked(kernel_bpf_map_t *map,
        const void *data, uint64_t size, uint64_t flags,
        int *notify_waiters) {
    uint64_t consumer;
    uint64_t producer;
    uint64_t pending;
    uint64_t overwrite;
    uint64_t new_producer;
    uint32_t record_size;
    uint32_t header[2];
    uint32_t padding;

    if (!map || map->type != KERNEL_BPF_MAP_TYPE_RINGBUF)
        return -EDGE_LINUX_EINVAL;
    if (flags & ~(BPF_RB_NO_WAKEUP | BPF_RB_FORCE_WAKEUP))
        return -EDGE_LINUX_EINVAL;
    if (size > UINT32_MAX / 4u ||
        size > map->max_entries - BPF_RINGBUF_HEADER_SIZE)
        return -EDGE_LINUX_EAGAIN;
    record_size = bpf_align8((uint32_t)size + BPF_RINGBUF_HEADER_SIZE);
    consumer = __atomic_load_n(
        (uint64_t *)(void *)map->storage, __ATOMIC_ACQUIRE);
    producer = __atomic_load_n(
        (uint64_t *)(void *)(map->storage + BPF_PAGE_SIZE),
        __ATOMIC_ACQUIRE);
    pending = __atomic_load_n(
        (uint64_t *)(void *)(map->storage + BPF_PAGE_SIZE + 8u),
        __ATOMIC_ACQUIRE);
    new_producer = producer + record_size;
    if (new_producer < producer ||
        new_producer - pending > map->max_entries - 1u)
        return -EDGE_LINUX_EAGAIN;
    if (!(map->flags & KERNEL_BPF_MAP_RB_OVERWRITE) &&
        new_producer - consumer > map->max_entries - 1u)
        return -EDGE_LINUX_EAGAIN;

    if (map->flags & KERNEL_BPF_MAP_RB_OVERWRITE) {
        overwrite = __atomic_load_n(
            (uint64_t *)(void *)(map->storage + BPF_PAGE_SIZE + 16u),
            __ATOMIC_ACQUIRE);
        while (new_producer - overwrite > map->max_entries - 1u) {
            uint32_t old_size = bpf_ringbuf_record_size_locked(
                map, overwrite);
            if (!old_size || old_size > map->max_entries)
                return -EDGE_LINUX_EAGAIN;
            overwrite += old_size;
        }
        __atomic_store_n(
            (uint64_t *)(void *)(map->storage + BPF_PAGE_SIZE + 16u),
            overwrite, __ATOMIC_RELEASE);
    }

    header[0] = (uint32_t)size | BPF_RINGBUF_BUSY_BIT;
    /* Linux keeps one private metadata page before the two mmap pages. */
    header[1] = 3u +
        (uint32_t)((producer & (map->max_entries - 1u)) /
                   BPF_PAGE_SIZE);
    bpf_ringbuf_copy(map, producer, header, sizeof(header));
    if (size)
        bpf_ringbuf_copy(
            map, producer + BPF_RINGBUF_HEADER_SIZE,
            data, (uint32_t)size);
    padding = record_size - (uint32_t)size - BPF_RINGBUF_HEADER_SIZE;
    if (padding)
        bpf_ringbuf_zero(map, producer + BPF_RINGBUF_HEADER_SIZE + size,
                         padding);
    header[0] = (uint32_t)size;
    __atomic_store_n(
        (uint32_t *)(void *)(map->storage + 2u * BPF_PAGE_SIZE +
            (producer & (map->max_entries - 1u))),
        header[0], __ATOMIC_RELEASE);
    __atomic_store_n(
        (uint64_t *)(void *)(map->storage + BPF_PAGE_SIZE + 8u),
        new_producer, __ATOMIC_RELEASE);
    __atomic_store_n(
        (uint64_t *)(void *)(map->storage + BPF_PAGE_SIZE),
        new_producer, __ATOMIC_RELEASE);
    if (notify_waiters &&
        ((flags & BPF_RB_FORCE_WAKEUP) ||
         (!(flags & BPF_RB_NO_WAKEUP) &&
          (consumer & (map->max_entries - 1u)) ==
              (producer & (map->max_entries - 1u)))))
        *notify_waiters = 1;
    return 0;
}

static int bpf_stack_trace_get_id_locked(kernel_bpf_map_t *map,
                                         uint64_t flags,
                                         uintptr_t callsite) {
    uint64_t frames[3];
    uint32_t frame_count;
    uint32_t skip;
    uint32_t hash = 2166136261u;
    uint32_t bucket;
    uint8_t *entry;

    if (!map || !bpf_map_is_stack_trace(map))
        return -EDGE_LINUX_EINVAL;
    if (flags & ~(uint64_t)(BPF_F_SKIP_FIELD_MASK |
                            BPF_F_USER_STACK |
                            BPF_F_FAST_STACK_CMP |
                            BPF_F_REUSE_STACKID))
        return -EDGE_LINUX_EINVAL;
    if (flags & BPF_F_USER_STACK) return -EDGE_LINUX_EFAULT;
    skip = (uint32_t)flags & BPF_F_SKIP_FIELD_MASK;
    frames[0] = (uint64_t)callsite;
    frames[1] =
        (uint64_t)(uintptr_t)&kernel_bpf_raw_tracepoint_sys_enter;
    frames[2] = (uint64_t)(uintptr_t)&bpf_stack_trace_get_id_locked;
    frame_count = map->value_size / sizeof(frames[0]);
    if (frame_count > sizeof(frames) / sizeof(frames[0]))
        frame_count = sizeof(frames) / sizeof(frames[0]);
    if (skip >= frame_count) return -EDGE_LINUX_EFAULT;
    frame_count -= skip;
    for (uint32_t index = 0; index < frame_count; ++index) {
        uint64_t value = frames[index + skip];

        for (uint32_t byte = 0; byte < sizeof(value); ++byte) {
            hash ^= (uint8_t)(value >> (byte * 8u));
            hash *= 16777619u;
        }
    }
    bucket = map->storage_entries & (map->storage_entries - 1u) ?
        hash % map->storage_entries : hash & (map->storage_entries - 1u);
    entry = bpf_map_entry(map, bucket);
    if (entry[0]) {
        int equal = memcmp(entry + 1u, frames + skip,
                           frame_count * sizeof(frames[0])) == 0;

        for (uint32_t offset = frame_count * sizeof(frames[0]);
             equal && offset < map->value_size; ++offset)
            if (entry[1u + offset]) equal = 0;
        if (equal)
            return (int)bucket;
        if (!(flags & BPF_F_REUSE_STACKID))
            return -EDGE_LINUX_EEXIST;
    } else {
        ++map->entry_count;
    }
    memset(entry, 0, map->entry_stride);
    entry[0] = 1u;
    memcpy(entry + 1u, frames + skip,
           frame_count * sizeof(frames[0]));
    return (int)bucket;
}

static int bpf_program_run_cgroup_device_locked(
        kernel_bpf_object_t *object,
        const void *context, uint32_t context_size,
        uint32_t *result, int *notify_waiters,
        uint32_t cgroup_id, uint32_t attach_type,
        uint32_t program_type) {
    kernel_bpf_instruction_t *instructions;
    uint32_t count;
    uint64_t registers[11] = {0};
    uint8_t stack[512] = {0};
    uint32_t tail_call_count = 0u;
    uint64_t invocation_start_us = 0u;
    uint32_t pc;

    if (!object || object->kind != KERNEL_BPF_OBJECT_PROGRAM ||
        object->value.program.type != program_type)
        return -EDGE_LINUX_EBADF;
    instructions = object->value.program.instructions;
    count = object->value.program.instruction_count;
    if (g_bpf_runtime_stats_users)
        invocation_start_us = boottime_monotonic_us();
    registers[1] = (uint64_t)(uintptr_t)context;
    registers[10] = (uint64_t)(uintptr_t)(stack + sizeof(stack));
    for (pc = 0; pc < count; ++pc) {
        const kernel_bpf_instruction_t *instruction = &instructions[pc];
        uint32_t destination = bpf_program_destination(instruction);
        uint32_t source = bpf_program_source(instruction);
        uint32_t operation = BPF_OP(instruction->code);
        uint64_t operand = BPF_SRC(instruction->code) == BPF_X ?
            registers[source] : (uint64_t)(int64_t)instruction->immediate;

        if (instruction->code == (BPF_LD | BPF_DW | BPF_IMM)) {
            registers[destination] =
                (uint64_t)(uint32_t)instruction->immediate;
            ++pc;
        } else if (BPF_CLASS(instruction->code) == BPF_ALU64) {
            registers[destination] = bpf_alu_result(
                operation, registers[destination], operand);
        } else if (BPF_CLASS(instruction->code) == BPF_LDX) {
            uintptr_t address = (uintptr_t)registers[source] +
                instruction->offset;
            uint32_t value;

            if (source == 1u) {
                if (context_size < sizeof(value) ||
                    address < (uintptr_t)context ||
                    address > (uintptr_t)context + context_size -
                                  sizeof(value))
                    return -EDGE_LINUX_EFAULT;
            } else if (!bpf_legacy_storage_address_locked(
                           address, sizeof(value))) {
                return -EDGE_LINUX_EFAULT;
            }
            memcpy(&value, (const void *)address, sizeof(value));
            registers[destination] = value;
        } else if (BPF_CLASS(instruction->code) == BPF_STX) {
            uintptr_t address = (uintptr_t)registers[destination] +
                instruction->offset;
            uint32_t value = (uint32_t)registers[source];

            if (!((address >= (uintptr_t)stack &&
                   address <= (uintptr_t)(stack + sizeof(stack) -
                                           sizeof(value))) ||
                  bpf_legacy_storage_address_locked(
                      address, sizeof(value))))
                return -EDGE_LINUX_EFAULT;
            memcpy((void *)address, &value, sizeof(value));
        } else if (BPF_CLASS(instruction->code) == BPF_JMP &&
                   operation == BPF_CALL &&
                   instruction->immediate == (int32_t)BPF_FUNC_TAIL_CALL) {
            kernel_bpf_object_t *map_object =
                bpf_object_locked((int32_t)registers[2]);
            kernel_bpf_object_t *next_program = 0;
            uint32_t index = (uint32_t)registers[3];
            int32_t next_program_id = -1;

            if (tail_call_count < BPF_MAX_TAIL_CALLS && map_object &&
                map_object->kind == KERNEL_BPF_OBJECT_MAP &&
                map_object->value.map.type ==
                    KERNEL_BPF_MAP_TYPE_PROG_ARRAY &&
                index < map_object->value.map.max_entries) {
                memcpy(&next_program_id,
                       bpf_map_value(&map_object->value.map, index),
                       sizeof(next_program_id));
                next_program = bpf_object_locked(next_program_id);
                if (!next_program ||
                    next_program->kind != KERNEL_BPF_OBJECT_PROGRAM ||
                    next_program->value.program.type !=
                        object->value.program.type ||
                    next_program->value.program.expected_attach_type !=
                        object->value.program.expected_attach_type)
                    next_program = 0;
            }
            if (!next_program) {
                registers[0] = 0u;
                continue;
            }
            if (g_bpf_runtime_stats_users) {
                uint64_t now = boottime_monotonic_us();

                ++object->value.program.run_count;
                object->value.program.run_time_ns +=
                    (now - invocation_start_us) * 1000u;
                invocation_start_us = now;
            }
            ++tail_call_count;
            object = next_program;
            instructions = object->value.program.instructions;
            count = object->value.program.instruction_count;
            memset(registers, 0, sizeof(registers));
            registers[1] = (uint64_t)(uintptr_t)context;
            registers[10] =
                (uint64_t)(uintptr_t)(stack + sizeof(stack));
            pc = UINT32_MAX;
        } else if (BPF_CLASS(instruction->code) == BPF_JMP &&
                   operation == BPF_CALL &&
                   instruction->immediate ==
                       (int32_t)BPF_FUNC_GET_STACKID) {
            kernel_bpf_object_t *map_object =
                bpf_object_locked((int32_t)registers[2]);
            int helper_status;

            if (program_type != KERNEL_BPF_PROG_TYPE_RAW_TRACEPOINT ||
                !map_object ||
                map_object->kind != KERNEL_BPF_OBJECT_MAP) {
                helper_status = -EDGE_LINUX_EINVAL;
            } else {
                helper_status = bpf_stack_trace_get_id_locked(
                    &map_object->value.map, registers[3],
                    (uintptr_t)__builtin_return_address(0));
            }
            registers[0] = (uint64_t)(int64_t)helper_status;
        } else if (BPF_CLASS(instruction->code) == BPF_JMP &&
                   operation == BPF_CALL &&
                   instruction->immediate ==
                       (int32_t)BPF_FUNC_GET_LOCAL_STORAGE) {
            kernel_bpf_object_t *map_object =
                bpf_object_locked((int32_t)registers[1]);
            uint8_t *value = 0;

            if (registers[2] || !map_object ||
                map_object->kind != KERNEL_BPF_OBJECT_MAP ||
                !bpf_map_is_legacy_cgroup_storage(
                    &map_object->value.map))
                return -EDGE_LINUX_EINVAL;
            value = bpf_legacy_cgroup_storage_value_locked(
                &map_object->value.map, cgroup_id, attach_type);
            if (!value) return -EDGE_LINUX_ENOENT;
            registers[0] = (uint64_t)(uintptr_t)value;
        } else if (BPF_CLASS(instruction->code) == BPF_JMP &&
                   operation == BPF_CALL &&
                   instruction->immediate ==
                       (int32_t)BPF_FUNC_RINGBUF_OUTPUT) {
            kernel_bpf_object_t *map_object =
                bpf_object_locked((int32_t)registers[1]);
            uintptr_t stack_start = (uintptr_t)stack;
            uintptr_t data_start = (uintptr_t)registers[2];
            uint64_t data_size = registers[3];
            int helper_status;

            if (!map_object ||
                map_object->kind != KERNEL_BPF_OBJECT_MAP ||
                map_object->value.map.type !=
                    KERNEL_BPF_MAP_TYPE_RINGBUF) {
                helper_status = -EDGE_LINUX_EINVAL;
            } else if (data_start < stack_start ||
                       data_size > sizeof(stack) ||
                       data_start - stack_start >
                           sizeof(stack) - data_size) {
                helper_status = -EDGE_LINUX_EFAULT;
            } else {
                helper_status = bpf_ringbuf_output_locked(
                    &map_object->value.map, (const void *)data_start,
                    data_size, registers[4], notify_waiters);
            }
            registers[0] = (uint64_t)(int64_t)helper_status;
        } else if (operation == BPF_EXIT) {
            *result = (uint32_t)registers[0];
            if (g_bpf_runtime_stats_users) {
                ++object->value.program.run_count;
                object->value.program.run_time_ns +=
                    (boottime_monotonic_us() - invocation_start_us) *
                    1000u;
            }
            return 0;
        } else if (bpf_jump_taken(operation, registers[destination], operand)) {
            pc += (uint32_t)instruction->offset;
        }
    }
    return -EDGE_LINUX_EINVAL;
}

int kernel_bpf_program_run_cgroup_device(
    int object_id, const kernel_bpf_cgroup_device_context_t *context,
    uint32_t *result) {
    return kernel_bpf_program_run_cgroup_device_at(
        object_id, 0u, context, result);
}

int kernel_bpf_program_run_socket_filter(
    int object_id, const kernel_bpf_socket_filter_context_t *context,
    uint32_t *result) {
    kernel_bpf_object_t *object;
    int notify_waiters = 0;
    int status;

    if (!context || !result) return -EDGE_LINUX_EINVAL;
    bpf_lock();
    object = bpf_object_locked(object_id);
    status = bpf_program_run_cgroup_device_locked(
        object, context, sizeof(*context), result, &notify_waiters,
        0u, 0u, KERNEL_BPF_PROG_TYPE_SOCKET_FILTER);
    bpf_unlock();
    if (notify_waiters) kernel_bpf_ringbuf_state_changed();
    return status;
}

int kernel_bpf_program_run_cgroup_device_at(
    int object_id, uint32_t cgroup_id,
    const kernel_bpf_cgroup_device_context_t *context,
    uint32_t *result) {
    kernel_bpf_object_t *object;
    int notify_waiters = 0;
    int status;

    if (!context || !result) return -EDGE_LINUX_EINVAL;
    bpf_lock();
    object = bpf_object_locked(object_id);
    status = bpf_program_run_cgroup_device_locked(
        object, context, sizeof(*context), result, &notify_waiters,
        cgroup_id, KERNEL_BPF_CGROUP_DEVICE,
        KERNEL_BPF_PROG_TYPE_CGROUP_DEVICE);
    bpf_unlock();
    if (notify_waiters) kernel_bpf_ringbuf_state_changed();
    return status;
}

int kernel_bpf_raw_tracepoint_open(const char *name, int object_id) {
    kernel_bpf_raw_tracepoint_attachment_t *attachment = 0;
    kernel_bpf_object_t *program;
    kernel_bpf_object_t *link;
    int link_object_id;
    int result = 0;

    if (!name || strcmp(name, "sys_enter"))
        return -EDGE_LINUX_ENOENT;
    bpf_lock();
    program = bpf_object_locked(object_id);
    if (!program || program->kind != KERNEL_BPF_OBJECT_PROGRAM ||
        program->value.program.type !=
            KERNEL_BPF_PROG_TYPE_RAW_TRACEPOINT) {
        result = program ? -EDGE_LINUX_EINVAL : -EDGE_LINUX_EBADF;
        goto out;
    }
    for (uint32_t index = 0;
         index < EDGE_RUNTIME_MAX_BPF_ATTACHMENTS; ++index) {
        if (!g_bpf_raw_tracepoints[index].used) {
            attachment = &g_bpf_raw_tracepoints[index];
            break;
        }
    }
    if (!attachment) {
        result = -EDGE_LINUX_ENOSPC;
        goto out;
    }
    if (program->references == UINT32_MAX) {
        result = -EDGE_LINUX_EBUSY;
        goto out;
    }
    link_object_id = bpf_allocate_object_locked(
        KERNEL_BPF_OBJECT_LINK, &link);
    if (link_object_id < 0) {
        result = link_object_id;
        goto out;
    }
    ++program->references;
    link->value.link.program_object_id = object_id;
    link->value.link.attach_type = BPF_RAW_TRACEPOINT_SYS_ENTER;
    memset(attachment, 0, sizeof(*attachment));
    attachment->used = 1u;
    attachment->tracepoint = BPF_RAW_TRACEPOINT_SYS_ENTER;
    attachment->object_id = object_id;
    attachment->link_object_id = link_object_id;
    __atomic_add_fetch(&g_bpf_raw_tracepoint_users, 1u,
                       __ATOMIC_RELEASE);
    result = link_object_id;
out:
    bpf_unlock();
    return result;
}

void kernel_bpf_raw_tracepoint_sys_enter(void *user_registers,
                                         uint64_t system_call_number) {
    uint64_t context[2];
    int notify_waiters = 0;

    if (!__atomic_load_n(&g_bpf_raw_tracepoint_users,
                         __ATOMIC_ACQUIRE))
        return;
    context[0] = (uint64_t)(uintptr_t)user_registers;
    context[1] = system_call_number;
    bpf_lock();
    for (uint32_t index = 0;
         index < EDGE_RUNTIME_MAX_BPF_ATTACHMENTS; ++index) {
        kernel_bpf_raw_tracepoint_attachment_t *attachment =
            &g_bpf_raw_tracepoints[index];
        kernel_bpf_object_t *program;
        uint32_t ignored = 0u;

        if (!attachment->used ||
            attachment->tracepoint != BPF_RAW_TRACEPOINT_SYS_ENTER)
            continue;
        program = bpf_object_locked(attachment->object_id);
        (void)bpf_program_run_cgroup_device_locked(
            program, context, sizeof(context), &ignored,
            &notify_waiters, 0u, 0u,
            KERNEL_BPF_PROG_TYPE_RAW_TRACEPOINT);
    }
    bpf_unlock();
    if (notify_waiters) kernel_bpf_ringbuf_state_changed();
}

static uint64_t *bpf_cgroup_revision_locked(uint32_t cgroup_id) {
    if (cgroup_id >= sizeof(g_bpf_cgroup_revisions) /
                         sizeof(g_bpf_cgroup_revisions[0]))
        return 0;
    if (!g_bpf_cgroup_revisions[cgroup_id])
        g_bpf_cgroup_revisions[cgroup_id] = 1u;
    return &g_bpf_cgroup_revisions[cgroup_id];
}

static int bpf_cgroup_program_valid_locked(
        kernel_bpf_object_t *object, uint32_t attach_type) {
    return object && object->kind == KERNEL_BPF_OBJECT_PROGRAM &&
           object->value.program.type ==
               KERNEL_BPF_PROG_TYPE_CGROUP_DEVICE &&
           attach_type == KERNEL_BPF_CGROUP_DEVICE &&
           (object->value.program.expected_attach_type == 0u ||
            object->value.program.expected_attach_type == attach_type);
}

static uint64_t bpf_attachment_next_sequence_locked(void) {
    ++g_bpf_attachment_sequence;
    if (!g_bpf_attachment_sequence) ++g_bpf_attachment_sequence;
    return g_bpf_attachment_sequence;
}

static void bpf_cgroup_resequence_locked(
        uint32_t cgroup_id, kernel_bpf_attachment_t *inserted,
        kernel_bpf_attachment_t *anchor, int before) {
    uint64_t original_max = 0u;
    uint64_t previous = 0u;
    int inserted_positioned = 0;

    for (uint32_t index = 0;
         index < EDGE_RUNTIME_MAX_BPF_ATTACHMENTS; ++index) {
        const kernel_bpf_attachment_t *attachment =
            &g_bpf_attachments[index];

        if (!attachment->used || attachment == inserted ||
            attachment->cgroup_id != cgroup_id)
            continue;
        if (attachment->sequence > original_max)
            original_max = attachment->sequence;
    }
    if (!anchor && before) {
        inserted->sequence = bpf_attachment_next_sequence_locked();
        inserted_positioned = 1;
    }
    for (;;) {
        kernel_bpf_attachment_t *next = 0;
        uint64_t next_original;

        for (uint32_t index = 0;
             index < EDGE_RUNTIME_MAX_BPF_ATTACHMENTS; ++index) {
            kernel_bpf_attachment_t *candidate =
                &g_bpf_attachments[index];

            if (!candidate->used || candidate == inserted ||
                candidate->cgroup_id != cgroup_id ||
                candidate->sequence <= previous ||
                candidate->sequence > original_max)
                continue;
            if (!next || candidate->sequence < next->sequence)
                next = candidate;
        }
        if (!next) break;
        next_original = next->sequence;
        if (next == anchor && before) {
            inserted->sequence = bpf_attachment_next_sequence_locked();
            inserted_positioned = 1;
        }
        next->sequence = bpf_attachment_next_sequence_locked();
        if (next == anchor && !before) {
            inserted->sequence = bpf_attachment_next_sequence_locked();
            inserted_positioned = 1;
        }
        previous = next_original;
    }
    if (!inserted_positioned)
        inserted->sequence = bpf_attachment_next_sequence_locked();
}

int kernel_bpf_cgroup_link_create(uint32_t cgroup_id, int object_id,
                                  uint32_t attach_type, uint32_t flags,
                                  int relative_object_id,
                                  uint64_t expected_revision) {
    kernel_bpf_attachment_t *free_attachment = 0;
    kernel_bpf_attachment_t *anchor = 0;
    kernel_bpf_object_t *program;
    kernel_bpf_object_t *link;
    uint64_t *revision;
    int link_object_id;
    int result = 0;
    int before = (flags & KERNEL_BPF_F_BEFORE) != 0;
    int after = (flags & KERNEL_BPF_F_AFTER) != 0;
    int anchor_preorder_mismatch = 0;
    int has_attachments = 0;

    if ((flags & ~(KERNEL_BPF_F_BEFORE | KERNEL_BPF_F_AFTER |
                   KERNEL_BPF_F_PREORDER | KERNEL_BPF_F_LINK)) ||
        (!!(flags & KERNEL_BPF_F_LINK) !=
         (relative_object_id >= 0)) ||
        (relative_object_id >= 0 && before == after))
        return -EDGE_LINUX_EINVAL;
    bpf_lock();
    revision = bpf_cgroup_revision_locked(cgroup_id);
    program = bpf_object_locked(object_id);
    if (!revision ||
        !bpf_cgroup_program_valid_locked(program, attach_type)) {
        result = program ? -EDGE_LINUX_EINVAL : -EDGE_LINUX_EBADF;
        goto out;
    }
    if (expected_revision && expected_revision != *revision) {
        result = -EDGE_LINUX_ESTALE;
        goto out;
    }
    for (uint32_t index = 0;
         index < EDGE_RUNTIME_MAX_BPF_ATTACHMENTS; ++index) {
        kernel_bpf_attachment_t *attachment = &g_bpf_attachments[index];

        if (!attachment->used) {
            if (!free_attachment) free_attachment = attachment;
            continue;
        }
        if (attachment->cgroup_id == cgroup_id &&
            !(attachment->flags & KERNEL_BPF_F_ALLOW_MULTI)) {
            result = -EDGE_LINUX_EPERM;
            goto out;
        }
        if (attachment->cgroup_id == cgroup_id &&
            attachment->attach_type == attach_type)
            has_attachments = 1;
        if (attachment->cgroup_id == cgroup_id &&
            attachment->attach_type == attach_type &&
            relative_object_id >= 0 &&
            (((flags & KERNEL_BPF_F_LINK) &&
              attachment->link_object_id == relative_object_id) ||
             (!(flags & KERNEL_BPF_F_LINK) &&
              attachment->object_id == relative_object_id)) &&
            !anchor) {
            if (!!(attachment->flags & KERNEL_BPF_F_PREORDER) ==
                !!(flags & KERNEL_BPF_F_PREORDER))
                anchor = attachment;
            else
                anchor_preorder_mismatch = 1;
        }
    }
    if (relative_object_id >= 0 && !anchor) {
        result = anchor_preorder_mismatch ?
            -EDGE_LINUX_EINVAL : -EDGE_LINUX_ENOENT;
        goto out;
    }
    if (relative_object_id < 0 && has_attachments && before && after) {
        result = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (!free_attachment) {
        result = -EDGE_LINUX_ENOSPC;
        goto out;
    }
    if (program->references == UINT32_MAX) {
        result = -EDGE_LINUX_EBUSY;
        goto out;
    }
    result = bpf_program_legacy_storage_link_locked(
        &program->value.program, cgroup_id, attach_type);
    if (result < 0) goto out;
    link_object_id = bpf_allocate_object_locked(
        KERNEL_BPF_OBJECT_LINK, &link);
    if (link_object_id < 0) {
        result = link_object_id;
        goto out;
    }
    ++program->references;
    link->value.link.program_object_id = object_id;
    link->value.link.cgroup_id = cgroup_id;
    link->value.link.attach_type = attach_type;
    link->value.link.attach_flags = flags;
    memset(free_attachment, 0, sizeof(*free_attachment));
    free_attachment->used = 1u;
    free_attachment->cgroup_id = cgroup_id;
    free_attachment->object_id = object_id;
    free_attachment->link_object_id = link_object_id;
    free_attachment->flags = KERNEL_BPF_F_ALLOW_MULTI |
        (flags & KERNEL_BPF_F_PREORDER);
    free_attachment->attach_type = attach_type;
    bpf_cgroup_resequence_locked(
        cgroup_id, free_attachment, anchor, before);
    ++*revision;
    result = link_object_id;
out:
    bpf_unlock();
    return result;
}

int kernel_bpf_link_update(int link_object_id, int new_object_id,
                           uint32_t flags, int old_object_id) {
    kernel_bpf_object_t *link;
    kernel_bpf_object_t *new_program;
    kernel_bpf_object_t *old_program;
    kernel_bpf_attachment_t *attachment = 0;
    int released_object = -1;
    int result = 0;

    if ((flags & ~KERNEL_BPF_F_REPLACE) ||
        ((flags & KERNEL_BPF_F_REPLACE) != 0) != (old_object_id >= 0))
        return -EDGE_LINUX_EINVAL;
    bpf_lock();
    link = bpf_object_locked(link_object_id);
    new_program = bpf_object_locked(new_object_id);
    if (!link || link->kind != KERNEL_BPF_OBJECT_LINK) {
        result = -EDGE_LINUX_EBADF;
        goto out;
    }
    if (link->value.link.detached) {
        result = -EDGE_LINUX_ENOENT;
        goto out;
    }
    if (!bpf_cgroup_program_valid_locked(
            new_program, link->value.link.attach_type)) {
        result = new_program ? -EDGE_LINUX_EINVAL : -EDGE_LINUX_EBADF;
        goto out;
    }
    old_program = bpf_object_locked(link->value.link.program_object_id);
    if (!old_program ||
        ((flags & KERNEL_BPF_F_REPLACE) &&
         link->value.link.program_object_id != old_object_id)) {
        result = -EDGE_LINUX_EPERM;
        goto out;
    }
    if (link->value.link.program_object_id == new_object_id) {
        result = -EDGE_LINUX_EEXIST;
        goto out;
    }
    for (uint32_t index = 0;
         index < EDGE_RUNTIME_MAX_BPF_ATTACHMENTS; ++index) {
        if (g_bpf_attachments[index].used &&
            g_bpf_attachments[index].link_object_id == link_object_id) {
            attachment = &g_bpf_attachments[index];
            break;
        }
    }
    if (!attachment) {
        result = -EDGE_LINUX_ENOENT;
        goto out;
    }
    if (new_program->references == UINT32_MAX) {
        result = -EDGE_LINUX_EBUSY;
        goto out;
    }
    result = bpf_program_legacy_storage_link_locked(
        &new_program->value.program, attachment->cgroup_id,
        attachment->attach_type);
    if (result < 0) goto out;
    ++new_program->references;
    released_object = link->value.link.program_object_id;
    link->value.link.program_object_id = new_object_id;
    attachment->object_id = new_object_id;
    if (bpf_cgroup_revision_locked(link->value.link.cgroup_id))
        ++*bpf_cgroup_revision_locked(link->value.link.cgroup_id);
out:
    bpf_unlock();
    if (released_object >= 0)
        kernel_bpf_object_release(released_object);
    return result;
}

int kernel_bpf_link_detach(int link_object_id) {
    kernel_bpf_object_t *link;
    int result = -EDGE_LINUX_ENOENT;

    bpf_lock();
    link = bpf_object_locked(link_object_id);
    if (!link || link->kind != KERNEL_BPF_OBJECT_LINK) {
        bpf_unlock();
        return -EDGE_LINUX_EBADF;
    }
    if (link->value.link.detached) {
        bpf_unlock();
        return -EDGE_LINUX_ENOENT;
    }
    for (uint32_t index = 0;
         index < EDGE_RUNTIME_MAX_BPF_ATTACHMENTS; ++index) {
        kernel_bpf_attachment_t *attachment = &g_bpf_attachments[index];
        if (!attachment->used ||
            attachment->link_object_id != link_object_id)
            continue;
        memset(attachment, 0, sizeof(*attachment));
        link->value.link.detached = 1u;
        if (bpf_cgroup_revision_locked(link->value.link.cgroup_id))
            ++*bpf_cgroup_revision_locked(link->value.link.cgroup_id);
        result = 0;
        break;
    }
    bpf_unlock();
    return result;
}

int kernel_bpf_cgroup_attach(uint32_t cgroup_id, int object_id,
                             uint32_t flags, int replace_object_id,
                             int relative_object_id,
                             uint64_t expected_revision) {
    kernel_bpf_attachment_t *free_attachment = 0;
    kernel_bpf_attachment_t *replacement = 0;
    kernel_bpf_attachment_t *anchor = 0;
    kernel_bpf_object_t *object;
    uint64_t *revision;
    int released_object = -1;
    int status = 0;
    int before = (flags & KERNEL_BPF_F_BEFORE) != 0;
    int after = (flags & KERNEL_BPF_F_AFTER) != 0;
    int anchor_preorder_mismatch = 0;
    int has_attachments = 0;
    uint32_t saved_flags = flags &
        (KERNEL_BPF_F_ALLOW_OVERRIDE | KERNEL_BPF_F_ALLOW_MULTI);

    if ((flags & ~(KERNEL_BPF_F_ALLOW_OVERRIDE |
                   KERNEL_BPF_F_ALLOW_MULTI |
                   KERNEL_BPF_F_REPLACE |
                   KERNEL_BPF_F_BEFORE |
                   KERNEL_BPF_F_AFTER |
                   KERNEL_BPF_F_PREORDER)) ||
        ((flags & KERNEL_BPF_F_ALLOW_OVERRIDE) &&
         (flags & KERNEL_BPF_F_ALLOW_MULTI)) ||
        ((flags & KERNEL_BPF_F_REPLACE) &&
         !(flags & KERNEL_BPF_F_ALLOW_MULTI)) ||
        ((flags & KERNEL_BPF_F_REPLACE) && (before || after)) ||
        ((flags & KERNEL_BPF_F_REPLACE) != 0) !=
            (replace_object_id >= 0) ||
        (relative_object_id >= 0 && before == after))
        return -EDGE_LINUX_EINVAL;

    bpf_lock();
    revision = bpf_cgroup_revision_locked(cgroup_id);
    object = bpf_object_locked(object_id);
    if (!revision || !object ||
        object->kind != KERNEL_BPF_OBJECT_PROGRAM ||
        object->value.program.type != KERNEL_BPF_PROG_TYPE_CGROUP_DEVICE ||
        (object->value.program.expected_attach_type != 0u &&
         object->value.program.expected_attach_type !=
             KERNEL_BPF_CGROUP_DEVICE)) {
        status = object ? -EDGE_LINUX_EINVAL : -EDGE_LINUX_EBADF;
        goto out;
    }
    if (expected_revision && expected_revision != *revision) {
        status = -EDGE_LINUX_ESTALE;
        goto out;
    }
    for (uint32_t index = 0;
         index < EDGE_RUNTIME_MAX_BPF_ATTACHMENTS; ++index) {
        kernel_bpf_attachment_t *attachment = &g_bpf_attachments[index];
        if (!attachment->used) {
            if (!free_attachment) free_attachment = attachment;
            continue;
        }
        if (attachment->cgroup_id != cgroup_id) continue;
        if (attachment->attach_type == KERNEL_BPF_CGROUP_DEVICE) {
            has_attachments = 1;
            if ((attachment->flags &
                 (KERNEL_BPF_F_ALLOW_OVERRIDE |
                  KERNEL_BPF_F_ALLOW_MULTI)) != saved_flags) {
                status = -EDGE_LINUX_EPERM;
                goto out;
            }
        }
        if (relative_object_id >= 0 && !anchor &&
            attachment->object_id == relative_object_id) {
            if (!!(attachment->flags & KERNEL_BPF_F_PREORDER) ==
                !!(flags & KERNEL_BPF_F_PREORDER))
                anchor = attachment;
            else
                anchor_preorder_mismatch = 1;
        }
        if (attachment->object_id == object_id &&
            !(flags & KERNEL_BPF_F_REPLACE)) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        if (flags & KERNEL_BPF_F_REPLACE) {
            if (attachment->object_id == replace_object_id)
                replacement = attachment;
            continue;
        }
        if (!(flags & KERNEL_BPF_F_ALLOW_MULTI)) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
    }
    if (relative_object_id >= 0 && !anchor) {
        status = anchor_preorder_mismatch ?
            -EDGE_LINUX_EINVAL : -EDGE_LINUX_ENOENT;
        goto out;
    }
    if (relative_object_id < 0 && has_attachments && before && after) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (flags & KERNEL_BPF_F_REPLACE) {
        kernel_bpf_object_t *replaced =
            bpf_object_locked(replace_object_id);
        if (!replacement || replacement->link_object_id >= 0 || !replaced ||
            replaced->kind != KERNEL_BPF_OBJECT_PROGRAM) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        if (object->references == UINT32_MAX) {
            status = -EDGE_LINUX_EBUSY;
            goto out;
        }
        {
            kernel_bpf_object_t *old_object = bpf_object_locked(
                replacement->object_id);

            if (!old_object || old_object->kind !=
                    KERNEL_BPF_OBJECT_PROGRAM) {
                status = -EDGE_LINUX_EBADF;
                goto out;
            }
            status = bpf_program_legacy_storage_link_locked(
                &object->value.program, cgroup_id,
                KERNEL_BPF_CGROUP_DEVICE);
            if (status < 0) goto out;
        }
        ++object->references;
        released_object = replacement->object_id;
        replacement->object_id = object_id;
        replacement->flags = flags &
            (KERNEL_BPF_F_ALLOW_OVERRIDE |
             KERNEL_BPF_F_ALLOW_MULTI |
             KERNEL_BPF_F_PREORDER);
    } else {
        if (!free_attachment) {
            status = -EDGE_LINUX_ENOSPC;
            goto out;
        }
        if (object->references == UINT32_MAX) {
            status = -EDGE_LINUX_EBUSY;
            goto out;
        }
        status = bpf_program_legacy_storage_link_locked(
            &object->value.program, cgroup_id,
            KERNEL_BPF_CGROUP_DEVICE);
        if (status < 0) goto out;
        ++object->references;
        memset(free_attachment, 0, sizeof(*free_attachment));
        free_attachment->used = 1u;
        free_attachment->cgroup_id = cgroup_id;
        free_attachment->object_id = object_id;
        free_attachment->link_object_id = -1;
        free_attachment->flags = flags &
            (KERNEL_BPF_F_ALLOW_OVERRIDE |
             KERNEL_BPF_F_ALLOW_MULTI |
             KERNEL_BPF_F_PREORDER);
        free_attachment->attach_type = KERNEL_BPF_CGROUP_DEVICE;
        bpf_cgroup_resequence_locked(
            cgroup_id, free_attachment, anchor, before);
    }
    ++*revision;
out:
    bpf_unlock();
    if (released_object >= 0)
        kernel_bpf_object_release(released_object);
    return status;
}

int kernel_bpf_cgroup_detach(uint32_t cgroup_id, int object_id,
                             uint64_t expected_revision) {
    uint64_t *revision;
    int released[EDGE_RUNTIME_MAX_BPF_ATTACHMENTS];
    uint32_t released_count = 0u;

    bpf_lock();
    revision = bpf_cgroup_revision_locked(cgroup_id);
    if (!revision) {
        bpf_unlock();
        return -EDGE_LINUX_EINVAL;
    }
    if (expected_revision && expected_revision != *revision) {
        bpf_unlock();
        return -EDGE_LINUX_ESTALE;
    }
    for (uint32_t index = 0;
         index < EDGE_RUNTIME_MAX_BPF_ATTACHMENTS; ++index) {
        kernel_bpf_attachment_t *attachment = &g_bpf_attachments[index];
        if (!attachment->used || attachment->cgroup_id != cgroup_id ||
            (object_id >= 0 && attachment->object_id != object_id))
            continue;
        released[released_count++] = attachment->object_id;
        memset(attachment, 0, sizeof(*attachment));
        if (object_id >= 0) break;
    }
    if (released_count) ++*revision;
    bpf_unlock();
    for (uint32_t index = 0; index < released_count; ++index)
        kernel_bpf_object_release(released[index]);
    return released_count ? 0 : -EDGE_LINUX_ENOENT;
}

int kernel_bpf_cgroup_query_links(uint32_t cgroup_id, int *object_ids,
                                  uint32_t *attach_flags,
                                  int *link_object_ids,
                                  uint32_t capacity, uint32_t *count,
                                  uint64_t *revision) {
    uint64_t *stored_revision;
    uint64_t previous_sequence = 0u;
    uint32_t found = 0u;

    if (!count || (capacity && !object_ids))
        return -EDGE_LINUX_EINVAL;
    bpf_lock();
    stored_revision = bpf_cgroup_revision_locked(cgroup_id);
    if (!stored_revision) {
        bpf_unlock();
        return -EDGE_LINUX_EINVAL;
    }
    for (;;) {
        const kernel_bpf_attachment_t *attachment = 0;
        for (uint32_t index = 0;
             index < EDGE_RUNTIME_MAX_BPF_ATTACHMENTS; ++index) {
            const kernel_bpf_attachment_t *candidate =
                &g_bpf_attachments[index];
            if (!candidate->used || candidate->cgroup_id != cgroup_id ||
                candidate->sequence <= previous_sequence)
                continue;
            if (!attachment || candidate->sequence < attachment->sequence)
                attachment = candidate;
        }
        if (!attachment) break;
        if (found < capacity) {
            object_ids[found] = attachment->object_id;
            if (attach_flags) attach_flags[found] = attachment->flags;
            if (link_object_ids)
                link_object_ids[found] = attachment->link_object_id;
        }
        previous_sequence = attachment->sequence;
        ++found;
    }
    *count = found;
    if (revision) *revision = *stored_revision;
    bpf_unlock();
    return found > capacity ? -EDGE_LINUX_ENOSPC : 0;
}

int kernel_bpf_cgroup_query(uint32_t cgroup_id, int *object_ids,
                            uint32_t *attach_flags, uint32_t capacity,
                            uint32_t *count, uint64_t *revision) {
    return kernel_bpf_cgroup_query_links(
        cgroup_id, object_ids, attach_flags, 0, capacity, count, revision);
}

int kernel_bpf_cgroup_device_run(
    uint32_t cgroup_id,
    const kernel_bpf_cgroup_device_context_t *context,
    uint32_t *result) {
    uint32_t aggregate = 1u;
    uint64_t previous_sequence = 0u;
    int notify_waiters = 0;
    int status = 0;

    if (!context || !result) return -EDGE_LINUX_EINVAL;
    bpf_lock();
    if (!bpf_cgroup_revision_locked(cgroup_id)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    for (;;) {
        const kernel_bpf_attachment_t *attachment = 0;
        kernel_bpf_object_t *object;
        uint32_t program_result = 0u;

        for (uint32_t index = 0;
             index < EDGE_RUNTIME_MAX_BPF_ATTACHMENTS; ++index) {
            const kernel_bpf_attachment_t *candidate =
                &g_bpf_attachments[index];
            if (!candidate->used || candidate->cgroup_id != cgroup_id ||
                candidate->sequence <= previous_sequence)
                continue;
            if (!attachment || candidate->sequence < attachment->sequence)
                attachment = candidate;
        }
        if (!attachment) break;
        previous_sequence = attachment->sequence;
        object = bpf_object_locked(attachment->object_id);
        status = bpf_program_run_cgroup_device_locked(
            object, context, sizeof(*context), &program_result,
            &notify_waiters, cgroup_id, attachment->attach_type,
            KERNEL_BPF_PROG_TYPE_CGROUP_DEVICE);
        if (status < 0) goto out;
        if (!program_result) aggregate = 0u;
    }
    *result = aggregate;
out:
    bpf_unlock();
    if (notify_waiters) kernel_bpf_ringbuf_state_changed();
    return status;
}

void kernel_bpf_cgroup_release(uint32_t cgroup_id) {
    (void)kernel_bpf_cgroup_detach(cgroup_id, -1, 0u);
    bpf_lock();
    bpf_legacy_cgroup_storage_release_locked(cgroup_id);
    bpf_unlock();
}

uint32_t kernel_bpf_cgroup_storage_owner_release(
        uint64_t cgroup_reference) {
    uint32_t released = 0u;

    if (!cgroup_reference) return 0u;
    bpf_lock();
    for (uint32_t object_index = 0;
         object_index < BPF_OBJECT_CAPACITY; ++object_index) {
        kernel_bpf_object_t *object = &g_bpf_objects[object_index];
        kernel_bpf_map_t *map;

        if (!object->used || object->kind != KERNEL_BPF_OBJECT_MAP)
            continue;
        map = &object->value.map;
        if (map->type != KERNEL_BPF_MAP_TYPE_CGRP_STORAGE)
            continue;
        for (uint32_t entry_index = 0;
             entry_index < map->storage_entries; ++entry_index) {
            uint8_t *entry = bpf_map_entry(map, entry_index);
            bpf_local_storage_owner_t owner = {0};

            if (!entry[0]) continue;
            memcpy(&owner, entry + 1u,
                   bpf_local_storage_owner_size(map));
            if (owner.primary != cgroup_reference) continue;
            memset(entry, 0, map->entry_stride);
            if (map->entry_count) --map->entry_count;
            ++released;
        }
    }
    bpf_unlock();
    return released;
}
