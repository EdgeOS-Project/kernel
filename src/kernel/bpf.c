/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux BPF object runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/bpf_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/runtime_limits.h"
#include "kernel/smp.h"
#include "mm/arch_vm.h"
#include "string.h"

#define BPF_OBJECT_CAPACITY EDGE_RUNTIME_MAX_BPF_OBJECTS
#define BPF_PAGE_SIZE 4096u
#define BPF_OBJECT_ALLOCATION_LIMIT (16u * 1024u * 1024u)

#define BPF_CLASS(code) ((code) & 0x07u)
#define BPF_SIZE(code)  ((code) & 0x18u)
#define BPF_MODE(code)  ((code) & 0xe0u)
#define BPF_OP(code)    ((code) & 0xf0u)
#define BPF_SRC(code)   ((code) & 0x08u)

#define BPF_LDX   0x01u
#define BPF_ALU64 0x07u
#define BPF_JMP   0x05u
#define BPF_W     0x00u
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
#define BPF_EXIT  0x90u

typedef struct kernel_bpf_map {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t flags;
    uint32_t entry_stride;
    uint32_t entry_count;
    uint32_t storage_pages;
    uint32_t queue_head;
    uint32_t queue_tail;
    uint32_t value_stride;
    uint32_t possible_cpu_count;
    uint64_t access_sequence;
    uint8_t frozen;
    uint8_t *storage;
    char name[KERNEL_BPF_OBJECT_NAME_LENGTH];
} kernel_bpf_map_t;

typedef struct kernel_bpf_program {
    uint32_t type;
    uint32_t instruction_count;
    uint32_t flags;
    uint32_t expected_attach_type;
    uint32_t created_by_uid;
    uint32_t gpl_compatible;
    uint32_t storage_pages;
    uint64_t run_time_ns;
    uint64_t run_count;
    uint8_t tag[8];
    kernel_bpf_instruction_t *instructions;
    char name[KERNEL_BPF_OBJECT_NAME_LENGTH];
} kernel_bpf_program_t;

typedef struct kernel_bpf_object {
    uint8_t used;
    uint8_t kind;
    uint16_t padding;
    uint32_t references;
    uint32_t user_id;
    union {
        kernel_bpf_map_t map;
        kernel_bpf_program_t program;
    } value;
} kernel_bpf_object_t;

typedef struct kernel_bpf_attachment {
    uint8_t used;
    uint8_t padding[3];
    uint32_t cgroup_id;
    int32_t object_id;
    uint32_t flags;
    uint64_t sequence;
} kernel_bpf_attachment_t;

static kernel_bpf_object_t g_bpf_objects[BPF_OBJECT_CAPACITY];
static kernel_bpf_attachment_t
    g_bpf_attachments[EDGE_RUNTIME_MAX_BPF_ATTACHMENTS];
static uint64_t g_bpf_cgroup_revisions[256];
static volatile uint32_t g_bpf_lock;
static uint32_t g_bpf_next_user_id = 1u;
static uint64_t g_bpf_attachment_sequence;

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
         map->type == KERNEL_BPF_MAP_TYPE_LRU_PERCPU_HASH);
}

static int bpf_map_is_array(const kernel_bpf_map_t *map) {
    return map &&
        (map->type == KERNEL_BPF_MAP_TYPE_ARRAY ||
         map->type == KERNEL_BPF_MAP_TYPE_PERCPU_ARRAY);
}

static int bpf_map_type_is_percpu(uint32_t type) {
    return type == KERNEL_BPF_MAP_TYPE_PERCPU_HASH ||
           type == KERNEL_BPF_MAP_TYPE_PERCPU_ARRAY ||
           type == KERNEL_BPF_MAP_TYPE_LRU_PERCPU_HASH;
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
    uint32_t value_stride;
    uint32_t possible_cpu_count;
    uint32_t actual_max_entries;
    uint64_t bytes;
    uint8_t *storage;
    int object_id;
    int status;

    if (!request || !bpf_name_valid(request->name) ||
        request->key_size > KERNEL_BPF_MAX_KEY_SIZE ||
        !request->value_size ||
        request->value_size > KERNEL_BPF_MAX_VALUE_SIZE ||
        !request->max_entries)
        return -EDGE_LINUX_EINVAL;
    if (bpf_map_type_is_queue_stack(request->type)) {
        if (request->key_size) return -EDGE_LINUX_EINVAL;
    } else if (!request->key_size) {
        return -EDGE_LINUX_EINVAL;
    }
    value_stride = bpf_align8(request->value_size);
    possible_cpu_count =
        (bpf_map_type_is_percpu(request->type) ||
         (bpf_map_type_is_lru_hash(request->type) &&
          (request->flags & KERNEL_BPF_MAP_NO_COMMON_LRU))) ?
        kernel_bpf_possible_cpu_count() : 1u;
    if (!possible_cpu_count) possible_cpu_count = 1u;
    actual_max_entries = request->max_entries;
    if (request->type == KERNEL_BPF_MAP_TYPE_ARRAY ||
        request->type == KERNEL_BPF_MAP_TYPE_PERCPU_ARRAY) {
        if (request->key_size != sizeof(uint32_t) || request->flags)
            return -EDGE_LINUX_EINVAL;
        stride = request->type == KERNEL_BPF_MAP_TYPE_PERCPU_ARRAY ?
            value_stride * possible_cpu_count : value_stride;
    } else if (request->type == KERNEL_BPF_MAP_TYPE_HASH ||
               request->type == KERNEL_BPF_MAP_TYPE_PERCPU_HASH) {
        if (request->flags & ~KERNEL_BPF_MAP_NO_PREALLOC)
            return -EDGE_LINUX_EINVAL;
        stride = request->type == KERNEL_BPF_MAP_TYPE_PERCPU_HASH ?
            bpf_align8(1u + request->key_size) +
                value_stride * possible_cpu_count :
            bpf_align8(1u + request->key_size + request->value_size);
    } else if (request->type == KERNEL_BPF_MAP_TYPE_LRU_HASH ||
               request->type == KERNEL_BPF_MAP_TYPE_LRU_PERCPU_HASH) {
        if (request->flags & KERNEL_BPF_MAP_NO_PREALLOC)
            return -EDGE_LINUX_ENOTSUPP;
        if (request->flags & ~KERNEL_BPF_MAP_NO_COMMON_LRU)
            return -EDGE_LINUX_EINVAL;
        if (request->flags & KERNEL_BPF_MAP_NO_COMMON_LRU) {
            uint64_t rounded =
                ((uint64_t)actual_max_entries + possible_cpu_count - 1u) /
                possible_cpu_count * possible_cpu_count;

            if (rounded > UINT32_MAX)
                rounded = actual_max_entries -
                    actual_max_entries % possible_cpu_count;
            if (!rounded) return -EDGE_LINUX_E2BIG;
            actual_max_entries = (uint32_t)rounded;
        }
        stride = request->type == KERNEL_BPF_MAP_TYPE_LRU_PERCPU_HASH ?
            bpf_align8(1u + request->key_size) +
                value_stride * possible_cpu_count + sizeof(uint64_t) :
            bpf_align8(1u + request->key_size + request->value_size) +
                sizeof(uint64_t);
    } else if (bpf_map_type_is_queue_stack(request->type)) {
        if (request->flags) return -EDGE_LINUX_EINVAL;
        stride = bpf_align8(request->value_size);
    } else {
        return -EDGE_LINUX_EINVAL;
    }
    bytes = (uint64_t)stride * actual_max_entries;
    status = bpf_allocation_size(bytes, &pages);
    if (status < 0) return status;
    storage = (uint8_t *)arch_vm_alloc_pages(pages);
    if (!storage) return -EDGE_LINUX_ENOMEM;
    memset(storage, 0, (uint64_t)pages * BPF_PAGE_SIZE);

    bpf_lock();
    object_id = bpf_allocate_object_locked(KERNEL_BPF_OBJECT_MAP, &object);
    if (object_id >= 0) {
        object->value.map.type = request->type;
        object->value.map.key_size = request->key_size;
        object->value.map.value_size = request->value_size;
        object->value.map.max_entries = actual_max_entries;
        object->value.map.flags = request->flags;
        object->value.map.entry_stride = stride;
        object->value.map.value_stride = value_stride;
        object->value.map.possible_cpu_count = possible_cpu_count;
        object->value.map.storage_pages = pages;
        object->value.map.storage = storage;
        memcpy(object->value.map.name, request->name,
               KERNEL_BPF_OBJECT_NAME_LENGTH);
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

static void bpf_program_tag(const kernel_bpf_instruction_t *instructions,
                            uint32_t count, uint8_t tag[8]) {
    uint32_t state[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
    };
    const uint8_t *bytes = (const uint8_t *)instructions;
    uint64_t length = (uint64_t)count * sizeof(*instructions);
    uint64_t offset = 0;
    uint8_t final_blocks[128];
    uint32_t final_size;

    while (length - offset >= 64u) {
        bpf_sha256_transform(state, bytes + offset);
        offset += 64u;
    }
    final_size = (uint32_t)(length - offset);
    memset(final_blocks, 0, sizeof(final_blocks));
    if (final_size) memcpy(final_blocks, bytes + offset, final_size);
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
    uint16_t initialized = 1u << 1;
    uint32_t pc;

    if (!request || !instructions ||
        request->type != KERNEL_BPF_PROG_TYPE_CGROUP_DEVICE ||
        !request->instruction_count ||
        request->instruction_count > KERNEL_BPF_MAX_INSTRUCTIONS ||
        request->flags ||
        (request->expected_attach_type &&
         request->expected_attach_type != KERNEL_BPF_CGROUP_DEVICE) ||
        !bpf_name_valid(request->name))
        return -EDGE_LINUX_EINVAL;

    for (pc = 0; pc < request->instruction_count; ++pc) {
        const kernel_bpf_instruction_t *instruction = &instructions[pc];
        uint32_t destination = bpf_program_destination(instruction);
        uint32_t source = bpf_program_source(instruction);
        uint32_t class = BPF_CLASS(instruction->code);
        uint32_t operation = BPF_OP(instruction->code);

        if (destination >= 11u || source >= 11u || destination == 10u)
            return -EDGE_LINUX_EINVAL;
        if (class == BPF_ALU64) {
            if (operation == BPF_MOV) {
                if (BPF_SRC(instruction->code) == BPF_X &&
                    !(initialized & (1u << source)))
                    return -EDGE_LINUX_EINVAL;
            } else {
                if (!(initialized & (1u << destination)) ||
                    (BPF_SRC(instruction->code) == BPF_X &&
                     !(initialized & (1u << source))) ||
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
            }
            initialized |= (uint16_t)(1u << destination);
            continue;
        }
        if (class == BPF_LDX && BPF_MODE(instruction->code) == BPF_MEM &&
            BPF_SIZE(instruction->code) == BPF_W && source == 1u &&
            (initialized & (1u << source)) &&
            instruction->offset >= 0 && instruction->offset <= 8 &&
            !(instruction->offset & 3)) {
            initialized |= (uint16_t)(1u << destination);
            continue;
        }
        if (class == BPF_JMP && operation == BPF_EXIT) {
            if (instruction->code != (BPF_JMP | BPF_EXIT) ||
                !(initialized & 1u) ||
                pc + 1u != request->instruction_count)
                return -EDGE_LINUX_EINVAL;
            return 0;
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

int kernel_bpf_program_create(
    const kernel_bpf_program_create_request_t *request,
    const kernel_bpf_instruction_t *instructions) {
    kernel_bpf_object_t *object;
    kernel_bpf_instruction_t *storage;
    uint32_t pages;
    int object_id;
    int status;

    status = bpf_program_validate(request, instructions);
    if (status < 0) return status;
    status = bpf_allocation_size(
        (uint64_t)request->instruction_count * sizeof(*instructions), &pages);
    if (status < 0) return status;
    storage = (kernel_bpf_instruction_t *)arch_vm_alloc_pages(pages);
    if (!storage) return -EDGE_LINUX_ENOMEM;
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
        object->value.program.instructions = storage;
        bpf_program_tag(
            storage, request->instruction_count,
            object->value.program.tag);
        memcpy(object->value.program.name, request->name,
               KERNEL_BPF_OBJECT_NAME_LENGTH);
    }
    bpf_unlock();
    if (object_id < 0) bpf_free_pages(storage, pages);
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

    bpf_lock();
    object = bpf_object_locked(object_id);
    if (object && object->references && !--object->references) {
        if (object->kind == KERNEL_BPF_OBJECT_MAP) {
            storage = object->value.map.storage;
            pages = object->value.map.storage_pages;
        } else if (object->kind == KERNEL_BPF_OBJECT_PROGRAM) {
            storage = object->value.program.instructions;
            pages = object->value.program.storage_pages;
        }
        memset(object, 0, sizeof(*object));
    }
    bpf_unlock();
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
    memcpy(info->name, object->value.map.name, sizeof(info->name));
    bpf_unlock();
    return 0;
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
    status = bpf_map_check_percpu_flags_locked(map, flags);
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
    for (index = 0; index < map->max_entries; ++index) {
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
    status = bpf_map_check_percpu_flags_locked(map, flags);
    if (status < 0 || ((uint32_t)flags & ~KERNEL_BPF_F_CPU)) {
        if (status == 0) status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (bpf_map_is_queue_stack(map)) {
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
        bpf_map_copy_value_out(map, index, value, flags);
    } else {
        bpf_map_hash_find(map, key, &index, &free_slot);
        if (index == UINT32_MAX) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        bpf_map_copy_value_out(map, index, value, flags);
        if (!bpf_map_is_percpu(map)) bpf_map_lru_touch(map, index);
    }
out:
    bpf_unlock();
    return status;
}

int kernel_bpf_map_lookup(int object_id, const void *key, void *value) {
    return kernel_bpf_map_lookup_flags(object_id, key, value, 0u);
}

int kernel_bpf_map_update(int object_id, const void *key, const void *value,
                          uint64_t flags) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint8_t *entry;
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
    if (bpf_map_is_queue_stack(map)) {
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
        if (flags == KERNEL_BPF_NOEXIST) {
            status = -EDGE_LINUX_EEXIST;
            goto out;
        }
        status = bpf_map_array_index(map, key, &index);
        if (status < 0) goto out;
        bpf_map_copy_value_in(map, index, value, flags);
    } else {
        bpf_map_hash_find(map, key, &index, &free_slot);
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
        bpf_map_copy_value_in(map, index, value, flags);
        bpf_map_lru_touch(map, index);
    }
out:
    bpf_unlock();
    return status;
}

int kernel_bpf_map_lookup_and_delete(int object_id, const void *key,
                                     void *value) {
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
    bpf_map_copy_value_out(map, index, value, 0u);
    memset(bpf_map_entry(map, index), 0, map->entry_stride);
    if (map->entry_count) --map->entry_count;
out:
    bpf_unlock();
    return status;
}

int kernel_bpf_map_delete(int object_id, const void *key) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint32_t index;
    uint32_t free_slot;
    int status = 0;

    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (map->frozen) {
        status = -EDGE_LINUX_EPERM;
        goto out;
    }
    if (bpf_map_is_queue_stack(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (!key) {
        status = -EDGE_LINUX_EFAULT;
        goto out;
    }
    if (bpf_map_is_array(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    bpf_map_hash_find(map, key, &index, &free_slot);
    if (index == UINT32_MAX) {
        status = -EDGE_LINUX_ENOENT;
        goto out;
    }
    memset(bpf_map_entry(map, index), 0, map->entry_stride);
    if (map->entry_count) --map->entry_count;
out:
    bpf_unlock();
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
    if (bpf_map_is_queue_stack(map)) {
        status = -EDGE_LINUX_EINVAL;
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
    if (key) bpf_map_hash_find(map, key, &index, &free_slot);
    next = index == UINT32_MAX ? 0u : index + 1u;
    while (next < map->max_entries && !bpf_map_entry(map, next)[0]) ++next;
    if (next >= map->max_entries) {
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
    if (delete_element && !bpf_map_is_hash(map)) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    index = *cursor;
    if (bpf_map_is_array(map)) {
        if (index >= map->max_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(key, &index, sizeof(index));
        bpf_map_copy_value_out(map, index, value, flags);
    } else {
        while (index < map->max_entries && !bpf_map_entry(map, index)[0])
            ++index;
        if (index >= map->max_entries) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(key, bpf_map_entry(map, index) + 1u, map->key_size);
        bpf_map_copy_value_out(map, index, value, flags);
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
        *has_more = *cursor < map->max_entries;
    } else {
        index = *cursor;
        while (index < map->max_entries && !bpf_map_entry(map, index)[0])
            ++index;
        *has_more = index < map->max_entries;
    }
out:
    bpf_unlock();
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

static int bpf_program_run_cgroup_device_locked(
        kernel_bpf_object_t *object,
        const kernel_bpf_cgroup_device_context_t *context,
        uint32_t *result) {
    kernel_bpf_instruction_t *instructions;
    uint32_t count;
    uint64_t registers[11] = {0};
    uint32_t pc;

    if (!object || object->kind != KERNEL_BPF_OBJECT_PROGRAM ||
        object->value.program.type != KERNEL_BPF_PROG_TYPE_CGROUP_DEVICE)
        return -EDGE_LINUX_EBADF;
    instructions = object->value.program.instructions;
    count = object->value.program.instruction_count;
    registers[1] = (uint64_t)(uintptr_t)context;
    for (pc = 0; pc < count; ++pc) {
        const kernel_bpf_instruction_t *instruction = &instructions[pc];
        uint32_t destination = bpf_program_destination(instruction);
        uint32_t source = bpf_program_source(instruction);
        uint32_t operation = BPF_OP(instruction->code);
        uint64_t operand = BPF_SRC(instruction->code) == BPF_X ?
            registers[source] : (uint64_t)(int64_t)instruction->immediate;

        if (BPF_CLASS(instruction->code) == BPF_ALU64) {
            registers[destination] = bpf_alu_result(
                operation, registers[destination], operand);
        } else if (BPF_CLASS(instruction->code) == BPF_LDX) {
            uint32_t value;
            memcpy(&value, (const uint8_t *)context + instruction->offset,
                   sizeof(value));
            registers[destination] = value;
        } else if (operation == BPF_EXIT) {
            *result = (uint32_t)registers[0];
            ++object->value.program.run_count;
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
    kernel_bpf_object_t *object;
    int status;

    if (!context || !result) return -EDGE_LINUX_EINVAL;
    bpf_lock();
    object = bpf_object_locked(object_id);
    status = bpf_program_run_cgroup_device_locked(object, context, result);
    bpf_unlock();
    return status;
}

static uint64_t *bpf_cgroup_revision_locked(uint32_t cgroup_id) {
    if (cgroup_id >= sizeof(g_bpf_cgroup_revisions) /
                         sizeof(g_bpf_cgroup_revisions[0]))
        return 0;
    return &g_bpf_cgroup_revisions[cgroup_id];
}

int kernel_bpf_cgroup_attach(uint32_t cgroup_id, int object_id,
                             uint32_t flags, int replace_object_id) {
    kernel_bpf_attachment_t *free_attachment = 0;
    kernel_bpf_attachment_t *replacement = 0;
    kernel_bpf_object_t *object;
    uint64_t *revision;
    int released_object = -1;
    int status = 0;

    if ((flags & ~(KERNEL_BPF_F_ALLOW_OVERRIDE |
                   KERNEL_BPF_F_ALLOW_MULTI |
                   KERNEL_BPF_F_REPLACE)) ||
        ((flags & KERNEL_BPF_F_ALLOW_OVERRIDE) &&
         (flags & KERNEL_BPF_F_ALLOW_MULTI)) ||
        ((flags & KERNEL_BPF_F_REPLACE) &&
         !(flags & KERNEL_BPF_F_ALLOW_MULTI)) ||
        ((flags & KERNEL_BPF_F_REPLACE) != 0) !=
            (replace_object_id >= 0))
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
    for (uint32_t index = 0;
         index < EDGE_RUNTIME_MAX_BPF_ATTACHMENTS; ++index) {
        kernel_bpf_attachment_t *attachment = &g_bpf_attachments[index];
        if (!attachment->used) {
            if (!free_attachment) free_attachment = attachment;
            continue;
        }
        if (attachment->cgroup_id != cgroup_id) continue;
        if (attachment->object_id == object_id &&
            !(flags & KERNEL_BPF_F_REPLACE)) {
            status = -EDGE_LINUX_EEXIST;
            goto out;
        }
        if (flags & KERNEL_BPF_F_REPLACE) {
            if (attachment->object_id == replace_object_id)
                replacement = attachment;
            continue;
        }
        if (!(flags & KERNEL_BPF_F_ALLOW_MULTI) ||
            !(attachment->flags & KERNEL_BPF_F_ALLOW_MULTI)) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
    }
    if (flags & KERNEL_BPF_F_REPLACE) {
        kernel_bpf_object_t *replaced =
            bpf_object_locked(replace_object_id);
        if (!replacement || !replaced ||
            replaced->kind != KERNEL_BPF_OBJECT_PROGRAM) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        if (object->references == UINT32_MAX) {
            status = -EDGE_LINUX_EBUSY;
            goto out;
        }
        ++object->references;
        released_object = replacement->object_id;
        replacement->object_id = object_id;
        replacement->flags = flags & ~KERNEL_BPF_F_REPLACE;
    } else {
        if (!free_attachment) {
            status = -EDGE_LINUX_ENOSPC;
            goto out;
        }
        if (object->references == UINT32_MAX) {
            status = -EDGE_LINUX_EBUSY;
            goto out;
        }
        ++object->references;
        memset(free_attachment, 0, sizeof(*free_attachment));
        free_attachment->used = 1u;
        free_attachment->cgroup_id = cgroup_id;
        free_attachment->object_id = object_id;
        free_attachment->flags =
            flags & ~KERNEL_BPF_F_REPLACE;
        ++g_bpf_attachment_sequence;
        if (!g_bpf_attachment_sequence) ++g_bpf_attachment_sequence;
        free_attachment->sequence = g_bpf_attachment_sequence;
    }
    ++*revision;
out:
    bpf_unlock();
    if (released_object >= 0)
        kernel_bpf_object_release(released_object);
    return status;
}

int kernel_bpf_cgroup_detach(uint32_t cgroup_id, int object_id) {
    uint64_t *revision;
    int released[EDGE_RUNTIME_MAX_BPF_ATTACHMENTS];
    uint32_t released_count = 0u;

    bpf_lock();
    revision = bpf_cgroup_revision_locked(cgroup_id);
    if (!revision) {
        bpf_unlock();
        return -EDGE_LINUX_EINVAL;
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

int kernel_bpf_cgroup_query(uint32_t cgroup_id, int *object_ids,
                            uint32_t *attach_flags, uint32_t capacity,
                            uint32_t *count, uint64_t *revision) {
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
        }
        previous_sequence = attachment->sequence;
        ++found;
    }
    *count = found;
    if (revision) *revision = *stored_revision;
    bpf_unlock();
    return found > capacity ? -EDGE_LINUX_ENOSPC : 0;
}

int kernel_bpf_cgroup_device_run(
    uint32_t cgroup_id,
    const kernel_bpf_cgroup_device_context_t *context,
    uint32_t *result) {
    uint32_t aggregate = 1u;
    uint64_t previous_sequence = 0u;
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
            object, context, &program_result);
        if (status < 0) goto out;
        if (!program_result) aggregate = 0u;
    }
    *result = aggregate;
out:
    bpf_unlock();
    return status;
}

void kernel_bpf_cgroup_release(uint32_t cgroup_id) {
    (void)kernel_bpf_cgroup_detach(cgroup_id, -1);
}
