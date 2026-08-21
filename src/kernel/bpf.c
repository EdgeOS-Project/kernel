/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux BPF object runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/bpf_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/runtime_limits.h"
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
    uint8_t *storage;
    char name[KERNEL_BPF_OBJECT_NAME_LENGTH];
} kernel_bpf_map_t;

typedef struct kernel_bpf_program {
    uint32_t type;
    uint32_t instruction_count;
    uint32_t flags;
    uint32_t expected_attach_type;
    uint32_t created_by_uid;
    uint32_t storage_pages;
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

static kernel_bpf_object_t g_bpf_objects[BPF_OBJECT_CAPACITY];
static volatile uint32_t g_bpf_lock;
static uint32_t g_bpf_next_user_id = 1u;

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
    uint64_t bytes;
    uint8_t *storage;
    int object_id;
    int status;

    if (!request || !bpf_name_valid(request->name) ||
        !request->key_size || request->key_size > KERNEL_BPF_MAX_KEY_SIZE ||
        !request->value_size ||
        request->value_size > KERNEL_BPF_MAX_VALUE_SIZE ||
        !request->max_entries)
        return -EDGE_LINUX_EINVAL;
    if (request->type == KERNEL_BPF_MAP_TYPE_ARRAY) {
        if (request->key_size != sizeof(uint32_t) || request->flags)
            return -EDGE_LINUX_EINVAL;
        stride = bpf_align8(request->value_size);
    } else if (request->type == KERNEL_BPF_MAP_TYPE_HASH) {
        if (request->flags & ~KERNEL_BPF_MAP_NO_PREALLOC)
            return -EDGE_LINUX_EINVAL;
        stride = bpf_align8(1u + request->key_size + request->value_size);
    } else {
        return -EDGE_LINUX_EINVAL;
    }
    bytes = (uint64_t)stride * request->max_entries;
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
        object->value.map.max_entries = request->max_entries;
        object->value.map.flags = request->flags;
        object->value.map.entry_stride = stride;
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
        object->value.program.storage_pages = pages;
        object->value.program.instructions = storage;
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
    memcpy(info->name, object->value.program.name, sizeof(info->name));
    bpf_unlock();
    return 0;
}

static uint8_t *bpf_map_entry(kernel_bpf_map_t *map, uint32_t index) {
    return map->storage + (uint64_t)index * map->entry_stride;
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

int kernel_bpf_map_lookup(int object_id, const void *key, void *value) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint32_t index;
    uint32_t free_slot;
    int status = 0;

    if (!key || !value) return -EDGE_LINUX_EFAULT;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (map->type == KERNEL_BPF_MAP_TYPE_ARRAY) {
        status = bpf_map_array_index(map, key, &index);
        if (status < 0) goto out;
        memcpy(value, bpf_map_entry(map, index), map->value_size);
    } else {
        bpf_map_hash_find(map, key, &index, &free_slot);
        if (index == UINT32_MAX) {
            status = -EDGE_LINUX_ENOENT;
            goto out;
        }
        memcpy(value, bpf_map_entry(map, index) + 1u + map->key_size,
               map->value_size);
    }
out:
    bpf_unlock();
    return status;
}

int kernel_bpf_map_update(int object_id, const void *key, const void *value,
                          uint64_t flags) {
    kernel_bpf_object_t *object;
    kernel_bpf_map_t *map;
    uint8_t *entry;
    uint32_t index;
    uint32_t free_slot;
    int status = 0;

    if (!key || !value) return -EDGE_LINUX_EFAULT;
    if (flags != KERNEL_BPF_ANY && flags != KERNEL_BPF_NOEXIST &&
        flags != KERNEL_BPF_EXIST)
        return -EDGE_LINUX_EINVAL;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (map->type == KERNEL_BPF_MAP_TYPE_ARRAY) {
        if (flags == KERNEL_BPF_NOEXIST) {
            status = -EDGE_LINUX_EEXIST;
            goto out;
        }
        status = bpf_map_array_index(map, key, &index);
        if (status < 0) goto out;
        memcpy(bpf_map_entry(map, index), value, map->value_size);
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
            if (free_slot == UINT32_MAX) {
                status = -EDGE_LINUX_E2BIG;
                goto out;
            }
            index = free_slot;
            ++map->entry_count;
        }
        entry = bpf_map_entry(map, index);
        entry[0] = 1u;
        memcpy(entry + 1u, key, map->key_size);
        memcpy(entry + 1u + map->key_size, value, map->value_size);
    }
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

    if (!key) return -EDGE_LINUX_EFAULT;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_MAP) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    map = &object->value.map;
    if (map->type == KERNEL_BPF_MAP_TYPE_ARRAY) {
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
    if (map->type == KERNEL_BPF_MAP_TYPE_ARRAY) {
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

int kernel_bpf_program_run_cgroup_device(
    int object_id, const kernel_bpf_cgroup_device_context_t *context,
    uint32_t *result) {
    kernel_bpf_object_t *object;
    kernel_bpf_instruction_t *instructions;
    uint32_t count;
    uint64_t registers[11] = {0};
    uint32_t pc;
    int status = 0;

    if (!context || !result) return -EDGE_LINUX_EINVAL;
    bpf_lock();
    object = bpf_object_locked(object_id);
    if (!object || object->kind != KERNEL_BPF_OBJECT_PROGRAM ||
        object->value.program.type != KERNEL_BPF_PROG_TYPE_CGROUP_DEVICE) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
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
            goto out;
        } else if (bpf_jump_taken(operation, registers[destination], operand)) {
            pc += (uint32_t)instruction->offset;
        }
    }
    status = -EDGE_LINUX_EINVAL;
out:
    bpf_unlock();
    return status;
}
