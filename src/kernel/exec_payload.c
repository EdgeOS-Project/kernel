/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS shared Linux exec argument and environment capture.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include "kernel/exec_payload.h"
#include "kernel/linux_errno.h"
#include "mm/arch_vm.h"
#include "string.h"
#ifdef EDGEOS_HOST_TEST
#include <stdio.h>
#else
#include "stdio.h"
#endif
#include "sys/spinlock.h"

typedef struct kernel_exec_payload_slot {
    uint8_t used;
    uint8_t cached;
    int32_t owner_pid;
    uint64_t generation;
    linux_exec_payload_t *payload;
} kernel_exec_payload_slot_t;

#define EXEC_PAYLOAD_PAGES \
    ((sizeof(linux_exec_payload_t) + EDGE_PAGE_SIZE - 1u) / EDGE_PAGE_SIZE)

static spinlock_t g_exec_payload_lock;
static kernel_exec_payload_slot_t *g_exec_payload_slots;
static uint32_t g_exec_payload_slot_count;
static kernel_exec_record_t **g_exec_records;
static uint32_t g_exec_record_count;
static uint8_t g_exec_payload_exhaustion_dumped;

static uint32_t string_length_limited(const char *string, uint32_t limit) {
    uint32_t length = 0;
    if (!string) return limit;
    while (length < limit && string[length]) ++length;
    return length;
}

static int payload_budget_valid(const linux_exec_payload_t *payload,
                                uint32_t additional_strings,
                                uint32_t additional_bytes) {
    uint64_t pointers;
    uint64_t total;
    if (!payload || payload->argc > LINUX_EXEC_POINTER_MAX ||
        payload->envc > LINUX_EXEC_POINTER_MAX - payload->argc ||
        additional_strings > LINUX_EXEC_POINTER_MAX - payload->argc - payload->envc ||
        payload->bytes_used > LINUX_EXEC_BYTES_MAX ||
        additional_bytes > LINUX_EXEC_BYTES_MAX - payload->bytes_used)
        return 0;
    pointers = (uint64_t)payload->argc + payload->envc + additional_strings + 2u;
    total = (uint64_t)payload->bytes_used + additional_bytes +
            pointers * sizeof(uint64_t);
    return total <= LINUX_EXEC_BYTES_MAX;
}

void linux_exec_payload_reset(linux_exec_payload_t *payload) {
    if (!payload) return;
    payload->argc = 0;
    payload->envc = 0;
    payload->bytes_used = 0;
}

int linux_exec_payload_append(linux_exec_payload_t *payload,
                              const char *string, int environment,
                              uint32_t *offset_out) {
    uint32_t length;
    uint32_t offset;
    uint32_t vector_index;
    if (offset_out) *offset_out = 0;
    if (!payload || !string) return -EDGE_LINUX_EFAULT;
    length = string_length_limited(string, LINUX_EXEC_STRING_MAX);
    if (length == LINUX_EXEC_STRING_MAX) return -EDGE_LINUX_E2BIG;
    ++length;
    if (!payload_budget_valid(payload, 1u, length)) return -EDGE_LINUX_E2BIG;
    offset = payload->bytes_used;
    memcpy(&payload->bytes[offset], string, length);
    payload->bytes_used += length;
    if (environment) {
        vector_index = payload->argc + payload->envc;
        payload->offsets[vector_index] = offset;
        ++payload->envc;
    } else {
        /* Keep the environment segment after argv while argv is extended. */
        for (uint32_t i = payload->envc; i > 0; --i)
            payload->offsets[payload->argc + i] =
                payload->offsets[payload->argc + i - 1u];
        payload->offsets[payload->argc++] = offset;
    }
    if (offset_out) *offset_out = offset;
    return 0;
}

static int payload_append_user_string(
    linux_exec_payload_t *payload, void *copy_context,
    linux_exec_copy_from_user_fn copy_from_user, uint64_t user_string,
    int environment) {
    uint32_t offset;
    uint32_t length = 0;
    uint32_t string_budget;
    uint32_t vector_index;
    char chunk[256];
    if (!payload || !copy_from_user || !user_string)
        return -EDGE_LINUX_EFAULT;
    if (!payload_budget_valid(payload, 1u, 1u)) return -EDGE_LINUX_E2BIG;
    offset = payload->bytes_used;
    /* Capture does not publish counts until the terminator is copied, so
     * the available byte budget is constant throughout this string. */
    string_budget = LINUX_EXEC_BYTES_MAX - offset -
        ((uint64_t)payload->argc + payload->envc + 3u) * sizeof(uint64_t);
    if (string_budget > LINUX_EXEC_STRING_MAX)
        string_budget = LINUX_EXEC_STRING_MAX;
    while (length < string_budget) {
        if (user_string + length < user_string)
            return -EDGE_LINUX_EFAULT;
        uint32_t page_available = 4096u -
            (uint32_t)((user_string + length) & 4095u);
        uint32_t remaining = string_budget - length;
        uint32_t count = page_available;
        if (count > sizeof(chunk)) count = sizeof(chunk);
        if (count > remaining) count = remaining;
        if (copy_from_user(copy_context, chunk, user_string + length,
                           count) < 0)
            return -EDGE_LINUX_EFAULT;
        for (uint32_t i = 0; i < count; ++i) {
            payload->bytes[offset + length + i] = chunk[i];
            if (!chunk[i]) {
                payload->bytes_used += length + i + 1u;
                if (environment) {
                    vector_index = payload->argc + payload->envc;
                    payload->offsets[vector_index] = offset;
                    ++payload->envc;
                } else {
                    for (uint32_t env = payload->envc; env > 0; --env)
                        payload->offsets[payload->argc + env] =
                            payload->offsets[payload->argc + env - 1u];
                    payload->offsets[payload->argc++] = offset;
                }
                return 0;
            }
        }
        length += count;
    }
    return -EDGE_LINUX_E2BIG;
}

int linux_exec_payload_capture_vector_with(
    linux_exec_payload_t *payload, void *copy_context,
    linux_exec_copy_from_user_fn copy_from_user, uint64_t user_vector,
    uint8_t vector_word_size, int environment) {
    uint32_t count = 0;
    if (!payload || !copy_from_user) return -EDGE_LINUX_EFAULT;
    if (vector_word_size != sizeof(uint32_t) &&
        vector_word_size != sizeof(uint64_t))
        return -EDGE_LINUX_EINVAL;
    if (!user_vector) return 0;
    while (payload->argc + payload->envc < LINUX_EXEC_POINTER_MAX) {
        uint64_t source = 0;
        uint64_t slot = user_vector +
            (uint64_t)count * vector_word_size;
        int result;
        if (slot < user_vector || copy_from_user(
                copy_context, &source, slot, vector_word_size) < 0)
            return -EDGE_LINUX_EFAULT;
        if (!source) return 0;
        result = payload_append_user_string(
            payload, copy_context, copy_from_user, source, environment);
        if (result < 0) return result;
        ++count;
    }
    return -EDGE_LINUX_E2BIG;
}

const char *linux_exec_payload_argument(const linux_exec_payload_t *payload,
                                        uint32_t index) {
    uint32_t offset;
    if (!payload || index >= payload->argc) return 0;
    offset = payload->offsets[index];
    return offset < payload->bytes_used ? &payload->bytes[offset] : 0;
}

const char *linux_exec_payload_environment(const linux_exec_payload_t *payload,
                                           uint32_t index) {
    uint32_t offset;
    if (!payload || index >= payload->envc) return 0;
    offset = payload->offsets[payload->argc + index];
    return offset < payload->bytes_used ? &payload->bytes[offset] : 0;
}

int linux_exec_payload_prepend_script(linux_exec_payload_t *payload,
                                      const char *interpreter,
                                      const char *interpreter_argument,
                                      const char *script_path) {
    uint32_t interpreter_offset;
    uint32_t argument_offset = 0;
    uint32_t script_offset;
    uint32_t retained;
    uint32_t inserted = interpreter_argument && interpreter_argument[0] ? 3u : 2u;
    uint32_t old_argc;
    uint32_t old_envc;
    int result;

    if (!payload || !interpreter || !script_path) return -EDGE_LINUX_EFAULT;
    old_argc = payload->argc;
    old_envc = payload->envc;
    retained = old_argc ? old_argc - 1u : 0u;
    if (inserted + retained > LINUX_EXEC_POINTER_MAX - old_envc)
        return -EDGE_LINUX_E2BIG;

    result = linux_exec_payload_append(payload, interpreter, 0,
                                       &interpreter_offset);
    if (result < 0) return result;
    if (inserted == 3u) {
        result = linux_exec_payload_append(payload, interpreter_argument, 0,
                                           &argument_offset);
        if (result < 0) return result;
    }
    result = linux_exec_payload_append(payload, script_path, 0, &script_offset);
    if (result < 0) return result;

    /* append() placed the new strings after old argv; now publish Linux order. */
    for (uint32_t i = 0; i < old_envc; ++i)
        payload->offsets[inserted + retained + i] =
            payload->offsets[old_argc + inserted + i];
    for (uint32_t i = retained; i > 0; --i)
        payload->offsets[inserted + i - 1u] = payload->offsets[i];
    payload->offsets[0] = interpreter_offset;
    if (inserted == 3u) payload->offsets[1] = argument_offset;
    payload->offsets[inserted - 1u] = script_offset;
    payload->argc = inserted + retained;
    payload->envc = old_envc;
    return payload_budget_valid(payload, 0, 0) ? 0 : -EDGE_LINUX_E2BIG;
}

int linux_exec_payload_ensure_argv0(linux_exec_payload_t *payload,
                                    const char *path) {
    if (!payload || !path) return -EDGE_LINUX_EFAULT;
    if (payload->argc) return 0;
    return linux_exec_payload_append(payload, path, 0, 0);
}

uint64_t kernel_exec_payload_pool_bytes(void) {
    return kernel_exec_payload_pool_bytes_for_slots(
        KERNEL_EXEC_PAYLOAD_SLOT_COUNT);
}

uint64_t kernel_exec_payload_pool_bytes_for_slots(uint32_t slot_count) {
    if (!slot_count || slot_count > KERNEL_EXEC_PAYLOAD_SLOT_COUNT)
        return 0;
    return (uint64_t)slot_count * sizeof(kernel_exec_payload_slot_t);
}

int kernel_exec_payload_pool_initialize(void *memory, uint64_t size,
                                        uint32_t slot_count) {
    uint64_t required = kernel_exec_payload_pool_bytes_for_slots(slot_count);
    if (!memory || !required || size < required)
        return -EDGE_LINUX_ENOMEM;
    g_exec_payload_slots = (kernel_exec_payload_slot_t *)memory;
    g_exec_payload_slot_count = (uint32_t)slot_count;
    memset(g_exec_payload_slots, 0, (uint32_t)required);
    spinlock_init(&g_exec_payload_lock);
    return 0;
}

uint64_t kernel_exec_payload_cache_bytes(uint32_t payload_count) {
    if (!payload_count || payload_count > KERNEL_EXEC_PAYLOAD_SLOT_COUNT)
        return 0;
    return (uint64_t)payload_count * sizeof(linux_exec_payload_t);
}

int kernel_exec_payload_cache_initialize(void *memory, uint64_t size,
                                         uint32_t payload_count) {
    uint64_t required = kernel_exec_payload_cache_bytes(payload_count);
    if (!memory || !required || size < required || !g_exec_payload_slots ||
        payload_count > g_exec_payload_slot_count)
        return -EDGE_LINUX_ENOMEM;
    for (uint32_t index = 0; index < payload_count; ++index) {
        kernel_exec_payload_slot_t *slot = &g_exec_payload_slots[index];
        slot->payload = (linux_exec_payload_t *)((uint8_t *)memory +
            (uint64_t)index * sizeof(linux_exec_payload_t));
        slot->cached = 1;
        linux_exec_payload_reset(slot->payload);
    }
    return 0;
}

int kernel_exec_payload_acquire(int32_t owner_pid,
                                kernel_exec_payload_handle_t *handle,
                                linux_exec_payload_t **payload_out) {
    uint64_t flags;
    if (payload_out) *payload_out = 0;
    if (!handle || !payload_out || !g_exec_payload_slots)
        return -EDGE_LINUX_ENOMEM;
    handle->slot = 0;
    handle->generation = 0;
    flags = spin_lock_irqsave(&g_exec_payload_lock);
    for (uint32_t index = 0; index < g_exec_payload_slot_count; ++index) {
        kernel_exec_payload_slot_t *slot = &g_exec_payload_slots[index];
        if (slot->used) continue;
        slot->used = 1;
        slot->owner_pid = owner_pid;
        if (++slot->generation == 0) ++slot->generation;
        spin_unlock_irqrestore(&g_exec_payload_lock, flags);
        /* Allocation can reclaim pages or wait for I/O. Never do it under
         * the transaction lock with interrupts masked. This slot remains
         * reserved until allocation completes or rolls back. */
        linux_exec_payload_t *payload = slot->payload;
        if (!payload) payload = arch_vm_alloc_pages(EXEC_PAYLOAD_PAGES);
        if (payload) linux_exec_payload_reset(payload);
        flags = spin_lock_irqsave(&g_exec_payload_lock);
        if (!payload) {
            slot->used = 0;
            slot->owner_pid = 0;
            spin_unlock_irqrestore(&g_exec_payload_lock, flags);
            printf("[exec-payload] allocation failed pid=%d pages=%u\n",
                   owner_pid, (unsigned)EXEC_PAYLOAD_PAGES);
            return -EDGE_LINUX_ENOMEM;
        }
        slot->payload = payload;
        handle->slot = slot;
        handle->generation = slot->generation;
        *payload_out = payload;
        spin_unlock_irqrestore(&g_exec_payload_lock, flags);
        return 0;
    }
    spin_unlock_irqrestore(&g_exec_payload_lock, flags);
    printf("[exec-payload] pool exhausted pid=%d slots=%u\n",
           owner_pid, (unsigned)g_exec_payload_slot_count);
    if (!g_exec_payload_exhaustion_dumped) {
        g_exec_payload_exhaustion_dumped = 1;
        for (uint32_t index = 0; index < g_exec_payload_slot_count; ++index) {
            kernel_exec_payload_slot_t *slot = &g_exec_payload_slots[index];
            printf("[exec-payload] active slot=%u owner=%d generation=%llu cached=%u\n",
                   (unsigned)index, slot->owner_pid,
                   (unsigned long long)slot->generation,
                   (unsigned)slot->cached);
        }
    }
    return -EDGE_LINUX_ENOMEM;
}

void kernel_exec_payload_release(kernel_exec_payload_handle_t *handle) {
    kernel_exec_payload_slot_t *slot;
    linux_exec_payload_t *payload = 0;
    uint64_t flags;
    if (!handle || !handle->slot) return;
    slot = (kernel_exec_payload_slot_t *)handle->slot;
    flags = spin_lock_irqsave(&g_exec_payload_lock);
    if (slot->used && slot->generation == handle->generation) {
        payload = slot->payload;
        if (!slot->cached) slot->payload = 0;
        slot->used = 0;
        slot->owner_pid = 0;
    }
    spin_unlock_irqrestore(&g_exec_payload_lock, flags);
    handle->slot = 0;
    handle->generation = 0;
    if (payload && !slot->cached) {
        for (uint64_t page = 0; page < EXEC_PAYLOAD_PAGES; ++page)
            arch_vm_free_page((uint8_t *)payload + page * EDGE_PAGE_SIZE);
    }
}

uint64_t kernel_exec_record_pool_bytes(uint32_t address_space_count) {
    if (!address_space_count) return 0;
    return (uint64_t)address_space_count * sizeof(g_exec_records[0]);
}

int kernel_exec_record_pool_initialize(void *memory, uint64_t size,
                                       uint32_t address_space_count) {
    uint64_t required =
        kernel_exec_record_pool_bytes(address_space_count);
    if (!memory || !required || size < required || required > UINT32_MAX)
        return -EDGE_LINUX_ENOMEM;
    g_exec_records = (kernel_exec_record_t **)memory;
    g_exec_record_count = address_space_count;
    memset(g_exec_records, 0, (uint32_t)required);
    return 0;
}

kernel_exec_record_t *kernel_exec_record_space(uint32_t address_space_index) {
    if (!g_exec_records || address_space_index >= g_exec_record_count)
        return 0;
    return g_exec_records[address_space_index];
}

kernel_exec_record_t *kernel_exec_record_acquire(uint32_t index) {
    if (!g_exec_records || index >= g_exec_record_count) return 0;
    if (!g_exec_records[index]) {
        uint64_t pages = (sizeof(kernel_exec_record_t) + EDGE_PAGE_SIZE - 1u) /
                         EDGE_PAGE_SIZE;
        kernel_exec_record_t *record = arch_vm_alloc_pages(pages);
        if (!record) return 0;
        memset(record, 0, pages * EDGE_PAGE_SIZE);
        g_exec_records[index] = record;
    }
    return g_exec_records[index];
}

void kernel_exec_record_release(uint32_t index) {
    kernel_exec_record_t *record = kernel_exec_record_space(index);
    if (!record) return;
    g_exec_records[index] = 0;
    uint64_t pages = (sizeof(*record) + EDGE_PAGE_SIZE - 1u) / EDGE_PAGE_SIZE;
    for (uint64_t page = 0; page < pages; ++page)
        arch_vm_free_page((uint8_t *)record + page * EDGE_PAGE_SIZE);
}

void kernel_exec_record_reset(kernel_exec_record_t *record) {
    if (!record) return;
    record->argc = 0;
    record->envc = 0;
    record->bytes_used = 0;
    record->reserved = 0;
    record->arguments[0] = 0;
    record->environment[0] = 0;
    record->bytes[0] = 0;
}

int kernel_exec_record_budget_ok(const kernel_exec_record_t *record) {
    uint64_t vector_bytes;
    if (!record || record->argc > KERNEL_EXEC_RECORD_ARG_MAX ||
        record->envc > KERNEL_EXEC_RECORD_ENV_MAX ||
        record->bytes_used > KERNEL_EXEC_RECORD_BYTE_MAX)
        return 0;
    vector_bytes =
        ((uint64_t)record->argc + record->envc + 2u) * sizeof(uint64_t);
    return vector_bytes <= KERNEL_EXEC_RECORD_BYTE_MAX &&
           record->bytes_used <=
               KERNEL_EXEC_RECORD_BYTE_MAX - vector_bytes;
}

int kernel_exec_record_append(kernel_exec_record_t *record, const char *string,
                              int environment, char **stored_out) {
    uint32_t length;
    uint32_t bytes;
    char *destination;
    if (stored_out) *stored_out = 0;
    if (!record || !string) return -EDGE_LINUX_EFAULT;
    if (environment) {
        if (record->envc >= KERNEL_EXEC_RECORD_ENV_MAX)
            return -EDGE_LINUX_E2BIG;
    } else if (record->argc >= KERNEL_EXEC_RECORD_ARG_MAX) {
        return -EDGE_LINUX_E2BIG;
    }
    length = string_length_limited(string, KERNEL_EXEC_RECORD_STRING_MAX);
    if (length == KERNEL_EXEC_RECORD_STRING_MAX)
        return -EDGE_LINUX_E2BIG;
    bytes = length + 1u;
    if (record->bytes_used > KERNEL_EXEC_RECORD_BYTE_MAX ||
        bytes > KERNEL_EXEC_RECORD_BYTE_MAX - record->bytes_used)
        return -EDGE_LINUX_E2BIG;
    destination = &record->bytes[record->bytes_used];
    memcpy(destination, string, bytes);
    record->bytes_used += bytes;
    if (environment) {
        record->environment[record->envc++] = destination;
        record->environment[record->envc] = 0;
    } else {
        record->arguments[record->argc++] = destination;
        record->arguments[record->argc] = 0;
    }
    if (!kernel_exec_record_budget_ok(record)) {
        if (environment) {
            record->environment[--record->envc] = 0;
        } else {
            record->arguments[--record->argc] = 0;
        }
        record->bytes_used -= bytes;
        record->bytes[record->bytes_used] = 0;
        return -EDGE_LINUX_E2BIG;
    }
    if (stored_out) *stored_out = destination;
    return 0;
}

int kernel_exec_record_contains(const kernel_exec_record_t *record,
                                const char *string) {
    uintptr_t address;
    uintptr_t begin;
    uintptr_t end;
    if (!record || !string ||
        record->bytes_used > KERNEL_EXEC_RECORD_BYTE_MAX)
        return 0;
    address = (uintptr_t)string;
    begin = (uintptr_t)&record->bytes[0];
    end = begin + record->bytes_used;
    return address >= begin && address < end;
}

static int exec_record_rebase_vector(
    char **destination, uint32_t count,
    const kernel_exec_record_t *source,
    const char *const *source_vector,
    kernel_exec_record_t *destination_record) {
    uintptr_t source_begin = (uintptr_t)&source->bytes[0];
    uintptr_t destination_begin =
        (uintptr_t)&destination_record->bytes[0];
    for (uint32_t index = 0; index < count; ++index) {
        uintptr_t source_address = (uintptr_t)source_vector[index];
        uint64_t offset;
        if (!kernel_exec_record_contains(source, source_vector[index]))
            return -EDGE_LINUX_EFAULT;
        offset = (uint64_t)(source_address - source_begin);
        if (offset >= destination_record->bytes_used)
            return -EDGE_LINUX_EFAULT;
        destination[index] =
            (char *)(destination_begin + (uintptr_t)offset);
    }
    destination[count] = 0;
    return 0;
}

int kernel_exec_record_copy(kernel_exec_record_t *destination,
                            const kernel_exec_record_t *source) {
    if (!destination || !source || destination == source)
        return destination == source ? 0 : -EDGE_LINUX_EFAULT;
    if (!kernel_exec_record_budget_ok(source))
        return -EDGE_LINUX_EFAULT;
    kernel_exec_record_reset(destination);
    destination->argc = source->argc;
    destination->envc = source->envc;
    destination->bytes_used = source->bytes_used;
    if (source->bytes_used)
        memcpy(destination->bytes, source->bytes, source->bytes_used);
    if (exec_record_rebase_vector(
            destination->arguments, destination->argc, source,
            (const char *const *)source->arguments, destination) < 0 ||
        exec_record_rebase_vector(
            destination->environment, destination->envc, source,
            (const char *const *)source->environment, destination) < 0) {
        kernel_exec_record_reset(destination);
        return -EDGE_LINUX_EFAULT;
    }
    return 0;
}
