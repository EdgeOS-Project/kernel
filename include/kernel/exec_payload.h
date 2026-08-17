/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS shared Linux exec payload storage.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_EXEC_PAYLOAD_H
#define EDGEOS_KERNEL_EXEC_PAYLOAD_H

#include <stdint.h>
#include "kernel/user_stack.h"

/*
 * Exec captures argv and envp before replacing the caller's address space.
 * A desktop can have many independent launchers, browser helpers, and D-Bus
 * activations in this transaction concurrently. Four global slots caused
 * otherwise healthy execve() calls to fail with ENOMEM during Chromium cold
 * start while more than a gigabyte of physical memory remained available.
 * Keep enough shared headroom for bursty desktop process creation without
 * reserving one 128 KiB payload for every possible task.
 */
#define KERNEL_EXEC_PAYLOAD_SLOT_COUNT 64u
#define KERNEL_EXEC_RECORD_ARG_MAX 256
#define KERNEL_EXEC_RECORD_ENV_MAX 256
#define KERNEL_EXEC_RECORD_BYTE_MAX (128u * 1024u)
#define KERNEL_EXEC_RECORD_STRING_MAX (32u * 4096u)

typedef struct kernel_exec_payload_handle {
    void *slot;
    uint64_t generation;
} kernel_exec_payload_handle_t;

/*
 * Persistent exec metadata belongs to a process address space, not to an
 * architecture trap frame or an individual thread.  It supplies the exact
 * argv/environment vectors used while constructing the initial user stack and
 * the Linux-visible /proc/<pid>/{cmdline,environ} data retained after exec.
 */
typedef struct kernel_exec_record {
    uint32_t argc;
    uint32_t envc;
    uint32_t bytes_used;
    uint32_t reserved;
    char *arguments[KERNEL_EXEC_RECORD_ARG_MAX + 1u];
    char *environment[KERNEL_EXEC_RECORD_ENV_MAX + 1u];
    char bytes[KERNEL_EXEC_RECORD_BYTE_MAX];
} kernel_exec_record_t;

uint64_t kernel_exec_payload_pool_bytes(void);
uint64_t kernel_exec_payload_pool_bytes_for_slots(uint32_t slot_count);
int kernel_exec_payload_pool_initialize(void *memory, uint64_t size);
int kernel_exec_payload_acquire(int32_t owner_pid,
                                kernel_exec_payload_handle_t *handle,
                                linux_exec_payload_t **payload_out);
void kernel_exec_payload_release(kernel_exec_payload_handle_t *handle);

uint64_t kernel_exec_record_pool_bytes(uint32_t address_space_count);
int kernel_exec_record_pool_initialize(void *memory, uint64_t size,
                                       uint32_t address_space_count);
kernel_exec_record_t *kernel_exec_record_space(uint32_t address_space_index);
void kernel_exec_record_reset(kernel_exec_record_t *record);
int kernel_exec_record_append(kernel_exec_record_t *record, const char *string,
                              int environment, char **stored_out);
int kernel_exec_record_contains(const kernel_exec_record_t *record,
                                const char *string);
int kernel_exec_record_budget_ok(const kernel_exec_record_t *record);
int kernel_exec_record_copy(kernel_exec_record_t *destination,
                            const kernel_exec_record_t *source);

#endif /* EDGEOS_KERNEL_EXEC_PAYLOAD_H */
