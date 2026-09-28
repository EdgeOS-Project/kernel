/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral task syscall scratch storage.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_TASK_SCRATCH_H
#define EDGEOS_KERNEL_TASK_SCRATCH_H

#include <stdint.h>
#include "kernel/fd_runtime.h"
#include "kernel/linux_abi.h"
#include "kernel/runtime_limits.h"
#include "kernel/wait_runtime.h"

#define KERNEL_TASK_PATH_MAX 4096u
#define KERNEL_TASK_PATH_SCRATCH_COUNT 13u
#define KERNEL_TASK_POLL_MAX 1024u
#define KERNEL_TASK_BPF_CGROUP_SCRATCH_SIZE 16384u
#define KERNEL_TASK_WAIT_SOURCE_MAX \
    (EDGE_RUNTIME_MAX_PIPES + EDGE_RUNTIME_MAX_SOCKETS + \
     EDGE_RUNTIME_MAX_EVENTFDS + EDGE_RUNTIME_MAX_INOTIFY_INSTANCES + \
     EDGE_RUNTIME_MAX_TIMERFDS)
#define KERNEL_TASK_FILESYSTEM_METADATA_WORDS 32u

typedef kernel_wait_pollfd_t kernel_linux_pollfd_t;

/*
 * Scratch memory is per task because two CLONE_VM threads may execute VFS,
 * xattr, vector-I/O, or futex syscalls concurrently.  It contains no
 * architecture register state and is shared by every architecture backend.
 */
typedef struct kernel_task_scratch {
    union {
        char path_scratch[KERNEL_TASK_PATH_SCRATCH_COUNT]
                         [KERNEL_TASK_PATH_MAX];
        uint64_t perf_event_values[EDGE_RUNTIME_MAX_PERF_EVENTS * 3u + 3u];
    };
    uint8_t xattr_scratch[EDGE_LINUX_XATTR_VALUE_MAX];
    /* Cgroup BPF evaluation may run while VFS path scratch remains live. */
    uint8_t bpf_cgroup_scratch[KERNEL_TASK_BPF_CGROUP_SCRATCH_SIZE];
    /*
     * SCM_RIGHTS receive keeps a 253-descriptor publication transaction off
     * the syscall stack. The target is inactive outside recvmsg and remains
     * address-stable for the complete prepare/copy/publish sequence.
     */
    kernel_fd_transfer_target_t socket_rights_target;
    uint8_t *block_io_scratch;
    uint32_t block_io_scratch_capacity;
    uint8_t *block_readahead_scratch;
    uint32_t block_readahead_scratch_capacity;
    uint8_t *loop_io_scratch;
    uint32_t loop_io_scratch_capacity;
    uint8_t *filesystem_io_scratch;
    uint32_t filesystem_io_scratch_capacity;
    uint64_t filesystem_metadata_scratch[
        KERNEL_TASK_FILESYSTEM_METADATA_WORDS];
} kernel_task_scratch_t;

typedef struct kernel_task_wait_scratch {
    kernel_linux_pollfd_t poll_fds[KERNEL_TASK_POLL_MAX];
    uint32_t wait_sources[KERNEL_TASK_WAIT_SOURCE_MAX];
    uint16_t wait_source_count;
} kernel_task_wait_scratch_t;

uint64_t kernel_task_scratch_pool_bytes(uint32_t task_count);
int kernel_task_scratch_pool_initialize(void *memory, uint64_t size,
                                        uint32_t task_count);
kernel_task_scratch_t *kernel_task_scratch_space(uint32_t task_index);

uint64_t kernel_task_wait_scratch_pool_bytes(uint32_t task_count);
int kernel_task_wait_scratch_pool_initialize(void *memory, uint64_t size,
                                             uint32_t task_count);
kernel_task_wait_scratch_t *kernel_task_wait_scratch_space(
    uint32_t task_index);

/* Space acquisition may allocate. The caller exclusively owns the task slot
 * and must not hold a scheduler lock. Release only after task users and wait
 * registrations have quiesced; it releases both scratch areas for that slot. */
void kernel_task_scratch_release(uint32_t task_index);

kernel_task_scratch_t *arch_task_scratch_current(void);
void *kernel_task_block_scratch_acquire(uint32_t capacity);
void *kernel_task_block_readahead_scratch_acquire(uint32_t capacity);
void *kernel_task_loop_io_scratch_acquire(uint32_t capacity);
void *kernel_task_filesystem_scratch_acquire(uint32_t capacity);
void *kernel_task_filesystem_metadata_scratch(void);

#endif /* EDGEOS_KERNEL_TASK_SCRATCH_H */
