/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */
#ifndef EDGEOS_KERNEL_SECCOMP_H
#define EDGEOS_KERNEL_SECCOMP_H

#include <stdint.h>

/* Linux seccomp(2) operations and modes shared by every architecture. */
#define EDGE_LINUX_SECCOMP_SET_MODE_STRICT 0u
#define EDGE_LINUX_SECCOMP_SET_MODE_FILTER 1u
#define EDGE_LINUX_SECCOMP_GET_ACTION_AVAIL 2u
#define EDGE_LINUX_SECCOMP_GET_NOTIF_SIZES 3u

#define EDGE_LINUX_SECCOMP_MODE_DISABLED 0u
#define EDGE_LINUX_SECCOMP_MODE_STRICT 1u
#define EDGE_LINUX_SECCOMP_MODE_FILTER 2u

#define EDGE_LINUX_SECCOMP_FILTER_FLAG_TSYNC (1u << 0)
#define EDGE_LINUX_SECCOMP_FILTER_FLAG_LOG (1u << 1)
#define EDGE_LINUX_SECCOMP_FILTER_FLAG_SPEC_ALLOW (1u << 2)
#define EDGE_LINUX_SECCOMP_FILTER_FLAG_NEW_LISTENER (1u << 3)
#define EDGE_LINUX_SECCOMP_FILTER_FLAG_TSYNC_ESRCH (1u << 4)
#define EDGE_LINUX_SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (1u << 5)
#define EDGE_LINUX_SECCOMP_FILTER_FLAG_ALL \
    (EDGE_LINUX_SECCOMP_FILTER_FLAG_TSYNC | \
     EDGE_LINUX_SECCOMP_FILTER_FLAG_LOG | \
     EDGE_LINUX_SECCOMP_FILTER_FLAG_SPEC_ALLOW | \
     EDGE_LINUX_SECCOMP_FILTER_FLAG_NEW_LISTENER | \
     EDGE_LINUX_SECCOMP_FILTER_FLAG_TSYNC_ESRCH | \
     EDGE_LINUX_SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV)
#define EDGE_LINUX_SECCOMP_FILTER_FLAG_UNSUPPORTED \
    (EDGE_LINUX_SECCOMP_FILTER_FLAG_NEW_LISTENER | \
     EDGE_LINUX_SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV)

#define EDGE_SECCOMP_RET_KILL_THREAD  0x00000000u
#define EDGE_SECCOMP_RET_TRAP         0x00030000u
#define EDGE_SECCOMP_RET_ERRNO        0x00050000u
#define EDGE_SECCOMP_RET_TRACE        0x7ff00000u
#define EDGE_SECCOMP_RET_LOG          0x7ffc0000u
#define EDGE_SECCOMP_RET_ALLOW        0x7fff0000u
#define EDGE_SECCOMP_RET_KILL_PROCESS 0x80000000u
#define EDGE_SECCOMP_RET_ACTION_FULL  0xffff0000u
#define EDGE_SECCOMP_RET_DATA         0x0000ffffu

typedef struct {
    int32_t nr;
    uint32_t arch;
    uint64_t instruction_pointer;
    uint64_t args[6];
} edge_seccomp_data_t;

typedef struct {
    uint16_t length;
    uint16_t head_filter_id;
    uint32_t total_instructions;
} edge_seccomp_state_t;

typedef int (*edge_seccomp_copy_from_user_fn)(void *context, void *destination,
                                               uint64_t source, uint64_t size);

void edge_seccomp_state_init(edge_seccomp_state_t *state);
int edge_seccomp_state_retain(edge_seccomp_state_t *state);
void edge_seccomp_state_release(edge_seccomp_state_t *state);
int edge_seccomp_state_is_ancestor(const edge_seccomp_state_t *ancestor,
                                   const edge_seccomp_state_t *descendant);
int edge_seccomp_install(edge_seccomp_state_t *state, uint64_t fprog_user,
                         edge_seccomp_copy_from_user_fn copy_from_user,
                         void *copy_context);
edge_seccomp_state_t *kernel_arch_current_seccomp_state(void);
int kernel_arch_seccomp_synchronize_thread_group(
    const edge_seccomp_state_t *previous,
    const edge_seccomp_state_t *installed, uint32_t flags);
int kernel_current_seccomp_filter_install(
    uint64_t user_program, edge_seccomp_copy_from_user_fn copy_from_user,
    void *copy_context);
int edge_linux_seccomp_filter_install_current(
    uint64_t fprog_user, edge_seccomp_copy_from_user_fn copy_from_user,
    void *copy_context);
int edge_linux_seccomp_filter_install_current_flags(
    uint64_t fprog_user, uint32_t flags,
    edge_seccomp_copy_from_user_fn copy_from_user, void *copy_context);
uint32_t edge_seccomp_evaluate(const edge_seccomp_state_t *state,
                               const edge_seccomp_data_t *data);

#endif
