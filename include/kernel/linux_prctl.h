/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux prctl ABI definitions.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_LINUX_PRCTL_H
#define EDGEOS_KERNEL_LINUX_PRCTL_H

#include <stdint.h>

#define EDGE_LINUX_PR_SET_PDEATHSIG 1u
#define EDGE_LINUX_PR_GET_PDEATHSIG 2u
#define EDGE_LINUX_PR_GET_DUMPABLE 3u
#define EDGE_LINUX_PR_SET_DUMPABLE 4u
#define EDGE_LINUX_PR_SET_NAME 15u
#define EDGE_LINUX_PR_GET_NAME 16u
#define EDGE_LINUX_PR_GET_SECCOMP 21u
#define EDGE_LINUX_PR_SET_SECCOMP 22u
#define EDGE_LINUX_PR_SET_TIMERSLACK 29u
#define EDGE_LINUX_PR_GET_TIMERSLACK 30u
#define EDGE_LINUX_PR_SET_CHILD_SUBREAPER 36u
#define EDGE_LINUX_PR_GET_CHILD_SUBREAPER 37u
#define EDGE_LINUX_PR_SET_NO_NEW_PRIVS 38u
#define EDGE_LINUX_PR_GET_NO_NEW_PRIVS 39u
#define EDGE_LINUX_PR_SET_THP_DISABLE 41u
#define EDGE_LINUX_PR_GET_THP_DISABLE 42u
#define EDGE_LINUX_PR_THP_DISABLE_EXCEPT_ADVISED (1u << 1)
#define EDGE_LINUX_PR_SET_VMA 0x53564d41u
#define EDGE_LINUX_PR_SET_VMA_ANON_NAME 0u

#define EDGE_LINUX_PRCTL_NAME_LENGTH 16u
#define EDGE_LINUX_DEFAULT_TIMER_SLACK_NS 50000u

typedef struct kernel_linux_prctl_state {
    uint32_t parent_death_signal;
    uint8_t dumpable;
    uint8_t no_new_privileges;
    uint8_t seccomp_mode;
    uint8_t thp_disabled;
    uint8_t child_subreaper;
    uint8_t padding[3];
    uint64_t timer_slack_ns;
    uint64_t default_timer_slack_ns;
    char name[EDGE_LINUX_PRCTL_NAME_LENGTH];
} kernel_linux_prctl_state_t;

enum {
    EDGE_LINUX_PRCTL_UPDATE_PARENT_DEATH_SIGNAL = 1u << 0,
    EDGE_LINUX_PRCTL_UPDATE_DUMPABLE = 1u << 1,
    EDGE_LINUX_PRCTL_UPDATE_NO_NEW_PRIVILEGES = 1u << 2,
    EDGE_LINUX_PRCTL_UPDATE_TIMER_SLACK = 1u << 3,
    EDGE_LINUX_PRCTL_UPDATE_THP_DISABLED = 1u << 4,
    EDGE_LINUX_PRCTL_UPDATE_NAME = 1u << 5,
    EDGE_LINUX_PRCTL_UPDATE_CHILD_SUBREAPER = 1u << 6,
};

typedef struct kernel_linux_prctl_commit {
    int32_t tid;
    int32_t expected_tgid;
    kernel_linux_prctl_state_t expected;
    kernel_linux_prctl_state_t requested;
    uint32_t update_mask;
} kernel_linux_prctl_commit_t;

int kernel_linux_prctl_state_matches(
    const kernel_linux_prctl_state_t *left,
    const kernel_linux_prctl_state_t *right, uint32_t update_mask);
int kernel_arch_current_prctl_state_commit(
    const kernel_linux_prctl_commit_t *commit);
int kernel_current_prctl_state_get(kernel_linux_prctl_state_t *state);
int kernel_current_prctl_state_update(
    const kernel_linux_prctl_state_t *state, uint32_t update_mask);

#endif
