/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux prctl state runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/linux_prctl.h"
#include "kernel/process_runtime.h"

static void prctl_state_clear(kernel_linux_prctl_state_t *state) {
    uint8_t *bytes = (uint8_t *)state;
    uint32_t index;
    for (index = 0; index < sizeof(*state); ++index) bytes[index] = 0;
}

static int kernel_current_prctl_state_snapshot(
    kernel_linux_prctl_state_t *state, int32_t *tid, int32_t *tgid) {
    kernel_linux_identity_t identity;
    kernel_proc_task_view_t view;

    if (!state) return -1;
    prctl_state_clear(state);
    if (kernel_current_linux_identity(&identity) < 0) return -1;
    if (kernel_proc_task_view_get(identity.global_tid, &view) == 0 &&
        view.state != KERNEL_PROC_TASK_ZOMBIE) {
        state->parent_death_signal = view.parent_death_signal;
        state->dumpable = view.dumpable;
        state->no_new_privileges = view.no_new_privileges;
        state->seccomp_mode = view.seccomp_mode;
        state->thp_disabled = view.thp_disabled;
        state->child_subreaper = view.child_subreaper;
        state->timer_slack_ns = view.timer_slack_ns;
        state->default_timer_slack_ns = view.default_timer_slack_ns;
        for (uint32_t index = 0; index + 1u < sizeof(state->name);
             ++index) {
            state->name[index] = view.comm[index];
            if (!view.comm[index]) break;
        }
        state->name[EDGE_LINUX_PRCTL_NAME_LENGTH - 1u] = 0;
        if (tid) *tid = identity.global_tid;
        if (tgid) *tgid = identity.global_tgid;
        return 0;
    }
    prctl_state_clear(state);
    return -1;
}

int kernel_current_prctl_state_get(kernel_linux_prctl_state_t *state) {
    return kernel_current_prctl_state_snapshot(state, 0, 0);
}

int kernel_linux_prctl_state_matches(
    const kernel_linux_prctl_state_t *left,
    const kernel_linux_prctl_state_t *right, uint32_t update_mask) {
    if (!left || !right) return 0;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_PARENT_DEATH_SIGNAL) &&
        left->parent_death_signal != right->parent_death_signal)
        return 0;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_DUMPABLE) &&
        left->dumpable != right->dumpable)
        return 0;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_NO_NEW_PRIVILEGES) &&
        left->no_new_privileges != right->no_new_privileges)
        return 0;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_TIMER_SLACK) &&
        left->timer_slack_ns != right->timer_slack_ns)
        return 0;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_THP_DISABLED) &&
        left->thp_disabled != right->thp_disabled)
        return 0;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_CHILD_SUBREAPER) &&
        left->child_subreaper != right->child_subreaper)
        return 0;
    if (update_mask & EDGE_LINUX_PRCTL_UPDATE_NAME) {
        for (uint32_t index = 0; index < EDGE_LINUX_PRCTL_NAME_LENGTH;
             ++index) {
            if (left->name[index] != right->name[index]) return 0;
            if (!left->name[index]) break;
        }
    }
    return 1;
}

int kernel_current_prctl_state_update(
    const kernel_linux_prctl_state_t *state, uint32_t update_mask) {
    kernel_linux_prctl_commit_t commit;
    const uint32_t valid_mask =
        EDGE_LINUX_PRCTL_UPDATE_PARENT_DEATH_SIGNAL |
        EDGE_LINUX_PRCTL_UPDATE_DUMPABLE |
        EDGE_LINUX_PRCTL_UPDATE_NO_NEW_PRIVILEGES |
        EDGE_LINUX_PRCTL_UPDATE_TIMER_SLACK |
        EDGE_LINUX_PRCTL_UPDATE_THP_DISABLED |
        EDGE_LINUX_PRCTL_UPDATE_NAME |
        EDGE_LINUX_PRCTL_UPDATE_CHILD_SUBREAPER;
    if (!state || (update_mask & ~valid_mask)) return -1;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_PARENT_DEATH_SIGNAL) &&
        state->parent_death_signal > 64u)
        return -1;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_DUMPABLE) &&
        state->dumpable > 1u)
        return -1;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_NO_NEW_PRIVILEGES) &&
        state->no_new_privileges != 1u)
        return -1;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_TIMER_SLACK) &&
        !state->timer_slack_ns)
        return -1;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_THP_DISABLED) &&
        state->thp_disabled != 0u && state->thp_disabled != 1u &&
        state->thp_disabled != 3u)
        return -1;
    if ((update_mask & EDGE_LINUX_PRCTL_UPDATE_CHILD_SUBREAPER) &&
        state->child_subreaper > 1u)
        return -1;
    if (kernel_current_prctl_state_snapshot(
            &commit.expected, &commit.tid, &commit.expected_tgid) < 0)
        return -1;
    commit.requested = *state;
    commit.update_mask = update_mask;
    return kernel_arch_current_prctl_state_commit(&commit);
}
