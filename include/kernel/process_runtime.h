/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_PROCESS_RUNTIME_H
#define EDGEOS_KERNEL_PROCESS_RUNTIME_H

#include <stdint.h>

#include "kernel/credentials.h"
#include "kernel/console_device.h"
#include "kernel/groups.h"
#include "kernel/linux_abi.h"
#include "kernel/restart_block.h"
#include "kernel/namespaces.h"
#include "kernel/linux_prctl.h"
#include "kernel/linux_ptrace.h"
#include "kernel/membarrier.h"
#include "kernel/process_session.h"
#include "kernel/process_control.h"
#include "kernel/scheduler_policy.h"
#include "kernel/seccomp.h"
#include "kernel/signal_runtime.h"
#include "kernel/system_runtime.h"

struct vfs_inode;
struct vfs_superblock;

typedef struct kernel_proc_task_snapshot {
    int32_t pid;
    int32_t tgid;
    int32_t ppid;
    int32_t pgid;
    int32_t sid;
    int32_t tty_pgrp;
    int8_t nice_value;
    uint8_t threads;
    uint32_t cgroup_id;
    uint32_t uid;
    uint32_t euid;
    uint32_t suid;
    uint32_t fsuid;
    uint32_t gid;
    uint32_t egid;
    uint32_t sgid;
    uint32_t fsgid;
    uint32_t syscall_nr;
    uint64_t syscall_args[6];
    uint64_t start_time_ticks;
    uint64_t user_time_ticks;
    uint64_t system_time_ticks;
    uint64_t children_user_time_ticks;
    uint64_t children_system_time_ticks;
    uint64_t minor_faults;
    uint64_t major_faults;
    uint64_t children_minor_faults;
    uint64_t children_major_faults;
    uint64_t virtual_size_bytes;
    uint64_t resident_size_bytes;
    uint64_t peak_resident_size_bytes;
    uint64_t locked_size_bytes;
    uint64_t text_size_bytes;
    uint64_t data_size_bytes;
    uint64_t stack_size_bytes;
    uint32_t processor;
    uint32_t scheduler_priority;
    uint32_t scheduler_policy;
    char state;
    char comm[16];
    char exec_path[256];
} kernel_proc_task_snapshot_t;

typedef enum kernel_proc_task_state {
    KERNEL_PROC_TASK_RUNNING = 1,
    KERNEL_PROC_TASK_SLEEPING = 2,
    KERNEL_PROC_TASK_STOPPED = 3,
    KERNEL_PROC_TASK_ZOMBIE = 4,
} kernel_proc_task_state_t;

typedef struct kernel_process_usage {
    uint64_t user_time_us;
    uint64_t sys_time_us;
    uint64_t maxrss_kb;
    uint64_t minor_faults;
    uint64_t major_faults;
    uint64_t input_blocks;
    uint64_t output_blocks;
    uint64_t voluntary_ctxt_switches;
    uint64_t involuntary_ctxt_switches;
} kernel_process_usage_t;

/* Security and process identity fields sampled from a native task record. */
typedef struct kernel_task_identity_view {
    int32_t tid;
    int32_t tgid;
    int32_t ppid;
    int32_t pgid;
    int32_t sid;
    uint32_t pid_namespace_id;
    uint32_t user_namespace_id;
    uint32_t uid;
    uint32_t euid;
    uint32_t suid;
    uint32_t fsuid;
    uint32_t gid;
    uint32_t egid;
    uint32_t sgid;
    uint32_t fsgid;
    uint8_t state;
    uint8_t dumpable;
    uint64_t permitted_capabilities;
    uint64_t effective_capabilities;
} kernel_task_identity_view_t;

typedef struct kernel_resource_limit {
    uint64_t current;
    uint64_t maximum;
} kernel_resource_limit_t;

/* Canonical task-table sample consumed by shared Linux process policy. */
typedef struct kernel_proc_task_view {
    int32_t tid;
    int32_t tgid;
    int32_t ppid;
    int32_t pgid;
    int32_t sid;
    int32_t tty_pgrp;
    int8_t nice_value;
    uint8_t state;
    uint16_t io_priority;
    uint16_t umask;
    edge_linux_scheduler_state_t scheduler;
    kernel_process_usage_t usage;
    kernel_process_usage_t children_usage;
    uint64_t start_time_ticks;
    uint32_t processor;
    uint64_t scheduler_vruntime_us;
    uint64_t scheduler_wait_us;
    uint64_t scheduler_migrations;
    uint64_t memory_context_id;
    uint64_t files_context_id;
    uint64_t fs_context_id;
    uint64_t sighand_context_id;
    uint64_t io_context_id;
    uint64_t sysvsem_context_id;
    uint64_t exec_file_handle;
    uint32_t cgroup_id;
    uint32_t mount_namespace_id;
    uint32_t pid_namespace_id;
    uint32_t user_namespace_id;
    uint32_t uid;
    uint32_t euid;
    uint32_t suid;
    uint32_t fsuid;
    uint32_t gid;
    uint32_t egid;
    uint32_t sgid;
    uint32_t fsgid;
    uint8_t dumpable;
    uint8_t no_new_privileges;
    uint8_t seccomp_mode;
    uint8_t thp_disabled;
    uint8_t execed_since_fork;
    uint8_t child_subreaper;
    uint32_t parent_death_signal;
    int32_t oom_score_adj;
    int32_t oom_score_adj_min;
    uint64_t timer_slack_ns;
    uint64_t default_timer_slack_ns;
    linux_capability_state_t capabilities;
    kernel_resource_limit_t resource_limits[EDGE_LINUX_RLIMIT_COUNT];
    uint64_t permitted_capabilities;
    uint64_t effective_capabilities;
    uint32_t syscall_nr;
    uint64_t syscall_args[6];
    char comm[16];
    char exec_path[256];
} kernel_proc_task_view_t;

typedef struct kernel_scheduler_cpu_stats {
    uint64_t user_time_us;
    uint64_t system_time_us;
    uint64_t idle_time_us;
    uint64_t runqueue_wait_us;
    uint64_t context_switches;
    uint64_t migrations;
    uint32_t nr_running;
} kernel_scheduler_cpu_stats_t;

typedef uintptr_t kernel_process_task_handle_t;

enum kernel_process_task_update_field {
    KERNEL_PROCESS_TASK_UPDATE_SESSION = 1u << 0,
    KERNEL_PROCESS_TASK_UPDATE_EXEC = 1u << 1,
    KERNEL_PROCESS_TASK_UPDATE_CGROUP = 1u << 2,
    KERNEL_PROCESS_TASK_UPDATE_RESOURCE_LIMIT = 1u << 3,
    KERNEL_PROCESS_TASK_UPDATE_OOM = 1u << 4,
    KERNEL_PROCESS_TASK_UPDATE_IO_PRIORITY = 1u << 5,
    KERNEL_PROCESS_TASK_UPDATE_SCHEDULER = 1u << 6,
    KERNEL_PROCESS_TASK_UPDATE_CREDENTIALS = 1u << 7,
    KERNEL_PROCESS_TASK_UPDATE_GROUPS = 1u << 8,
    KERNEL_PROCESS_TASK_UPDATE_UMASK = 1u << 9,
    KERNEL_PROCESS_TASK_UPDATE_PRCTL = 1u << 10,
};

/*
 * Architecture task backends expose native storage through opaque handles.
 * Linux-visible validation, target selection, and group updates stay in the
 * shared process commit runtime.
 */
typedef struct kernel_process_task_update {
    uint32_t fields;
    int32_t pgid;
    int32_t sid;
    uint8_t detach_controlling_terminal;
    uint8_t execed_since_fork;
    uint16_t io_priority;
    uint32_t cgroup_id;
    uint32_t resource;
    kernel_resource_limit_t resource_limit;
    int32_t oom_score_adj;
    int32_t oom_score_adj_min;
    edge_linux_scheduler_state_t scheduler;
    uint32_t scheduler_update_mask;
    linux_credential_state_t credentials;
    uint8_t clear_parent_death_signal;
    linux_group_list_t *groups;
    linux_group_list_t *previous_groups;
    int *result;
    uint16_t umask;
    kernel_linux_prctl_state_t prctl;
    uint32_t prctl_update_mask;
} kernel_process_task_update_t;

uint64_t arch_process_task_lock(void);
void arch_process_task_unlock(uint64_t flags);
uint32_t arch_process_task_capacity(void);
kernel_process_task_handle_t arch_process_task_at_locked(uint32_t slot);
kernel_process_task_handle_t arch_process_task_find_locked(int32_t tid);
kernel_process_task_handle_t arch_process_current_task_locked(void);
int arch_process_task_identity_locked(
    kernel_process_task_handle_t handle,
    kernel_task_identity_view_t *view);
int arch_process_task_view_locked(kernel_process_task_handle_t handle,
                                  kernel_proc_task_view_t *view);
void arch_process_task_apply_locked(
    kernel_process_task_handle_t handle,
    const kernel_process_task_update_t *update);
edge_seccomp_state_t *arch_process_task_seccomp_locked(
    kernel_process_task_handle_t handle);
void arch_process_task_seccomp_replace_locked(
    kernel_process_task_handle_t handle,
    const edge_seccomp_state_t *installed, int set_no_new_privileges);
uint32_t *arch_process_task_membarrier_locked(
    kernel_process_task_handle_t handle);

typedef struct kernel_linux_identity {
    int32_t global_tgid;
    int32_t global_tid;
    int32_t global_ppid;
    int32_t global_pgid;
    int32_t global_sid;
    int32_t pid;
    int32_t tgid;
    int32_t tid;
    int32_t ppid;
    int32_t pgid;
    int32_t sid;
    uint32_t pid_namespace_id;
    uint32_t user_namespace_id;
    uint32_t uid;
    uint32_t euid;
    uint32_t suid;
    uint32_t fsuid;
    uint32_t gid;
    uint32_t egid;
    uint32_t sgid;
    uint32_t fsgid;
    uint8_t dumpable;
    uint64_t permitted_capabilities;
    uint64_t effective_capabilities;
} kernel_linux_identity_t;

typedef enum kernel_procfd_link_kind {
    KERNEL_PROCFD_LINK_PATH = 1,
    KERNEL_PROCFD_LINK_PIPE,
    KERNEL_PROCFD_LINK_SOCKET,
    KERNEL_PROCFD_LINK_PIDFD,
    KERNEL_PROCFD_LINK_ANONYMOUS,
} kernel_procfd_link_kind_t;

typedef struct kernel_procfd_link_view {
    kernel_procfd_link_kind_t kind;
    uint64_t identity;
    char *path;
    uint32_t path_capacity;
    uint32_t path_length;
} kernel_procfd_link_view_t;

#define EDGE_LINUX_OOM_SCORE_ADJ_MIN (-1000)
#define EDGE_LINUX_OOM_SCORE_ADJ_MAX 1000

typedef struct kernel_oom_score_adj_access {
    uint32_t caller_euid;
    uint64_t caller_effective_capabilities;
    uint32_t target_uid;
    uint32_t target_suid;
    int32_t target_minimum;
} kernel_oom_score_adj_access_t;

typedef struct kernel_oom_score_adj_commit {
    int32_t caller_tid;
    uint32_t caller_euid;
    uint64_t caller_effective_capabilities;
    int32_t target_tid;
    int32_t target_tgid;
    uint32_t target_uid;
    uint32_t target_suid;
    int32_t target_minimum;
    int32_t value;
    int32_t new_minimum;
} kernel_oom_score_adj_commit_t;

enum kernel_process_wait_flags {
    KERNEL_PROCESS_WAIT_NOHANG = 1u << 0,
    KERNEL_PROCESS_WAIT_NOREAP = 1u << 1,
    KERNEL_PROCESS_WAIT_NOTHREAD = 1u << 2,
    KERNEL_PROCESS_WAIT_WALL = 1u << 3,
    KERNEL_PROCESS_WAIT_WCLONE = 1u << 4,
    KERNEL_PROCESS_WAIT_STOPPED = 1u << 5,
    KERNEL_PROCESS_WAIT_CONTINUED = 1u << 6,
    KERNEL_PROCESS_WAIT_EXITED = 1u << 7,
};

typedef struct kernel_process_wait_request {
    /* Linux wait4 selector form: >0 PID, 0 caller PGID, -1 any, <-1 PGID. */
    int32_t selector;
    uint32_t flags;
    uint32_t pid_namespace_id;
} kernel_process_wait_request_t;

typedef struct kernel_process_wait_result {
    int32_t pid;
    uint32_t uid;
    uint32_t status;
    kernel_process_usage_t usage;
} kernel_process_wait_result_t;

enum kernel_process_wait_id_type {
    KERNEL_PROCESS_WAIT_ID_ALL = 0,
    KERNEL_PROCESS_WAIT_ID_PID = 1,
    KERNEL_PROCESS_WAIT_ID_PGID = 2,
};

typedef struct kernel_process_wait_query {
    uint8_t id_type;
    int32_t id;
    uint32_t flags;
    uint32_t pid_namespace_id;
} kernel_process_wait_query_t;

int kernel_process_wait_query_build(
    const kernel_process_wait_request_t *request, int32_t caller_pgid,
    kernel_process_wait_query_t *query);
int kernel_process_wait_query_matches(
    const kernel_process_wait_query_t *query, int32_t candidate_pid,
    int32_t candidate_pgid);
uint32_t kernel_process_wait_exit_status(int32_t exit_code,
                                         uint32_t termination_signal);
uint32_t kernel_process_wait_stop_status(uint32_t stop_signal,
                                         uint32_t ptrace_event);
uint32_t kernel_process_wait_continue_status(void);

typedef struct kernel_process_times {
    uint64_t user_ticks;
    uint64_t system_ticks;
    uint64_t children_user_ticks;
    uint64_t children_system_ticks;
    uint64_t elapsed_ticks;
} kernel_process_times_t;

typedef struct kernel_linux_thread_state {
    uint64_t clear_child_tid;
    uint64_t robust_list_head;
    uint64_t robust_list_length;
    struct edge_linux_rseq_state rseq;
    uint32_t personality;
    uint32_t io_uring_wait_submitted;
    uint32_t io_uring_wait_active;
    uint64_t io_uring_wait_deadline_us;
    uint64_t io_uring_wait_minimum_deadline_us;
    kernel_restart_block_t restart_block;
} kernel_linux_thread_state_t;

typedef struct kernel_linux_rseq_binding {
    kernel_linux_thread_state_t *thread_state;
    edge_linux_copy_from_user_fn copy_from_user;
    edge_linux_copy_to_user_fn copy_to_user;
    void *copy_context;
    uint32_t cpu_id;
    uint32_t node_id;
    uint32_t mm_cid;
} kernel_linux_rseq_binding_t;

/*
 * Read-only task fields consumed by architecture-independent Linux policy.
 * Native runtimes populate this view without exposing their task structure.
 */
typedef struct kernel_process_native_view {
    uintptr_t context_token;
    int32_t pid;
    int32_t tgid;
    int32_t ppid;
    uint32_t uid;
    uint32_t euid;
    uint32_t suid;
    uint32_t gid;
    uint32_t egid;
    uint32_t sgid;
    uint8_t dumpable;
    uint8_t stopped;
    uint8_t zombie;
    uint8_t stop_reported;
    uint8_t stop_signal;
    const char *comm;
    kernel_linux_thread_state_t *linux_thread;
    edge_namespace_set_t *namespaces;
    edge_linux_ptrace_state_t *ptrace;
    edge_linux_signal_action_t *signal_actions;
    uint64_t *signal_mask;
} kernel_process_native_view_t;

int edge_process_runtime_current_view(
    kernel_process_native_view_t *view);
int edge_process_runtime_view(
    int32_t pid, kernel_process_native_view_t *view);
void edge_process_runtime_namespace_committed(
    const edge_namespace_set_t *namespaces);
int edge_process_runtime_fs_snapshot(
    int32_t pid, char *cwd, uint32_t cwd_capacity,
    char *root, uint32_t root_capacity);
int edge_process_runtime_fs_set_location(
    int32_t pid, const char *path, int set_root);
int edge_process_runtime_fs_unshare(int32_t pid);

void kernel_linux_thread_state_clone(
    kernel_linux_thread_state_t *child,
    const kernel_linux_thread_state_t *parent);
void kernel_linux_thread_state_exec(kernel_linux_thread_state_t *state);

int kernel_current_pid(void);
uintptr_t kernel_current_context_token(void);
__attribute__((noreturn)) void kernel_current_exit(int32_t code,
                                                   int whole_thread_group);
__attribute__((noreturn)) void arch_current_exit(int32_t code,
                                                 int whole_thread_group);
int kernel_current_identity(int32_t *pid, uint32_t *euid, uint32_t *egid);
int kernel_current_linux_identity(kernel_linux_identity_t *identity);
int kernel_current_cgroup_id(uint32_t *cgroup_id);
int kernel_current_no_new_privileges(void);
int kernel_process_linux_identity(int32_t pid,
                                  kernel_linux_identity_t *identity);
int kernel_process_resource_id(int32_t pid, uint32_t resource_type,
                               uint64_t *resource_id);
int kernel_process_usage(int who, kernel_process_usage_t *usage);
/* Returns one for an event, zero for WNOHANG, or a negative Linux errno. */
int64_t kernel_process_wait(const kernel_process_wait_request_t *request,
                            kernel_process_wait_result_t *result,
                            void *user_registers);
int64_t arch_process_wait(const kernel_process_wait_query_t *query,
                          kernel_process_wait_result_t *result,
                          void *user_registers);
int kernel_process_times(kernel_process_times_t *times);
int kernel_process_resource_limit_get(int32_t pid, uint32_t resource,
                                      kernel_resource_limit_t *limit);
int kernel_process_resource_limit_set(int32_t pid, uint32_t resource,
                                      const kernel_resource_limit_t *limit);
uint64_t kernel_resource_limit_ceiling(uint32_t resource);
int kernel_arch_process_resource_limit_commit(
    int32_t tid, int32_t expected_tgid, uint32_t resource,
    const kernel_resource_limit_t *limit);
int kernel_process_nice_set(const kernel_process_control_t *target,
                            int8_t nice_value);
uint64_t kernel_scheduler_online_cpu_mask(void);
int kernel_scheduler_state_get(int32_t tid,
                               edge_linux_scheduler_state_t *state);
int kernel_scheduler_state_set(const kernel_scheduler_target_t *target,
                               const edge_linux_scheduler_state_t *requested,
                               uint32_t update_mask);
uint64_t kernel_arch_scheduler_online_cpu_mask(void);
int kernel_arch_scheduler_state_commit(
    const kernel_scheduler_state_commit_t *commit);
int64_t kernel_scheduler_yield(void *user_registers);
int kernel_scheduler_proc_task_render(int32_t tid, char *buffer,
                                      uint32_t capacity);
int kernel_scheduler_proc_task_schedstat(int32_t tid, char *buffer,
                                         uint32_t capacity);
int kernel_scheduler_proc_system_schedstat(char *buffer,
                                           uint32_t capacity);
void kernel_scheduler_load_tick(void);
void kernel_scheduler_load_snapshot(uint32_t *one_hundredths,
                                    uint32_t *five_hundredths,
                                    uint32_t *fifteen_hundredths);
int kernel_arch_scheduler_cpu_stats(
    uint32_t cpu, kernel_scheduler_cpu_stats_t *stats);
int kernel_current_personality_get(uint32_t *personality);
int kernel_current_personality_set(uint32_t personality);
int kernel_current_clear_child_tid_set(uint64_t address);
int kernel_current_robust_list_set(uint64_t head, uint64_t length);
int kernel_process_robust_list_get(int32_t pid, uint64_t *head,
                                   uint64_t *length);
int kernel_current_rseq_register(uint64_t address, uint64_t length,
                                 uint64_t flags, uint64_t signature);
int kernel_current_rseq_slice_prctl(uint64_t operation, uint64_t value);
int kernel_current_rseq_slice_syscall_enter(int slice_yield_syscall,
                                            int *force_reschedule);
int kernel_current_rseq_slice_yield(void);
int kernel_current_rseq_slice_interrupt(uint64_t now_us);
int kernel_arch_current_request_reschedule(void);
int kernel_arch_current_rseq_slice_timer_arm(uint32_t microseconds);
void kernel_arch_current_rseq_slice_timer_cancel(void);
int kernel_arch_current_linux_thread_state(
    kernel_linux_thread_state_t **state);
int kernel_arch_process_linux_thread_state(
    int32_t pid, kernel_linux_thread_state_t **state);
int kernel_arch_current_rseq_binding(kernel_linux_rseq_binding_t *binding);
int edge_process_runtime_current_rseq_binding(
    kernel_linux_rseq_binding_t *binding);
/*
 * Sleep policy converts Linux clock values to an absolute monotonic deadline
 * before entering the architecture runtime.  The runtime only owns task
 * suspension and interrupted-sleep remainder delivery.
 */
int64_t kernel_current_sleep_until(uint64_t deadline_microseconds,
                                   uint64_t remaining_user,
                                   int write_remaining,
                                   void *user_registers);
int kernel_process_credentials_get(
    int32_t tid, linux_credential_state_t *credentials);
int kernel_arch_current_credentials_commit(
    const linux_credential_state_t *credentials,
    int clear_parent_death_signal);
int kernel_arch_process_credentials_commit(
    int32_t tid, const linux_credential_state_t *credentials,
    int clear_parent_death_signal);
int kernel_process_capabilities_get(int32_t tid,
                                    linux_capability_state_t *capabilities);
int kernel_arch_process_oom_score_adj_commit(
    const kernel_oom_score_adj_commit_t *commit);
int kernel_oom_score_adj_transition(
    const kernel_oom_score_adj_access_t *access,
    int32_t value, int32_t *new_minimum);
int kernel_process_oom_score_adj_get(int32_t tid, int32_t *value);
int kernel_process_oom_score_adj_set(int32_t tid, int32_t value);
int kernel_current_capabilities_set(
    const linux_capability_state_t *capabilities);
int kernel_current_credentials_get(linux_credential_state_t *credentials);
int kernel_current_credentials_set(
    const linux_credential_state_t *credentials);
int kernel_arch_process_groups_snapshot(int32_t tid,
                                        linux_group_list_t *groups);
int kernel_arch_current_groups_commit(linux_group_list_t *groups);
int kernel_process_groups_snapshot(int32_t pid, linux_group_list_t *groups);
int kernel_current_groups_snapshot(linux_group_list_t *groups);
int kernel_current_groups_replace(linux_group_list_t *groups);
int kernel_runtime_yield(void);
int kernel_runtime_contention_begin(void);
void kernel_runtime_contention_end(int released);
void kernel_runtime_fuse_notify(uint64_t description_identity);
void kernel_runtime_fuse_reply_wait(uint64_t description_identity);
void kernel_runtime_fuse_reply_notify(uint64_t description_identity,
                                      uintptr_t context_token);
int64_t arch_scheduler_yield(void *user_registers);
int64_t arch_current_sleep_until(uint64_t deadline_microseconds,
                                 uint64_t remaining_user,
                                 int write_remaining,
                                 void *user_registers);
int arch_runtime_yield(void);
int arch_runtime_contention_begin(void);
void arch_runtime_contention_end(int released);
void arch_runtime_fuse_notify(uint64_t description_identity);
void arch_runtime_fuse_reply_wait(uint64_t description_identity);
void arch_runtime_fuse_reply_notify(uint64_t description_identity,
                                    uintptr_t context_token);
int kernel_current_in_group(uint32_t gid);
int kernel_arch_current_fs_snapshot(char *cwd, uint32_t cwd_capacity,
                                    char *root, uint32_t root_capacity);
int kernel_arch_current_fs_set_location(const char *path, int set_root);
int kernel_arch_current_fs_unshare(void);
int kernel_arch_current_umask_commit(uint16_t mask, uint16_t *previous);
int kernel_current_fs_snapshot(char *cwd, uint32_t cwd_capacity,
                               char *root, uint32_t root_capacity);
int kernel_current_fs_set_cwd(const char *path);
int kernel_current_fs_set_root(const char *path);
int kernel_current_fs_unshare(void);
uint16_t kernel_current_umask(void);
uint16_t kernel_current_umask_set(uint16_t mask);
const char *kernel_current_comm(void);
const char *kernel_current_hostname(void);
const char *kernel_current_domainname(void);
int kernel_current_set_hostname(const char *name, uint32_t length);
int kernel_current_set_domainname(const char *name, uint32_t length);
void kernel_current_exec_committed(void);
int kernel_arch_process_exec_committed(int32_t tgid);
/* Returns zero for a live slot, one for an unused slot, and -1 past the table. */
int kernel_arch_proc_task_sample(uint32_t slot,
                                 kernel_proc_task_view_t *view);
int kernel_arch_proc_task_lookup(int32_t tid,
                                 kernel_proc_task_view_t *view);
int kernel_arch_proc_task_at_ordinal(uint32_t ordinal, int32_t *pid_out);
int kernel_arch_proc_thread_at_ordinal(int32_t tgid, uint32_t ordinal,
                                       int32_t *tid_out);
uint32_t kernel_arch_proc_thread_group_count(int32_t tgid);
int kernel_arch_proc_task_fs_snapshot(int32_t pid, char *cwd,
                                      uint32_t cwd_capacity, char *root,
                                      uint32_t root_capacity);
int kernel_arch_current_identity_sample(kernel_task_identity_view_t *view);
void kernel_proc_task_view_set_identity(
    kernel_proc_task_view_t *view,
    const kernel_task_identity_view_t *identity);
void kernel_proc_task_view_set_names(kernel_proc_task_view_t *view,
                                     const char *comm,
                                     const char *exec_path);
int kernel_proc_task_view_get(int32_t tid, kernel_proc_task_view_t *view);
int kernel_proc_task_at(uint32_t ordinal, int32_t *pid_out);
int kernel_proc_thread_at(int32_t tgid, uint32_t ordinal, int32_t *tid_out);
int kernel_proc_task_load_snapshot(uint32_t *running_out,
                                   uint32_t *total_out);
int kernel_proc_task_snapshot(int32_t pid, kernel_proc_task_snapshot_t *out);
int kernel_proc_task_fs_snapshot(int32_t pid, char *cwd,
                                 uint32_t cwd_capacity, char *root,
                                 uint32_t root_capacity);
int kernel_proc_task_exec_file(int32_t pid, struct vfs_inode *inode,
                               struct vfs_superblock **superblock);
int arch_proc_namespace_inode(int32_t pid, uint32_t kind,
                              uint64_t *inode_out);
int kernel_process_mount_namespace_id(int32_t pid, uint32_t *id_out);
int arch_proc_task_cmdline(int32_t pid, char *buffer, uint32_t capacity);
int arch_proc_task_environ(int32_t pid, char *buffer, uint32_t capacity);
int arch_procfd_at(int32_t pid, uint32_t ordinal, uint32_t *fd_out);
int kernel_procfd_readlink_target(int32_t pid, int32_t descriptor,
                                  char *target, uint32_t capacity);
int arch_procfd_link_view(int32_t pid, int32_t descriptor,
                          kernel_procfd_link_view_t *view);
int kernel_proc_cgroup_attach(int32_t pid, uint32_t cgroup_id,
                              int entire_thread_group);
/* Atomically commits the target selected and validated by the shared core. */
int kernel_arch_proc_cgroup_attach(int32_t tid, int32_t expected_tgid,
                                   uint32_t cgroup_id,
                                   int entire_thread_group);
uint64_t kernel_runtime_sysv_shmem_bytes(void);

/*
 * Architecture runtimes own task frames and scheduling mechanics.  The shared
 * ptrace core owns Linux request policy and reaches those mechanisms only
 * through this interface.
 */
int kernel_ptrace_traceme(int32_t tracer_pid);
int kernel_ptrace_attach(int32_t pid, int32_t tracer_pid, int seized,
                         uint32_t options);
int kernel_ptrace_attach_child(int32_t pid, int32_t tracer_pid, int seized,
                               uint32_t options);
int kernel_ptrace_detach(int32_t pid, int32_t tracer_pid, uint32_t signal);
int kernel_ptrace_set_options(int32_t pid, int32_t tracer_pid,
                              uint32_t options);
int kernel_ptrace_resume(int32_t pid, int32_t tracer_pid,
                         edge_linux_ptrace_resume_mode_t mode,
                         uint32_t signal);
int kernel_ptrace_interrupt(int32_t pid, int32_t tracer_pid);
int kernel_ptrace_kill(int32_t pid, int32_t tracer_pid);
int kernel_ptrace_read_memory(int32_t pid, uint64_t address, void *buffer,
                              uint64_t size);
int kernel_ptrace_write_memory(int32_t pid, uint64_t address,
                               const void *buffer, uint64_t size);
int kernel_ptrace_read_user_area(int32_t pid, uint64_t offset,
                                 uint64_t *value);
int kernel_ptrace_write_user_area(int32_t pid, uint64_t offset,
                                  uint64_t value);
int kernel_ptrace_get_regset(int32_t pid, uint32_t note, void *buffer,
                             uint64_t *size);
int kernel_ptrace_set_regset(int32_t pid, uint32_t note, const void *buffer,
                             uint64_t size);
int kernel_ptrace_stop_current(void *user_registers,
                               const edge_linux_ptrace_stop_t *stop);
int kernel_ptrace_consume_syscall_restart(void *user_registers);
int kernel_ptrace_current_syscall(void *user_registers, uint64_t *number,
                                  uint64_t arguments[6], int64_t *result);

int arch_ptrace_attach(int32_t pid, int seized);
int arch_ptrace_attach_child(int32_t pid, int seized);
int arch_ptrace_detach(int32_t pid, uint32_t signal);
int arch_ptrace_resume(int32_t pid,
                       edge_linux_ptrace_resume_mode_t mode,
                       uint32_t signal);
int arch_ptrace_interrupt(int32_t pid);
int arch_ptrace_kill(int32_t pid);
int arch_ptrace_stop_current(void *user_registers,
                             const edge_linux_ptrace_stop_t *stop);
int arch_ptrace_consume_syscall_restart(void *user_registers);

#endif
