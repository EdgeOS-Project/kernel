#ifndef SYS_PROCESS_H
#define SYS_PROCESS_H

#include <stdint.h>
#include "kernel/credentials.h"
#include "kernel/event_runtime.h"
#include "kernel/exec_payload.h"
#include "kernel/groups.h"
#include "kernel/linux_abi.h"
#include "kernel/linux_ptrace.h"
#include "kernel/mm_runtime.h"
#include "kernel/namespaces.h"
#include "kernel/process_runtime.h"
#include "kernel/runtime_limits.h"
#include "kernel/seccomp.h"
#include "kernel/signal_policy.h"
#include "kernel/task_scratch.h"
#include "mm/page_allocator.h"
#include "sys/spinlock.h"

struct kernel_exec_reset_configuration;

#define TASK_NAME_MAX 32
#define TASK_SYSCALL_HISTORY 12
#define TASK_CWD_MAX 4096
/*
 * Keep the task table large enough for Linux desktop thread churn.  Only the
 * first USER_AS_MAX_TASKS entries own full fixed process address-space backing;
 * entries above that are task/kernel-stack scheduler slots for CLONE_VM
 * threads.  GLib/GTK/XFCE can create many short-lived worker threads across
 * DBus, GIO, thumbnailing, AT-SPI, terminal, and settings processes.  Linux
 * exposes this as ordinary pthread capacity, so EdgeOS must not return EAGAIN
 * from clone(2) in a normal XFCE session just because the static task-only
 * headroom is too small.  The entries above USER_AS_MAX_TASKS carry only task
 * bookkeeping plus runtime-carved kernel stack backing, not the large fixed
 * userspace backing.
 */
#define PROC_MAX_TASKS EDGE_RUNTIME_MAX_TASKS
/*
 * Kernel-owned copies used while replacing a task image with execve().
 *
 * Linux limits the combined argument/environment strings and pointer vectors,
 * not every string to a tiny fixed slot.  A 1 KiB per-string limit rejected
 * ordinary ssh and desktop launcher commands even when their complete exec
 * payload was small.  Keep a single 128 KiB compatibility budget (the POSIX
 * minimum ARG_MAX), allow a Linux-sized individual string, and return E2BIG
 * when either the combined byte budget or vector capacity is exhausted.
 */
#define EDGE_EXEC_ARG_MAX KERNEL_EXEC_RECORD_ARG_MAX
#define EDGE_EXEC_ENV_MAX KERNEL_EXEC_RECORD_ENV_MAX
#define EDGE_EXEC_BYTE_MAX KERNEL_EXEC_RECORD_BYTE_MAX
#define EDGE_EXEC_STR_MAX KERNEL_EXEC_RECORD_STRING_MAX
/*
 * XFCE/DBus/Xorg syscall paths can nest through VFS, sockets, poll wakeups,
 * signal handling, and scheduler entry before returning to userspace.  A 16 KiB
 * task kernel stack was enough for tiny shells but overflowed during desktop
 * startup, corrupting adjacent task contexts and later resuming into .bss.
 * A 64 KiB stack still crossed into an adjacent task during repeated browser
 * launches while VFS, mmap fault handling, and process snapshots were nested.
 * Keep enough headroom for that measured Linux desktop path; do not work
 * around kernel-stack corruption in userland or rootfs scripts.
 */
#define EDGE_TASK_KSTACK_SIZE (128 * 1024)
/*
 * Linux desktops and plugin scanners map many shared objects, fonts, caches,
 * and allocator arenas. Match Linux's common default map-count ceiling while
 * allocating descriptor storage on demand; do not reserve the ceiling for
 * every process or filter plugins in userland to hide VMA exhaustion.
 */
#define PROCESS_USER_VMA_MAX KERNEL_MM_VMA_MAX
#define EDGE_USER_MIN_ADDR 0x0000000000001000ULL
/*
 * Keep the sparse userspace arena below the supervisor-only PCI aperture at
 * PML4 slot 0x70.  Linux applications can reserve multi-terabyte PROT_NONE
 * ranges without committing RAM; Chromium's V8 sandbox relies on this.  The
 * x86 page-table backend allocates intermediate roots on demand, so widening
 * this virtual range does not multiply per-process physical memory use.
 */
#define EDGE_USER_MMAP_BASE_ADDR 0x0000008000000000ULL
#define EDGE_USER_MMAP_LIMIT_ADDR 0x0000380000000000ULL
#define EDGE_USER_MMAP_ALLOC_BASE_ADDR 0x0000000080000000ULL
#define EDGE_USER_MMAP_ALLOC_LIMIT_ADDR 0x00000000C0000000ULL
#define EDGE_USER_MAX_ADDR EDGE_USER_MMAP_LIMIT_ADDR
/*
 * The brk window uses demand-allocated page tables and backing pages.  Keep a
 * Linux-sized virtual headroom for unmodified allocators without reserving
 * the corresponding physical memory for every address space.  The window
 * remains below the low sparse mmap arena, so brk growth and mmap placement
 * cannot collide.
 */
#define USER_HEAP_MAX_DELTA (512ULL * 1024ULL * 1024ULL)
#define USER_HEAP_DEFAULT_DELTA USER_HEAP_MAX_DELTA
#define USER_HEAP_PY_EXTRA_DELTA (4ULL * 1024ULL * 1024ULL)
#define PROCESS_CTTY_NONE 0
#define PROCESS_CTTY_CONSOLE 1
#define PROCESS_CTTY_PTY 2
#define PROCESS_CTTY_SERIAL 3

/*
 * Linux capability syscalls expose 64-bit effective/permitted/inheritable
 * sets split into two 32-bit words.  EdgeOS does not yet enforce every Linux
 * capability in every subsystem, but task credentials must still carry real
 * capability state so capget/capset, fork/clone inheritance, and setuid
 * transitions are coherent for unmodified Linux userspace.
 */
#define EDGE_PROCESS_FD_LIMIT EDGE_RUNTIME_MAX_OPEN_FILES

typedef enum {
    TASK_UNUSED = 0,
    TASK_RUNNABLE,
    TASK_RUNNING,
    TASK_BLOCKED,
    TASK_STOPPED,
    TASK_ZOMBIE,
} task_state_t;

#include "arch/task.h"

typedef kernel_vm_area_t edge_user_vma_t;

typedef kernel_process_usage_t process_rusage_snapshot_t;

typedef struct task_struct {
    int pid;
    int ppid;
    int parent_tid;
    int tgid;
    int vm_owner_pid;
    int fd_owner_pid;
    uint64_t fs_context_id;
    uint64_t sighand_context_id;
    int exit_code;
    /* Signal delivered to the parent when this process exits. */
    uint8_t exit_signal;
    /* Signal that terminated this process, or zero for a normal exit. */
    uint8_t termination_signal;
    /* Signal delivered when the task that created this process terminates. */
    uint8_t parent_death_signal;
    uint8_t child_subreaper;
    task_state_t state;
    char name[TASK_NAME_MAX];
    cpu_context_t context;
    edge_trap_frame_t fork_tf;
    edge_trap_frame_t ptrace_frame;
    uintptr_t ptrace_live_frame;
    uint64_t cr3;
    uint64_t kernel_stack_top;
    uint64_t user_stack_top;
    uint64_t user_heap_base;
    uint64_t user_brk;
    uint64_t user_heap_limit;
    uint64_t user_mmap_next;
    uint64_t last_syscall_nr;
    uint64_t last_syscall_args[6];
    int64_t last_syscall_ret;
    uint32_t syscall_history_pos;
    uint32_t _syscall_history_pad;
    uint64_t syscall_history_nr[TASK_SYSCALL_HISTORY];
    uint64_t syscall_history_arg1[TASK_SYSCALL_HISTORY];
    uint64_t syscall_history_arg2[TASK_SYSCALL_HISTORY];
    uint64_t syscall_history_arg3[TASK_SYSCALL_HISTORY];
    uint64_t syscall_history_arg4[TASK_SYSCALL_HISTORY];
    uint64_t syscall_history_arg5[TASK_SYSCALL_HISTORY];
    uint64_t syscall_history_arg6[TASK_SYSCALL_HISTORY];
    int64_t syscall_history_ret[TASK_SYSCALL_HISTORY];
    uint64_t futex_wait_count;
    uint64_t futex_wake_count;
    uint64_t futex_woken_count;
    uint64_t futex_block_count;
    uint64_t futex_block_return_count;
    uint64_t futex_missed_wake_count;
    uint64_t futex_timeout_count;
    uint64_t futex_intr_count;
    uint64_t last_futex_wait_uaddr;
    uint64_t last_futex_wake_uaddr;
    uint64_t last_futex_deadline_us;
    uint32_t last_futex_op;
    uint32_t last_futex_bitset;
    int32_t last_futex_wait_expected;
    int32_t last_futex_wait_observed;
    int32_t last_futex_result;
    int last_futex_wake_requested;
    int last_futex_wake_matched;
    uint8_t in_syscall;
    uint8_t _syscall_debug_pad[7];
    edge_linux_ptrace_state_t ptrace;
    volatile uint32_t user_vma_mutation_lock;
    int32_t user_vma_mutation_owner_pid;
    uint16_t user_vma_mutation_depth;
    uint16_t _user_vma_mutation_pad;
    volatile uint32_t user_page_table_lock;
    int32_t user_page_table_owner_pid;
    uint16_t user_page_table_lock_depth;
    uint16_t _user_page_table_lock_pad;
    volatile uint64_t user_mm_cpu_mask;
    uint32_t user_vma_count;
    uint32_t user_vma_capacity;
    uint32_t user_vma_dynamic_pages;
    uint8_t user_vma_refs_owned;
    uint8_t _user_vma_pad[3];
    uint64_t fs_base;
    uint64_t gs_base;
    /* Native x86 LDT state is owned by the address-space leader. */
    uint64_t *x86_ldt_entries;
    uint32_t x86_ldt_nr_entries;
    uint32_t x86_ldt_capacity;
    spinlock_t x86_ldt_lock;
    uint64_t start_entry;
    uint64_t start_at_phdr;
    uint64_t start_at_phnum;
    uint64_t start_at_entry;
    uint64_t start_at_base;
    int start_pending;
    uint32_t uid;
    uint32_t gid;
    uint32_t euid;
    uint32_t egid;
    uint32_t suid;
    uint32_t sgid;
    uint32_t fsuid;
    uint32_t fsgid;
    uint8_t dumpable;
    uint8_t no_new_privs;
    uint8_t thp_disabled;
    uint8_t credential_padding;
    int32_t oom_score_adj;
    int32_t oom_score_adj_min;
    uint64_t timer_slack_ns;
    uint64_t default_timer_slack_ns;
    edge_seccomp_state_t seccomp;
    uint32_t umask;
    int pgid;
    int sid;
    uint8_t execed_since_fork;
    int vfork_parent_pid;
    int vfork_child_pid;
    int ctty_kind;
    int ctty_id;
    edge_namespace_set_t namespaces;
    uint8_t pid_namespace_attached;
    uint8_t cgroup_accounted;
    uint16_t _cgroup_account_padding;
    uint32_t cgroup_memory_oom_id;
    uint32_t cgroup_id;
    char cwd[TASK_CWD_MAX];
    char root[TASK_CWD_MAX];
    edge_linux_signal_action_t signal_actions[EDGE_LINUX_SIGNAL_MAX];
    uint64_t signal_pending;
    uint64_t signal_shared_pending;
    uint8_t group_exit_pending;
    int32_t group_exit_code;
    uint64_t sigmask;
    uint64_t signal_saved_mask;
    uint8_t signal_restore_mask_pending;
    uint8_t sleep_wait_active;
    uint8_t fd_wait_active;
    uint8_t vt_wait_active;
    uint8_t vt_wait_target;
    uint8_t child_wait_active;
    uint8_t file_lock_wait_active;
    kernel_epoll_wait_lease_t epoll_wait_lease;
    spinlock_t file_lock_wait_lock;
    int64_t file_lock_wait_result;
    uint64_t sleep_deadline_us;
    uint8_t stop_signal;
    uint8_t stop_reported;
    uint8_t continued_pending;
    uint8_t seccomp_sigsys_valid;
    int32_t seccomp_sigsys_errno;
    int32_t seccomp_sigsys_nr;
    uint32_t seccomp_sigsys_arch;
    uint64_t seccomp_sigsys_call_addr;
    uint64_t seccomp_notification_id;
    uint8_t sig_stub_installed;
    uint64_t active_signal_frame;
    uint64_t active_signal_restorer_rsp;
    uint64_t sigaltstack_sp;
    uint64_t sigaltstack_size;
    uint32_t sigaltstack_flags;
    kernel_linux_thread_state_t linux_thread;
    uint32_t membarrier_registrations;
    edge_linux_scheduler_state_t scheduler;
    edge_linux_scheduler_state_t futex_pi_base_scheduler;
    edge_linux_scheduler_entity_t scheduler_entity;
    uint8_t futex_pi_boosted;
    uint64_t scheduler_vruntime_us;
    uint64_t scheduler_wait_start_us;
    uint64_t scheduler_wait_us;
    uint64_t scheduler_migrations;
    uint16_t io_priority;
    uint64_t rusage_start_us;
    uint64_t rusage_run_start_us;
    uint64_t rusage_user_time_us;
    uint64_t rusage_sys_time_us;
    uint64_t rusage_child_user_time_us;
    uint64_t rusage_child_sys_time_us;
    uint64_t rusage_minor_faults;
    uint64_t rusage_major_faults;
    uint64_t rusage_child_minor_faults;
    uint64_t rusage_child_major_faults;
    uint64_t rusage_voluntary_ctxt_switches;
    uint64_t rusage_involuntary_ctxt_switches;
    uint64_t rusage_child_voluntary_ctxt_switches;
    uint64_t rusage_child_involuntary_ctxt_switches;
    uint64_t rlimits[EDGE_LINUX_RLIMIT_COUNT][2];
    linux_capability_state_t capabilities;
    linux_group_list_t supplementary_groups;
    uint8_t need_resched;
    uint8_t on_runqueue;
    uint8_t is_idle;
    uint8_t scheduler_vruntime_valid;
    /*
     * Context ownership is independent of the Linux-visible task state.  A
     * task can mark itself blocked before the final condition check while its
     * kernel stack is still executing.  `on_cpu` prevents that live stack from
     * being queued, and `context_ready` records that the saved architecture
     * context may be selected by another CPU.
     */
    uint8_t on_cpu;
    uint8_t context_ready;
    /* Set until a later task proves the architecture stack switch completed. */
    uint8_t switch_pending;
    /* Serializes terminal task cleanup across CPUs. */
    uint32_t reap_claimed;
    uint64_t context_generation;
    uint64_t consumed_context_generation;
    int assigned_cpu;
    struct task_struct *rq_prev;
    struct task_struct *rq_next;
    struct task_struct *parent;
    struct task_struct *first_child;
    struct task_struct *sibling_prev;
    struct task_struct *sibling_next;
    /*
     * Resolved path used by Linux-compatible /proc/<pid>/exe readlink.
     * Keep this kernel-owned metadata; do not infer userland/rootfs paths in
     * procfs or syscall code after exec has already resolved the binary.
     */
    char exec_path[TASK_CWD_MAX];
    uint64_t exec_file_handle;
    uint8_t fxsave_region[512] __attribute__((aligned(16)));
    edge_user_vma_t *user_vmas;
    kernel_exec_record_t *exec_record;
    kernel_task_scratch_t *scratch;
    uint8_t userfaultfd_wait_active;
    int32_t userfaultfd_wait_context;
    uint64_t userfaultfd_wait_ticket;
} task_t;

typedef void (*process_task_exit_hook_t)(task_t *t);
typedef void (*process_task_prestart_hook_t)(task_t *t);
typedef int (*process_user_vma_retain_hook_t)(const edge_user_vma_t *vma);
typedef void (*process_user_vma_release_hook_t)(const edge_user_vma_t *vma);

void process_mmap_backing_init(uint32_t magic, void *mb_info);
int process_kernel_runtime_alloc_pages(uint32_t pages, void **kva_out, uint64_t *phys_out);
int process_kernel_runtime_reserve_pages(uint32_t pages, void **kva_out,
                                         uint64_t *phys_out);
void process_exec_storage_reset(task_t *task);
int process_exec_storage_append(task_t *task, const char *string,
                                char **stored_out);
int process_exec_storage_contains(const task_t *task, const char *string);
void process_debug_dump_tasks(const char *reason);
int process_exec_storage_budget_ok(const task_t *task, int argc, int envc);
void process_init(void);
void process_register_task_prestart_hook(process_task_prestart_hook_t hook);
void process_register_task_exit_hook(process_task_exit_hook_t hook);
void process_register_task_zombie_hook(process_task_exit_hook_t hook);
void process_register_user_vma_backing_hooks(
    process_user_vma_retain_hook_t retain_hook,
    process_user_vma_release_hook_t release_hook);
int process_user_vma_retain_backing(const edge_user_vma_t *vma);
void process_user_vma_release_backing(const edge_user_vma_t *vma);
int process_user_vma_reserve(task_t *task, uint32_t required_count);
int process_fork(const edge_trap_frame_t *parent_tf,
                 uint64_t namespace_flags);
int process_fork_shared_vm(const edge_trap_frame_t *parent_tf,
                           uint64_t namespace_flags);
int process_vfork_shared_vm(const edge_trap_frame_t *parent_tf,
                            uint64_t namespace_flags);
int process_clone_clear_signal_handlers(int pid);
int process_clone_share_signal_handlers(int pid);
int process_clone_set_parent(int pid, int parent_pid);
int process_set_current(int pid);
int process_cgroup_account_publish(int pid);
int process_cgroup_account_rebuilt(int pid);
void process_rebase_mount_namespace_paths(uint32_t namespace_id,
                                          const char *new_root,
                                          const char *put_old);
void process_rebase_mount_move_paths(uint32_t namespace_id,
                                     const char *source,
                                     const char *target);
int process_fd_owner_uses_mount_namespace(int owner_pid,
                                          uint32_t namespace_id);
int process_getpid(void);
int process_gettid(void);
int process_gettgid(void);
int process_getppid(void);
int process_getfdpid(void);
const char *process_user_mmap_file_path_for_slot(uint16_t slot);
int process_set_fd_owner(int pid, int owner_pid);
int process_prepare_exec_current(void);
int process_exec_de_thread_current(void);
int process_exec_reset_current(
    const struct kernel_exec_reset_configuration *configuration);
void process_exec_wake_vfork_parent_current(void);
int process_spawn_exec(const char *path, int argc, char **argv);
int process_spawn_exec_env(const char *path, int argc, char **argv, int envc, char **envp);
int process_clone_thread(const edge_trap_frame_t *parent_tf);
int process_abort_clone(int pid);
int process_set_fork_frame_rsp(int pid, uint64_t rsp);
int process_read_user_memory(int pid, uint64_t src_u, void *dst, uint64_t len);
int process_write_user_memory(int pid, uint64_t dst_u, const void *src, uint64_t len);
int process_user_fixed_map_pid(int pid, uint64_t start, uint64_t len);
int process_user_fixed_reserve_pid(int pid, uint64_t start, uint64_t len);
int process_user_elf_map_file_pid(int pid, const char *path, uint64_t start,
                                  uint64_t len, uint64_t file_offset,
                                  uint32_t protection);
struct vfs_inode;
struct vfs_superblock;
int process_user_elf_map_inode_pid(int pid, const char *display_path,
                                   const struct vfs_inode *inode,
                                   struct vfs_superblock *superblock,
                                   uint64_t start, uint64_t len,
                                   uint64_t file_offset,
                                   uint32_t protection);
void process_exit_current(int code);
void process_exit_current_group(int code);
void process_release_detached_zombie_thread(task_t *t);
int process_reap_detached_zombie_threads_periodic(const char *reason);
int process_task_group_exit_requested(const task_t *task, int *code);
int process_current_group_exit_requested(int *code);
int process_thread_group_size(int tgid);
int process_wait_any(int *status);
/*
 * Internal wait flags.  Keep these separate from Linux userspace option bits
 * where possible: syscall handlers translate ABI flags before entering the
 * process core, so future wait states can be added without leaking kernel
 * implementation detail back into user-visible validation.
 */
#define PROCESS_WAIT_NOHANG 0x01
#define PROCESS_WAIT_NOREAP 0x02
#define PROCESS_WAIT_NOTHREAD 0x04
#define PROCESS_WAIT_WALL 0x08
#define PROCESS_WAIT_WCLONE 0x10
#define PROCESS_WAIT_STOPPED 0x20
#define PROCESS_WAIT_CONTINUED 0x40
#define PROCESS_WAIT_EXITED 0x80
int process_wait_pid(int pid, int *status, int options);
int process_wait_pid_rusage(int pid, int *status, int options, process_rusage_snapshot_t *usage);
int process_getrusage_self(process_rusage_snapshot_t *usage);
int process_getrusage_children(process_rusage_snapshot_t *usage);
void process_account_minor_fault(task_t *t);
void process_account_major_fault(task_t *t);
int process_adopt_orphans(int from_ppid, int to_ppid);
int process_kill_pid(int pid, int code);
void process_list_print(void);
const task_t *process_get_task(int pid);
task_t *process_task_by_pid(int pid);
const task_t *process_task_by_index(int index);
int process_task_pointer_valid(const task_t *task);
task_t *process_task_for_kernel_stack(uint64_t stack_pointer);
task_t *process_current_task(void);
task_t *process_vm_task(task_t *t);
void process_user_mm_cpu_enter(task_t *task, uint32_t cpu_id);
void process_user_vma_mutation_lock(task_t *task);
void process_user_vma_mutation_unlock(task_t *task);
void process_refresh_fixed_user_mappings(task_t *t);
int process_user_fixed_mprotect(task_t *t, uint64_t start, uint64_t len, uint32_t prot);
int process_user_fixed_mprotect_pid(int pid, uint64_t start, uint64_t len,
                                    uint32_t prot);
void process_update_thread_group_signal_action(int sig, uint64_t handler, uint64_t mask, uint64_t flags, uint64_t restorer);
int process_set_fs_base(uint64_t base);
uint64_t process_get_fs_base(void);
int process_set_gs_base(uint64_t base);
uint64_t process_get_gs_base(void);
int process_x86_ldt_snapshot(task_t *task, void *buffer,
                             uint32_t byte_count);
int process_x86_ldt_write(task_t *task, uint32_t entry,
                          uint64_t descriptor);
int process_x86_ldt_clone(task_t *destination, const task_t *source);
void process_x86_ldt_reset(task_t *task);
void process_x86_ldt_activate(task_t *task);
uint32_t process_getuid(void);
uint32_t process_getgid(void);
uint32_t process_geteuid(void);
uint32_t process_getegid(void);
void process_apply_exec_file_creds(uint16_t mode, uint32_t file_uid,
                                   uint32_t file_gid,
                                   uint32_t mount_flags);
int process_getpgid(int pid);
int process_getsid(int pid);
int process_kill_pgid(int pgid, int code);
int process_send_signal(int pid, int sig);
int process_send_signal_thread(int pid, int sig);
int process_send_signal_info(int pid, int sig, const void *signal_info);
int process_send_signal_pgid(int pgid, int sig);
int process_send_signal_pgid_info(int pgid, int sig,
                                  const void *signal_info);
void process_stop_current_group(int signal);
int process_set_state(int pid, task_state_t state);
int process_pick_target_cpu(void);
int process_publish_new_task(int pid);
int process_user_mmap_range_ok(uint64_t start, uint64_t len);
int process_user_mmap_commit(task_t *t, uint64_t start, uint64_t len);
int process_user_mmap_protect(task_t *t, uint64_t start, uint64_t len, uint32_t prot);
int process_user_heap_unmap(task_t *t, uint64_t start, uint64_t len);
int process_user_mmap_handle_fault(task_t *t, uint64_t addr, int write);
int process_consume_cgroup_memory_oom(task_t *t);
uint32_t process_user_mmap_swap_reclaim(uint32_t cgroup_id,
                                        uint32_t target_pages,
                                        uint64_t *scanned_pages_out);
void process_user_mmap_discard_private(task_t *t, uint64_t start,
                                       uint64_t len);
uint32_t process_user_mmap_deactivate_range(task_t *t, uint64_t start,
                                            uint64_t len);
uint32_t process_user_mmap_pageout_range(task_t *t, uint64_t start,
                                         uint64_t len,
                                         uint64_t *scanned_pages_out);
uint32_t process_user_mmap_drop_file_cache_range(task_t *t, uint64_t start,
                                                 uint64_t len);
void process_user_mmap_unmap(task_t *t, uint64_t start, uint64_t len);
void process_user_mmap_unmap_fast(task_t *t, uint64_t start, uint64_t len);
int process_user_mmap_unmap_page_if_backing(task_t *t, uint64_t address,
                                            int backing_index);
int process_user_mmap_move_present(task_t *t, uint64_t old_start, uint64_t new_start, uint64_t len);
void process_user_mmap_reset(task_t *t);
int process_user_mmap_clone(task_t *dst, const task_t *src);
int process_user_mmap_alloc_backing_page(void);
int process_user_mmap_alloc_file_backing_page(void);
void *process_user_mmap_alloc_contiguous_backing_pages(uint32_t page_count);
void *process_user_mmap_backing_page_ptr(int idx);
int process_user_mmap_backing_page_index(const void *page);
void process_user_mmap_retain_backing_page(int idx);
void process_user_mmap_release_backing_page(int idx);
int process_user_mmap_backing_page_active(int idx);
uint16_t process_user_mmap_backing_page_refcount(int idx);
uint32_t process_user_mmap_backing_page_generation(int idx);
int process_user_mmap_backing_page_cgroup(int idx,
                                          uint32_t *cgroup_id_out);
int process_user_mmap_map_backing_page(task_t *t, uint64_t va, int backing_idx, int writable);
int process_user_device_install_page(task_t *t, uint64_t va,
                                     uint64_t physical, uint32_t protection,
                                     int32_t memory_attribute);
int process_user_mmap_map_file_cache_page(task_t *t, uint64_t va,
                                          int backing_idx, int writable,
                                          int private_cow);
int process_user_mmap_map_file_cache_pages(
    task_t *t, uint64_t start, const int *backing_indices,
    uint32_t page_count, uint32_t required_index, int writable,
    int private_cow);
void process_user_mmap_writeprotect_all_file_cache(void);
void process_user_mmap_file_page_write_notify(uint16_t file_slot,
                                              uint64_t file_page_offset);
int user_mmap_populate_file_page(task_t *t, const edge_user_vma_t *v, uint64_t page, int write);
const char *process_user_mmap_file_path_for_slot(uint16_t slot);
void process_user_fbdev_owner_set(task_t *t, int active);
void process_user_fbdev_owner_refresh(task_t *t);
int process_user_fbdev_install_vma(task_t *t, uint64_t start, uint64_t len);
void process_user_fbdev_writeprotect_all(void);
void process_user_fbdev_collect_dirty_all(void);
uint32_t process_user_mmap_backing_used_pages(void);
uint32_t process_user_mmap_backing_total_pages(void);
uint64_t process_user_mmap_backing_free_bytes(void);
int process_page_allocator_snapshot(edge_page_allocator_snapshot_t *snapshot);
uint32_t process_user_mmap_pt_used_pages(void);
uint32_t process_user_mmap_pt_total_pages(void);
void process_user_mmap_debug_dump_addr(const char *tag, task_t *t, uint64_t addr);

#endif
