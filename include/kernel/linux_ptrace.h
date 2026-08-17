/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux ptrace ABI.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_LINUX_PTRACE_H
#define EDGEOS_KERNEL_LINUX_PTRACE_H

#include <stdint.h>

struct edge_linux_syscall_context;

enum {
    EDGE_LINUX_PTRACE_TRACEME = 0,
    EDGE_LINUX_PTRACE_PEEKTEXT = 1,
    EDGE_LINUX_PTRACE_PEEKDATA = 2,
    EDGE_LINUX_PTRACE_PEEKUSER = 3,
    EDGE_LINUX_PTRACE_POKETEXT = 4,
    EDGE_LINUX_PTRACE_POKEDATA = 5,
    EDGE_LINUX_PTRACE_POKEUSER = 6,
    EDGE_LINUX_PTRACE_CONT = 7,
    EDGE_LINUX_PTRACE_KILL = 8,
    EDGE_LINUX_PTRACE_SINGLESTEP = 9,
    EDGE_LINUX_PTRACE_GETREGS = 12,
    EDGE_LINUX_PTRACE_SETREGS = 13,
    EDGE_LINUX_PTRACE_GETFPREGS = 14,
    EDGE_LINUX_PTRACE_SETFPREGS = 15,
    EDGE_LINUX_PTRACE_ATTACH = 16,
    EDGE_LINUX_PTRACE_DETACH = 17,
    EDGE_LINUX_PTRACE_GETFPXREGS = 18,
    EDGE_LINUX_PTRACE_SETFPXREGS = 19,
    EDGE_LINUX_PTRACE_SYSCALL = 24,
    EDGE_LINUX_PTRACE_SETOPTIONS = 0x4200,
    EDGE_LINUX_PTRACE_GETEVENTMSG = 0x4201,
    EDGE_LINUX_PTRACE_GETSIGINFO = 0x4202,
    EDGE_LINUX_PTRACE_SETSIGINFO = 0x4203,
    EDGE_LINUX_PTRACE_GETREGSET = 0x4204,
    EDGE_LINUX_PTRACE_SETREGSET = 0x4205,
    EDGE_LINUX_PTRACE_SEIZE = 0x4206,
    EDGE_LINUX_PTRACE_INTERRUPT = 0x4207,
    EDGE_LINUX_PTRACE_LISTEN = 0x4208,
    EDGE_LINUX_PTRACE_PEEKSIGINFO = 0x4209,
    EDGE_LINUX_PTRACE_GETSIGMASK = 0x420a,
    EDGE_LINUX_PTRACE_SETSIGMASK = 0x420b,
    EDGE_LINUX_PTRACE_SECCOMP_GET_FILTER = 0x420c,
    EDGE_LINUX_PTRACE_SECCOMP_GET_METADATA = 0x420d,
    EDGE_LINUX_PTRACE_GET_SYSCALL_INFO = 0x420e,
    EDGE_LINUX_PTRACE_GET_RSEQ_CONFIGURATION = 0x420f,
    EDGE_LINUX_PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG = 0x4210,
    EDGE_LINUX_PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG = 0x4211,
    EDGE_LINUX_PTRACE_SET_SYSCALL_INFO = 0x4212,
};

enum {
    EDGE_LINUX_PTRACE_EVENT_FORK = 1,
    EDGE_LINUX_PTRACE_EVENT_VFORK = 2,
    EDGE_LINUX_PTRACE_EVENT_CLONE = 3,
    EDGE_LINUX_PTRACE_EVENT_EXEC = 4,
    EDGE_LINUX_PTRACE_EVENT_VFORK_DONE = 5,
    EDGE_LINUX_PTRACE_EVENT_EXIT = 6,
    EDGE_LINUX_PTRACE_EVENT_SECCOMP = 7,
    EDGE_LINUX_PTRACE_EVENT_STOP = 128,
};

#define EDGE_LINUX_PTRACE_O_TRACESYSGOOD 0x00000001u
#define EDGE_LINUX_PTRACE_O_TRACEFORK 0x00000002u
#define EDGE_LINUX_PTRACE_O_TRACEVFORK 0x00000004u
#define EDGE_LINUX_PTRACE_O_TRACECLONE 0x00000008u
#define EDGE_LINUX_PTRACE_O_TRACEEXEC 0x00000010u
#define EDGE_LINUX_PTRACE_O_TRACEVFORKDONE 0x00000020u
#define EDGE_LINUX_PTRACE_O_TRACEEXIT 0x00000040u
#define EDGE_LINUX_PTRACE_O_TRACESECCOMP 0x00000080u
#define EDGE_LINUX_PTRACE_O_EXITKILL 0x00100000u
#define EDGE_LINUX_PTRACE_O_SUSPEND_SECCOMP 0x00200000u
#define EDGE_LINUX_PTRACE_O_MASK 0x003000ffu

#define EDGE_LINUX_NT_PRSTATUS 1u
#define EDGE_LINUX_NT_PRFPREG 2u
#define EDGE_LINUX_NT_X86_XSTATE 0x202u
#define EDGE_LINUX_NT_ARM_TLS 0x401u
#define EDGE_LINUX_NT_ARM_SYSTEM_CALL 0x404u
#define EDGE_LINUX_PTRACE_LEGACY_GPR 0x80000001u
#define EDGE_LINUX_PTRACE_LEGACY_FP 0x80000002u
#define EDGE_LINUX_PTRACE_LEGACY_FPX 0x80000003u

#define EDGE_LINUX_PTRACE_SIGTRAP 5u
#define EDGE_LINUX_PTRACE_SIGKILL 9u
#define EDGE_LINUX_PTRACE_SIGSTOP 19u

typedef enum edge_linux_ptrace_resume_mode {
    EDGE_LINUX_PTRACE_RESUME_CONT = 0,
    EDGE_LINUX_PTRACE_RESUME_SYSCALL = 1,
    EDGE_LINUX_PTRACE_RESUME_SINGLESTEP = 2,
    EDGE_LINUX_PTRACE_RESUME_LISTEN = 3,
} edge_linux_ptrace_resume_mode_t;

typedef enum edge_linux_ptrace_stop_reason {
    EDGE_LINUX_PTRACE_STOP_NONE = 0,
    EDGE_LINUX_PTRACE_STOP_SIGNAL = 1,
    EDGE_LINUX_PTRACE_STOP_SYSCALL_ENTRY = 2,
    EDGE_LINUX_PTRACE_STOP_SYSCALL_EXIT = 3,
    EDGE_LINUX_PTRACE_STOP_EVENT = 4,
    EDGE_LINUX_PTRACE_STOP_SINGLESTEP = 5,
    EDGE_LINUX_PTRACE_STOP_INTERRUPT = 6,
} edge_linux_ptrace_stop_reason_t;

typedef enum edge_linux_ptrace_exit_wait_action {
    EDGE_LINUX_PTRACE_EXIT_WAIT_REAP = 0,
    EDGE_LINUX_PTRACE_EXIT_WAIT_DEFER = 1,
    EDGE_LINUX_PTRACE_EXIT_WAIT_RELEASE = 2,
} edge_linux_ptrace_exit_wait_action_t;

typedef enum edge_linux_ptrace_tracer_exit_action {
    EDGE_LINUX_PTRACE_TRACER_EXIT_DETACH = 0,
    EDGE_LINUX_PTRACE_TRACER_EXIT_KILL = 1,
    EDGE_LINUX_PTRACE_TRACER_EXIT_RELEASE_ZOMBIE = 2,
} edge_linux_ptrace_tracer_exit_action_t;

typedef struct edge_linux_ptrace_state {
    int32_t tracer_pid;
    uint32_t options;
    uint64_t event_message;
    uint64_t syscall_number;
    uint64_t syscall_arguments[6];
    int64_t syscall_result;
    uint64_t instruction_pointer;
    uint64_t stack_pointer;
    uint8_t seized;
    uint8_t resume_mode;
    uint8_t stop_reason;
    uint8_t stop_signal;
    uint8_t stop_event;
    uint8_t syscall_info_op;
    uint8_t signal_info_valid;
    uint8_t restart_syscall;
    uint8_t syscall_active;
    uint8_t suppress_signal_stop;
    uint8_t injected_signal;
    uint8_t interrupt_pending;
    uint8_t group_stop_continue_pending;
    uint8_t group_stop_continue_delivery;
    uint8_t group_stop_signal;
    uint8_t reserved;
    uint8_t signal_info[128];
} edge_linux_ptrace_state_t;

typedef struct edge_linux_ptrace_stop {
    edge_linux_ptrace_stop_reason_t reason;
    uint32_t signal;
    uint32_t event;
    uint64_t event_message;
    uint64_t syscall_number;
    uint64_t syscall_arguments[6];
    int64_t syscall_result;
    uint64_t instruction_pointer;
    uint64_t stack_pointer;
} edge_linux_ptrace_stop_t;

typedef struct edge_linux_ptrace_signal_resume_action {
    uint32_t consume_signal;
    uint32_t inject_signal;
    uint8_t suppress_signal_stop;
} edge_linux_ptrace_signal_resume_action_t;

typedef struct edge_linux_ptrace_task_info {
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
    uint32_t stop_signal;
    edge_linux_ptrace_state_t ptrace;
} edge_linux_ptrace_task_info_t;

typedef struct edge_linux_ptrace_task_runtime {
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
    uint32_t stop_signal;
    edge_linux_ptrace_state_t *ptrace;
    uint64_t *signal_mask;
    uint64_t rseq_address;
    uint32_t rseq_size;
    uint32_t rseq_signature;
} edge_linux_ptrace_task_runtime_t;

typedef struct edge_linux_ptrace_syscall_info {
    uint8_t op;
    uint8_t reserved;
    uint16_t flags;
    uint32_t architecture;
    uint64_t instruction_pointer;
    uint64_t stack_pointer;
    union {
        struct {
            uint64_t number;
            uint64_t arguments[6];
        } entry;
        struct {
            int64_t result;
            uint8_t is_error;
            uint8_t padding[7];
        } exit;
        struct {
            uint64_t number;
            uint64_t arguments[6];
            uint32_t return_data;
            uint32_t reserved;
        } seccomp;
    } data;
} edge_linux_ptrace_syscall_info_t;

typedef struct edge_linux_ptrace_rseq_configuration {
    uint64_t address;
    uint32_t size;
    uint32_t signature;
    uint32_t flags;
    uint32_t padding;
} edge_linux_ptrace_rseq_configuration_t;

void edge_linux_ptrace_state_reset(edge_linux_ptrace_state_t *state);
void edge_linux_ptrace_state_record_stop(
    edge_linux_ptrace_state_t *state,
    const edge_linux_ptrace_stop_t *stop);
void edge_linux_ptrace_state_record_signal_info(
    edge_linux_ptrace_state_t *state, uint32_t signal, int32_t code,
    int32_t sender_pid, uint32_t sender_uid);
edge_linux_ptrace_exit_wait_action_t edge_linux_ptrace_exit_wait_action(
    const edge_linux_ptrace_state_t *state, int32_t waiter_pid,
    int32_t waiter_tgid, int32_t natural_parent_tgid);
int edge_linux_ptrace_exit_is_deferred(
    const edge_linux_ptrace_state_t *state);
edge_linux_ptrace_tracer_exit_action_t edge_linux_ptrace_tracer_exit_action(
    const edge_linux_ptrace_state_t *state, int tracee_is_zombie);
void edge_linux_ptrace_signal_resume_action(
    const edge_linux_ptrace_state_t *state, uint32_t requested_signal,
    edge_linux_ptrace_signal_resume_action_t *action);
uint32_t edge_linux_ptrace_internal_stop_signal(
    const edge_linux_ptrace_stop_t *stop);

int kernel_arch_ptrace_task_runtime(
    int32_t pid, edge_linux_ptrace_task_runtime_t *runtime);
int kernel_ptrace_task_info(
    int32_t pid, edge_linux_ptrace_task_info_t *information);
int kernel_ptrace_get_signal_info(int32_t pid, void *buffer, uint64_t size);
int kernel_ptrace_set_signal_info(int32_t pid, const void *buffer,
                                  uint64_t size);
int kernel_ptrace_get_signal_mask(int32_t pid, uint64_t *mask);
int kernel_ptrace_set_signal_mask(int32_t pid, uint64_t mask);
int kernel_ptrace_get_rseq_configuration(
    int32_t pid, edge_linux_ptrace_rseq_configuration_t *configuration);

int64_t edge_linux_sys_ptrace(struct edge_linux_syscall_context *context);
void edge_linux_ptrace_syscall_enter(void *user_registers,
                                     uint64_t *number,
                                     uint64_t arguments[6]);
void edge_linux_ptrace_syscall_exit(void *user_registers, int64_t *result);
void edge_linux_ptrace_deferred_syscall_exit(void *user_registers);
int edge_linux_ptrace_clone_stop(void *user_registers, uint64_t clone_flags,
                                 int32_t child_global_pid,
                                 int32_t child_visible_pid);
void edge_linux_ptrace_exec_stop(void *user_registers);
int edge_linux_ptrace_signal_stop(void *user_registers, uint32_t signal);
int edge_linux_ptrace_debug_stop(void *user_registers);

#endif
