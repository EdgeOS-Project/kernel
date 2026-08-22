/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux perf event service.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_PERF_EVENT_H
#define EDGEOS_KERNEL_PERF_EVENT_H

#include <stdint.h>

#define KERNEL_PERF_TYPE_HARDWARE   0u
#define KERNEL_PERF_TYPE_SOFTWARE   1u
#define KERNEL_PERF_TYPE_TRACEPOINT 2u
#define KERNEL_PERF_TYPE_HW_CACHE   3u
#define KERNEL_PERF_TYPE_RAW        4u
#define KERNEL_PERF_TYPE_BREAKPOINT 5u

#define KERNEL_PERF_COUNT_SW_CPU_CLOCK        0u
#define KERNEL_PERF_COUNT_SW_TASK_CLOCK       1u
#define KERNEL_PERF_COUNT_SW_PAGE_FAULTS      2u
#define KERNEL_PERF_COUNT_SW_CONTEXT_SWITCHES 3u
#define KERNEL_PERF_COUNT_SW_CPU_MIGRATIONS   4u
#define KERNEL_PERF_COUNT_SW_PAGE_FAULTS_MIN  5u
#define KERNEL_PERF_COUNT_SW_PAGE_FAULTS_MAJ  6u
#define KERNEL_PERF_COUNT_SW_ALIGNMENT_FAULTS 7u
#define KERNEL_PERF_COUNT_SW_EMULATION_FAULTS 8u
#define KERNEL_PERF_COUNT_SW_DUMMY            9u
#define KERNEL_PERF_COUNT_SW_BPF_OUTPUT       10u
#define KERNEL_PERF_COUNT_SW_CGROUP_SWITCHES  11u
#define KERNEL_PERF_COUNT_SW_MAX              12u

#define KERNEL_PERF_FORMAT_TOTAL_TIME_ENABLED (1ULL << 0)
#define KERNEL_PERF_FORMAT_TOTAL_TIME_RUNNING (1ULL << 1)
#define KERNEL_PERF_FORMAT_ID                 (1ULL << 2)
#define KERNEL_PERF_FORMAT_GROUP              (1ULL << 3)
#define KERNEL_PERF_FORMAT_LOST               (1ULL << 4)
#define KERNEL_PERF_FORMAT_MASK               ((1ULL << 5) - 1u)

#define KERNEL_PERF_ATTR_DISABLED       (1ULL << 0)
#define KERNEL_PERF_ATTR_INHERIT        (1ULL << 1)
#define KERNEL_PERF_ATTR_PINNED         (1ULL << 2)
#define KERNEL_PERF_ATTR_EXCLUSIVE      (1ULL << 3)
#define KERNEL_PERF_ATTR_EXCLUDE_USER   (1ULL << 4)
#define KERNEL_PERF_ATTR_EXCLUDE_KERNEL (1ULL << 5)
#define KERNEL_PERF_ATTR_EXCLUDE_HV     (1ULL << 6)
#define KERNEL_PERF_ATTR_EXCLUDE_IDLE   (1ULL << 7)
#define KERNEL_PERF_ATTR_FREQ           (1ULL << 10)
#define KERNEL_PERF_ATTR_ENABLE_ON_EXEC (1ULL << 12)
#define KERNEL_PERF_ATTR_USE_CLOCKID    (1ULL << 25)
#define KERNEL_PERF_ATTR_REMOVE_ON_EXEC (1ULL << 36)
#define KERNEL_PERF_ATTR_RESERVED_MASK  (0xffffffULL << 40)

#define KERNEL_PERF_FLAG_FD_NO_GROUP (1ULL << 0)
#define KERNEL_PERF_FLAG_FD_OUTPUT   (1ULL << 1)
#define KERNEL_PERF_FLAG_PID_CGROUP  (1ULL << 2)
#define KERNEL_PERF_FLAG_FD_CLOEXEC  (1ULL << 3)
#define KERNEL_PERF_FLAG_MASK        ((1ULL << 4) - 1u)

#define KERNEL_PERF_IOC_ENABLE  0x00002400u
#define KERNEL_PERF_IOC_DISABLE 0x00002401u
#define KERNEL_PERF_IOC_REFRESH 0x00002402u
#define KERNEL_PERF_IOC_RESET   0x00002403u
#define KERNEL_PERF_IOC_PERIOD  0x40082404u
#define KERNEL_PERF_IOC_SET_OUTPUT 0x00002405u
#define KERNEL_PERF_IOC_SET_FILTER 0x40082406u
#define KERNEL_PERF_IOC_ID      0x80082407u
#define KERNEL_PERF_IOC_SET_BPF 0x40042408u
#define KERNEL_PERF_IOC_PAUSE_OUTPUT 0x40042409u
#define KERNEL_PERF_IOC_QUERY_BPF 0xc008240au
#define KERNEL_PERF_IOC_MODIFY_ATTRIBUTES 0x4008240bu
#define KERNEL_PERF_IOC_FLAG_GROUP 1u

#define KERNEL_PERF_ATTR_SIZE_VER0 64u
#define KERNEL_PERF_ATTR_SIZE_CURRENT 144u

typedef struct kernel_perf_event_attr {
    uint32_t type;
    uint32_t size;
    uint64_t config;
    uint64_t sample_period;
    uint64_t sample_type;
    uint64_t read_format;
    uint64_t flags;
    uint32_t wakeup_events;
    uint32_t breakpoint_type;
    uint64_t config1;
    uint64_t config2;
    uint64_t branch_sample_type;
    uint64_t sample_registers_user;
    uint32_t sample_stack_user;
    int32_t clock_id;
    uint64_t sample_registers_interrupt;
    uint32_t auxiliary_watermark;
    uint16_t sample_max_stack;
    uint16_t reserved2;
    uint32_t auxiliary_sample_size;
    uint32_t auxiliary_action;
    uint64_t signal_data;
    uint64_t config3;
    uint64_t config4;
} kernel_perf_event_attr_t;

typedef struct kernel_perf_event_open_request {
    kernel_perf_event_attr_t attr;
    int32_t target_tid;
    int32_t cpu;
    int32_t group_id;
    uint32_t flags;
} kernel_perf_event_open_request_t;

typedef struct kernel_perf_event_state {
    uint64_t id;
    int32_t target_tid;
    int32_t cpu;
    int32_t group_leader;
    uint8_t enabled;
    uint8_t enable_on_exec;
    uint8_t remove_on_exec;
    uint8_t padding;
} kernel_perf_event_state_t;

int kernel_perf_event_open(const kernel_perf_event_open_request_t *request);
int kernel_perf_event_retain(int event_id);
void kernel_perf_event_release(int event_id);
int kernel_perf_event_query(int event_id, kernel_perf_event_state_t *state);
int64_t kernel_perf_event_read(int event_id, uint64_t *values,
                               uint32_t value_capacity);
int kernel_perf_event_control(int event_id, uint32_t command,
                              uint32_t flags, uint64_t *id_out);
void kernel_perf_event_task_exec(int32_t tid);
void kernel_perf_event_task_fork(int32_t parent_tid, int32_t child_tid);
void kernel_perf_event_task_exit(int32_t tid);

#endif
