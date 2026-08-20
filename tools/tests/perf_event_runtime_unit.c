/* SPDX-License-Identifier: MPL-2.0 */
/* Host unit coverage for the shared Linux perf software counter service. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/perf_event.h"
#include "kernel/process_runtime.h"

static kernel_proc_task_view_t g_task;
static kernel_scheduler_cpu_stats_t g_cpu;
static uint64_t g_now_us;

uint64_t boottime_monotonic_us(void) { return g_now_us; }

int kernel_proc_task_view_get(int32_t tid, kernel_proc_task_view_t *view) {
    if (!view || tid != g_task.tid || g_task.state == KERNEL_PROC_TASK_ZOMBIE)
        return -1;
    *view = g_task;
    return 0;
}

int kernel_arch_scheduler_cpu_stats(
    uint32_t cpu, kernel_scheduler_cpu_stats_t *stats) {
    if (!stats || cpu != 0) return -1;
    *stats = g_cpu;
    return 0;
}

uint64_t kernel_scheduler_online_cpu_mask(void) { return 1u; }

static int check(int condition, const char *name) {
    if (condition) return 0;
    fprintf(stderr, "FAIL %s\n", name);
    return 1;
}

int main(void) {
    kernel_perf_event_open_request_t request;
    uint64_t values[16];
    uint64_t id = 0;
    int leader;
    int member;
    int failures = 0;

    memset(&g_task, 0, sizeof(g_task));
    g_task.tid = 42;
    g_task.tgid = 42;
    g_task.state = KERNEL_PROC_TASK_RUNNING;
    memset(&request, 0, sizeof(request));
    request.attr.type = KERNEL_PERF_TYPE_SOFTWARE;
    request.attr.size = KERNEL_PERF_ATTR_SIZE_CURRENT;
    request.attr.config = KERNEL_PERF_COUNT_SW_TASK_CLOCK;
    request.attr.flags = KERNEL_PERF_ATTR_DISABLED;
    request.attr.read_format =
        KERNEL_PERF_FORMAT_TOTAL_TIME_ENABLED |
        KERNEL_PERF_FORMAT_TOTAL_TIME_RUNNING |
        KERNEL_PERF_FORMAT_ID;
    request.target_tid = 42;
    request.cpu = -1;
    request.group_id = -1;

    leader = kernel_perf_event_open(&request);
    failures += check(leader >= 0, "open disabled task clock");
    failures += check(kernel_perf_event_read(leader, values, 16) == 32,
                      "single read layout");
    failures += check(values[0] == 0 && values[1] == 0 &&
                      values[2] == 0 && values[3] != 0,
                      "disabled counter state");
    failures += check(kernel_perf_event_control(
                          leader, KERNEL_PERF_IOC_ENABLE, 0, 0) == 0,
                      "enable");
    g_task.usage.user_time_us = 700;
    g_task.usage.sys_time_us = 300;
    g_now_us = 1500;
    failures += check(kernel_perf_event_read(leader, values, 16) == 32,
                      "enabled read");
    failures += check(values[0] == 1000000u && values[1] == 1500000u &&
                      values[2] == 1500000u,
                      "task clock and enabled time");
    failures += check(kernel_perf_event_control(
                          leader, KERNEL_PERF_IOC_ID, 0, &id) == 0 && id,
                      "event id");
    failures += check(kernel_perf_event_control(
                          leader, KERNEL_PERF_IOC_DISABLE, 0, 0) == 0,
                      "disable");
    g_task.usage.user_time_us += 1000;
    failures += check(kernel_perf_event_read(leader, values, 16) == 32 &&
                      values[0] == 1000000u,
                      "disabled counter remains stable");
    failures += check(kernel_perf_event_control(
                          leader, KERNEL_PERF_IOC_RESET, 0, 0) == 0,
                      "reset");
    failures += check(kernel_perf_event_read(leader, values, 16) == 32 &&
                      values[0] == 0 && values[1] == 1500000u,
                      "reset clears count but preserves enabled time");

    request.attr.config = KERNEL_PERF_COUNT_SW_PAGE_FAULTS_MIN;
    request.attr.read_format = KERNEL_PERF_FORMAT_GROUP |
                               KERNEL_PERF_FORMAT_ID;
    member = kernel_perf_event_open(&request);
    failures += check(member >= 0, "standalone group-format leader");
    request.attr.config = KERNEL_PERF_COUNT_SW_CONTEXT_SWITCHES;
    request.attr.flags = KERNEL_PERF_ATTR_DISABLED;
    request.group_id = member;
    {
        int sibling = kernel_perf_event_open(&request);
        failures += check(sibling >= 0, "group sibling");
        g_task.usage.minor_faults = 9;
        g_task.usage.voluntary_ctxt_switches = 4;
        failures += check(kernel_perf_event_control(
                              member, KERNEL_PERF_IOC_ENABLE,
                              KERNEL_PERF_IOC_FLAG_GROUP, 0) == 0,
                          "group enable");
        g_task.usage.minor_faults = 12;
        g_task.usage.voluntary_ctxt_switches = 10;
        failures += check(kernel_perf_event_read(member, values, 16) == 40,
                          "group read size");
        failures += check(values[0] == 2 && values[1] == 3 &&
                          values[3] == 6,
                          "group counter values");
        kernel_perf_event_release(member);
        failures += check(kernel_perf_event_control(
                              sibling, KERNEL_PERF_IOC_DISABLE,
                              KERNEL_PERF_IOC_FLAG_GROUP, 0) == 0,
                          "group leader retained by sibling");
        kernel_perf_event_release(sibling);
    }

    request.group_id = -1;
    request.attr.type = KERNEL_PERF_TYPE_HARDWARE;
    failures += check(kernel_perf_event_open(&request) ==
                          -EDGE_LINUX_ENOENT,
                      "hardware backend absent");
    request.attr.type = KERNEL_PERF_TYPE_SOFTWARE;
    request.attr.config = KERNEL_PERF_COUNT_SW_MAX;
    failures += check(kernel_perf_event_open(&request) ==
                          -EDGE_LINUX_EINVAL,
                      "invalid software event");
    request.attr.config = KERNEL_PERF_COUNT_SW_TASK_CLOCK;
    request.attr.flags = KERNEL_PERF_ATTR_INHERIT;
    failures += check(kernel_perf_event_open(&request) ==
                          -EDGE_LINUX_EOPNOTSUPP,
                      "unsupported inheritance is explicit");
    request.attr.flags = 0;
    request.cpu = -2;
    failures += check(kernel_perf_event_open(&request) ==
                          -EDGE_LINUX_EINVAL,
                      "invalid negative cpu");
    kernel_perf_event_release(leader);

    if (!failures) puts("PERF_EVENT_RUNTIME_UNIT_PASS");
    return failures ? 1 : 0;
}
