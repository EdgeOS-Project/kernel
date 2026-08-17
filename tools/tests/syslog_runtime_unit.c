/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent kernel-log runtime unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>

#include "kernel/syslog_runtime.h"

static int g_failures;
static uint64_t g_next_offset;
static uint64_t g_observed_next;
static void *g_user_registers;
static int g_wait_calls;
static int g_notify_calls;

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

uint64_t bootlog_next_offset(void) {
    return g_next_offset;
}

int arch_syslog_wait_for_data(uint64_t observed_next,
                              void *user_registers) {
    ++g_wait_calls;
    g_observed_next = observed_next;
    g_user_registers = user_registers;
    return -17;
}

void arch_syslog_notify_data(void) {
    ++g_notify_calls;
}

int main(void) {
    void *registers = (void *)(uintptr_t)0x4567u;

    g_next_offset = 10;
    expect_true("changed log fast path",
                kernel_syslog_wait_for_data(9, registers) == 1 &&
                g_wait_calls == 0);

    expect_true("unchanged log wait dispatch",
                kernel_syslog_wait_for_data(10, registers) == -17 &&
                g_wait_calls == 1 && g_observed_next == 10 &&
                g_user_registers == registers);

    kernel_syslog_notify_data();
    expect_true("notify dispatch", g_notify_calls == 1);

    if (g_failures) return 1;
    puts("syslog_runtime_unit: PASS");
    return 0;
}
