/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent kernel-log runtime unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_abi.h"
#include "kernel/linux_errno.h"
#include "kernel/syslog_runtime.h"

static int g_failures;
static uint64_t g_next_offset;
static uint64_t g_observed_next;
static void *g_user_registers;
static int g_wait_calls;
static int g_notify_calls;
static char g_page[4096];
static char g_record[4096];
static char g_console[4096];
static int g_page_live;
static int g_allocate_fail;
static int g_timestamp_fail;
static int g_copy_calls;
static int g_copy_fail_call;
static int g_record_calls;
static int g_console_calls;
static int g_batch_depth;

void *arch_vm_alloc_pages(uint64_t count) {
    if (g_allocate_fail) return 0;
    if (count != 1 || g_page_live) {
        ++g_failures;
        return 0;
    }
    g_page_live = 1;
    memset(g_page, 0xa5, sizeof(g_page));
    return g_page;
}

void arch_vm_free_page(void *page) {
    if (page != g_page || !g_page_live) ++g_failures;
    g_page_live = 0;
    memset(g_page, 0xdd, sizeof(g_page));
}

int bootlog_format_timestamp_prefix(char *buffer, uint32_t capacity) {
    static const char prefix[] = "[   12.345678] ";
    if (g_timestamp_fail || capacity < sizeof(prefix)) return -1;
    memcpy(buffer, prefix, sizeof(prefix));
    return (int)sizeof(prefix) - 1;
}

void bootlog_append_raw(const char *text, uint32_t length) {
    ++g_record_calls;
    if (length >= sizeof(g_record)) {
        ++g_failures;
        return;
    }
    memcpy(g_record, text, length);
    g_record[length] = 0;
    g_next_offset += length;
}

void console_output_batch_begin(void) { ++g_batch_depth; }
void console_output_batch_end(void) { --g_batch_depth; }

void console_kernel_log_putstr(const char *text) {
    ++g_console_calls;
    if (g_batch_depth != 1 || strlen(text) >= sizeof(g_console)) {
        ++g_failures;
        return;
    }
    strcpy(g_console, text);
}

static int copy_log_text(void *context, void *destination,
                          uint64_t source, uint64_t length) {
    (void)context;
    ++g_copy_calls;
    if (g_copy_calls == g_copy_fail_call) return -1;
    memcpy(destination, (const void *)(uintptr_t)source, (size_t)length);
    return 0;
}

static struct edge_linux_iovec text_vector(const char *text) {
    struct edge_linux_iovec result = {
        .iov_base = (uint64_t)(uintptr_t)text,
        .iov_len = strlen(text)
    };
    return result;
}

static void reset_log_test(void) {
    g_allocate_fail = 0;
    g_timestamp_fail = 0;
    g_copy_calls = 0;
    g_copy_fail_call = 0;
    g_record_calls = 0;
    g_console_calls = 0;
    g_record[0] = g_console[0] = 0;
}

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

static void test_log_writes(void) {
    struct edge_linux_iovec vectors[] = {
        text_vector("<"), text_vector("30>systemd[1]: "),
        text_vector("Failed to start service: "), text_vector("I/O error\n")
    };
    uint64_t length = 0;
    int64_t result;
    char large[KERNEL_SYSLOG_RECORD_MAX];
    for (unsigned index = 0; index < 4; ++index)
        length += vectors[index].iov_len;
    reset_log_test();
    result = kernel_syslog_writev(vectors, 4, length, copy_log_text, 0);
    expect_true("writev returns all bytes", result == (int64_t)length);
    expect_true("one record and console emission per writev",
        g_record_calls == 1 && g_console_calls == 1 && !g_page_live &&
        !g_batch_depth);
    expect_true("systemd fragments preserve original error and prefix",
        strcmp(g_record, "[   12.345678] <30>systemd[1]: Failed to start "
                         "service: I/O error\n") == 0 &&
        strcmp(g_record, g_console) == 0);

    reset_log_test();
    g_copy_fail_call = 3;
    result = kernel_syslog_writev(vectors, 4, length, copy_log_text, 0);
    expect_true("later iovec fault publishes nothing",
        result == -EDGE_LINUX_EFAULT && !g_record_calls &&
        !g_console_calls && !g_page_live);

    memset(large, 'x', sizeof(large));
    reset_log_test();
    result = kernel_syslog_write_user((uint64_t)(uintptr_t)large,
        sizeof(large), copy_log_text, 0);
    expect_true("maximum record crosses old chunk boundaries intact",
        result == (int64_t)sizeof(large) && g_record_calls == 1 &&
        g_console_calls == 1 && strlen(g_record) == sizeof(large) + 16u &&
        memcmp(g_record + 15u, large, sizeof(large)) == 0 &&
        g_record[15u + sizeof(large)] == '\n' && !g_page_live);

    reset_log_test();
    result = kernel_syslog_write_user((uint64_t)(uintptr_t)large,
        sizeof(large) + 1u, copy_log_text, 0);
    expect_true("oversize fails without a fragment or user copy",
        result == -EDGE_LINUX_EINVAL && !g_copy_calls && !g_record_calls &&
        !g_console_calls && !g_page_live);

    reset_log_test();
    g_allocate_fail = 1;
    result = kernel_syslog_writev(vectors, 4, length, copy_log_text, 0);
    expect_true("allocation failure is reported without output",
        result == -EDGE_LINUX_ENOMEM && !g_copy_calls && !g_record_calls);

    reset_log_test();
    g_timestamp_fail = 1;
    result = kernel_syslog_writev(vectors, 4, length, copy_log_text, 0);
    expect_true("format failure is reported without losing allocation",
        result == -EDGE_LINUX_EIO && !g_record_calls && !g_console_calls &&
        !g_page_live);

    reset_log_test();
    struct edge_linux_iovec lines[] = {
        { .iov_base = 0, .iov_len = 0 }, text_vector("first\nsecond\r\n\n")
    };
    result = kernel_syslog_writev(lines, 2, lines[1].iov_len,
                                  copy_log_text, 0);
    expect_true("embedded and trailing newlines are preserved",
        result == (int64_t)lines[1].iov_len && g_copy_calls == 1 &&
        strcmp(g_record, "[   12.345678] first\nsecond\r\n\n") == 0);

    reset_log_test();
    struct edge_linux_iovec short_record = text_vector("no newline");
    for (unsigned index = 0; index < 2; ++index)
        expect_true("separate writes complete independently",
            kernel_syslog_writev(&short_record, 1, short_record.iov_len,
                                 copy_log_text, 0) ==
                (int64_t)short_record.iov_len);
    expect_true("separate writes are not merged awaiting a newline",
        g_record_calls == 2 && g_console_calls == 2 &&
        strcmp(g_record, "[   12.345678] no newline\n") == 0);

    reset_log_test();
    expect_true("zero write needs no buffer and emits nothing",
        kernel_syslog_writev(0, 0, 0, 0, 0) == 0 && !g_record_calls);
    short_record.iov_base = UINT64_MAX;
    short_record.iov_len = 2;
    expect_true("wrapped user range is rejected before copy",
        kernel_syslog_writev(&short_record, 1, 2, copy_log_text, 0) ==
            -EDGE_LINUX_EFAULT && !g_copy_calls && !g_page_live);
    short_record = text_vector("short");
    expect_true("incomplete vector list emits no partial record",
        kernel_syslog_writev(&short_record, 1, 6, copy_log_text, 0) ==
            -EDGE_LINUX_EINVAL && !g_record_calls && !g_page_live);
}

uint64_t bootlog_next_offset(void) {
    return g_next_offset;
}

static void test_log_reader_seek(void) {
    const kernel_syslog_reader_bounds_t bounds = {
        .first_record = 120,
        .last_clear = 480,
        .next_record = 960
    };
    uint64_t position = 77;
    expect_true("kmsg SET selects first complete record",
        kernel_syslog_reader_seek(&bounds, 0, EDGE_LINUX_SEEK_SET,
                                   &position) == EDGE_LINUX_SEEK_OK &&
        position == 120);
    expect_true("kmsg END selects the next record, not file size",
        kernel_syslog_reader_seek(&bounds, 0, EDGE_LINUX_SEEK_END,
                                   &position) == EDGE_LINUX_SEEK_OK &&
        position == 960);
    expect_true("kmsg DATA selects the clear marker",
        kernel_syslog_reader_seek(&bounds, 0, EDGE_LINUX_SEEK_DATA,
                                   &position) == EDGE_LINUX_SEEK_OK &&
        position == 480);

    const uint32_t origins[] = {
        EDGE_LINUX_SEEK_SET, EDGE_LINUX_SEEK_CUR, EDGE_LINUX_SEEK_END,
        EDGE_LINUX_SEEK_DATA, EDGE_LINUX_SEEK_HOLE, UINT32_MAX
    };
    const int64_t offsets[] = { 1, -1, INT64_MIN, INT64_MAX };
    for (unsigned origin = 0; origin < sizeof(origins) / sizeof(origins[0]);
         ++origin) {
        for (unsigned offset = 0; offset < sizeof(offsets) / sizeof(offsets[0]);
             ++offset) {
            position = 77;
            expect_true("nonzero kmsg displacement is ESPIPE and preserves cursor",
                kernel_syslog_reader_seek(&bounds, offsets[offset],
                    origins[origin], &position) == EDGE_LINUX_SEEK_ILLEGAL &&
                position == 77);
        }
        if (origins[origin] == EDGE_LINUX_SEEK_CUR ||
            origins[origin] == EDGE_LINUX_SEEK_HOLE ||
            origins[origin] == UINT32_MAX) {
            position = 77;
            expect_true("unsupported zero-offset kmsg origin is EINVAL",
                kernel_syslog_reader_seek(&bounds, 0, origins[origin],
                    &position) == EDGE_LINUX_SEEK_INVALID && position == 77);
        }
    }

    const kernel_syslog_reader_bounds_t wrapped = {
        .first_record = 8000, .last_clear = 4000, .next_record = 16000
    };
    expect_true("DATA retains overwritten clear marker for read EPIPE",
        kernel_syslog_reader_seek(&wrapped, 0, EDGE_LINUX_SEEK_DATA,
                                   &position) == EDGE_LINUX_SEEK_OK &&
        position == 4000);
    expect_true("SET after ring wrap starts at first retained record",
        kernel_syslog_reader_seek(&wrapped, 0, EDGE_LINUX_SEEK_SET,
                                   &position) == EDGE_LINUX_SEEK_OK &&
        position == 8000);
    const kernel_syslog_reader_bounds_t empty = {0};
    expect_true("empty log can seek to END",
        kernel_syslog_reader_seek(&empty, 0, EDGE_LINUX_SEEK_END,
                                   &position) == EDGE_LINUX_SEEK_OK &&
        position == 0);
    expect_true("seek does not clear or otherwise mutate the log bounds",
        bounds.first_record == 120 && bounds.last_clear == 480 &&
        bounds.next_record == 960 && wrapped.last_clear == 4000);
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

    test_log_writes();
    test_log_reader_seek();

    if (g_failures) return 1;
    puts("syslog_runtime_unit: PASS");
    return 0;
}
