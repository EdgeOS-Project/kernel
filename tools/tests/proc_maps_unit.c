/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent procfs maps policy unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/proc_maps.h"

static int g_failures;
static int g_backend_mode;
static int g_account_mode;

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

int arch_proc_vma_next(int32_t pid,
                       const kernel_proc_vma_cursor_t *after,
                       kernel_proc_vma_snapshot_t *snapshot) {
    static const kernel_proc_vma_snapshot_t records[] = {
        {
            .start = UINT64_C(0x1000),
            .end = UINT64_C(0x2000),
            .file_offset = 0,
            .inode = 7,
            .device_major = 8,
            .device_minor = 1,
            .flags = KERNEL_PROC_MAP_READ | KERNEL_PROC_MAP_EXEC,
            .order = 1,
            .path = "/bin/test",
        },
        {
            .start = UINT64_C(0x3000),
            .end = UINT64_C(0x5000),
            .file_offset = UINT64_C(0x2000),
            .inode = 0,
            .flags = KERNEL_PROC_MAP_READ | KERNEL_PROC_MAP_WRITE,
            .order = 2,
            .path = "[heap]",
        },
    };

    (void)pid;
    if (!snapshot) return -1;
    if (g_backend_mode == 1) {
        *snapshot = records[0];
        snapshot->end = snapshot->start;
        return 1;
    }
    if (g_backend_mode == 2) {
        *snapshot = records[0];
        snapshot->order = 0;
        return 1;
    }
    if (!after || !after->valid) {
        *snapshot = records[0];
        return 1;
    }
    if (after->start == records[0].start &&
        after->order == records[0].order) {
        *snapshot = records[1];
        return 1;
    }
    return 0;
}

int arch_proc_vma_account(int32_t pid,
                          kernel_proc_vma_accounting_t *accounting) {
    if (pid <= 0 || !accounting || !g_account_mode) return -1;
    memset(accounting, 0, sizeof(*accounting));
    kernel_proc_vma_account_mapping(
        accounting, UINT64_C(0x1000), UINT64_C(0x2000),
        KERNEL_PROC_MAP_READ | KERNEL_PROC_MAP_EXEC, 0);
    kernel_proc_vma_account_mapping(
        accounting, UINT64_C(0x3000), UINT64_C(0x5000),
        KERNEL_PROC_MAP_READ | KERNEL_PROC_MAP_WRITE, 0);
    return 0;
}

int arch_proc_vma_residency(int32_t pid, uint64_t start, uint64_t end,
                            kernel_proc_vma_residency_t *residency) {
    (void)pid;
    if (!residency || end <= start) return -1;
    memset(residency, 0, sizeof(*residency));
    if (start == UINT64_C(0x1000)) {
        residency->resident_pages = 1u;
        residency->shared_resident_pages = 1u;
        residency->locked_resident_pages = 1u;
        residency->proportional_resident_bytes = 2048u;
        return 0;
    }
    if (start == UINT64_C(0x3000)) {
        residency->resident_pages = 1u;
        residency->swapped_pages = 1u;
        residency->proportional_resident_bytes = 4096u;
        residency->proportional_swapped_bytes = 2048u;
        return 0;
    }
    return -1;
}

static void test_shared_iterator_validation(void) {
    kernel_proc_vma_cursor_t after = {
        .start = UINT64_C(0x1000),
        .order = 1,
        .valid = 1,
    };
    kernel_proc_vma_snapshot_t snapshot;

    expect_true("iterator invalid pid",
                kernel_proc_vma_next(0, 0, &snapshot) < 0);
    expect_true("iterator null snapshot",
                kernel_proc_vma_next(1, 0, 0) < 0);
    g_backend_mode = 1;
    expect_true("iterator rejects empty mapping",
                kernel_proc_vma_next(1, 0, &snapshot) < 0);
    g_backend_mode = 2;
    expect_true("iterator rejects nonmonotonic mapping",
                kernel_proc_vma_next(1, &after, &snapshot) < 0);
    g_backend_mode = 0;
    expect_true("iterator accepts next mapping",
                kernel_proc_vma_next(1, &after, &snapshot) == 1 &&
                snapshot.start == UINT64_C(0x3000) &&
                snapshot.end == UINT64_C(0x5000));
}

static void test_render_and_read(void) {
    static const char expected[] =
        "0000000000001000-0000000000002000 r-xp 00000000 08:01 7 /bin/test\n"
        "0000000000003000-0000000000005000 rw-p 00002000 00:00 0 [heap]\n";
    char rendered[512];
    char slice[24];
    int length;
    int copied;

    g_backend_mode = 0;
    length = kernel_proc_maps_render(1, rendered, sizeof(rendered));
    expect_true("render complete",
                length == (int)strlen(expected) &&
                strcmp(rendered, expected) == 0);
    copied = kernel_proc_maps_read(1, 17u, slice, sizeof(slice));
    expect_true("read slice length", copied == (int)sizeof(slice));
    expect_true("read slice content",
                memcmp(slice, expected + 17, sizeof(slice)) == 0);
    expect_true("render rejects short buffer",
                kernel_proc_maps_render(1, rendered, 8u) < 0);
}

static void test_vma_accounting(void) {
    kernel_proc_vma_accounting_t accounting;

    g_backend_mode = 0;
    g_account_mode = 0;
    expect_true("accounting iterator fallback",
                kernel_proc_vma_account(1, &accounting) == 0 &&
                accounting.virtual_size_bytes == UINT64_C(0x3000) &&
                accounting.text_size_bytes == UINT64_C(0x1000) &&
                accounting.data_size_bytes == UINT64_C(0x2000));
    g_account_mode = 1;
    expect_true("accounting architecture fast path",
                kernel_proc_vma_account(1, &accounting) == 0 &&
                accounting.virtual_size_bytes == UINT64_C(0x3000) &&
                accounting.text_size_bytes == UINT64_C(0x1000) &&
                accounting.data_size_bytes == UINT64_C(0x2000));
    memset(&accounting, 0, sizeof(accounting));
    kernel_proc_vma_account_mapping(
        &accounting, UINT64_C(0xfffffffffffff000), UINT64_MAX,
        KERNEL_PROC_MAP_READ | KERNEL_PROC_MAP_WRITE, 1);
    kernel_proc_vma_account_mapping(
        &accounting, 0, UINT64_MAX, KERNEL_PROC_MAP_READ, 0);
    expect_true("accounting saturates",
                accounting.virtual_size_bytes == UINT64_MAX &&
                accounting.stack_size_bytes == UINT64_C(0xfff));
}

static void test_smaps_and_rollup(void) {
    char buffer[4096];
    char chunked[4096];
    int length;
    int chunked_length = 0;

    memset(buffer, 0, sizeof(buffer));
    length = kernel_proc_smaps_read(1, 0, buffer, sizeof(buffer) - 1u);
    expect_true("smaps read", length > 0);
    expect_true("smaps file header",
                strstr(buffer, "/bin/test\nSize:           4 kB\n") != 0);
    expect_true("smaps resident",
                strstr(buffer, "Rss:            4 kB\n") != 0);
    expect_true("smaps proportional share",
                strstr(buffer, "Pss:            2 kB\n") != 0);
    expect_true("smaps shared by physical aliases",
                strstr(buffer, "Shared_Clean:   4 kB\n") != 0);
    expect_true("smaps resident lock",
                strstr(buffer, "Locked:         4 kB\n") != 0);
    expect_true("smaps swapped",
                strstr(buffer, "Swap:           4 kB\n") != 0);
    expect_true("smaps flags",
                strstr(buffer, "VmFlags: rd ex lo mr\n") != 0);
    while ((uint32_t)chunked_length < sizeof(chunked)) {
        int chunk = kernel_proc_smaps_read(
            1, (uint64_t)chunked_length, chunked + chunked_length, 37u);
        expect_true("smaps chunk read", chunk >= 0);
        if (chunk <= 0) break;
        chunked_length += chunk;
    }
    expect_true("smaps chunk length", chunked_length == length);
    expect_true("smaps chunk contents",
                chunked_length == length &&
                memcmp(chunked, buffer, (size_t)length) == 0);

    memset(buffer, 0, sizeof(buffer));
    length = kernel_proc_smaps_rollup_read(
        1, 0, buffer, sizeof(buffer) - 1u);
    expect_true("smaps rollup read", length > 0);
    expect_true("smaps rollup header",
                strstr(buffer, "[rollup]\n") != 0);
    expect_true("smaps rollup rss",
                strstr(buffer, "Rss:            8 kB\n") != 0);
    expect_true("smaps rollup pss",
                strstr(buffer, "Pss:            6 kB\n") != 0);
    expect_true("smaps rollup swap",
                strstr(buffer, "Swap:           4 kB\n") != 0);
    expect_true("smaps rollup swap pss",
                strstr(buffer, "SwapPss:        2 kB\n") != 0);
    expect_true("smaps rollup locked",
                strstr(buffer, "Locked:         4 kB\n") != 0);
}

int main(void) {
    test_shared_iterator_validation();
    test_render_and_read();
    test_vma_accounting();
    test_smaps_and_rollup();
    if (g_failures) return 1;
    puts("proc_maps_unit: PASS");
    return 0;
}
