/* SPDX-License-Identifier: MPL-2.0 */
/* Exercise actual bootlog cursor bounds and record reads across ring wrap. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "sys/bootlog.h"

static uint64_t now_us;

uint64_t boottime_monotonic_us(void) { return ++now_us; }
void console_kernel_log_putstr(const char *text) { (void)text; }
void kernel_syslog_notify_data(void) { }

int main(void) {
    uint64_t first, clear, next, cursor;
    char output[512];
    char record[300];
    int length;

    bootlog_kmsg_seek_bounds(&first, &clear, &next);
    assert(first == 0 && clear == 0 && next == 0);
    bootlog_append_raw("first\n", 6);
    bootlog_clear();
    bootlog_append_raw("second\n", 7);
    bootlog_kmsg_seek_bounds(&first, &clear, &next);
    assert(first == 0 && clear == 6 && next == 13);

    cursor = clear;
    length = bootlog_kmsg_read_from(&cursor, output, sizeof(output) - 1u);
    assert(length > 0 && cursor == next);
    output[length] = 0;
    assert(strstr(output, ";second\n") != NULL);
    assert(bootlog_kmsg_read_from(&cursor, output, sizeof(output)) == 0);
    cursor = first;
    length = bootlog_kmsg_read_from(&cursor, output, sizeof(output) - 1u);
    assert(length > 0 && cursor == clear);
    output[length] = 0;
    assert(strstr(output, ";first\n") != NULL);

    memset(record, 'x', sizeof(record));
    record[sizeof(record) - 1u] = '\n';
    for (unsigned index = 0; index < 256; ++index)
        bootlog_append_raw(record, sizeof(record));
    bootlog_kmsg_seek_bounds(&first, &clear, &next);
    assert(first > clear && clear == 6);
    assert(first == bootlog_kmsg_first_offset());
    assert(first > bootlog_first_offset());
    assert(next == 13u + 256u * sizeof(record));
    cursor = clear;
    assert(bootlog_kmsg_read_from(&cursor, output, sizeof(output)) ==
           -EDGE_LINUX_EPIPE);
    assert(cursor == first);
    assert(bootlog_kmsg_read_from(&cursor, output, sizeof(output)) > 0);
    bootlog_kmsg_seek_bounds(NULL, &clear, NULL);
    assert(clear == 6);
    bootlog_kmsg_seek_bounds(NULL, NULL, NULL);
    puts("bootlog_seek_unit: PASS");
    return 0;
}
