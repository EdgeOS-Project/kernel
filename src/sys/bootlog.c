/* SPDX-License-Identifier: MPL-2.0 */
/* Copyright (c) EdgeOS Contributors. */

#include "sys/bootlog.h"

#include "console.h"
#include "kernel/linux_errno.h"
#include "kernel/linux_utsname.h"
#include "kernel/syslog_runtime.h"
#include "serial_console.h"
#include "string.h"
#include "sys/boottime.h"
#include "sys/spinlock.h"

#ifndef EDGEOS_KERNEL_RELEASE
#define EDGEOS_KERNEL_RELEASE "unknown"
#endif

#ifndef CONFIG_LINUX_ABI_RELEASE
#define CONFIG_LINUX_ABI_RELEASE "unknown"
#endif

/*
 * Keep this deliberately simple and self-contained.  Linux userland commonly
 * expects syslog(2), /proc/kmsg, and dmesg output to retain early boot records;
 * a fixed append-only buffer stops being useful once noisy drivers initialize.
 * This ring keeps the newest messages without allocating memory during panic or
 * early device bring-up paths.
 */
#define BOOTLOG_RING_SIZE 65536u
#define BOOTLOG_LINE_MAX 512u
#define BOOTLOG_RECORD_CAPACITY 2048u

typedef struct {
    uint64_t byte_offset;
    uint64_t sequence;
    uint64_t timestamp_us;
    uint32_t length;
    uint16_t text_offset;
    uint8_t priority;
    uint8_t reserved;
} bootlog_record_t;

static char g_bootlog_ring[BOOTLOG_RING_SIZE];
static bootlog_record_t g_bootlog_records[BOOTLOG_RECORD_CAPACITY];
static uint32_t g_bootlog_start;
static uint32_t g_bootlog_len;
static uint32_t g_bootlog_record_start;
static uint32_t g_bootlog_record_count;
static uint64_t g_bootlog_total_bytes;
static uint64_t g_bootlog_next_sequence;
static uint64_t g_bootlog_clear_offset;
static spinlock_t g_bootlog_lock;
static int g_bootlog_ready;

static void bootlog_ensure_ready(void) {
    if (g_bootlog_ready) return;
    spinlock_init(&g_bootlog_lock);
    g_bootlog_start = 0;
    g_bootlog_len = 0;
    g_bootlog_record_start = 0;
    g_bootlog_record_count = 0;
    g_bootlog_total_bytes = 0;
    g_bootlog_next_sequence = 0;
    g_bootlog_clear_offset = 0;
    g_bootlog_ready = 1;
}

static int append_char(char *buf, uint32_t max, uint32_t *off, char ch) {
    if (!buf || !off || max == 0) return -1;
    if (*off + 1u >= max) return -1;
    buf[*off] = ch;
    *off += 1u;
    buf[*off] = 0;
    return 0;
}

static int append_str(char *buf, uint32_t max, uint32_t *off, const char *s) {
    if (!s) s = "";
    while (*s) {
        if (append_char(buf, max, off, *s++) < 0) return -1;
    }
    return 0;
}

static uint32_t decimal_digits_u64(uint64_t v) {
    uint32_t n = 1;
    while (v >= 10u) {
        v /= 10u;
        n++;
    }
    return n;
}

static int append_u64_dec_width(char *buf, uint32_t max, uint32_t *off,
                                uint64_t v, uint32_t width, char pad) {
    char tmp[32];
    uint32_t n = 0;
    uint32_t digits = decimal_digits_u64(v);
    while (width > digits) {
        if (append_char(buf, max, off, pad) < 0) return -1;
        width--;
    }
    if (v == 0) {
        tmp[n++] = '0';
    } else {
        while (v && n < (uint32_t)sizeof(tmp)) {
            tmp[n++] = (char)('0' + (v % 10u));
            v /= 10u;
        }
    }
    while (n > 0) {
        if (append_char(buf, max, off, tmp[--n]) < 0) return -1;
    }
    return 0;
}

static int bootlog_format_timestamp_prefix_at(char *buf, uint32_t max,
                                              uint64_t us) {
    uint64_t sec = us / 1000000ull;
    uint64_t frac = us % 1000000ull;
    uint32_t off = 0;

    buf[0] = 0;
    if (append_char(buf, max, &off, '[') < 0) return -1;
    if (append_u64_dec_width(buf, max, &off, sec, 5, ' ') < 0) return -1;
    if (append_char(buf, max, &off, '.') < 0) return -1;
    if (append_u64_dec_width(buf, max, &off, frac, 6, '0') < 0) return -1;
    if (append_str(buf, max, &off, "] ") < 0) return -1;
    return (int)off;
}

int bootlog_format_timestamp_prefix(char *buf, uint32_t max) {
    return bootlog_format_timestamp_prefix_at(
        buf, max, boottime_monotonic_us());
}

static int format_kmsg_line(char *buf, uint32_t max, const char *msg,
                            uint64_t timestamp_us,
                            uint16_t *text_offset) {
    int prefix_len;
    uint32_t off;

    prefix_len = bootlog_format_timestamp_prefix_at(buf, max, timestamp_us);
    if (prefix_len < 0) return -1;
    if (text_offset) *text_offset = (uint16_t)prefix_len;
    off = (uint32_t)prefix_len;
    if (append_str(buf, max, &off, msg ? msg : "") < 0) return -1;
    if (append_char(buf, max, &off, '\n') < 0) return -1;
    return (int)off;
}

static void bootlog_ring_append_locked(const char *s, uint32_t n) {
    if (!s || n == 0) return;
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t pos;
        if (g_bootlog_len < BOOTLOG_RING_SIZE) {
            pos = (g_bootlog_start + g_bootlog_len) % BOOTLOG_RING_SIZE;
            g_bootlog_len++;
        } else {
            pos = g_bootlog_start;
            g_bootlog_start = (g_bootlog_start + 1u) % BOOTLOG_RING_SIZE;
        }
        g_bootlog_ring[pos] = s[i];
        g_bootlog_total_bytes++;
    }
}

static void bootlog_record_drop_oldest_locked(void) {
    if (!g_bootlog_record_count) return;
    g_bootlog_record_start =
        (g_bootlog_record_start + 1u) % BOOTLOG_RECORD_CAPACITY;
    --g_bootlog_record_count;
}

static void bootlog_record_append_locked(const char *text, uint32_t length,
                                         uint16_t text_offset,
                                         uint64_t timestamp_us,
                                         uint8_t priority) {
    bootlog_record_t *record;
    uint64_t byte_offset;
    uint64_t first_byte;
    uint32_t slot;

    if (!text || !length || text_offset > length) return;
    byte_offset = g_bootlog_total_bytes;
    bootlog_ring_append_locked(text, length);
    first_byte = g_bootlog_total_bytes - g_bootlog_len;
    while (g_bootlog_record_count) {
        record = &g_bootlog_records[g_bootlog_record_start];
        if (record->byte_offset >= first_byte) break;
        bootlog_record_drop_oldest_locked();
    }
    if (g_bootlog_record_count == BOOTLOG_RECORD_CAPACITY)
        bootlog_record_drop_oldest_locked();
    slot = (g_bootlog_record_start + g_bootlog_record_count) %
           BOOTLOG_RECORD_CAPACITY;
    record = &g_bootlog_records[slot];
    record->byte_offset = byte_offset;
    record->sequence = g_bootlog_next_sequence++;
    record->timestamp_us = timestamp_us;
    record->length = length;
    record->text_offset = text_offset;
    record->priority = priority;
    record->reserved = 0;
    ++g_bootlog_record_count;
}

static int bootlog_timestamp_prefix_parse(const char *text, uint32_t length,
                                          uint64_t *timestamp_us,
                                          uint16_t *text_offset) {
    uint64_t seconds = 0;
    uint64_t fraction = 0;
    uint32_t index = 0;
    uint32_t fraction_digits = 0;
    int saw_seconds = 0;

    if (!text || length < 6u || text[0] != '[') return 0;
    index = 1;
    while (index < length && text[index] == ' ') ++index;
    while (index < length && text[index] >= '0' && text[index] <= '9') {
        saw_seconds = 1;
        seconds = seconds * 10u + (uint64_t)(text[index] - '0');
        ++index;
    }
    if (!saw_seconds || index >= length || text[index++] != '.') return 0;
    while (index < length && text[index] >= '0' && text[index] <= '9' &&
           fraction_digits < 6u) {
        fraction = fraction * 10u + (uint64_t)(text[index] - '0');
        ++fraction_digits;
        ++index;
    }
    while (fraction_digits < 6u) {
        fraction *= 10u;
        ++fraction_digits;
    }
    if (index + 1u >= length || text[index] != ']' ||
        text[index + 1u] != ' ')
        return 0;
    if (timestamp_us) *timestamp_us = seconds * 1000000u + fraction;
    if (text_offset) *text_offset = (uint16_t)(index + 2u);
    return 1;
}

static char bootlog_ring_byte_locked(uint64_t absolute_offset) {
    uint64_t first = g_bootlog_total_bytes - g_bootlog_len;
    uint32_t relative = (uint32_t)(absolute_offset - first);
    return g_bootlog_ring[(g_bootlog_start + relative) % BOOTLOG_RING_SIZE];
}

static const bootlog_record_t *bootlog_record_at_or_after_locked(
    uint64_t position) {
    for (uint32_t index = 0; index < g_bootlog_record_count; ++index) {
        const bootlog_record_t *record = &g_bootlog_records[
            (g_bootlog_record_start + index) % BOOTLOG_RECORD_CAPACITY];
        if (position <= record->byte_offset) return record;
        if (position < record->byte_offset + record->length) return record;
    }
    return 0;
}

static int bootlog_kmsg_prefix(char *buffer, uint32_t capacity,
                               const bootlog_record_t *record) {
    uint32_t offset = 0;
    if (!buffer || !record || !capacity) return -1;
    buffer[0] = 0;
    if (append_u64_dec_width(buffer, capacity, &offset,
                             record->priority, 0, '0') < 0 ||
        append_char(buffer, capacity, &offset, ',') < 0 ||
        append_u64_dec_width(buffer, capacity, &offset,
                             record->sequence, 0, '0') < 0 ||
        append_char(buffer, capacity, &offset, ',') < 0 ||
        append_u64_dec_width(buffer, capacity, &offset,
                             record->timestamp_us, 0, '0') < 0 ||
        append_str(buffer, capacity, &offset, ",-;") < 0)
        return -1;
    return (int)offset;
}

int bootlog_format_version(char *buf, uint32_t max) {
    uint32_t off = 0;
    if (!buf || max == 0) return -1;
    buf[0] = 0;
    if (append_str(buf, max, &off, "EdgeOS version ") < 0) return -1;
    if (append_str(buf, max, &off, EDGEOS_KERNEL_RELEASE) < 0) return -1;
    if (append_str(buf, max, &off, " (gcc ") < 0) return -1;
    if (append_str(buf, max, &off, __VERSION__) < 0) return -1;
    if (append_str(buf, max, &off, ") ") < 0) return -1;
    if (append_str(buf, max, &off, EDGEOS_LINUX_ABI_VERSION) < 0) return -1;
    return (int)off;
}

int bootlog_format_linux_version(char *buf, uint32_t max) {
    uint32_t off = 0;
    if (!buf || max == 0) return -1;
    buf[0] = 0;
    if (append_str(buf, max, &off, "Linux version ") < 0) return -1;
    if (append_str(buf, max, &off, CONFIG_LINUX_ABI_RELEASE) < 0) return -1;
    if (append_str(buf, max, &off, " (EdgeOS ") < 0) return -1;
    if (append_str(buf, max, &off, EDGEOS_KERNEL_RELEASE) < 0) return -1;
    if (append_str(buf, max, &off, "; ") < 0) return -1;
    if (append_str(buf, max, &off, __VERSION__) < 0) return -1;
    if (append_str(buf, max, &off, ") ") < 0) return -1;
    if (append_str(buf, max, &off, EDGEOS_LINUX_ABI_VERSION) < 0) return -1;
    return (int)off;
}

void bootlog_init(void) {
    char version[256];
    serial_console_write_raw('A');
    bootlog_ensure_ready();
    serial_console_write_raw('B');
    if (bootlog_format_version(version, sizeof(version)) >= 0) {
        serial_console_write_raw('C');
        bootlog_stage(version);
    }
    serial_console_write_raw('D');
}

void bootlog_stage(const char *msg) {
    char line[BOOTLOG_LINE_MAX];
    int n;
    uint16_t text_offset = 0;
    uint64_t timestamp_us;
    uint64_t flags;

    serial_console_write_raw('J');
    bootlog_ensure_ready();
    serial_console_write_raw('K');
    timestamp_us = boottime_monotonic_us();
    serial_console_write_raw('L');
    n = format_kmsg_line(line, sizeof(line), msg, timestamp_us,
                         &text_offset);
    serial_console_write_raw('M');
    if (n < 0) {
        /*
         * Long records should never corrupt the ring.  Preserve a clear marker
         * so a future debug session knows the original line exceeded the
         * in-kernel console record size instead of disappearing silently.
         */
        timestamp_us = boottime_monotonic_us();
        n = format_kmsg_line(line, sizeof(line),
                             "bootlog: dropped oversized message",
                             timestamp_us, &text_offset);
        if (n < 0) return;
    }

    serial_console_write_raw('E');
    console_kernel_log_putstr(line);
    serial_console_write_raw('F');

    flags = spin_lock_irqsave(&g_bootlog_lock);
    serial_console_write_raw('G');
    bootlog_record_append_locked(line, (uint32_t)n, text_offset,
                                 timestamp_us, 6u);
    spin_unlock_irqrestore(&g_bootlog_lock, flags);
    serial_console_write_raw('H');
    kernel_syslog_notify_data();
    serial_console_write_raw('I');
}

void bootlog_append_raw(const char *s, uint32_t n) {
    uint64_t timestamp_us;
    uint16_t text_offset = 0;
    uint64_t flags;
    if (!s || n == 0) return;
    bootlog_ensure_ready();
    timestamp_us = boottime_monotonic_us();
    (void)bootlog_timestamp_prefix_parse(s, n, &timestamp_us,
                                         &text_offset);
    flags = spin_lock_irqsave(&g_bootlog_lock);
    bootlog_record_append_locked(s, n, text_offset, timestamp_us, 6u);
    spin_unlock_irqrestore(&g_bootlog_lock, flags);
    kernel_syslog_notify_data();
}

uint32_t bootlog_read(uint32_t off, void *buf, uint32_t len) {
    uint64_t flags;
    uint32_t copied = 0;
    char *out = (char *)buf;

    if (!out || len == 0) return 0;
    bootlog_ensure_ready();
    flags = spin_lock_irqsave(&g_bootlog_lock);
    if (off < g_bootlog_len) {
        uint32_t avail = g_bootlog_len - off;
        if (len > avail) len = avail;
        while (copied < len) {
            uint32_t pos = (g_bootlog_start + off + copied) % BOOTLOG_RING_SIZE;
            uint32_t chunk = BOOTLOG_RING_SIZE - pos;
            if (chunk > len - copied) chunk = len - copied;
            memcpy(out + copied, g_bootlog_ring + pos, chunk);
            copied += chunk;
        }
    }
    spin_unlock_irqrestore(&g_bootlog_lock, flags);
    return copied;
}

int bootlog_read_from(uint64_t *pos_io, void *buf, uint32_t len) {
    uint64_t flags;
    uint64_t first;
    uint64_t pos;
    uint32_t copied = 0;
    char *out = (char *)buf;

    if (!pos_io || !out) return -1;
    if (len == 0) return 0;
    bootlog_ensure_ready();

    flags = spin_lock_irqsave(&g_bootlog_lock);
    first = g_bootlog_total_bytes - (uint64_t)g_bootlog_len;
    pos = *pos_io;
    /*
     * /dev/kmsg readers keep file positions for longer than one syscall.
     * Interpret those positions as absolute bytes produced by the ring, not
     * as offsets relative to the current start, so a reader cannot receive
     * unrelated bytes after the fixed-size buffer wraps.  Linux reports lost
     * records through sequence metadata; until EdgeOS has per-record metadata,
     * clamp stale readers to the oldest retained byte.
     */
    if (pos < first) pos = first;
    if (pos > g_bootlog_total_bytes) pos = g_bootlog_total_bytes;
    if (pos < g_bootlog_total_bytes) {
        uint64_t avail64 = g_bootlog_total_bytes - pos;
        uint32_t rel = (uint32_t)(pos - first);
        if ((uint64_t)len > avail64) len = (uint32_t)avail64;
        while (copied < len) {
            uint32_t ring_pos = (g_bootlog_start + rel + copied) % BOOTLOG_RING_SIZE;
            uint32_t chunk = BOOTLOG_RING_SIZE - ring_pos;
            if (chunk > len - copied) chunk = len - copied;
            memcpy(out + copied, g_bootlog_ring + ring_pos, chunk);
            copied += chunk;
        }
        pos += copied;
    }
    *pos_io = pos;
    spin_unlock_irqrestore(&g_bootlog_lock, flags);
    return (int)copied;
}

uint64_t bootlog_first_offset(void) {
    uint64_t flags;
    uint64_t first;

    bootlog_ensure_ready();
    flags = spin_lock_irqsave(&g_bootlog_lock);
    first = g_bootlog_total_bytes - (uint64_t)g_bootlog_len;
    spin_unlock_irqrestore(&g_bootlog_lock, flags);
    return first;
}

uint64_t bootlog_next_offset(void) {
    uint64_t flags;
    uint64_t next;

    bootlog_ensure_ready();
    flags = spin_lock_irqsave(&g_bootlog_lock);
    next = g_bootlog_total_bytes;
    spin_unlock_irqrestore(&g_bootlog_lock, flags);
    return next;
}

uint64_t bootlog_kmsg_first_offset(void) {
    uint64_t flags;
    uint64_t first;

    bootlog_ensure_ready();
    flags = spin_lock_irqsave(&g_bootlog_lock);
    first = g_bootlog_record_count ?
        g_bootlog_records[g_bootlog_record_start].byte_offset :
        g_bootlog_total_bytes;
    spin_unlock_irqrestore(&g_bootlog_lock, flags);
    return first;
}

int bootlog_kmsg_has_record(uint64_t position) {
    uint64_t flags;
    int ready;

    bootlog_ensure_ready();
    flags = spin_lock_irqsave(&g_bootlog_lock);
    ready = bootlog_record_at_or_after_locked(position) != 0;
    spin_unlock_irqrestore(&g_bootlog_lock, flags);
    return ready;
}

uint32_t bootlog_kmsg_next_record_length(uint64_t position) {
    char prefix[80];
    const bootlog_record_t *record;
    uint64_t flags;
    uint32_t body_length;
    uint32_t result = 0;
    int prefix_length;

    bootlog_ensure_ready();
    flags = spin_lock_irqsave(&g_bootlog_lock);
    record = bootlog_record_at_or_after_locked(position);
    if (record) {
        prefix_length = bootlog_kmsg_prefix(prefix, sizeof(prefix), record);
        body_length = record->length - record->text_offset;
        if (prefix_length >= 0) {
            result = (uint32_t)prefix_length + body_length;
            if (!body_length || bootlog_ring_byte_locked(
                    record->byte_offset + record->length - 1u) != '\n')
                ++result;
        }
    }
    spin_unlock_irqrestore(&g_bootlog_lock, flags);
    return result;
}

int bootlog_kmsg_read_from(uint64_t *pos_io, void *buf, uint32_t len) {
    char prefix[80];
    const bootlog_record_t *record;
    char *output = (char *)buf;
    uint64_t flags;
    uint64_t first;
    uint32_t body_length;
    uint32_t required;
    uint32_t copied;
    int prefix_length;

    if (!pos_io || !output) return -EDGE_LINUX_EFAULT;
    if (!len) return 0;
    bootlog_ensure_ready();
    flags = spin_lock_irqsave(&g_bootlog_lock);
    first = g_bootlog_record_count ?
        g_bootlog_records[g_bootlog_record_start].byte_offset :
        g_bootlog_total_bytes;
    if (*pos_io < first) {
        *pos_io = first;
        spin_unlock_irqrestore(&g_bootlog_lock, flags);
        return -EDGE_LINUX_EPIPE;
    }
    record = bootlog_record_at_or_after_locked(*pos_io);
    if (!record) {
        spin_unlock_irqrestore(&g_bootlog_lock, flags);
        return 0;
    }
    prefix_length = bootlog_kmsg_prefix(prefix, sizeof(prefix), record);
    if (prefix_length < 0) {
        spin_unlock_irqrestore(&g_bootlog_lock, flags);
        return -EDGE_LINUX_EIO;
    }
    body_length = record->length - record->text_offset;
    required = (uint32_t)prefix_length + body_length;
    if (!body_length || bootlog_ring_byte_locked(
            record->byte_offset + record->length - 1u) != '\n')
        ++required;
    if (len < required) {
        spin_unlock_irqrestore(&g_bootlog_lock, flags);
        return -EDGE_LINUX_EINVAL;
    }
    memcpy(output, prefix, (uint32_t)prefix_length);
    copied = (uint32_t)prefix_length;
    for (uint32_t index = 0; index < body_length; ++index)
        output[copied++] = bootlog_ring_byte_locked(
            record->byte_offset + record->text_offset + index);
    if (!body_length || output[copied - 1u] != '\n') output[copied++] = '\n';
    *pos_io = record->byte_offset + record->length;
    spin_unlock_irqrestore(&g_bootlog_lock, flags);
    return (int)copied;
}

void bootlog_snapshot_bounds(uint64_t *first_offset,
                             uint64_t *clear_offset,
                             uint64_t *next_offset) {
    uint64_t flags;
    uint64_t first;
    uint64_t clear;

    bootlog_ensure_ready();
    flags = spin_lock_irqsave(&g_bootlog_lock);
    first = g_bootlog_total_bytes - (uint64_t)g_bootlog_len;
    clear = g_bootlog_clear_offset < first ? first :
        g_bootlog_clear_offset;
    if (first_offset) *first_offset = first;
    if (clear_offset) *clear_offset = clear;
    if (next_offset) *next_offset = g_bootlog_total_bytes;
    spin_unlock_irqrestore(&g_bootlog_lock, flags);
}

uint32_t bootlog_buffer_size(void) {
    uint64_t flags;
    uint32_t n;

    bootlog_ensure_ready();
    flags = spin_lock_irqsave(&g_bootlog_lock);
    n = g_bootlog_len;
    spin_unlock_irqrestore(&g_bootlog_lock, flags);
    return n;
}

uint32_t bootlog_buffer_capacity(void) {
    return BOOTLOG_RING_SIZE;
}

void bootlog_clear(void) {
    uint64_t flags;

    bootlog_ensure_ready();
    flags = spin_lock_irqsave(&g_bootlog_lock);
    /* Linux clear advances the READ_ALL marker; it does not erase the ring. */
    g_bootlog_clear_offset = g_bootlog_total_bytes;
    spin_unlock_irqrestore(&g_bootlog_lock, flags);
}
