/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent /proc/<pid>/maps formatter.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/proc_maps.h"
#include "mm/arch_vm.h"
#include "string.h"

#define PROC_MAPS_SNAPSHOT_SLOTS 512u
#define PROC_MAPS_SNAPSHOT_PAGE_SIZE 4096u
#define PROC_MAPS_SNAPSHOT_INITIAL_PAGES 16u
#define PROC_MAPS_SNAPSHOT_MAX_PAGES 4096u

typedef struct proc_maps_snapshot {
    uint64_t description_identity;
    int32_t pid;
    uint32_t view;
    char *data;
    uint32_t length;
    uint32_t pages;
    uint8_t active;
} proc_maps_snapshot_t;

static proc_maps_snapshot_t g_proc_maps_snapshots[PROC_MAPS_SNAPSHOT_SLOTS];
static volatile uint32_t g_proc_maps_snapshot_lock;

static void proc_maps_snapshot_lock(void) {
    while (__sync_lock_test_and_set(&g_proc_maps_snapshot_lock, 1u))
        __asm__ volatile("" ::: "memory");
}

static void proc_maps_snapshot_unlock(void) {
    __sync_lock_release(&g_proc_maps_snapshot_lock);
}

static void proc_maps_snapshot_free(char *data, uint32_t pages) {
    uint32_t page;

    if (!data) return;
    for (page = 0; page < pages; ++page)
        arch_vm_free_page(data + (uint64_t)page *
                                   PROC_MAPS_SNAPSHOT_PAGE_SIZE);
}

static int maps_append(char *buffer, uint32_t capacity, uint32_t *length,
                       const char *text) {
    if (!buffer || !length || !text) return -1;
    while (*text) {
        if (*length + 1u >= capacity) return -1;
        buffer[(*length)++] = *text++;
    }
    buffer[*length] = 0;
    return 0;
}

static int maps_append_hex(char *buffer, uint32_t capacity, uint32_t *length,
                           uint64_t value, uint32_t width) {
    static const char digits[] = "0123456789abcdef";
    char encoded[16];

    if (width > sizeof(encoded)) return -1;
    for (uint32_t index = 0; index < width; ++index) {
        encoded[width - index - 1u] = digits[value & 0xfu];
        value >>= 4u;
    }
    for (uint32_t index = 0; index < width; ++index) {
        char byte[2] = {encoded[index], 0};
        if (maps_append(buffer, capacity, length, byte) < 0) return -1;
    }
    return 0;
}

static int maps_append_u64(char *buffer, uint32_t capacity, uint32_t *length,
                           uint64_t value) {
    char reversed[24];
    uint32_t count = 0;

    if (!value) reversed[count++] = '0';
    while (value && count < sizeof(reversed)) {
        reversed[count++] = (char)('0' + value % 10u);
        value /= 10u;
    }
    while (count) {
        char byte[2] = {reversed[--count], 0};
        if (maps_append(buffer, capacity, length, byte) < 0) return -1;
    }
    return 0;
}

static uint32_t maps_hex_width(uint64_t value, uint32_t minimum) {
    uint32_t width = 1u;

    while ((value >>= 4u) != 0u) ++width;
    return width < minimum ? minimum : width;
}

static uint64_t maps_saturating_add(uint64_t left, uint64_t right) {
    return left > UINT64_MAX - right ? UINT64_MAX : left + right;
}

void kernel_proc_vma_account_mapping(
    kernel_proc_vma_accounting_t *accounting,
    uint64_t start, uint64_t end, uint32_t flags, int is_stack) {
    uint64_t bytes;

    if (!accounting || end <= start) return;
    bytes = end - start;
    accounting->virtual_size_bytes = maps_saturating_add(
        accounting->virtual_size_bytes, bytes);
    if (is_stack)
        accounting->stack_size_bytes = maps_saturating_add(
            accounting->stack_size_bytes, bytes);
    else if (flags & KERNEL_PROC_MAP_EXEC)
        accounting->text_size_bytes = maps_saturating_add(
            accounting->text_size_bytes, bytes);
    else if (flags & KERNEL_PROC_MAP_WRITE)
        accounting->data_size_bytes = maps_saturating_add(
            accounting->data_size_bytes, bytes);
}

int kernel_proc_vma_account(int32_t pid,
                            kernel_proc_vma_accounting_t *accounting) {
    kernel_proc_vma_cursor_t cursor = {0, 0, 0};
    kernel_proc_vma_snapshot_t mapping;
    uint32_t records = 0;

    if (pid <= 0 || !accounting) return -1;
    memset(accounting, 0, sizeof(*accounting));
    if (arch_proc_vma_account(pid, accounting) == 0)
        return 0;
    memset(accounting, 0, sizeof(*accounting));
    for (;;) {
        int result = kernel_proc_vma_next(pid, &cursor, &mapping);
        if (result < 0) return -1;
        if (!result) break;
        kernel_proc_vma_account_mapping(
            accounting, mapping.start, mapping.end, mapping.flags,
            mapping.path[0] && !strcmp(mapping.path, "[stack]"));
        cursor.start = mapping.start;
        cursor.order = mapping.order;
        cursor.valid = 1;
        if (++records > 65536u) return -1;
    }
    return 0;
}

static int maps_append_record(char *buffer, uint32_t capacity,
                              uint32_t *length,
                              const kernel_proc_vma_snapshot_t *mapping) {
    char permissions[5];

    if (!mapping || mapping->end <= mapping->start) return -1;
    permissions[0] = (mapping->flags & KERNEL_PROC_MAP_READ) ? 'r' : '-';
    permissions[1] = (mapping->flags & KERNEL_PROC_MAP_WRITE) ? 'w' : '-';
    permissions[2] = (mapping->flags & KERNEL_PROC_MAP_EXEC) ? 'x' : '-';
    permissions[3] = (mapping->flags & KERNEL_PROC_MAP_SHARED) ? 's' : 'p';
    permissions[4] = 0;

    if (maps_append_hex(buffer, capacity, length, mapping->start, 16u) < 0 ||
        maps_append(buffer, capacity, length, "-") < 0 ||
        maps_append_hex(buffer, capacity, length, mapping->end, 16u) < 0 ||
        maps_append(buffer, capacity, length, " ") < 0 ||
        maps_append(buffer, capacity, length, permissions) < 0 ||
        maps_append(buffer, capacity, length, " ") < 0 ||
        maps_append_hex(buffer, capacity, length,
                        mapping->file_offset,
                        maps_hex_width(mapping->file_offset, 8u)) < 0 ||
        maps_append(buffer, capacity, length, " ") < 0 ||
        maps_append_hex(buffer, capacity, length,
                        mapping->device_major,
                        maps_hex_width(mapping->device_major, 2u)) < 0 ||
        maps_append(buffer, capacity, length, ":") < 0 ||
        maps_append_hex(buffer, capacity, length,
                        mapping->device_minor,
                        maps_hex_width(mapping->device_minor, 2u)) < 0 ||
        maps_append(buffer, capacity, length, " ") < 0 ||
        maps_append_u64(buffer, capacity, length, mapping->inode) < 0)
        return -1;
    if (mapping->path[0] &&
        (maps_append(buffer, capacity, length, " ") < 0 ||
         maps_append(buffer, capacity, length, mapping->path) < 0))
        return -1;
    return maps_append(buffer, capacity, length, "\n");
}

typedef struct proc_smaps_totals {
    uint64_t size_bytes;
    uint64_t resident_bytes;
    uint64_t proportional_bytes;
    uint64_t shared_bytes;
    uint64_t private_bytes;
    uint64_t anonymous_bytes;
    uint64_t locked_bytes;
    uint64_t swapped_bytes;
    uint64_t swapped_proportional_bytes;
} proc_smaps_totals_t;

typedef struct proc_smaps_metrics {
    uint64_t size_bytes;
    uint64_t resident_bytes;
    uint64_t proportional_bytes;
    uint64_t shared_bytes;
    uint64_t private_bytes;
    uint64_t anonymous_bytes;
    uint64_t locked_bytes;
    uint64_t swapped_bytes;
    uint64_t swapped_proportional_bytes;
} proc_smaps_metrics_t;

typedef struct proc_smaps_output {
    uint8_t *buffer;
    uint64_t offset;
    uint64_t position;
    uint32_t capacity;
    uint32_t copied;
} proc_smaps_output_t;

static void smaps_output_text(proc_smaps_output_t *output, const char *text) {
    if (!output || !text) return;
    while (*text) {
        if (output->position >= output->offset &&
            output->copied < output->capacity)
            output->buffer[output->copied++] = (uint8_t)*text;
        ++output->position;
        ++text;
    }
}

static void smaps_output_u64(proc_smaps_output_t *output, uint64_t value) {
    char reversed[24];
    uint32_t count = 0;

    if (!value) reversed[count++] = '0';
    while (value && count < sizeof(reversed)) {
        reversed[count++] = (char)('0' + value % 10u);
        value /= 10u;
    }
    while (count) {
        char byte[2] = {reversed[--count], 0};
        smaps_output_text(output, byte);
    }
}

static void smaps_output_hex(proc_smaps_output_t *output, uint64_t value,
                             uint32_t width) {
    static const char digits[] = "0123456789abcdef";
    char encoded[17];

    if (width > 16u) width = 16u;
    encoded[width] = 0;
    for (uint32_t index = 0; index < width; ++index) {
        encoded[width - index - 1u] = digits[value & 0xfu];
        value >>= 4u;
    }
    smaps_output_text(output, encoded);
}

static void smaps_output_kb(proc_smaps_output_t *output, const char *label,
                            uint64_t bytes) {
    smaps_output_text(output, label);
    smaps_output_u64(output, bytes / 1024u);
    smaps_output_text(output, " kB\n");
}

static void smaps_output_mapping(proc_smaps_output_t *output,
                                 const kernel_proc_vma_snapshot_t *mapping) {
    char permissions[5];

    permissions[0] = (mapping->flags & KERNEL_PROC_MAP_READ) ? 'r' : '-';
    permissions[1] = (mapping->flags & KERNEL_PROC_MAP_WRITE) ? 'w' : '-';
    permissions[2] = (mapping->flags & KERNEL_PROC_MAP_EXEC) ? 'x' : '-';
    permissions[3] = (mapping->flags & KERNEL_PROC_MAP_SHARED) ? 's' : 'p';
    permissions[4] = 0;
    smaps_output_hex(output, mapping->start, 16u);
    smaps_output_text(output, "-");
    smaps_output_hex(output, mapping->end, 16u);
    smaps_output_text(output, " ");
    smaps_output_text(output, permissions);
    smaps_output_text(output, " ");
    smaps_output_hex(output, mapping->file_offset,
                     maps_hex_width(mapping->file_offset, 8u));
    smaps_output_text(output, " ");
    smaps_output_hex(output, mapping->device_major,
                     maps_hex_width(mapping->device_major, 2u));
    smaps_output_text(output, ":");
    smaps_output_hex(output, mapping->device_minor,
                     maps_hex_width(mapping->device_minor, 2u));
    smaps_output_text(output, " ");
    smaps_output_u64(output, mapping->inode);
    if (mapping->path[0]) {
        smaps_output_text(output, " ");
        smaps_output_text(output, mapping->path);
    }
    smaps_output_text(output, "\n");
}

static int smaps_measure_record(
    int32_t pid, const kernel_proc_vma_snapshot_t *mapping,
    proc_smaps_metrics_t *metrics) {
    kernel_proc_vma_residency_t residency;

    if (!mapping || !metrics || mapping->end <= mapping->start ||
        arch_proc_vma_residency(
            pid, mapping->start, mapping->end, &residency) < 0)
        return -1;
    metrics->size_bytes = mapping->end - mapping->start;
    metrics->resident_bytes = residency.resident_pages * UINT64_C(4096);
    metrics->proportional_bytes = residency.proportional_resident_bytes;
    metrics->swapped_bytes = residency.swapped_pages * UINT64_C(4096);
    metrics->swapped_proportional_bytes =
        residency.proportional_swapped_bytes;
    metrics->shared_bytes =
        residency.shared_resident_pages * UINT64_C(4096);
    metrics->private_bytes = metrics->resident_bytes >= metrics->shared_bytes ?
        metrics->resident_bytes - metrics->shared_bytes : 0u;
    metrics->anonymous_bytes = mapping->inode == 0u ?
                               metrics->resident_bytes : 0u;
    metrics->locked_bytes =
        residency.locked_resident_pages * UINT64_C(4096);
    return 0;
}

static void smaps_accumulate(proc_smaps_totals_t *totals,
                             const proc_smaps_metrics_t *metrics) {
    if (totals && metrics) {
        totals->size_bytes = maps_saturating_add(
            totals->size_bytes, metrics->size_bytes);
        totals->resident_bytes = maps_saturating_add(
            totals->resident_bytes, metrics->resident_bytes);
        totals->proportional_bytes = maps_saturating_add(
            totals->proportional_bytes, metrics->proportional_bytes);
        totals->shared_bytes = maps_saturating_add(
            totals->shared_bytes, metrics->shared_bytes);
        totals->private_bytes = maps_saturating_add(
            totals->private_bytes, metrics->private_bytes);
        totals->anonymous_bytes = maps_saturating_add(
            totals->anonymous_bytes, metrics->anonymous_bytes);
        totals->locked_bytes = maps_saturating_add(
            totals->locked_bytes, metrics->locked_bytes);
        totals->swapped_bytes = maps_saturating_add(
            totals->swapped_bytes, metrics->swapped_bytes);
        totals->swapped_proportional_bytes = maps_saturating_add(
            totals->swapped_proportional_bytes,
            metrics->swapped_proportional_bytes);
    }
}

static void smaps_output_record(
    proc_smaps_output_t *output,
    const kernel_proc_vma_snapshot_t *mapping,
    const proc_smaps_metrics_t *metrics) {
    smaps_output_mapping(output, mapping);
    smaps_output_kb(output, "Size:           ", metrics->size_bytes);
    smaps_output_kb(output, "KernelPageSize: ", 4096u);
    smaps_output_kb(output, "MMUPageSize:    ", 4096u);
    smaps_output_kb(output, "Rss:            ", metrics->resident_bytes);
    smaps_output_kb(output, "Pss:            ", metrics->proportional_bytes);
    smaps_output_kb(output, "Shared_Clean:   ", metrics->shared_bytes);
    smaps_output_kb(output, "Shared_Dirty:   ", 0u);
    smaps_output_kb(output, "Private_Clean:  ", metrics->private_bytes);
    smaps_output_kb(output, "Private_Dirty:  ", 0u);
    smaps_output_kb(output, "Referenced:     ", metrics->resident_bytes);
    smaps_output_kb(output, "Anonymous:      ", metrics->anonymous_bytes);
    smaps_output_kb(output, "KSM:            ", 0u);
    smaps_output_kb(output, "LazyFree:       ", 0u);
    smaps_output_kb(output, "AnonHugePages:  ", 0u);
    smaps_output_kb(output, "ShmemPmdMapped: ", 0u);
    smaps_output_kb(output, "FilePmdMapped:  ", 0u);
    smaps_output_kb(output, "Shared_Hugetlb: ", 0u);
    smaps_output_kb(output, "Private_Hugetlb: ", 0u);
    smaps_output_kb(output, "Swap:           ", metrics->swapped_bytes);
    smaps_output_kb(output, "SwapPss:        ",
                    metrics->swapped_proportional_bytes);
    smaps_output_kb(output, "Locked:         ", metrics->locked_bytes);
    smaps_output_text(output, "THPeligible:    0\nVmFlags:");
    if (mapping->flags & KERNEL_PROC_MAP_READ)
        smaps_output_text(output, " rd");
    if (mapping->flags & KERNEL_PROC_MAP_WRITE)
        smaps_output_text(output, " wr");
    if (mapping->flags & KERNEL_PROC_MAP_EXEC)
        smaps_output_text(output, " ex");
    if (metrics->locked_bytes)
        smaps_output_text(output, " lo");
    if (mapping->flags & KERNEL_PROC_MAP_SEALED)
        smaps_output_text(output, " sl");
    smaps_output_text(output,
                      (mapping->flags & KERNEL_PROC_MAP_SHARED) ?
                      " sh\n" : " mr\n");
}

int kernel_proc_vma_next(int32_t pid,
                         const kernel_proc_vma_cursor_t *after,
                         kernel_proc_vma_snapshot_t *snapshot) {
    int result;

    if (pid <= 0 || !snapshot) return -1;
    memset(snapshot, 0, sizeof(*snapshot));
    result = arch_proc_vma_next(pid, after, snapshot);
    if (result <= 0) return result;
    snapshot->path[sizeof(snapshot->path) - 1u] = 0;
    if (snapshot->end <= snapshot->start ||
        (after && after->valid &&
         (snapshot->start < after->start ||
          (snapshot->start == after->start &&
           snapshot->order <= after->order))))
        return -1;
    return 1;
}

int kernel_proc_maps_render(int32_t pid, char *buffer, uint32_t capacity) {
    kernel_proc_vma_cursor_t cursor = {0, 0, 0};
    kernel_proc_vma_snapshot_t mapping;
    uint32_t length = 0;
    uint32_t records = 0;

    if (pid <= 0 || !buffer || capacity < 2u) return -1;
    buffer[0] = 0;
    for (;;) {
        int result = kernel_proc_vma_next(pid, &cursor, &mapping);
        if (result < 0) return -1;
        if (!result) break;
        if (maps_append_record(buffer, capacity, &length, &mapping) < 0)
            return -1;
        cursor.start = mapping.start;
        cursor.order = mapping.order;
        cursor.valid = 1;
        if (++records > 65536u) return -1;
    }
    return (int)length;
}

int kernel_proc_maps_read(int32_t pid, uint64_t offset, void *buffer,
                          uint32_t length) {
    kernel_proc_vma_cursor_t cursor = {0, 0, 0};
    kernel_proc_vma_snapshot_t mapping;
    char record[KERNEL_PROC_MAP_PATH_MAX + 128u];
    uint64_t position = 0;
    uint32_t copied = 0;
    uint32_t records = 0;

    if (pid <= 0 || (!buffer && length)) return -1;
    while (copied < length) {
        uint32_t record_length = 0;
        int result = kernel_proc_vma_next(pid, &cursor, &mapping);
        if (result < 0) return -1;
        if (!result) break;
        if (maps_append_record(record, sizeof(record), &record_length,
                               &mapping) < 0)
            return -1;
        if (offset < position + record_length) {
            uint32_t begin = offset > position ?
                             (uint32_t)(offset - position) : 0u;
            uint32_t count = record_length - begin;
            if (count > length - copied) count = length - copied;
            memcpy((uint8_t *)buffer + copied, record + begin, count);
            copied += count;
            offset += count;
        }
        position += record_length;
        cursor.start = mapping.start;
        cursor.order = mapping.order;
        cursor.valid = 1;
        if (++records > 65536u) return -1;
    }
    return (int)copied;
}

int kernel_proc_smaps_read(int32_t pid, uint64_t offset, void *buffer,
                           uint32_t length) {
    kernel_proc_vma_cursor_t cursor = {0, 0, 0};
    kernel_proc_vma_snapshot_t mapping;
    proc_smaps_metrics_t metrics;
    proc_smaps_output_t output;
    uint32_t records = 0;

    if (pid <= 0 || (!buffer && length)) return -1;
    memset(&output, 0, sizeof(output));
    output.buffer = (uint8_t *)buffer;
    output.offset = offset;
    output.capacity = length;
    while (output.copied < length) {
        int result = kernel_proc_vma_next(pid, &cursor, &mapping);
        if (result < 0) return -1;
        if (!result) break;
        if (smaps_measure_record(pid, &mapping, &metrics) < 0)
            return -1;
        smaps_output_record(&output, &mapping, &metrics);
        cursor.start = mapping.start;
        cursor.order = mapping.order;
        cursor.valid = 1;
        if (++records > 65536u) return -1;
    }
    return (int)output.copied;
}

int kernel_proc_smaps_rollup_read(int32_t pid, uint64_t offset, void *buffer,
                                  uint32_t length) {
    kernel_proc_vma_cursor_t cursor = {0, 0, 0};
    kernel_proc_vma_snapshot_t mapping;
    kernel_proc_vma_snapshot_t rollup;
    proc_smaps_metrics_t metrics;
    proc_smaps_output_t output;
    proc_smaps_totals_t totals;
    uint32_t records = 0;
    uint64_t first = UINT64_MAX;
    uint64_t last = 0;

    if (pid <= 0 || (!buffer && length)) return -1;
    memset(&totals, 0, sizeof(totals));
    for (;;) {
        int result = kernel_proc_vma_next(pid, &cursor, &mapping);
        if (result < 0) return -1;
        if (!result) break;
        if (smaps_measure_record(pid, &mapping, &metrics) < 0)
            return -1;
        smaps_accumulate(&totals, &metrics);
        if (mapping.start < first) first = mapping.start;
        if (mapping.end > last) last = mapping.end;
        cursor.start = mapping.start;
        cursor.order = mapping.order;
        cursor.valid = 1;
        if (++records > 65536u) return -1;
    }
    if (!records) return 0;
    memset(&rollup, 0, sizeof(rollup));
    rollup.start = first;
    rollup.end = last;
    rollup.order = 1u;
    strcpy(rollup.path, "[rollup]");
    memset(&output, 0, sizeof(output));
    output.buffer = (uint8_t *)buffer;
    output.offset = offset;
    output.capacity = length;
    smaps_output_mapping(&output, &rollup);
    smaps_output_kb(&output, "Rss:            ", totals.resident_bytes);
    smaps_output_kb(&output, "Pss:            ", totals.proportional_bytes);
    smaps_output_kb(&output, "Shared_Clean:   ", totals.shared_bytes);
    smaps_output_kb(&output, "Shared_Dirty:   ", 0u);
    smaps_output_kb(&output, "Private_Clean:  ", totals.private_bytes);
    smaps_output_kb(&output, "Private_Dirty:  ", 0u);
    smaps_output_kb(&output, "Referenced:     ", totals.resident_bytes);
    smaps_output_kb(&output, "Anonymous:      ", totals.anonymous_bytes);
    smaps_output_kb(&output, "Swap:           ", totals.swapped_bytes);
    smaps_output_kb(&output, "SwapPss:        ",
                    totals.swapped_proportional_bytes);
    smaps_output_kb(&output, "Locked:         ", totals.locked_bytes);
    return (int)output.copied;
}

static int proc_maps_snapshot_generate(int32_t pid, uint32_t view,
                                       char **data_out,
                                       uint32_t *length_out,
                                       uint32_t *pages_out) {
    uint32_t pages = PROC_MAPS_SNAPSHOT_INITIAL_PAGES;

    if (!data_out || !length_out || !pages_out) return -1;
    while (pages <= PROC_MAPS_SNAPSHOT_MAX_PAGES) {
        uint32_t capacity = pages * PROC_MAPS_SNAPSHOT_PAGE_SIZE;
        char *data = (char *)arch_vm_alloc_pages(pages);
        int result = -1;

        if (!data) return -1;
        if (view == KERNEL_PROC_MAPS_VIEW_MAPS)
            result = kernel_proc_maps_render(pid, data, capacity);
        else if (view == KERNEL_PROC_MAPS_VIEW_SMAPS)
            result = kernel_proc_smaps_read(pid, 0, data, capacity);
        else if (view == KERNEL_PROC_MAPS_VIEW_SMAPS_ROLLUP)
            result = kernel_proc_smaps_rollup_read(pid, 0, data, capacity);
        else {
            proc_maps_snapshot_free(data, pages);
            return -1;
        }
        if (result >= 0 && (uint32_t)result < capacity) {
            *data_out = data;
            *length_out = (uint32_t)result;
            *pages_out = pages;
            return 0;
        }
        proc_maps_snapshot_free(data, pages);
        if (pages > PROC_MAPS_SNAPSHOT_MAX_PAGES / 2u) break;
        pages *= 2u;
    }
    return -1;
}

static int proc_maps_snapshot_copy_locked(
        const proc_maps_snapshot_t *snapshot, uint64_t offset,
        void *buffer, uint32_t length) {
    uint32_t copied;

    if (!snapshot || !snapshot->data || (!buffer && length)) return -1;
    if (offset >= snapshot->length || !length) return 0;
    copied = snapshot->length - (uint32_t)offset;
    if (copied > length) copied = length;
    memcpy(buffer, snapshot->data + offset, copied);
    return (int)copied;
}

int kernel_proc_maps_read_description(uint64_t description_identity,
                                      int32_t pid, uint32_t view,
                                      uint64_t offset, void *buffer,
                                      uint32_t length) {
    proc_maps_snapshot_t *snapshot = 0;
    char *generated = 0;
    uint32_t generated_length = 0;
    uint32_t generated_pages = 0;
    uint32_t index;
    int result;

    if (pid <= 0 || (!buffer && length)) return -1;
    if (!description_identity) {
        if (view == KERNEL_PROC_MAPS_VIEW_MAPS)
            return kernel_proc_maps_read(pid, offset, buffer, length);
        if (view == KERNEL_PROC_MAPS_VIEW_SMAPS)
            return kernel_proc_smaps_read(pid, offset, buffer, length);
        if (view == KERNEL_PROC_MAPS_VIEW_SMAPS_ROLLUP)
            return kernel_proc_smaps_rollup_read(pid, offset, buffer, length);
        return -1;
    }

    proc_maps_snapshot_lock();
    for (index = 0; index < PROC_MAPS_SNAPSHOT_SLOTS; ++index) {
        proc_maps_snapshot_t *candidate = &g_proc_maps_snapshots[index];
        if (!candidate->active ||
            candidate->description_identity != description_identity)
            continue;
        if (candidate->pid != pid || candidate->view != view) {
            proc_maps_snapshot_unlock();
            return -1;
        }
        snapshot = candidate;
        if (snapshot->data) {
            result = proc_maps_snapshot_copy_locked(
                snapshot, offset, buffer, length);
            proc_maps_snapshot_unlock();
            return result;
        }
        break;
    }
    if (!snapshot) {
        for (index = 0; index < PROC_MAPS_SNAPSHOT_SLOTS; ++index) {
            if (g_proc_maps_snapshots[index].active) continue;
            snapshot = &g_proc_maps_snapshots[index];
            memset(snapshot, 0, sizeof(*snapshot));
            snapshot->description_identity = description_identity;
            snapshot->pid = pid;
            snapshot->view = view;
            snapshot->active = 1u;
            break;
        }
    }
    proc_maps_snapshot_unlock();
    if (!snapshot) return -1;

    if (proc_maps_snapshot_generate(
            pid, view, &generated, &generated_length,
            &generated_pages) < 0) {
        proc_maps_snapshot_lock();
        if (snapshot->active &&
            snapshot->description_identity == description_identity &&
            !snapshot->data)
            memset(snapshot, 0, sizeof(*snapshot));
        proc_maps_snapshot_unlock();
        return -1;
    }

    proc_maps_snapshot_lock();
    if (!snapshot->active ||
        snapshot->description_identity != description_identity ||
        snapshot->pid != pid || snapshot->view != view) {
        proc_maps_snapshot_unlock();
        proc_maps_snapshot_free(generated, generated_pages);
        return -1;
    }
    if (!snapshot->data) {
        snapshot->data = generated;
        snapshot->length = generated_length;
        snapshot->pages = generated_pages;
        generated = 0;
        generated_pages = 0;
    }
    result = proc_maps_snapshot_copy_locked(
        snapshot, offset, buffer, length);
    proc_maps_snapshot_unlock();
    proc_maps_snapshot_free(generated, generated_pages);
    return result;
}

void kernel_proc_maps_description_release(uint64_t description_identity) {
    char *data = 0;
    uint32_t pages = 0;
    uint32_t index;

    if (!description_identity) return;
    proc_maps_snapshot_lock();
    for (index = 0; index < PROC_MAPS_SNAPSHOT_SLOTS; ++index) {
        proc_maps_snapshot_t *snapshot = &g_proc_maps_snapshots[index];
        if (!snapshot->active ||
            snapshot->description_identity != description_identity)
            continue;
        data = snapshot->data;
        pages = snapshot->pages;
        memset(snapshot, 0, sizeof(*snapshot));
        break;
    }
    proc_maps_snapshot_unlock();
    proc_maps_snapshot_free(data, pages);
}
