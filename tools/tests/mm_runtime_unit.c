/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent memory policy unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/mm_runtime.h"
#include "kernel/vfs_runtime.h"

static int g_failures;
static uint64_t g_last_address;
static uint64_t g_last_length;
static uint64_t g_last_protection;
static uint32_t g_last_flags;
static uint32_t g_last_map_flags;
static uint32_t g_last_page_count;
static int32_t g_last_pid;
static void *g_last_buffer;
static kernel_mm_process_vm_operation_t g_last_process_vm_operation;
static kernel_madvise_operation_t g_last_madvise_operation;
static int g_last_madvise_validate_only;
static int g_sealed_discard_allowed = 1;
static int g_range_mapped_result;
static uint64_t g_current_address_space;
static int g_process_mrelease_result;
static uint32_t g_descriptor_attributes;
static int g_lock_result = 19;
static kernel_mm_program_break_state_t g_break_state = {
    .base = 0x1000u,
    .current = 0x1800u,
    .maximum = 0x8000u,
};
static int g_break_resize_result;
static uint32_t g_last_reclaim_cgroup;
static uint32_t g_last_reclaim_pages;
static uint32_t g_noted_reclaim_cgroup;
static uint64_t g_noted_scanned_pages;
static uint64_t g_noted_reclaimed_pages;
static uint64_t g_monotonic_us;
static uint64_t g_noted_pressure_some_us;
static uint64_t g_noted_pressure_full_us;
static uint32_t g_pressure_pages;
static uint32_t g_pressure_cgroup;
static uint32_t g_max_excess_pages;
static uint32_t g_max_cgroup;
static uint8_t g_vm_pages[4][KERNEL_MM_USER_PAGE_SIZE]
    __attribute__((aligned(KERNEL_MM_USER_PAGE_SIZE)));
static uint8_t g_vm_page_used[4];
static uint32_t g_vm_pages_used;
static uint32_t g_vm_page_free_calls;

void *arch_vm_alloc_pages(uint64_t page_count) {
    if (page_count != 1u) return 0;
    for (uint32_t index = 0; index < 4u; ++index) {
        if (g_vm_page_used[index]) continue;
        g_vm_page_used[index] = 1u;
        ++g_vm_pages_used;
        memset(g_vm_pages[index], 0, sizeof(g_vm_pages[index]));
        return g_vm_pages[index];
    }
    return 0;
}

void arch_vm_free_page(void *page) {
    for (uint32_t index = 0; index < 4u; ++index) {
        if (page != g_vm_pages[index] || !g_vm_page_used[index]) continue;
        g_vm_page_used[index] = 0u;
        --g_vm_pages_used;
        ++g_vm_page_free_calls;
        return;
    }
}

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

int arch_mm_query_residency(uint64_t address, uint32_t page_count,
                            uint8_t *vector) {
    g_last_address = address;
    g_last_page_count = page_count;
    if (vector && page_count) vector[0] = 1u;
    return 17;
}

int arch_mm_resolve_user_page(uint64_t address_space, uint64_t address,
                              uint32_t access) {
    g_last_address = address;
    g_last_length = address_space;
    g_last_flags = access;
    return 16;
}

uint32_t arch_mm_reclaim_pages(uint32_t cgroup_id, uint32_t target_pages,
                               uint64_t *scanned_pages_out) {
    uint32_t reclaimed = target_pages / 2u;

    g_last_reclaim_cgroup = cgroup_id;
    g_last_reclaim_pages = target_pages;
    if (scanned_pages_out) *scanned_pages_out = target_pages * 3u;
    if (g_pressure_pages && cgroup_id == g_pressure_cgroup) {
        if (reclaimed > g_pressure_pages) reclaimed = g_pressure_pages;
        g_pressure_pages -= reclaimed;
    }
    return reclaimed;
}

int cgroupfs_memory_pressure(uint32_t cgroup_id, uint64_t *excess_bytes) {
    if (excess_bytes)
        *excess_bytes = cgroup_id == g_pressure_cgroup ?
            (uint64_t)g_pressure_pages * KERNEL_MM_USER_PAGE_SIZE : 0u;
    return cgroup_id == g_pressure_cgroup && g_pressure_pages != 0u;
}

int cgroupfs_memory_prepare_charge(uint32_t cgroup_id, uint64_t bytes,
                                   uint64_t *excess_bytes) {
    (void)bytes;
    if (excess_bytes)
        *excess_bytes = cgroup_id == g_max_cgroup ?
            (uint64_t)g_max_excess_pages * KERNEL_MM_USER_PAGE_SIZE : 0u;
    return cgroup_id == g_max_cgroup && g_max_excess_pages != 0u;
}

void cgroupfs_memory_note_reclaim(uint32_t cgroup_id,
                                  uint64_t scanned_pages,
                                  uint64_t reclaimed_pages) {
    g_noted_reclaim_cgroup = cgroup_id;
    g_noted_scanned_pages = scanned_pages;
    g_noted_reclaimed_pages = reclaimed_pages;
}

uint64_t boottime_monotonic_us(void) {
    g_monotonic_us += 25u;
    return g_monotonic_us;
}

void edge_mm_statistics_note_pressure(uint64_t now_us,
                                      uint64_t some_stall_us,
                                      uint64_t full_stall_us) {
    (void)now_us;
    g_noted_pressure_some_us = some_stall_us;
    g_noted_pressure_full_us = full_stall_us;
}

void cgroupfs_memory_note_pressure(uint32_t cgroup_id, uint64_t now_us,
                                   uint64_t some_stall_us,
                                   uint64_t full_stall_us) {
    (void)cgroup_id;
    (void)now_us;
    g_noted_pressure_some_us = some_stall_us;
    g_noted_pressure_full_us = full_stall_us;
}

int arch_mm_process_madvise(
    int32_t pid, uint64_t address, uint64_t length,
    kernel_madvise_operation_t operation, int validate_only) {
    g_last_pid = pid;
    g_last_madvise_operation = operation;
    g_last_madvise_validate_only = validate_only;
    g_last_address = address;
    g_last_length = length;
    return 18;
}

int arch_mm_sealed_discard_allowed(
    int32_t pid, uint64_t address, uint64_t length) {
    g_last_pid = pid;
    g_last_address = address;
    g_last_length = length;
    return g_sealed_discard_allowed;
}

int arch_mm_process_mrelease(int32_t pid) {
    g_last_pid = pid;
    return g_process_mrelease_result;
}

static void test_process_mrelease_dispatch(void) {
    g_process_mrelease_result = 31;
    expect_true("process mrelease rejects invalid pid",
                kernel_process_mrelease(0) == -EDGE_LINUX_ESRCH);
    expect_true("process mrelease reaches architecture mechanism",
                kernel_process_mrelease(47) == 31 && g_last_pid == 47);
}

static void test_madvise_fork_policy(void) {
    expect_true("wipe-on-fork advice is recognized",
                kernel_mm_madvise_known(18u));
    expect_true("keep-on-fork advice is recognized",
                kernel_mm_madvise_known(19u));
    expect_true("wipe-on-fork reaches architecture policy",
                kernel_process_madvise(
                    41, 0x4000u, 0x2000u, 18u, 0u) == 18 &&
                g_last_pid == 41 && g_last_address == 0x4000u &&
                g_last_length == 0x2000u &&
                g_last_madvise_operation ==
                    KERNEL_MADVISE_SET_WIPE_ON_FORK &&
                !g_last_madvise_validate_only);
    expect_true("keep-on-fork reaches architecture policy",
                kernel_process_madvise(
                    42, 0x8000u, 0x1000u, 19u,
                    KERNEL_PROCESS_MADVISE_VALIDATE_ONLY) == 18 &&
                g_last_pid == 42 &&
                g_last_madvise_operation ==
                    KERNEL_MADVISE_CLEAR_WIPE_ON_FORK &&
                g_last_madvise_validate_only);
    expect_true("fork policy advice stays process local",
                !kernel_mm_madvise_cross_process_allowed(18u) &&
                !kernel_mm_madvise_cross_process_allowed(19u));
}

static void test_madvise_reclaim_policy(void) {
    expect_true("lazy-free advice reaches architecture policy",
                kernel_process_madvise(
                    43, 0xc000u, 0x3000u, 8u, 0u) == 18 &&
                g_last_pid == 43 && g_last_address == 0xc000u &&
                g_last_length == 0x3000u &&
                g_last_madvise_operation ==
                    KERNEL_MADVISE_LAZY_FREE &&
                !g_last_madvise_validate_only);
    expect_true("lazy-free stays process local",
                !kernel_mm_madvise_cross_process_allowed(8u));
    g_sealed_discard_allowed = 0;
    expect_true("sealed read-only range rejects lazy-free advice",
                kernel_process_madvise(
                    43, 0xc000u, 0x3000u, 8u, 0u) ==
                    -EDGE_LINUX_EPERM &&
                g_last_pid == 43 && g_last_address == 0xc000u &&
                g_last_length == 0x3000u);
    g_sealed_discard_allowed = 1;
    expect_true("cold advice reaches architecture policy",
                kernel_process_madvise(
                    44, 0x10000u, 0x4000u, 20u, 0u) == 18 &&
                g_last_pid == 44 && g_last_address == 0x10000u &&
                g_last_length == 0x4000u &&
                g_last_madvise_operation ==
                    KERNEL_MADVISE_DEACTIVATE &&
                !g_last_madvise_validate_only);
    expect_true("pageout advice reaches architecture policy",
                kernel_process_madvise(
                    45, 0x14000u, 0x5000u, 21u, 0u) == 18 &&
                g_last_pid == 45 && g_last_address == 0x14000u &&
                g_last_length == 0x5000u &&
                g_last_madvise_operation ==
                    KERNEL_MADVISE_PAGEOUT &&
                !g_last_madvise_validate_only);
}

int arch_mm_process_vm_copy(
        int32_t pid, uint64_t address, void *buffer, uint64_t size,
        kernel_mm_process_vm_operation_t operation) {
    g_last_pid = pid;
    g_last_address = address;
    g_last_buffer = buffer;
    g_last_length = size;
    g_last_process_vm_operation = operation;
    return 25;
}

int arch_mm_lock_range(uint64_t address, uint64_t length, uint32_t flags) {
    g_last_address = address;
    g_last_length = length;
    g_last_flags = flags;
    return g_lock_result;
}

int kernel_vfs_describe_descriptor(
        int32_t descriptor, kernel_vfs_descriptor_t *description) {
    if (descriptor < 0 || !description) return -EDGE_LINUX_EBADF;
    memset(description, 0, sizeof(*description));
    description->kind = KERNEL_VFS_DESCRIPTOR_MEMORY;
    description->attributes = g_descriptor_attributes;
    return 0;
}

int arch_mm_unlock_range(uint64_t address, uint64_t length) {
    g_last_address = address;
    g_last_length = length;
    return 26;
}

int arch_mm_lock_all(uint32_t flags) {
    g_last_flags = flags;
    return 27;
}

int arch_mm_unlock_all(void) {
    return 28;
}

uint64_t arch_mm_current_address_space(void) {
    return g_current_address_space;
}

int arch_mm_range_mapped(uint64_t address, uint64_t length) {
    g_last_address = address;
    g_last_length = length;
    return g_range_mapped_result;
}

int arch_mm_sync_range(uint64_t address, uint64_t length, uint32_t flags) {
    g_last_address = address;
    g_last_length = length;
    g_last_flags = flags;
    return 20;
}

int64_t arch_mm_protect_range(uint64_t address, uint64_t length,
                              uint64_t protection) {
    g_last_address = address;
    g_last_length = length;
    g_last_protection = protection;
    return 21;
}

int64_t arch_mm_unmap_range(uint64_t address, uint64_t length) {
    g_last_address = address;
    g_last_length = length;
    return 22;
}

int64_t arch_mm_map(const kernel_mm_map_request_t *request) {
    if (!request) return -1;
    g_last_address = request->address;
    g_last_length = request->length;
    g_last_flags = (uint32_t)request->flags;
    g_last_map_flags = (uint32_t)request->flags;
    return 23;
}

int64_t arch_mm_remap_range(uint64_t old_address, uint64_t old_length,
                            uint64_t new_length, uint32_t flags,
                            uint64_t new_address) {
    (void)old_length;
    g_last_address = old_address;
    g_last_length = new_length;
    g_last_flags = flags;
    g_last_protection = new_address;
    return 24;
}

int arch_mm_file_mapping_info(
        uint64_t address, kernel_mm_file_mapping_info_t *information) {
    (void)address;
    (void)information;
    return -1;
}

int64_t arch_mm_remap_file_pages(
        uint64_t address, uint64_t length, uint64_t file_offset,
        uint32_t flags) {
    (void)address;
    (void)length;
    (void)file_offset;
    (void)flags;
    return -1;
}

int arch_mm_program_break_snapshot(
    kernel_mm_program_break_state_t *state) {
    if (!state) return -1;
    *state = g_break_state;
    return 0;
}

int arch_mm_program_break_resize(uint64_t old_page, uint64_t new_page) {
    g_last_address = old_page;
    g_last_length = new_page;
    return g_break_resize_result;
}

void arch_mm_program_break_commit(uint64_t address) {
    g_break_state.current = address;
}

static void test_residency_and_lock_policy(void) {
    uint8_t vector[2] = {0};

    expect_true("resolve user page backend",
                kernel_mm_resolve_user_page(0x4000u, 0x7000u,
                    KERNEL_MM_PROT_WRITE) == 16 &&
                g_last_length == 0x4000u &&
                g_last_address == 0x7000u &&
                g_last_flags == KERNEL_MM_PROT_WRITE);
    expect_true("residency null vector",
                kernel_mm_query_residency(0x1000u, 1u, 0) ==
                    -EDGE_LINUX_EFAULT);
    expect_true("residency zero pages",
                kernel_mm_query_residency(0x1000u, 0u, 0) == 0);
    expect_true("residency backend",
                kernel_mm_query_residency(0x2000u, 2u, vector) == 17 &&
                g_last_address == 0x2000u && g_last_page_count == 2u &&
                vector[0] == 1u);

    expect_true("lock invalid flags",
                kernel_mm_lock_range(0x1000u, 0x1000u, 2u) ==
                    -EDGE_LINUX_EINVAL);
    expect_true("lock zero length",
                kernel_mm_lock_range(0x1000u, 0u, 0u) == 0);
    expect_true("lock backend",
                kernel_mm_lock_range(
                    0x3000u, 0x2000u, KERNEL_MM_LOCK_RANGE_ONFAULT) == 19 &&
                g_last_address == 0x3000u && g_last_length == 0x2000u &&
                g_last_flags == KERNEL_MM_LOCK_RANGE_ONFAULT);
    expect_true("lock all invalid flags",
                kernel_mm_lock_all(8u) == -EDGE_LINUX_EINVAL);
    expect_true("lock all resident mappings",
                kernel_mm_lock_all(
                    KERNEL_MM_LOCK_ALL_CURRENT |
                    KERNEL_MM_LOCK_ALL_FUTURE) == 27 &&
                g_last_flags == (KERNEL_MM_LOCK_ALL_CURRENT |
                                 KERNEL_MM_LOCK_ALL_FUTURE));
    expect_true("unlock all resident mappings",
                kernel_mm_unlock_all() == 28);
}

static void test_process_vm_dispatch(void) {
    uint8_t buffer[16] = {0};

    expect_true("process vm read backend",
                kernel_process_vm_read_memory(
                    41, 0x1234u, buffer, sizeof(buffer)) == 25 &&
                g_last_pid == 41 && g_last_address == 0x1234u &&
                g_last_buffer == buffer &&
                g_last_length == sizeof(buffer) &&
                g_last_process_vm_operation ==
                    KERNEL_MM_PROCESS_VM_READ);
    expect_true("process vm write backend",
                kernel_process_vm_write_memory(
                    42, 0x5678u, buffer, 7u) == 25 &&
                g_last_pid == 42 && g_last_address == 0x5678u &&
                g_last_buffer == buffer && g_last_length == 7u &&
                g_last_process_vm_operation ==
                    KERNEL_MM_PROCESS_VM_WRITE);
}

static void test_sync_and_protect_policy(void) {
    expect_true("sync invalid flags",
                kernel_mm_sync_range(0x1000u, 0x1000u, 8u) ==
                    -EDGE_LINUX_EINVAL);
    expect_true("sync zero length",
                kernel_mm_sync_range(0x1000u, 0u, 0u) == 0);
    expect_true("sync backend",
                kernel_mm_sync_range(
                    0x4000u, 0x3000u, KERNEL_MM_SYNC_SYNC) == 20 &&
                g_last_address == 0x4000u && g_last_length == 0x3000u &&
                g_last_flags == KERNEL_MM_SYNC_SYNC);

    expect_true("protect unaligned",
                kernel_mm_protect_range(
                    0x4001u, 0x1000u, KERNEL_MM_PROT_READ) ==
                    -EDGE_LINUX_EINVAL);
    expect_true("protect invalid growth",
                kernel_mm_protect_range(
                    0x4000u, 0x1000u,
                    KERNEL_MM_PROT_READ | KERNEL_MM_PROT_GROWSDOWN) ==
                    -EDGE_LINUX_EINVAL);
    expect_true("protect rounds length",
                kernel_mm_protect_range(
                    0x4000u, 1u,
                    KERNEL_MM_PROT_READ | KERNEL_MM_PROT_WRITE) == 21 &&
                g_last_address == 0x4000u && g_last_length == 0x1000u &&
                g_last_protection ==
                    (KERNEL_MM_PROT_READ | KERNEL_MM_PROT_WRITE));
}

static void test_unmap_policy(void) {
    expect_true("unmap unaligned",
                kernel_mm_unmap_range(0x1001u, 0x1000u) ==
                    -EDGE_LINUX_EINVAL);
    expect_true("unmap zero length",
                kernel_mm_unmap_range(0x1000u, 0u) ==
                    -EDGE_LINUX_EINVAL);
    expect_true("unmap length overflow",
                kernel_mm_unmap_range(0x1000u, UINT64_MAX) ==
                    -EDGE_LINUX_EINVAL);
    expect_true("unmap address overflow is successful",
                kernel_mm_unmap_range(UINT64_MAX - 0xfffu, 0x1000u) == 0);
    expect_true("unmap rounds length",
                kernel_mm_unmap_range(0x8000u, 1u) == 22 &&
                g_last_address == 0x8000u && g_last_length == 0x1000u);
}

static void test_map_and_remap_policy(void) {
    kernel_mm_map_request_t map = {0};

    expect_true("map null request",
                kernel_mm_map(0) == -EDGE_LINUX_EIO);
    map.length = 1u;
    expect_true("map invalid type",
                kernel_mm_map(&map) == -EDGE_LINUX_EINVAL);
    map.flags = KERNEL_MM_MAP_PRIVATE | KERNEL_MM_MAP_ANONYMOUS;
    map.descriptor = -1;
    expect_true("anonymous map backend",
                kernel_mm_map(&map) == 23 &&
                g_last_length == 1u &&
                g_last_map_flags ==
                    (KERNEL_MM_MAP_PRIVATE | KERNEL_MM_MAP_ANONYMOUS));
    map.flags = KERNEL_MM_MAP_PRIVATE;
    expect_true("file map invalid descriptor",
                kernel_mm_map(&map) == -EDGE_LINUX_EBADF);
    map.descriptor = 3;
    map.offset = 1u;
    expect_true("file map unaligned offset",
                kernel_mm_map(&map) == -EDGE_LINUX_EINVAL);
    map.offset = 0u;
    g_descriptor_attributes = KERNEL_VFS_DESCRIPTOR_SECRET_MEMORY;
    expect_true("secret memory rejects private mapping",
                kernel_mm_map(&map) == -EDGE_LINUX_EINVAL);
    map.flags = KERNEL_MM_MAP_SHARED;
    g_lock_result = 0;
    expect_true("secret memory is shared and locked",
                kernel_mm_map(&map) == 23 &&
                g_last_map_flags ==
                    (KERNEL_MM_MAP_SHARED | KERNEL_MM_MAP_LOCKED |
                     KERNEL_MM_MAP_SECRET));
    g_lock_result = 19;
    g_descriptor_attributes = 0u;

    expect_true("remap invalid high flags",
                kernel_mm_remap_range(
                    0x1000u, 0x1000u, 0x1000u, 1ull << 40, 0u) ==
                    -EDGE_LINUX_EINVAL);
    expect_true("remap fixed requires maymove",
                kernel_mm_remap_range(
                    0x1000u, 0x1000u, 0x1000u,
                    KERNEL_MM_REMAP_FIXED, 0x8000u) ==
                    -EDGE_LINUX_EINVAL);
    expect_true("remap dontunmap unsupported",
                kernel_mm_remap_range(
                    0x1000u, 0x1000u, 0x1000u,
                    KERNEL_MM_REMAP_MAYMOVE |
                    KERNEL_MM_REMAP_DONTUNMAP, 0u) ==
                    -EDGE_LINUX_EINVAL);
    expect_true("remap rounds lengths",
                kernel_mm_remap_range(
                    0x1000u, 1u, 0x1001u,
                    KERNEL_MM_REMAP_MAYMOVE, 0u) == 24 &&
                g_last_address == 0x1000u &&
                g_last_length == 0x2000u &&
                g_last_flags == KERNEL_MM_REMAP_MAYMOVE);
}

static void test_program_break_policy(void) {
    g_break_state.current = 0x1800u;
    g_break_resize_result = 0;
    expect_true("program break query",
                kernel_mm_program_break(0u) == 0x1800);
    expect_true("program break below base",
                kernel_mm_program_break(0x800u) == 0x1800);
    expect_true("program break above maximum",
                kernel_mm_program_break(0x9000u) == 0x1800);
    expect_true("program break grow",
                kernel_mm_program_break(0x2800u) == 0x2800 &&
                g_last_address == 0x2000u &&
                g_last_length == 0x3000u &&
                g_break_state.current == 0x2800u);
    g_break_resize_result = -1;
    expect_true("program break failed resize preserves state",
                kernel_mm_program_break(0x3800u) == 0x2800 &&
                g_break_state.current == 0x2800u);
}

static void test_reclaim_candidate_policy(void) {
    kernel_mm_reclaim_candidate_t selection[3] = {0};
    kernel_mm_reclaim_candidate_t candidate = {0};
    uint32_t selected = 0;

    candidate.used = 1;
    candidate.slot = 4;
    candidate.last_used_sequence = 40;
    selected = kernel_mm_reclaim_candidate_offer(
        selection, selected, 3, &candidate);
    candidate.slot = 2;
    candidate.last_used_sequence = 20;
    selected = kernel_mm_reclaim_candidate_offer(
        selection, selected, 3, &candidate);
    candidate.slot = 3;
    candidate.last_used_sequence = 30;
    selected = kernel_mm_reclaim_candidate_offer(
        selection, selected, 3, &candidate);
    candidate.slot = 1;
    candidate.last_used_sequence = 10;
    selected = kernel_mm_reclaim_candidate_offer(
        selection, selected, 3, &candidate);
    expect_true("reclaim keeps oldest bounded candidates",
                selected == 3 &&
                selection[0].slot == 1 &&
                selection[1].slot == 2 &&
                selection[2].slot == 3);

    candidate.slot = 0;
    candidate.last_used_sequence = 0;
    candidate.references = 1;
    expect_true("reclaim excludes referenced candidate",
                kernel_mm_reclaim_candidate_offer(
                    selection, selected, 3, &candidate) == selected &&
                selection[0].slot == 1);
    candidate.references = 0;
    candidate.busy = 1;
    expect_true("reclaim excludes busy candidate",
                kernel_mm_reclaim_candidate_offer(
                    selection, selected, 3, &candidate) == selected &&
                selection[0].slot == 1);
    candidate.busy = 0;
    candidate.pinned = 1;
    expect_true("reclaim excludes pinned candidate",
                kernel_mm_reclaim_candidate_offer(
                    selection, selected, 3, &candidate) == selected &&
                selection[0].slot == 1);

    memset(selection, 0, sizeof(selection));
    selected = 0;
    memset(&candidate, 0, sizeof(candidate));
    candidate.used = 1;
    candidate.active = 1;
    candidate.slot = 70000u;
    candidate.last_used_sequence = 1u;
    selected = kernel_mm_reclaim_candidate_offer(
        selection, selected, 3, &candidate);
    candidate.active = 0;
    candidate.slot = 80000u;
    candidate.last_used_sequence = 100u;
    selected = kernel_mm_reclaim_candidate_offer(
        selection, selected, 3, &candidate);
    expect_true("reclaim prefers inactive cache pages",
                selected == 2u && selection[0].slot == 80000u &&
                selection[1].slot == 70000u);
}

static void test_reclaim_dispatch(void) {
    expect_true("reclaim zero skips backend",
                kernel_mm_reclaim_pages(7u, 0u) == 0u);
    expect_true("reclaim dispatches cgroup and target",
                kernel_mm_reclaim_pages(9u, 10u) == 5u &&
                g_last_reclaim_cgroup == 9u &&
                g_last_reclaim_pages == 10u &&
                g_noted_reclaim_cgroup == 9u &&
                g_noted_scanned_pages == 30u &&
                g_noted_reclaimed_pages == 5u &&
                g_noted_pressure_some_us == 25u &&
                g_noted_pressure_full_us == 0u);
    expect_true("reclaim bounds synchronous batch",
                kernel_mm_reclaim_pages(11u, 1000u) == 32u &&
                g_last_reclaim_cgroup == 11u &&
                g_last_reclaim_pages == 64u &&
                g_noted_reclaim_cgroup == 11u &&
                g_noted_scanned_pages == 192u &&
                g_noted_reclaimed_pages == 32u);

    g_pressure_cgroup = 17u;
    g_pressure_pages = 8u;
    expect_true("memory.high pressure gets bounded repeated reclaim",
                kernel_mm_reclaim_cgroup_pressure(17u) == 7u &&
                g_pressure_pages == 1u &&
                g_last_reclaim_cgroup == 17u);
    g_pressure_cgroup = 0u;
    g_pressure_pages = 0u;

    g_max_cgroup = 23u;
    g_max_excess_pages = 8u;
    expect_true("memory.max pressure reclaims before final charge",
                kernel_mm_prepare_cgroup_charge(
                    23u, KERNEL_MM_USER_PAGE_SIZE) == 4u &&
                g_last_reclaim_cgroup == 23u &&
                g_last_reclaim_pages == 8u);
    g_max_cgroup = 0u;
    g_max_excess_pages = 0u;
}

static void test_cache_state_policy(void) {
    kernel_mm_cache_state_t state;

    kernel_mm_cache_state_insert(&state, 4u);
    expect_true("cache insert begins inactive referenced",
                state.last_used_sequence == 4u &&
                state.access_count == 1u && state.referenced &&
                !state.active);
    kernel_mm_cache_state_access(&state, 8u);
    expect_true("cache second access promotes active",
                state.last_used_sequence == 8u &&
                state.access_count == 2u && state.referenced &&
                state.active);
    kernel_mm_cache_state_age(&state);
    expect_true("cache first aging clears reference",
                !state.referenced && state.active);
    kernel_mm_cache_state_age(&state);
    expect_true("cache second aging demotes active", !state.active);
    kernel_mm_cache_state_access(&state, 12u);
    expect_true("cache access promotes after aging",
                state.referenced && state.active);
    kernel_mm_cache_state_deactivate(&state);
    expect_true("explicit cold hint clears reclaim activity",
                !state.referenced && !state.active &&
                state.last_used_sequence == 12u);
}

static void test_file_cache_shadow_policy(void) {
    uint64_t evicted = 0;
    uint64_t recent = 0;

    kernel_mm_file_cache_note_eviction(0x1000u, 42u, 7u, 0u);
    kernel_mm_file_cache_note_eviction(0x1000u, 42u, 7u, 4096u);
    kernel_mm_file_cache_note_eviction(0x2000u, 42u, 7u, 0u);
    kernel_mm_file_cache_shadow_stat_range(
        0x1000u, 42u, 7u, 0u, 0u, &evicted, &recent);
    expect_true("file shadow reports complete inode eviction range",
                evicted == 2u && recent == 2u);
    kernel_mm_file_cache_shadow_stat_range(
        0x1000u, 42u, 7u, 4096u, 4096u, &evicted, &recent);
    expect_true("file shadow honors byte range",
                evicted == 1u && recent == 1u);
    kernel_mm_file_cache_note_refault(0x1000u, 42u, 7u, 4096u);
    kernel_mm_file_cache_shadow_stat_range(
        0x1000u, 42u, 7u, 0u, 0u, &evicted, &recent);
    expect_true("file shadow refault replaces nonresident entry",
                evicted == 1u && recent == 1u);
}

static void test_file_install_race_policy(void) {
    expect_true("same writable file page accepts a concurrent install",
                kernel_mm_file_install_race_satisfied(
                    41u, 41u, 1, 1, 1, 1, 1, 0));
    expect_true("write-notify file page accepts a read-only resident PTE",
                kernel_mm_file_install_race_satisfied(
                    41u, 41u, 1, 1, 1, 0, 1, 0));
    expect_true("different resident page is not accepted",
                !kernel_mm_file_install_race_satisfied(
                    40u, 41u, 1, 1, 1, 0, 1, 0));
    expect_true("private COW install still requires compatible protection",
                !kernel_mm_file_install_race_satisfied(
                    41u, 41u, 1, 1, 1, 0, 1, 1));
}

static void test_dynamic_vma_storage(void) {
    kernel_vm_area_t initial[2] = {0};
    kernel_vm_area_t *areas = initial;
    uint32_t capacity = 2u;
    uint32_t dynamic_pages = 0u;

    initial[0].start = 0x1000u;
    initial[0].end = 0x2000u;
    initial[1].start = 0x3000u;
    initial[1].end = 0x4000u;
    expect_true("dynamic VMA storage grows",
                kernel_mm_vma_storage_grow(
                    &areas, &capacity, 2u, 3u, &dynamic_pages) == 0 &&
                areas != initial && capacity == 4u &&
                dynamic_pages == 1u && g_vm_pages_used == 1u);
    expect_true("dynamic VMA storage preserves descriptors",
                areas[0].start == 0x1000u && areas[0].end == 0x2000u &&
                areas[1].start == 0x3000u && areas[1].end == 0x4000u &&
                areas[2].start == 0u && areas[2].end == 0u);
    expect_true("dynamic VMA storage enforces map count",
                kernel_mm_vma_storage_grow(
                    &areas, &capacity, 2u, KERNEL_MM_VMA_MAX + 1u,
                    &dynamic_pages) == -EDGE_LINUX_ENOMEM);
    kernel_mm_vma_storage_release(areas, dynamic_pages);
    expect_true("dynamic VMA storage releases pages",
                g_vm_pages_used == 0u && g_vm_page_free_calls == 1u);
}

static void test_locked_range_registry(void) {
    struct {
        kernel_mm_lock_space_t locks[4];
        kernel_mm_seal_space_t seals[4];
    } spaces;
    uint64_t pool_bytes = kernel_mm_lock_space_pool_bytes(4u);

    expect_true("lock registry pool size",
                pool_bytes == sizeof(spaces));
    expect_true("lock registry initializes",
                kernel_mm_lock_space_pool_initialize(
                    &spaces, sizeof(spaces), 4u) == 0);
    expect_true("lock registry rejects zero identity",
                kernel_mm_lock_space_add(0u, 0x1000u, 0x1000u) ==
                    -EDGE_LINUX_EINVAL);
    expect_true("lock registry adds first range",
                kernel_mm_lock_space_add(
                    0x44u, 0x2000u, 0x3000u) == 0 &&
                kernel_mm_lock_space_contains(0x44u, 0x2000u) &&
                kernel_mm_lock_space_contains(0x44u, 0x4fffu) &&
                !kernel_mm_lock_space_contains(0x44u, 0x5000u));
    expect_true("lock registry coalesces adjacent range",
                kernel_mm_lock_space_add(
                    0x44u, 0x5000u, 0x2000u) == 0 &&
                kernel_mm_lock_space_bytes(0x44u) == 0x5000u);
    expect_true("resident peak starts at first observation",
                kernel_mm_resident_peak_observe(0x44u, 0x9000u) ==
                    0x9000u);
    expect_true("resident peak survives a lower observation",
                kernel_mm_resident_peak_observe(0x44u, 0x3000u) ==
                    0x9000u &&
                kernel_mm_resident_peak_bytes(0x44u) == 0x9000u);
    {
        int32_t mode = -1;
        uint32_t flags = UINT32_MAX;
        uint64_t nodes = 0;
        expect_true("memory policy is shared by address space",
                    kernel_mm_mempolicy_set(
                        0x44u, 2, 0x4000u, 1u) == 0 &&
                    kernel_mm_mempolicy_get(
                        0x44u, &mode, &flags, &nodes) == 0 &&
                    mode == 2 && flags == 0x4000u && nodes == 1u);
    }
    expect_true("lock registry enforces byte limit atomically",
                kernel_mm_lock_space_add_limited(
                    0x44u, 0x7000u, 0x1000u, 0x5000u) ==
                    -EDGE_LINUX_ENOMEM &&
                !kernel_mm_lock_space_contains(0x44u, 0x7000u));
    expect_true("lock registry splits middle unlock",
                kernel_mm_lock_space_remove(
                    0x44u, 0x3000u, 0x2000u) == 0 &&
                kernel_mm_lock_space_contains(0x44u, 0x2fffu) &&
                !kernel_mm_lock_space_contains(0x44u, 0x3000u) &&
                kernel_mm_lock_space_contains(0x44u, 0x5000u) &&
                kernel_mm_lock_space_bytes(0x44u) == 0x3000u);
    expect_true("lock registry tracks future policy",
                kernel_mm_lock_space_set_future(
                    0x44u, KERNEL_MM_LOCK_ALL_FUTURE |
                           KERNEL_MM_LOCK_ALL_ONFAULT) == 0 &&
                kernel_mm_lock_space_future_flags(0x44u) ==
                    (KERNEL_MM_LOCK_ALL_FUTURE |
                     KERNEL_MM_LOCK_ALL_ONFAULT));
    expect_true("lock registry moves partial mremap locks",
                kernel_mm_lock_space_remap(
                    0x44u, 0x1000u, 0x6000u,
                    0x10000u, 0x6000u) == 0 &&
                kernel_mm_lock_space_contains(0x44u, 0x11000u) &&
                !kernel_mm_lock_space_contains(0x44u, 0x12000u) &&
                kernel_mm_lock_space_contains(0x44u, 0x14000u) &&
                !kernel_mm_lock_space_contains(0x44u, 0x2000u));
    expect_true("lock registry preserves locked mremap growth",
                kernel_mm_lock_space_remap(
                    0x44u, 0x14000u, 0x2000u,
                    0x14000u, 0x4000u) == 0 &&
                kernel_mm_lock_space_contains(0x44u, 0x17fffu));
    expect_true("lock registry drops mremap shrink tail",
                kernel_mm_lock_space_remap(
                    0x44u, 0x14000u, 0x4000u,
                    0x14000u, 0x2000u) == 0 &&
                kernel_mm_lock_space_contains(0x44u, 0x15fffu) &&
                !kernel_mm_lock_space_contains(0x44u, 0x16000u));
    expect_true("lock registry preserves locks beside shrink",
                kernel_mm_lock_space_add(
                    0x44u, 0x20000u, 0x5000u) == 0 &&
                kernel_mm_lock_space_remap(
                    0x44u, 0x21000u, 0x3000u,
                    0x21000u, 0x1000u) == 0 &&
                kernel_mm_lock_space_contains(0x44u, 0x21fffu) &&
                !kernel_mm_lock_space_contains(0x44u, 0x22000u) &&
                kernel_mm_lock_space_contains(0x44u, 0x24000u));
    kernel_mm_lock_space_release(0x44u);
    expect_true("lock registry release drops state",
                !kernel_mm_lock_space_contains(0x44u, 0x2000u) &&
                kernel_mm_lock_space_future_flags(0x44u) == 0u &&
                kernel_mm_resident_peak_bytes(0x44u) == 0u &&
                g_vm_pages_used == 0u && g_vm_page_free_calls == 2u);

    g_current_address_space = 0x55u;
    g_range_mapped_result = -EDGE_LINUX_ENOMEM;
    expect_true("seal rejects an unmapped range",
                kernel_mm_seal_range(0x3000u, 0x1000u, 0u) ==
                    -EDGE_LINUX_ENOMEM);
    g_range_mapped_result = 0;
    expect_true("seal rejects unsupported flags",
                kernel_mm_seal_range(0x3000u, 0x1000u, 1u) ==
                    -EDGE_LINUX_EINVAL);
    expect_true("seal rejects an unaligned address",
                kernel_mm_seal_range(0x3001u, 0x1000u, 0u) ==
                    -EDGE_LINUX_EINVAL);
    expect_true("seal records a mapped range",
                kernel_mm_seal_range(0x3000u, 0x1001u, 0u) == 0 &&
                kernel_mm_seal_space_overlaps(
                    0x55u, 0x3000u, 0x2000u));
    expect_true("seal blocks mapping mutations",
                kernel_mm_protect_range(
                    0x3000u, 0x1000u, KERNEL_MM_PROT_READ) ==
                    -EDGE_LINUX_EPERM &&
                kernel_mm_unmap_range(0x3000u, 0x1000u) ==
                    -EDGE_LINUX_EPERM);
    expect_true("seal state is inherited by an address-space clone",
                kernel_mm_seal_space_clone(0x55u, 0x66u) == 0 &&
                kernel_mm_seal_space_overlaps(
                    0x66u, 0x4000u, 0x1000u));
    kernel_mm_lock_space_release(0x55u);
    kernel_mm_lock_space_release(0x66u);
    expect_true("seal registry release drops state",
                !kernel_mm_seal_space_overlaps(
                    0x55u, 0x3000u, 0x2000u) &&
                !kernel_mm_seal_space_overlaps(
                    0x66u, 0x3000u, 0x2000u) &&
                g_vm_pages_used == 0u && g_vm_page_free_calls == 4u);
    g_current_address_space = 0u;
}

int main(void) {
    test_madvise_fork_policy();
    test_madvise_reclaim_policy();
    test_process_mrelease_dispatch();
    test_process_vm_dispatch();
    test_residency_and_lock_policy();
    test_sync_and_protect_policy();
    test_unmap_policy();
    test_map_and_remap_policy();
    test_program_break_policy();
    test_reclaim_dispatch();
    test_reclaim_candidate_policy();
    test_cache_state_policy();
    test_file_cache_shadow_policy();
    test_file_install_race_policy();
    test_dynamic_vma_storage();
    test_locked_range_registry();
    if (g_failures) return 1;
    puts("mm_runtime_unit: PASS");
    return 0;
}
