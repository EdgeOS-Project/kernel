/* SPDX-License-Identifier: MPL-2.0 */
/* Shared Linux-compatible vDSO mapping and time-data publication. */

#include <stdint.h>

#include "kernel/arch_cpu.h"
#include "kernel/linux_vdso.h"
#include "mm/arch_vm.h"
#include "string.h"
#include "sys/process.h"

#define VDSO_PAGE_SIZE 4096u
#define VDSO_IMAGE_PAGES 2u

typedef struct {
    volatile uint32_t sequence;
    uint32_t clock_mode;
    uint64_t cycle_last;
    uint64_t monotonic_base_us;
    uint64_t realtime_offset_us;
    uint64_t frequency;
} edge_linux_vdso_data_t;

extern const uint8_t edge_linux_vdso_image[8192];
extern const uint64_t edge_linux_vdso_image_size;

static volatile uint32_t g_image_state;
static void *g_image_pages[VDSO_IMAGE_PAGES];
static edge_linux_vdso_data_t *g_data;
static volatile uint32_t g_latest_sequence;
static volatile uint32_t g_time_update_lock;
static uint64_t g_latest_cycle_last;
static uint64_t g_latest_monotonic_base_us;
static uint64_t g_latest_realtime_offset_us;
static uint64_t g_latest_frequency;

static void linux_vdso_write_data(edge_linux_vdso_data_t *data,
                                  uint64_t cycle_last,
                                  uint64_t monotonic_base_us,
                                  uint64_t realtime_offset_us,
                                  uint64_t frequency) {
    uint32_t sequence;

    if (!data) return;
    sequence = __atomic_load_n(&data->sequence, __ATOMIC_RELAXED);
    __atomic_store_n(&data->sequence, sequence + 1u, __ATOMIC_RELEASE);
    data->clock_mode = frequency ? 1u : 0u;
    data->cycle_last = cycle_last;
    data->monotonic_base_us = monotonic_base_us;
    data->realtime_offset_us = realtime_offset_us;
    data->frequency = frequency;
    __atomic_store_n(&data->sequence, sequence + 2u, __ATOMIC_RELEASE);
}

static void linux_vdso_copy_latest(edge_linux_vdso_data_t *data) {
    uint32_t before;
    uint32_t after;
    uint64_t cycle_last;
    uint64_t monotonic_base_us;
    uint64_t realtime_offset_us;
    uint64_t frequency;

    do {
        before = __atomic_load_n(&g_latest_sequence, __ATOMIC_ACQUIRE);
        if (before & 1u) continue;
        cycle_last = g_latest_cycle_last;
        monotonic_base_us = g_latest_monotonic_base_us;
        realtime_offset_us = g_latest_realtime_offset_us;
        frequency = g_latest_frequency;
        after = __atomic_load_n(&g_latest_sequence, __ATOMIC_ACQUIRE);
    } while (before != after || (after & 1u));
    linux_vdso_write_data(data, cycle_last, monotonic_base_us,
                          realtime_offset_us, frequency);
}

static int linux_vdso_prepare_image(void) {
    uint32_t expected = 0;

    if (__atomic_load_n(&g_image_state, __ATOMIC_ACQUIRE) == 2u) return 0;
    if (__atomic_compare_exchange_n(&g_image_state, &expected, 1u, 0,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        for (uint32_t page = 0; page < VDSO_IMAGE_PAGES; ++page) {
            g_image_pages[page] = arch_vm_alloc_page();
            if (!g_image_pages[page]) {
                for (uint32_t release = 0; release < page; ++release) {
                    arch_vm_free_page(g_image_pages[release]);
                    g_image_pages[release] = 0;
                }
                __atomic_store_n(&g_image_state, 0u, __ATOMIC_RELEASE);
                return -1;
            }
            memcpy(g_image_pages[page],
                   edge_linux_vdso_image + page * VDSO_PAGE_SIZE,
                   VDSO_PAGE_SIZE);
        }
        arch_vm_sync_loaded_page(g_image_pages[0], 1);
        g_data = (edge_linux_vdso_data_t *)g_image_pages[1];
        linux_vdso_copy_latest(g_data);
        __atomic_store_n(&g_image_state, 2u, __ATOMIC_RELEASE);
        return 0;
    }
    while (__atomic_load_n(&g_image_state, __ATOMIC_ACQUIRE) == 1u)
        arch_cpu_relax();
    return __atomic_load_n(&g_image_state, __ATOMIC_ACQUIRE) == 2u ? 0 : -1;
}

uint64_t linux_vdso_map(uint64_t address_space) {
    uint64_t base;

    if (!address_space || edge_linux_vdso_image_size != 8192u ||
        linux_vdso_prepare_image() < 0)
        return 0;
    base = arch_cpu_user_vdso_base();
    if (!base) return 0;
    if (arch_vm_map_user_page(address_space, base,
                              (uint64_t)(uintptr_t)g_image_pages[0],
                              ARCH_VM_PROT_READ | ARCH_VM_PROT_EXEC) < 0)
        return 0;
    if (arch_vm_map_user_page(address_space, base + VDSO_PAGE_SIZE,
                              (uint64_t)(uintptr_t)g_image_pages[1],
                              ARCH_VM_PROT_READ) < 0)
        return 0;
    return base;
}

void linux_vdso_time_update(uint64_t cycle_last,
                            uint64_t monotonic_base_us,
                            uint64_t realtime_offset_us,
                            uint64_t frequency) {
    uint32_t sequence;

    /*
     * Timer interrupts can publish from several CPUs concurrently.  The
     * sequence counter protects readers, but it does not serialize writers:
     * two writers can otherwise leave an odd final value and make every vDSO
     * reader spin forever.  Keep the publication section short and enforce a
     * single writer across the shared latest and mapped data snapshots.
     */
    while (__atomic_exchange_n(
               &g_time_update_lock, 1u, __ATOMIC_ACQUIRE) != 0u)
        arch_cpu_relax();
    sequence =
        __atomic_load_n(&g_latest_sequence, __ATOMIC_RELAXED) & ~1u;

    __atomic_store_n(&g_latest_sequence, sequence + 1u, __ATOMIC_RELEASE);
    g_latest_cycle_last = cycle_last;
    g_latest_monotonic_base_us = monotonic_base_us;
    g_latest_realtime_offset_us = realtime_offset_us;
    g_latest_frequency = frequency;
    __atomic_store_n(&g_latest_sequence, sequence + 2u, __ATOMIC_RELEASE);
    if (__atomic_load_n(&g_image_state, __ATOMIC_ACQUIRE) == 2u)
        linux_vdso_write_data(g_data, cycle_last, monotonic_base_us,
                              realtime_offset_us, frequency);
    __atomic_store_n(&g_time_update_lock, 0u, __ATOMIC_RELEASE);
}
