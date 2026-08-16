/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS userspace fbdev synchronization policy. */

#include <stdint.h>
#include "fb.h"
#include "mm/arch_vm.h"

static int fbdev_physical_range(uint64_t *physical_start,
                                uint64_t *size_out) {
    uint64_t physical_base;
    uint64_t physical_offset;
    uint64_t size;
    uint32_t physical_pages;

    if (!fb_get_2m_phys_window(&physical_base, &physical_pages,
                               &physical_offset))
        return 0;
    (void)physical_pages;
    size = (uint64_t)fb.pitch * fb.height;
    if (!size) return 0;
    if (physical_start) *physical_start = physical_base + physical_offset;
    if (size_out) *size_out = size;
    return 1;
}

void process_user_fbdev_writeprotect_all(void) {
    uint64_t physical_start;
    uint64_t framebuffer_size;
    if (fbdev_physical_range(&physical_start, &framebuffer_size))
        (void)arch_vm_writeprotect_physical_aliases(physical_start,
                                                    framebuffer_size);
}

void process_user_fbdev_collect_dirty_all(void) {
    /* ARM64 write-notify faults are the authoritative damage source. */
}
