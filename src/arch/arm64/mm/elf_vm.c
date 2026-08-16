/* SPDX-License-Identifier: MPL-2.0 */
/* ARM64 page-table and cache hooks used by the common ELF image loader. */

#include <stdint.h>
#include "arch/arm64/vm.h"
#include "kernel/mm_runtime.h"
#include "mm/arch_vm.h"

void *arch_vm_alloc_page(void) {
    return edgeos_arm64_early_alloc_page();
}

void *arch_vm_alloc_pages(uint64_t page_count) {
    return edgeos_arm64_early_alloc_pages(page_count);
}

void *arch_vm_reserve_pages(uint64_t page_count) {
    return edgeos_arm64_early_reserve_pages(page_count);
}

uint64_t arch_vm_address_space_resident_pages(uint64_t address_space) {
    return edgeos_arm64_address_space_resident_pages(address_space);
}

int arch_vm_retain_page(void *page) {
    return edgeos_arm64_early_retain_page(page);
}

int arch_vm_shared_zero_page_acquire(uint64_t *physical_out) {
    return edgeos_arm64_shared_zero_page_acquire(physical_out);
}

void arch_vm_free_page(void *page) {
    edgeos_arm64_early_free_page(page);
}

int arch_vm_address_space_create(uint64_t *address_space_out) {
    return edgeos_arm64_address_space_create(address_space_out);
}

int arch_vm_address_space_clone(uint64_t parent_address_space,
                                uint64_t *child_address_space_out) {
    return edgeos_arm64_address_space_clone(parent_address_space,
                                             child_address_space_out);
}

void arch_vm_address_space_destroy(uint64_t address_space) {
    edgeos_arm64_address_space_destroy(address_space);
}

void arch_vm_address_space_activate(uint64_t address_space) {
    edgeos_arm64_address_space_activate(address_space);
}

static uint32_t common_protection_to_arm64(uint32_t protection) {
    uint32_t arm64_protection = protection &
        ~(ARCH_VM_PROT_COW | ARCH_VM_PROT_WRITE_NOTIFY);

    if (protection & ARCH_VM_PROT_COW)
        arm64_protection |= EDGEOS_ARM64_VM_PROT_COW;
    if (protection & ARCH_VM_PROT_WRITE_NOTIFY)
        arm64_protection |= EDGEOS_ARM64_VM_PROT_WRITE_NOTIFY;
    return arm64_protection;
}

static uint32_t arm64_protection_to_common(uint32_t protection) {
    uint32_t common_protection = protection &
        ~(EDGEOS_ARM64_VM_PROT_COW | EDGEOS_ARM64_VM_PROT_WRITE_NOTIFY);

    if (protection & EDGEOS_ARM64_VM_PROT_COW)
        common_protection |= ARCH_VM_PROT_COW;
    if (protection & EDGEOS_ARM64_VM_PROT_WRITE_NOTIFY)
        common_protection |= ARCH_VM_PROT_WRITE_NOTIFY;
    return common_protection;
}

int arch_vm_map_user_page(uint64_t address_space, uint64_t virtual_address,
                          uint64_t physical_address, uint32_t protection) {
    return edgeos_arm64_address_space_map_user_page(address_space, virtual_address,
        physical_address, common_protection_to_arm64(protection));
}

int arch_vm_map_user_pages(uint64_t address_space, uint64_t virtual_address,
                           const uint64_t *physical_pages,
                           uint32_t page_count, uint32_t protection,
                           uint32_t *mapped_count) {
    return edgeos_arm64_address_space_map_user_pages(
        address_space, virtual_address, physical_pages, page_count,
        common_protection_to_arm64(protection), mapped_count);
}

int arch_vm_protect_user_range(uint64_t address_space, uint64_t virtual_address,
                               uint64_t length, uint32_t protection) {
    return edgeos_arm64_address_space_protect_user_range(address_space,
                                                          virtual_address, length,
        common_protection_to_arm64(protection));
}

int arch_vm_protect_user_resident_range(uint64_t address_space,
                                        uint64_t virtual_address,
                                        uint64_t length,
                                        uint32_t protection) {
    return edgeos_arm64_address_space_protect_user_resident_range(
        address_space, virtual_address, length,
        common_protection_to_arm64(protection));
}

int arch_vm_unmap_user_range(uint64_t address_space, uint64_t virtual_address,
                             uint64_t length) {
    return edgeos_arm64_address_space_unmap_user_range(address_space,
                                                        virtual_address, length);
}

int arch_vm_unmap_user_page_if_physical(uint64_t address_space,
                                        uint64_t virtual_address,
                                        uint64_t physical_address) {
    return edgeos_arm64_address_space_unmap_user_page_if_physical(
        address_space, virtual_address, physical_address);
}

int arch_vm_user_range_mapped(uint64_t address_space,
                              uint64_t virtual_address, uint64_t length) {
    return edgeos_arm64_address_space_user_range_mapped(
        address_space, virtual_address, length);
}

uint64_t arch_vm_user_overlap_end(uint64_t address_space,
                                  uint64_t virtual_address, uint64_t length) {
    return edgeos_arm64_address_space_user_overlap_end(
        address_space, virtual_address, length);
}

int arch_vm_translate(uint64_t address_space, uint64_t virtual_address,
                      uint64_t *physical_address, uint64_t *entry_out) {
    return edgeos_arm64_address_space_translate(address_space, virtual_address,
                                                 physical_address, entry_out);
}

int arch_vm_user_page_protection(uint64_t address_space,
                                 uint64_t virtual_address,
                                 uint32_t *protection_out) {
    uint32_t protection;

    if (!protection_out ||
        edgeos_arm64_address_space_user_protection(address_space,
                                                    virtual_address,
                                                    &protection) < 0)
        return -1;
    *protection_out = arm64_protection_to_common(protection);
    return 0;
}

int arch_vm_retry_user_page(uint64_t address_space,
                            uint64_t virtual_address) {
    return edgeos_arm64_address_space_retry_user_page(
        address_space, virtual_address);
}

int arch_vm_handle_cow_fault(uint64_t address_space, uint64_t virtual_address) {
    return edgeos_arm64_address_space_handle_cow(address_space,
                                                  virtual_address);
}

int arch_vm_handle_write_notify_fault(uint64_t address_space,
                                      uint64_t virtual_address,
                                      uint64_t *physical_address) {
    return edgeos_arm64_address_space_handle_write_notify(
        address_space, virtual_address, physical_address);
}

int arch_vm_discard_private_page(uint64_t address_space,
                                 uint64_t virtual_address) {
    return edgeos_arm64_address_space_discard_private_page(address_space,
                                                            virtual_address);
}

int arch_copy_from_user(uint64_t address_space, void *kernel_destination,
                        uint64_t user_source, uint64_t length) {
    uint8_t *destination = (uint8_t *)kernel_destination;
    if (!edgeos_arm64_address_space_is_live(address_space)) return -1;
    while (length) {
        uint64_t available = 4096u - (user_source & 4095u);
        uint64_t count = length < available ? length : available;
        if (edgeos_arm64_copy_from_user(address_space, destination,
                                        user_source, count) < 0) {
            if (kernel_mm_resolve_user_page(
                    address_space, user_source, KERNEL_MM_PROT_READ) <= 0 ||
                edgeos_arm64_copy_from_user(address_space, destination,
                                             user_source, count) < 0)
                return -1;
        }
        destination += count;
        user_source += count;
        length -= count;
    }
    return 0;
}

int arch_copy_to_user(uint64_t address_space, uint64_t user_destination,
                      const void *kernel_source, uint64_t length) {
    const uint8_t *source = (const uint8_t *)kernel_source;
    if (!edgeos_arm64_address_space_is_live(address_space)) return -1;
    while (length) {
        uint64_t available = 4096u - (user_destination & 4095u);
        uint64_t count = length < available ? length : available;
        if (edgeos_arm64_copy_to_user(address_space, user_destination,
                                      source, count) < 0) {
            if (kernel_mm_resolve_user_page(
                    address_space, user_destination,
                    KERNEL_MM_PROT_WRITE) <= 0 ||
                edgeos_arm64_copy_to_user(address_space, user_destination,
                                           source, count) < 0)
                return -1;
        }
        source += count;
        user_destination += count;
        length -= count;
    }
    return 0;
}

uint64_t arch_vm_memory_total_bytes(void) {
    return edgeos_arm64_memory_total_bytes();
}

uint64_t arch_vm_memory_free_bytes(void) {
    return edgeos_arm64_memory_free_bytes();
}

int arch_vm_page_allocator_snapshot(
    edge_page_allocator_snapshot_t *snapshot) {
    return edgeos_arm64_page_allocator_snapshot(snapshot);
}

int arch_vm_clean_physical_aliases(uint64_t physical_address, uint64_t length) {
    return edgeos_arm64_address_space_clean_physical_aliases(physical_address,
                                                              length);
}

int arch_vm_writeprotect_physical_aliases(uint64_t physical_address,
                                          uint64_t length) {
    return edgeos_arm64_address_space_writeprotect_physical_aliases(
        physical_address, length);
}

int arch_vm_write_notify_supported(void) {
    return 1;
}

uint32_t arch_vm_count_physical_aliases(uint64_t physical_address,
                                        uint64_t length) {
    return edgeos_arm64_address_space_count_physical_aliases(physical_address,
                                                              length);
}

int arch_vm_sync_user_exec_range(uint64_t address_space,
                                 uint64_t virtual_address,
                                 uint64_t length) {
    return edgeos_arm64_address_space_sync_user_exec_range(
        address_space, virtual_address, length);
}

void arch_vm_sync_loaded_pages(void *const *pages, uint32_t page_count,
                               int executable) {
    uint64_t ctr;
    uint64_t line;
    uint64_t cursor;

    if (!pages || !page_count) return;
    __asm__ __volatile__("mrs %0, ctr_el0" : "=r"(ctr));
    line = 4ULL << ((ctr >> 16) & 0xfu);
    for (uint32_t page_index = 0; page_index < page_count; ++page_index) {
        uint64_t start = (uint64_t)(uintptr_t)pages[page_index];
        uint64_t end;
        if (!start) continue;
        end = start + 4096u;
        for (cursor = start & ~(line - 1u); cursor < end; cursor += line)
            __asm__ __volatile__("dc cvau, %0" :: "r"(cursor) : "memory");
    }
    __asm__ __volatile__("dsb ish" ::: "memory");
    if (!executable) return;
    /*
     * ELF pages are populated through the kernel identity alias and later
     * fetched through a process VA.  ARM64 requires cleaning modified data to
     * the point of unification and invalidating the corresponding instruction
     * lines before execution.  Invalidate the loaded range, not the complete
     * instruction cache: a global I-cache flush for every demand-fault batch
     * makes large shared libraries pathologically expensive and is not needed
     * for newly published pages.
     */
    for (uint32_t page_index = 0; page_index < page_count; ++page_index) {
        uint64_t start = (uint64_t)(uintptr_t)pages[page_index];
        uint64_t end;
        if (!start) continue;
        end = start + 4096u;
        for (cursor = start & ~(line - 1u); cursor < end; cursor += line)
            __asm__ __volatile__("ic ivau, %0" :: "r"(cursor) : "memory");
    }
    __asm__ __volatile__("dsb ish\n\tisb" ::: "memory");
}

void arch_vm_sync_loaded_page(void *page, int executable) {
    void *pages[1] = {page};
    arch_vm_sync_loaded_pages(pages, 1u, executable);
}
