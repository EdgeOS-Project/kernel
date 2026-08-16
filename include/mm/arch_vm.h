/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_MM_ARCH_VM_H
#define EDGEOS_MM_ARCH_VM_H

#include <stdint.h>
#include "mm/page_allocator.h"

#define ARCH_VM_PROT_READ  0x1u
#define ARCH_VM_PROT_WRITE 0x2u
#define ARCH_VM_PROT_EXEC  0x4u
#define ARCH_VM_PROT_DEVICE  0x8u
#define ARCH_VM_PROT_SHARED  0x10u
#define ARCH_VM_PROT_NOCACHE 0x20u
#define ARCH_VM_PROT_WRITE_NOTIFY 0x40u
#define ARCH_VM_PROT_COW 0x80u
#define ARCH_VM_PROT_EXTERNAL 0x100u

void *arch_vm_alloc_page(void);
void *arch_vm_alloc_pages(uint64_t page_count);
void *arch_vm_reserve_pages(uint64_t page_count);
int arch_vm_retain_page(void *page);
int arch_vm_shared_zero_page_acquire(uint64_t *physical_out);
void arch_vm_free_page(void *page);
int arch_vm_address_space_create(uint64_t *address_space_out);
int arch_vm_address_space_clone(uint64_t parent_address_space,
                                uint64_t *child_address_space_out);
void arch_vm_address_space_destroy(uint64_t address_space);
void arch_vm_address_space_activate(uint64_t address_space);
int arch_vm_map_user_page(uint64_t address_space, uint64_t virtual_address,
                          uint64_t physical_address, uint32_t protection);
int arch_vm_map_user_pages(uint64_t address_space, uint64_t virtual_address,
                           const uint64_t *physical_pages,
                           uint32_t page_count, uint32_t protection,
                           uint32_t *mapped_count);
int arch_vm_protect_user_range(uint64_t address_space, uint64_t virtual_address,
                               uint64_t length, uint32_t protection);
int arch_vm_protect_user_resident_range(uint64_t address_space,
                                        uint64_t virtual_address,
                                        uint64_t length,
                                        uint32_t protection);
int arch_vm_unmap_user_range(uint64_t address_space, uint64_t virtual_address,
                             uint64_t length);
int arch_vm_unmap_user_page_if_physical(uint64_t address_space,
                                        uint64_t virtual_address,
                                        uint64_t physical_address);
int arch_vm_user_range_mapped(uint64_t address_space,
                              uint64_t virtual_address, uint64_t length);
uint64_t arch_vm_user_overlap_end(uint64_t address_space,
                                  uint64_t virtual_address, uint64_t length);
void arch_vm_sync_loaded_page(void *page, int executable);
void arch_vm_sync_loaded_pages(void *const *pages, uint32_t page_count,
                               int executable);
int arch_vm_sync_user_exec_range(uint64_t address_space,
                                 uint64_t virtual_address,
                                 uint64_t length);
int arch_vm_translate(uint64_t address_space, uint64_t virtual_address,
                      uint64_t *physical_address, uint64_t *entry_out);
int arch_vm_user_page_protection(uint64_t address_space,
                                 uint64_t virtual_address,
                                 uint32_t *protection_out);
int arch_vm_retry_user_page(uint64_t address_space,
                            uint64_t virtual_address);
int arch_vm_handle_cow_fault(uint64_t address_space, uint64_t virtual_address);
int arch_vm_handle_write_notify_fault(uint64_t address_space,
                                      uint64_t virtual_address,
                                      uint64_t *physical_address);
int arch_vm_discard_private_page(uint64_t address_space,
                                 uint64_t virtual_address);
int arch_copy_from_user(uint64_t address_space, void *kernel_destination,
                        uint64_t user_source, uint64_t length);
int arch_copy_to_user(uint64_t address_space, uint64_t user_destination,
                      const void *kernel_source, uint64_t length);
uint64_t arch_vm_memory_total_bytes(void);
uint64_t arch_vm_memory_free_bytes(void);
uint64_t arch_vm_address_space_resident_pages(uint64_t address_space);
int arch_vm_page_allocator_snapshot(
    edge_page_allocator_snapshot_t *snapshot);
int arch_vm_clean_physical_aliases(uint64_t physical_address, uint64_t length);
int arch_vm_writeprotect_physical_aliases(uint64_t physical_address,
                                          uint64_t length);
int arch_vm_write_notify_supported(void);
uint32_t arch_vm_count_physical_aliases(uint64_t physical_address,
                                        uint64_t length);

#endif
