/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS ARM64 early virtual-memory interface. */
#ifndef EDGEOS_ARCH_ARM64_VM_H
#define EDGEOS_ARCH_ARM64_VM_H

#include <stdint.h>
#include "arch/arm64/bootinfo.h"
#include "mm/page_allocator.h"

#define EDGEOS_ARM64_VM_PROT_READ  (1u << 0)
#define EDGEOS_ARM64_VM_PROT_WRITE (1u << 1)
#define EDGEOS_ARM64_VM_PROT_EXEC  (1u << 2)
#define EDGEOS_ARM64_VM_PROT_DEVICE (1u << 3)
#define EDGEOS_ARM64_VM_PROT_SHARED (1u << 4)
#define EDGEOS_ARM64_VM_PROT_NOCACHE (1u << 5)
#define EDGEOS_ARM64_VM_PROT_COW (1u << 6)
#define EDGEOS_ARM64_VM_PROT_WRITE_NOTIFY (1u << 7)
#define EDGEOS_ARM64_VM_PROT_EXTERNAL (1u << 8)
#define EDGEOS_ARM64_VM_PROT_POISON (1u << 9)
#define EDGEOS_ARM64_TTBR0_BASE_MASK 0x0000FFFFFFFFF000ULL

int edgeos_arm64_vm_init(const edgeos_arm64_bootinfo_t *bootinfo);
void *edgeos_arm64_early_alloc_page(void);
void *edgeos_arm64_early_alloc_pages(uint64_t page_count);
void *edgeos_arm64_early_reserve_pages(uint64_t page_count);
int edgeos_arm64_early_retain_page(void *page);
int edgeos_arm64_shared_zero_page_acquire(uint64_t *physical_out);
void edgeos_arm64_early_free_page(void *page);
uint64_t edgeos_arm64_memory_total_bytes(void);
uint64_t edgeos_arm64_memory_free_bytes(void);
int edgeos_arm64_page_allocator_snapshot(
    edge_page_allocator_snapshot_t *snapshot);
void edgeos_arm64_page_allocator_set_reclaim(
    edge_page_reclaim_callback_t reclaim, void *context);
uint64_t edgeos_arm64_kernel_ttbr0(void);
uint64_t edgeos_arm64_address_space_ttbr_value(uint64_t ttbr0);
uint32_t edgeos_arm64_address_space_cgroup(uint64_t ttbr0);
int edgeos_arm64_page_cgroup_owner(uint64_t physical,
                                   uint32_t *cgroup_id_out);
void edgeos_arm64_address_space_set_cgroup(uint64_t ttbr0,
                                           uint32_t cgroup_id);
void edgeos_arm64_address_space_note_memory_oom(uint64_t ttbr0,
                                                uint32_t oom_cgroup_id);
int edgeos_arm64_address_space_create(uint64_t *ttbr0_out);
int edgeos_arm64_address_space_ensure_kernel_image(uint64_t ttbr0);
int edgeos_arm64_address_space_clone(uint64_t parent_ttbr0, uint64_t *child_ttbr0_out);
void edgeos_arm64_address_space_destroy(uint64_t ttbr0);
int edgeos_arm64_address_space_map_user_page(uint64_t ttbr0, uint64_t va,
                                             uint64_t pa, uint32_t prot);
int edgeos_arm64_address_space_map_user_pages(uint64_t ttbr0, uint64_t va,
                                              const uint64_t *physical_pages,
                                              uint32_t page_count,
                                              uint32_t prot,
                                              uint32_t *mapped_count);
int edgeos_arm64_address_space_poison_user_page(uint64_t ttbr0, uint64_t va);
int edgeos_arm64_address_space_user_page_poisoned(uint64_t ttbr0,
                                                   uint64_t va);
int edgeos_arm64_address_space_protect_user_range(uint64_t ttbr0, uint64_t va,
                                                   uint64_t length, uint32_t prot);
int edgeos_arm64_address_space_protect_user_resident_range(
    uint64_t ttbr0, uint64_t va, uint64_t length, uint32_t prot);
int edgeos_arm64_address_space_unmap_user_range(uint64_t ttbr0, uint64_t va,
                                                 uint64_t length);
int edgeos_arm64_address_space_unmap_user_page_if_physical(
    uint64_t ttbr0, uint64_t va, uint64_t physical);
int edgeos_arm64_address_space_user_range_mapped(uint64_t ttbr0, uint64_t va,
                                                  uint64_t length);
uint64_t edgeos_arm64_address_space_user_overlap_end(uint64_t ttbr0,
                                                      uint64_t va,
                                                      uint64_t length);
int edgeos_arm64_address_space_translate(uint64_t ttbr0, uint64_t va,
                                         uint64_t *pa_out, uint64_t *desc_out);
int edgeos_arm64_address_space_is_live(uint64_t ttbr0);
uint64_t edgeos_arm64_address_space_resident_pages(uint64_t ttbr0);
int edgeos_arm64_address_space_user_protection(uint64_t ttbr0, uint64_t va,
                                               uint32_t *prot_out);
int edgeos_arm64_address_space_retry_user_page(uint64_t ttbr0, uint64_t va);
int edgeos_arm64_address_space_retry_user_access(uint64_t ttbr0, uint64_t va,
                                                 uint32_t access);
int edgeos_arm64_address_space_handle_cow(uint64_t ttbr0, uint64_t va);
int edgeos_arm64_address_space_handle_write_notify(uint64_t ttbr0,
                                                    uint64_t va,
                                                    uint64_t *pa_out);
int edgeos_arm64_address_space_discard_private_page(uint64_t ttbr0,
                                                     uint64_t va);
uint32_t edgeos_arm64_page_lifecycle(uint64_t physical,
                                     uint64_t *last_free_caller,
                                     uint64_t *last_alloc_caller);
int edgeos_arm64_copy_from_user(uint64_t ttbr0, void *dst, uint64_t src,
                                uint64_t length);
int edgeos_arm64_copy_to_user(uint64_t ttbr0, uint64_t dst, const void *src,
                              uint64_t length);
int edgeos_arm64_compare_exchange_user_u32(uint64_t ttbr0, uint64_t address,
                                           uint32_t *expected,
                                           uint32_t desired);
void edgeos_arm64_address_space_activate(uint64_t ttbr0);
int edgeos_arm64_address_space_sync_user_exec_range(uint64_t ttbr0,
                                                     uint64_t virtual_address,
                                                     uint64_t length);
uint32_t edgeos_arm64_address_space_clean_physical_aliases(
    uint64_t physical_start, uint64_t length);
uint32_t edgeos_arm64_address_space_writeprotect_physical_aliases(
    uint64_t physical_start, uint64_t length);
uint32_t edgeos_arm64_address_space_count_physical_aliases(
    uint64_t physical_start, uint64_t length);

#endif
