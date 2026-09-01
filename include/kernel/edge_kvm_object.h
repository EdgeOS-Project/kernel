/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_EDGE_KVM_OBJECT_H
#define EDGEOS_KERNEL_EDGE_KVM_OBJECT_H

#include <stdint.h>

#include "kernel/edge_kvm_abi.h"

#define EDGE_KVM_API_VERSION 12u
#define EDGE_KVM_OBJECT_MAX_VMS 16u
#define EDGE_KVM_OBJECT_MAX_VCPUS 256u
#define EDGE_KVM_OBJECT_MAX_DEVICES 32u
#define EDGE_KVM_OBJECT_MAX_MEMORY_SLOTS 64u
#define EDGE_KVM_PAGE_SIZE 4096u

#define EDGE_KVM_MEMORY_LOG_DIRTY_PAGES 0x1u
#define EDGE_KVM_MEMORY_READONLY 0x2u
#define EDGE_KVM_MEMORY_VALID_FLAGS \
    (EDGE_KVM_MEMORY_LOG_DIRTY_PAGES | EDGE_KVM_MEMORY_READONLY)

typedef struct edge_kvm_handle {
    uint32_t slot;
    uint32_t generation;
} edge_kvm_handle_t;

typedef struct edge_kvm_memory_region {
    uint32_t slot;
    uint32_t flags;
    uint64_t guest_physical_address;
    uint64_t memory_size;
    uint64_t userspace_address;
} edge_kvm_memory_region_t;

typedef struct edge_kvm_ioeventfd_registration {
    uint64_t datamatch;
    uint64_t address;
    uint32_t length;
    int32_t event_id;
    uint32_t flags;
} edge_kvm_ioeventfd_registration_t;

typedef struct edge_kvm_irqfd_registration {
    int32_t event_id;
    uint32_t gsi;
    uint32_t flags;
    int32_t resample_event_id;
} edge_kvm_irqfd_registration_t;

typedef struct edge_kvm_backend_ops {
    void *context;
    int (*get_supported_cpuid)(void *context,
                               edge_kvm_cpuid_entry2_t *entries,
                               uint32_t capacity, uint32_t *count);
    int (*get_msr_index_list)(void *context, uint32_t *indices,
                              uint32_t capacity, uint32_t *count);
    int (*get_msr_feature_index_list)(void *context, uint32_t *indices,
                                      uint32_t capacity, uint32_t *count);
    int (*get_msr_features)(void *context, edge_kvm_msr_entry_t *entries,
                            uint32_t count);
    int (*get_mce_cap_supported)(void *context, uint64_t *capability);
    int (*vm_create)(void *context, uint32_t machine_type,
                     uint64_t *backend_cookie);
    void (*vm_destroy)(void *context, uint64_t backend_cookie);
    int (*vm_get_preferred_target)(void *context, uint64_t vm_cookie,
                                   edge_kvm_vcpu_init_t *init);
    int (*vm_set_tss_address)(void *context, uint64_t vm_cookie,
                              uint64_t address);
    int (*vm_set_identity_map_address)(void *context, uint64_t vm_cookie,
                                       uint64_t address);
    int (*vm_create_irqchip)(void *context, uint64_t vm_cookie);
    int (*vm_set_gsi_routing)(void *context, uint64_t vm_cookie,
                              const edge_kvm_irq_routing_entry_t *entries,
                              uint32_t count);
    int (*vm_set_irq_line)(void *context, uint64_t vm_cookie,
                           edge_kvm_irq_level_t *level);
    int (*vm_signal_msi)(void *context, uint64_t vm_cookie,
                         const edge_kvm_msi_t *message);
    int (*vm_get_irqchip)(void *context, uint64_t vm_cookie,
                          edge_kvm_irqchip_t *state);
    int (*vm_set_irqchip)(void *context, uint64_t vm_cookie,
                          const edge_kvm_irqchip_t *state);
    int (*vm_create_pit)(void *context, uint64_t vm_cookie,
                         const edge_kvm_pit_config_t *config);
    int (*vm_get_pit)(void *context, uint64_t vm_cookie,
                      edge_kvm_pit_state2_t *state);
    int (*vm_set_pit)(void *context, uint64_t vm_cookie,
                      const edge_kvm_pit_state2_t *state);
    int (*vm_get_clock)(void *context, uint64_t vm_cookie,
                        edge_kvm_clock_data_t *state);
    int (*vm_set_clock)(void *context, uint64_t vm_cookie,
                        const edge_kvm_clock_data_t *state);
    int (*vm_ioeventfd)(void *context, uint64_t vm_cookie,
                        const edge_kvm_ioeventfd_registration_t *event);
    int (*vm_irqfd)(void *context, uint64_t vm_cookie,
                    const edge_kvm_irqfd_registration_t *irq);
    int (*vm_coalesced_mmio)(
        void *context, uint64_t vm_cookie,
        const edge_kvm_coalesced_mmio_zone_t *zone, uint8_t unregister);
    int (*vcpu_create)(void *context, uint64_t vm_cookie, uint32_t vcpu_id,
                       uint64_t *backend_cookie);
    void (*vcpu_destroy)(void *context, uint64_t vcpu_cookie);
    int (*vcpu_init)(void *context, uint64_t vcpu_cookie,
                     const edge_kvm_vcpu_init_t *init);
    int (*vcpu_get_one_reg)(void *context, uint64_t vcpu_cookie,
                            uint64_t id, void *value, uint32_t size);
    int (*vcpu_set_one_reg)(void *context, uint64_t vcpu_cookie,
                            uint64_t id, const void *value, uint32_t size);
    int (*vcpu_get_reg_list)(void *context, uint64_t vcpu_cookie,
                             uint64_t *ids, uint32_t capacity,
                             uint32_t *count);
    int (*vcpu_run)(void *context, uint64_t vcpu_cookie,
                    edge_kvm_run_t *run);
    int (*vcpu_pre_fault_memory)(
        void *context, uint64_t vcpu_cookie,
        edge_kvm_pre_fault_memory_t *request);
    int (*vcpu_translate)(void *context, uint64_t vcpu_cookie,
                          edge_kvm_translation_t *translation);
    int (*vcpu_get_regs)(void *context, uint64_t vcpu_cookie,
                         edge_kvm_regs_t *registers);
    int (*vcpu_set_regs)(void *context, uint64_t vcpu_cookie,
                         const edge_kvm_regs_t *registers);
    int (*vcpu_get_sregs)(void *context, uint64_t vcpu_cookie,
                          edge_kvm_sregs_t *registers);
    int (*vcpu_set_sregs)(void *context, uint64_t vcpu_cookie,
                          const edge_kvm_sregs_t *registers);
    int (*vcpu_get_sregs2)(void *context, uint64_t vcpu_cookie,
                           edge_kvm_sregs2_t *registers);
    int (*vcpu_set_sregs2)(void *context, uint64_t vcpu_cookie,
                           const edge_kvm_sregs2_t *registers);
    int (*vcpu_get_fpu)(void *context, uint64_t vcpu_cookie,
                        edge_kvm_fpu_t *state);
    int (*vcpu_set_fpu)(void *context, uint64_t vcpu_cookie,
                        const edge_kvm_fpu_t *state);
    int (*vcpu_get_lapic)(void *context, uint64_t vcpu_cookie,
                          edge_kvm_lapic_state_t *state);
    int (*vcpu_set_lapic)(void *context, uint64_t vcpu_cookie,
                          const edge_kvm_lapic_state_t *state);
    int (*vcpu_get_debugregs)(void *context, uint64_t vcpu_cookie,
                              edge_kvm_debugregs_t *state);
    int (*vcpu_set_debugregs)(void *context, uint64_t vcpu_cookie,
                              const edge_kvm_debugregs_t *state);
    int (*vcpu_set_guest_debug)(void *context, uint64_t vcpu_cookie,
                                const edge_kvm_guest_debug_x86_t *state);
    int (*vcpu_get_xcrs)(void *context, uint64_t vcpu_cookie,
                         edge_kvm_xcrs_t *state);
    int (*vcpu_set_xcrs)(void *context, uint64_t vcpu_cookie,
                         const edge_kvm_xcrs_t *state);
    int (*vcpu_get_xsave)(void *context, uint64_t vcpu_cookie,
                          edge_kvm_xsave_t *state);
    int (*vcpu_set_xsave)(void *context, uint64_t vcpu_cookie,
                          const edge_kvm_xsave_t *state);
    int (*vcpu_get_msrs)(void *context, uint64_t vcpu_cookie,
                         edge_kvm_msr_entry_t *entries, uint32_t count);
    int (*vcpu_set_msrs)(void *context, uint64_t vcpu_cookie,
                         const edge_kvm_msr_entry_t *entries,
                         uint32_t count);
    int (*vcpu_get_mp_state)(void *context, uint64_t vcpu_cookie,
                             edge_kvm_mp_state_t *state);
    int (*vcpu_set_mp_state)(void *context, uint64_t vcpu_cookie,
                             const edge_kvm_mp_state_t *state);
    int (*vcpu_get_events)(void *context, uint64_t vcpu_cookie,
                           edge_kvm_vcpu_events_t *events);
    int (*vcpu_set_events)(void *context, uint64_t vcpu_cookie,
                           const edge_kvm_vcpu_events_t *events);
    int64_t (*vcpu_get_tsc_khz)(void *context, uint64_t vcpu_cookie);
    int (*vcpu_set_tsc_khz)(void *context, uint64_t vcpu_cookie,
                            uint32_t frequency_khz);
    int (*vcpu_setup_mce)(void *context, uint64_t vcpu_cookie,
                          uint64_t capability);
    int (*vcpu_set_mce)(void *context, uint64_t vcpu_cookie,
                        const edge_kvm_x86_mce_t *machine_check);
    int (*vcpu_set_signal_mask)(void *context, uint64_t vcpu_cookie,
                                uint64_t mask);
    int (*vcpu_set_cpuid)(void *context, uint64_t vcpu_cookie,
                          const edge_kvm_cpuid_entry2_t *entries,
                          uint32_t count);
    int (*vcpu_get_cpuid)(void *context, uint64_t vcpu_cookie,
                          edge_kvm_cpuid_entry2_t *entries,
                          uint32_t capacity, uint32_t *count);
    int (*vcpu_mmap_page)(void *context, uint64_t vcpu_cookie,
                          uint32_t page_index,
                          uint64_t *physical_address);
    int (*device_create)(void *context, uint64_t vm_cookie, uint32_t type,
                         uint32_t flags, uint64_t *backend_cookie);
    void (*device_destroy)(void *context, uint64_t backend_cookie);
    int (*device_set_attr)(void *context, uint64_t device_cookie,
                           const edge_kvm_device_attr_t *attribute,
                           const void *value, uint32_t value_size);
    int (*device_get_attr)(void *context, uint64_t device_cookie,
                           const edge_kvm_device_attr_t *attribute,
                           void *value, uint32_t value_size);
    int (*device_has_attr)(void *context, uint64_t device_cookie,
                           const edge_kvm_device_attr_t *attribute);
    int (*memory_region_set)(void *context, uint64_t vm_cookie,
                             const edge_kvm_memory_region_t *region);
    int (*memory_dirty_log_get)(void *context, uint64_t vm_cookie,
                                uint32_t slot, uint32_t first_page,
                                uint32_t page_count, uint64_t *bitmap,
                                uint32_t bitmap_words, uint8_t clear);
    int (*memory_dirty_log_clear)(void *context, uint64_t vm_cookie,
                                  uint32_t slot, uint32_t first_page,
                                  uint32_t page_count,
                                  const uint64_t *bitmap,
                                  uint32_t bitmap_words);
} edge_kvm_backend_ops_t;

typedef struct edge_kvm_memory_slot {
    uint8_t active;
    uint8_t reserved[7];
    edge_kvm_memory_region_t region;
} edge_kvm_memory_slot_t;

typedef struct edge_kvm_vm_object {
    uint8_t active;
    uint8_t reserved[3];
    uint32_t generation;
    uint32_t machine_type;
    uint32_t descriptor_references;
    uint32_t vcpu_count;
    uint32_t device_count;
    uint8_t manual_dirty_log;
    uint8_t reserved2[3];
    uint64_t backend_cookie;
    edge_kvm_memory_slot_t memory_slots[EDGE_KVM_OBJECT_MAX_MEMORY_SLOTS];
} edge_kvm_vm_object_t;

typedef struct edge_kvm_vcpu_object {
    uint8_t active;
    uint8_t reserved[3];
    uint32_t generation;
    uint32_t vcpu_id;
    uint32_t descriptor_references;
    edge_kvm_handle_t vm;
    uint64_t backend_cookie;
    uint64_t vapic_address;
    uint64_t run_calls;
} edge_kvm_vcpu_object_t;

typedef struct edge_kvm_device_object {
    uint8_t active;
    uint8_t reserved[3];
    uint32_t generation;
    uint32_t type;
    uint32_t descriptor_references;
    edge_kvm_handle_t vm;
    uint64_t backend_cookie;
} edge_kvm_device_object_t;

typedef struct edge_kvm_object_table {
    uint32_t next_generation;
    uint32_t active_vm_count;
    uint32_t active_vcpu_count;
    uint32_t active_device_count;
    uint32_t reserved;
    edge_kvm_backend_ops_t backend;
    edge_kvm_vm_object_t vms[EDGE_KVM_OBJECT_MAX_VMS];
    edge_kvm_vcpu_object_t vcpus[EDGE_KVM_OBJECT_MAX_VCPUS];
    edge_kvm_device_object_t devices[EDGE_KVM_OBJECT_MAX_DEVICES];
} edge_kvm_object_table_t;

typedef struct edge_kvm_vm_snapshot {
    uint32_t machine_type;
    uint32_t descriptor_references;
    uint32_t vcpu_count;
    uint32_t device_count;
    uint32_t memory_slot_count;
    uint64_t backend_cookie;
} edge_kvm_vm_snapshot_t;

typedef struct edge_kvm_vcpu_snapshot {
    uint32_t vcpu_id;
    uint32_t descriptor_references;
    edge_kvm_handle_t vm;
    uint64_t backend_cookie;
    uint64_t run_calls;
} edge_kvm_vcpu_snapshot_t;

/* Callers must serialize mutations of one table. */
int edge_kvm_object_table_init(edge_kvm_object_table_t *table,
                               const edge_kvm_backend_ops_t *backend);
int edge_kvm_get_mce_cap_supported(edge_kvm_object_table_t *table,
                                   uint64_t *capability);
void edge_kvm_object_table_reset(edge_kvm_object_table_t *table);
int edge_kvm_vm_create(edge_kvm_object_table_t *table, uint32_t machine_type,
                       edge_kvm_handle_t *handle);
int edge_kvm_vm_retain(edge_kvm_object_table_t *table,
                       edge_kvm_handle_t handle);
int edge_kvm_vm_release(edge_kvm_object_table_t *table,
                        edge_kvm_handle_t handle);
int edge_kvm_vm_snapshot(const edge_kvm_object_table_t *table,
                         edge_kvm_handle_t handle,
                         edge_kvm_vm_snapshot_t *snapshot);
int edge_kvm_vm_set_memory_region(edge_kvm_object_table_t *table,
                                  edge_kvm_handle_t handle,
                                  const edge_kvm_memory_region_t *region);
int edge_kvm_vm_coalesced_mmio(
    edge_kvm_object_table_t *table, edge_kvm_handle_t handle,
    const edge_kvm_coalesced_mmio_zone_t *zone, uint8_t unregister);
int edge_kvm_vm_dirty_log_page_count(edge_kvm_object_table_t *table,
                                     edge_kvm_handle_t handle,
                                     uint32_t slot,
                                     uint32_t *page_count);
int edge_kvm_vm_get_dirty_log(edge_kvm_object_table_t *table,
                              edge_kvm_handle_t handle, uint32_t slot,
                              uint32_t first_page, uint32_t page_count,
                              uint64_t *bitmap, uint32_t bitmap_words);
int edge_kvm_vm_enable_cap(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           const edge_kvm_enable_cap_t *capability);
int edge_kvm_vm_clear_dirty_log(edge_kvm_object_table_t *table,
                                edge_kvm_handle_t handle, uint32_t slot,
                                uint32_t first_page, uint32_t page_count,
                                const uint64_t *bitmap,
                                uint32_t bitmap_words);
int edge_kvm_vm_get_preferred_target(edge_kvm_object_table_t *table,
                                     edge_kvm_handle_t handle,
                                     edge_kvm_vcpu_init_t *init);
int edge_kvm_vm_set_tss_address(edge_kvm_object_table_t *table,
                                edge_kvm_handle_t handle,
                                uint64_t address);
int edge_kvm_vm_set_identity_map_address(edge_kvm_object_table_t *table,
                                         edge_kvm_handle_t handle,
                                         uint64_t address);
int edge_kvm_vm_create_irqchip(edge_kvm_object_table_t *table,
                               edge_kvm_handle_t handle);
int edge_kvm_vm_set_gsi_routing(
    edge_kvm_object_table_t *table, edge_kvm_handle_t handle,
    const edge_kvm_irq_routing_entry_t *entries, uint32_t count);
int edge_kvm_vm_set_irq_line(edge_kvm_object_table_t *table,
                             edge_kvm_handle_t handle,
                             edge_kvm_irq_level_t *level);
int edge_kvm_vm_signal_msi(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           const edge_kvm_msi_t *message);
int edge_kvm_vm_get_irqchip(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            edge_kvm_irqchip_t *state);
int edge_kvm_vm_set_irqchip(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            const edge_kvm_irqchip_t *state);
int edge_kvm_vm_get_pit(edge_kvm_object_table_t *table,
                        edge_kvm_handle_t handle,
                        edge_kvm_pit_state2_t *state);
int edge_kvm_vm_set_pit(edge_kvm_object_table_t *table,
                        edge_kvm_handle_t handle,
                        const edge_kvm_pit_state2_t *state);
int edge_kvm_vm_create_pit(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           const edge_kvm_pit_config_t *config);
int edge_kvm_vm_get_clock(edge_kvm_object_table_t *table,
                          edge_kvm_handle_t handle,
                          edge_kvm_clock_data_t *state);
int edge_kvm_vm_set_clock(edge_kvm_object_table_t *table,
                          edge_kvm_handle_t handle,
                          const edge_kvm_clock_data_t *state);
int edge_kvm_vm_ioeventfd(edge_kvm_object_table_t *table,
                          edge_kvm_handle_t handle,
                          const edge_kvm_ioeventfd_registration_t *event);
int edge_kvm_vm_irqfd(edge_kvm_object_table_t *table,
                      edge_kvm_handle_t handle,
                      const edge_kvm_irqfd_registration_t *irq);
int edge_kvm_vcpu_create(edge_kvm_object_table_t *table,
                         edge_kvm_handle_t vm_handle, uint32_t vcpu_id,
                         edge_kvm_handle_t *vcpu_handle);
int edge_kvm_vcpu_retain(edge_kvm_object_table_t *table,
                         edge_kvm_handle_t handle);
int edge_kvm_vcpu_release(edge_kvm_object_table_t *table,
                          edge_kvm_handle_t handle);
int edge_kvm_vcpu_snapshot(const edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           edge_kvm_vcpu_snapshot_t *snapshot);
int edge_kvm_vcpu_run(edge_kvm_object_table_t *table,
                      edge_kvm_handle_t handle);
int edge_kvm_vcpu_init(edge_kvm_object_table_t *table,
                       edge_kvm_handle_t handle,
                       const edge_kvm_vcpu_init_t *init);
int edge_kvm_vcpu_get_one_reg(edge_kvm_object_table_t *table,
                              edge_kvm_handle_t handle, uint64_t id,
                              void *value, uint32_t size);
int edge_kvm_vcpu_set_one_reg(edge_kvm_object_table_t *table,
                              edge_kvm_handle_t handle, uint64_t id,
                              const void *value, uint32_t size);
int edge_kvm_vcpu_get_reg_list(edge_kvm_object_table_t *table,
                               edge_kvm_handle_t handle, uint64_t *ids,
                               uint32_t capacity, uint32_t *count);
int edge_kvm_vcpu_get_regs(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           edge_kvm_regs_t *registers);
int edge_kvm_vcpu_set_regs(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           const edge_kvm_regs_t *registers);
int edge_kvm_vcpu_get_sregs(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            edge_kvm_sregs_t *registers);
int edge_kvm_vcpu_set_sregs(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            const edge_kvm_sregs_t *registers);
int edge_kvm_vcpu_get_sregs2(edge_kvm_object_table_t *table,
                             edge_kvm_handle_t handle,
                             edge_kvm_sregs2_t *registers);
int edge_kvm_vcpu_set_sregs2(edge_kvm_object_table_t *table,
                             edge_kvm_handle_t handle,
                             const edge_kvm_sregs2_t *registers);
int edge_kvm_vcpu_get_fpu(edge_kvm_object_table_t *table,
                          edge_kvm_handle_t handle,
                          edge_kvm_fpu_t *state);
int edge_kvm_vcpu_set_fpu(edge_kvm_object_table_t *table,
                          edge_kvm_handle_t handle,
                          const edge_kvm_fpu_t *state);
int edge_kvm_vcpu_get_lapic(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            edge_kvm_lapic_state_t *state);
int edge_kvm_vcpu_set_lapic(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            const edge_kvm_lapic_state_t *state);
int edge_kvm_vcpu_get_debugregs(edge_kvm_object_table_t *table,
                                edge_kvm_handle_t handle,
                                edge_kvm_debugregs_t *state);
int edge_kvm_vcpu_set_debugregs(edge_kvm_object_table_t *table,
                                edge_kvm_handle_t handle,
                                const edge_kvm_debugregs_t *state);
int edge_kvm_vcpu_set_guest_debug(edge_kvm_object_table_t *table,
                                  edge_kvm_handle_t handle,
                                  const edge_kvm_guest_debug_x86_t *state);
int edge_kvm_vcpu_get_xcrs(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           edge_kvm_xcrs_t *state);
int edge_kvm_vcpu_set_xcrs(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           const edge_kvm_xcrs_t *state);
int edge_kvm_vcpu_get_xsave(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            edge_kvm_xsave_t *state);
int edge_kvm_vcpu_set_xsave(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            const edge_kvm_xsave_t *state);
int edge_kvm_get_msr_index_list(edge_kvm_object_table_t *table,
                                uint32_t *indices, uint32_t capacity,
                                uint32_t *count);
int edge_kvm_get_msr_feature_index_list(edge_kvm_object_table_t *table,
                                        uint32_t *indices,
                                        uint32_t capacity,
                                        uint32_t *count);
int edge_kvm_get_msr_features(edge_kvm_object_table_t *table,
                              edge_kvm_msr_entry_t *entries,
                              uint32_t count);
int edge_kvm_vcpu_get_msrs(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           edge_kvm_msr_entry_t *entries, uint32_t count);
int edge_kvm_vcpu_set_msrs(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           const edge_kvm_msr_entry_t *entries,
                           uint32_t count);
int edge_kvm_vcpu_get_mp_state(edge_kvm_object_table_t *table,
                               edge_kvm_handle_t handle,
                               edge_kvm_mp_state_t *state);
int edge_kvm_vcpu_set_mp_state(edge_kvm_object_table_t *table,
                               edge_kvm_handle_t handle,
                               const edge_kvm_mp_state_t *state);
int edge_kvm_vcpu_get_events(edge_kvm_object_table_t *table,
                             edge_kvm_handle_t handle,
                             edge_kvm_vcpu_events_t *events);
int edge_kvm_vcpu_set_events(edge_kvm_object_table_t *table,
                             edge_kvm_handle_t handle,
                             const edge_kvm_vcpu_events_t *events);
int edge_kvm_vcpu_set_vapic_address(edge_kvm_object_table_t *table,
                                    edge_kvm_handle_t handle,
                                    uint64_t address);
int64_t edge_kvm_vcpu_get_tsc_khz(edge_kvm_object_table_t *table,
                                  edge_kvm_handle_t handle);
int edge_kvm_vcpu_set_tsc_khz(edge_kvm_object_table_t *table,
                              edge_kvm_handle_t handle,
                              uint32_t frequency_khz);
int edge_kvm_vcpu_setup_mce(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            uint64_t capability);
int edge_kvm_vcpu_set_mce(edge_kvm_object_table_t *table,
                          edge_kvm_handle_t handle,
                          const edge_kvm_x86_mce_t *machine_check);
int edge_kvm_vcpu_set_signal_mask(edge_kvm_object_table_t *table,
                                  edge_kvm_handle_t handle,
                                  uint64_t mask);
int edge_kvm_get_supported_cpuid(edge_kvm_object_table_t *table,
                                 edge_kvm_cpuid_entry2_t *entries,
                                 uint32_t capacity, uint32_t *count);
int edge_kvm_vcpu_set_cpuid(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            const edge_kvm_cpuid_entry2_t *entries,
                            uint32_t count);
int edge_kvm_vcpu_get_cpuid(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            edge_kvm_cpuid_entry2_t *entries,
                            uint32_t capacity, uint32_t *count);
int edge_kvm_vcpu_mmap_page(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            uint32_t page_index,
                            uint64_t *physical_address);
int edge_kvm_vcpu_pre_fault_memory(
    edge_kvm_object_table_t *table, edge_kvm_handle_t handle,
    edge_kvm_pre_fault_memory_t *request);
int edge_kvm_vcpu_translate(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            edge_kvm_translation_t *translation);
int edge_kvm_device_create(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t vm, uint32_t type,
                           uint32_t flags, edge_kvm_handle_t *device);
int edge_kvm_device_test(edge_kvm_object_table_t *table,
                         edge_kvm_handle_t vm, uint32_t type);
int edge_kvm_device_retain(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t device);
int edge_kvm_device_release(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t device);
int edge_kvm_device_set_attr(edge_kvm_object_table_t *table,
                             edge_kvm_handle_t device,
                             const edge_kvm_device_attr_t *attribute,
                             const void *value, uint32_t value_size);
int edge_kvm_device_get_attr(edge_kvm_object_table_t *table,
                             edge_kvm_handle_t device,
                             const edge_kvm_device_attr_t *attribute,
                             void *value, uint32_t value_size);
int edge_kvm_device_has_attr(edge_kvm_object_table_t *table,
                             edge_kvm_handle_t device,
                             const edge_kvm_device_attr_t *attribute);

#endif
