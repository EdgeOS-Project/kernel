/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_EDGE_KVM_FACADE_H
#define EDGEOS_KERNEL_EDGE_KVM_FACADE_H

#include <stdint.h>

#include "kernel/edge_kvm_abi.h"
#include "kernel/edge_kvm_capability.h"
#include "kernel/edge_kvm_object.h"

typedef enum edge_kvm_descriptor_kind {
    EDGE_KVM_DESCRIPTOR_VM = 1,
    EDGE_KVM_DESCRIPTOR_VCPU,
    EDGE_KVM_DESCRIPTOR_DEVICE,
} edge_kvm_descriptor_kind_t;

typedef struct edge_kvm_descriptor_ops {
    void *context;
    int (*install)(void *context, edge_kvm_descriptor_kind_t kind,
                   edge_kvm_handle_t handle);
} edge_kvm_descriptor_ops_t;

typedef struct edge_kvm_facade {
    uint8_t initialized;
    uint8_t reserved[7];
    edge_kvm_capability_table_t capabilities;
    edge_kvm_descriptor_ops_t descriptors;
    edge_kvm_object_table_t objects;
} edge_kvm_facade_t;

int edge_kvm_facade_init(edge_kvm_facade_t *facade,
                         const edge_kvm_backend_ops_t *backend,
                         const edge_kvm_descriptor_ops_t *descriptors,
                         const edge_kvm_capability_table_t *capabilities);
void edge_kvm_facade_reset(edge_kvm_facade_t *facade);
int64_t edge_kvm_facade_system_ioctl(edge_kvm_facade_t *facade,
                                     uint32_t request, uint64_t argument);
/* Pointer arguments must reference kernel-owned copies validated by usercopy. */
int64_t edge_kvm_facade_vm_ioctl(edge_kvm_facade_t *facade,
                                 edge_kvm_handle_t vm, uint32_t request,
                                 uint64_t argument);
int edge_kvm_facade_vm_get_preferred_target(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vm,
    edge_kvm_vcpu_init_t *init);
int edge_kvm_facade_device_create(edge_kvm_facade_t *facade,
                                  edge_kvm_handle_t vm, uint32_t type,
                                  uint32_t flags);
int edge_kvm_facade_device_test(edge_kvm_facade_t *facade,
                                edge_kvm_handle_t vm, uint32_t type);
int edge_kvm_facade_device_set_attr(
    edge_kvm_facade_t *facade, edge_kvm_handle_t device,
    const edge_kvm_device_attr_t *attribute, const void *value,
    uint32_t value_size);
int edge_kvm_facade_device_get_attr(
    edge_kvm_facade_t *facade, edge_kvm_handle_t device,
    const edge_kvm_device_attr_t *attribute, void *value,
    uint32_t value_size);
int edge_kvm_facade_device_has_attr(
    edge_kvm_facade_t *facade, edge_kvm_handle_t device,
    const edge_kvm_device_attr_t *attribute);
int edge_kvm_facade_vm_set_gsi_routing(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vm,
    const edge_kvm_irq_routing_entry_t *entries, uint32_t count);
int edge_kvm_facade_vm_set_irq_line(edge_kvm_facade_t *facade,
                                    edge_kvm_handle_t vm,
                                    edge_kvm_irq_level_t *level);
int edge_kvm_facade_vm_signal_msi(edge_kvm_facade_t *facade,
                                  edge_kvm_handle_t vm,
                                  const edge_kvm_msi_t *message);
int edge_kvm_facade_vm_get_irqchip(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vm,
                                   edge_kvm_irqchip_t *state);
int edge_kvm_facade_vm_set_irqchip(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vm,
                                   const edge_kvm_irqchip_t *state);
int edge_kvm_facade_vm_get_pit(edge_kvm_facade_t *facade,
                               edge_kvm_handle_t vm,
                               edge_kvm_pit_state2_t *state);
int edge_kvm_facade_vm_set_pit(edge_kvm_facade_t *facade,
                               edge_kvm_handle_t vm,
                               const edge_kvm_pit_state2_t *state);
int edge_kvm_facade_vm_get_clock(edge_kvm_facade_t *facade,
                                 edge_kvm_handle_t vm,
                                 edge_kvm_clock_data_t *state);
int edge_kvm_facade_vm_set_clock(edge_kvm_facade_t *facade,
                                 edge_kvm_handle_t vm,
                                 const edge_kvm_clock_data_t *state);
int edge_kvm_facade_vm_ioeventfd(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vm,
    const edge_kvm_ioeventfd_registration_t *event);
int edge_kvm_facade_vm_irqfd(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vm,
    const edge_kvm_irqfd_registration_t *irq);
int64_t edge_kvm_facade_vcpu_ioctl(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vcpu,
                                   uint32_t request, uint64_t argument);
int edge_kvm_facade_vcpu_init(edge_kvm_facade_t *facade,
                              edge_kvm_handle_t vcpu,
                              const edge_kvm_vcpu_init_t *init);
int edge_kvm_facade_vcpu_get_one_reg(edge_kvm_facade_t *facade,
                                     edge_kvm_handle_t vcpu, uint64_t id,
                                     void *value, uint32_t size);
int edge_kvm_facade_vcpu_set_one_reg(edge_kvm_facade_t *facade,
                                     edge_kvm_handle_t vcpu, uint64_t id,
                                     const void *value, uint32_t size);
int edge_kvm_facade_vcpu_get_reg_list(edge_kvm_facade_t *facade,
                                      edge_kvm_handle_t vcpu,
                                      uint64_t *ids, uint32_t capacity,
                                      uint32_t *count);
int edge_kvm_facade_vcpu_mmap_page(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vcpu,
                                   uint32_t page_index,
                                   uint64_t *physical_address);
int edge_kvm_facade_vcpu_pre_fault_memory(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
    edge_kvm_pre_fault_memory_t *request);
int edge_kvm_facade_vcpu_translate(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vcpu,
                                   edge_kvm_translation_t *translation);
int edge_kvm_facade_vcpu_get_regs(edge_kvm_facade_t *facade,
                                  edge_kvm_handle_t vcpu,
                                  edge_kvm_regs_t *registers);
int edge_kvm_facade_vcpu_set_regs(edge_kvm_facade_t *facade,
                                  edge_kvm_handle_t vcpu,
                                  const edge_kvm_regs_t *registers);
int edge_kvm_facade_vcpu_get_sregs(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vcpu,
                                   edge_kvm_sregs_t *registers);
int edge_kvm_facade_vcpu_set_sregs(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vcpu,
                                   const edge_kvm_sregs_t *registers);
int edge_kvm_facade_vcpu_get_sregs2(edge_kvm_facade_t *facade,
                                    edge_kvm_handle_t vcpu,
                                    edge_kvm_sregs2_t *registers);
int edge_kvm_facade_vcpu_set_sregs2(edge_kvm_facade_t *facade,
                                    edge_kvm_handle_t vcpu,
                                    const edge_kvm_sregs2_t *registers);
int edge_kvm_facade_vcpu_get_fpu(edge_kvm_facade_t *facade,
                                 edge_kvm_handle_t vcpu,
                                 edge_kvm_fpu_t *state);
int edge_kvm_facade_vcpu_set_fpu(edge_kvm_facade_t *facade,
                                 edge_kvm_handle_t vcpu,
                                 const edge_kvm_fpu_t *state);
int edge_kvm_facade_vcpu_get_lapic(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vcpu,
                                   edge_kvm_lapic_state_t *state);
int edge_kvm_facade_vcpu_set_lapic(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vcpu,
                                   const edge_kvm_lapic_state_t *state);
int edge_kvm_facade_vcpu_get_debugregs(edge_kvm_facade_t *facade,
                                       edge_kvm_handle_t vcpu,
                                       edge_kvm_debugregs_t *state);
int edge_kvm_facade_vcpu_set_debugregs(edge_kvm_facade_t *facade,
                                       edge_kvm_handle_t vcpu,
                                       const edge_kvm_debugregs_t *state);
int edge_kvm_facade_vcpu_set_guest_debug(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
    const edge_kvm_guest_debug_x86_t *state);
int edge_kvm_facade_vcpu_get_xcrs(edge_kvm_facade_t *facade,
                                  edge_kvm_handle_t vcpu,
                                  edge_kvm_xcrs_t *state);
int edge_kvm_facade_vcpu_set_xcrs(edge_kvm_facade_t *facade,
                                  edge_kvm_handle_t vcpu,
                                  const edge_kvm_xcrs_t *state);
int edge_kvm_facade_vcpu_get_xsave(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vcpu,
                                   edge_kvm_xsave_t *state);
int edge_kvm_facade_vcpu_set_xsave(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vcpu,
                                   const edge_kvm_xsave_t *state);
int edge_kvm_facade_get_msr_index_list(
    edge_kvm_facade_t *facade, uint32_t *indices,
    uint32_t capacity, uint32_t *count);
int edge_kvm_facade_get_msr_feature_index_list(
    edge_kvm_facade_t *facade, uint32_t *indices,
    uint32_t capacity, uint32_t *count);
int edge_kvm_facade_get_msr_features(
    edge_kvm_facade_t *facade, edge_kvm_msr_entry_t *entries,
    uint32_t count);
int edge_kvm_facade_get_mce_cap_supported(edge_kvm_facade_t *facade,
                                          uint64_t *capability);
int edge_kvm_facade_vcpu_get_msrs(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
    edge_kvm_msr_entry_t *entries, uint32_t count);
int edge_kvm_facade_vcpu_set_msrs(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
    const edge_kvm_msr_entry_t *entries, uint32_t count);
int edge_kvm_facade_vcpu_get_mp_state(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
    edge_kvm_mp_state_t *state);
int edge_kvm_facade_vcpu_set_mp_state(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
    const edge_kvm_mp_state_t *state);
int edge_kvm_facade_vcpu_get_events(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
    edge_kvm_vcpu_events_t *events);
int edge_kvm_facade_vcpu_set_events(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
    const edge_kvm_vcpu_events_t *events);
int edge_kvm_facade_vcpu_set_vapic_address(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu, uint64_t address);
int64_t edge_kvm_facade_vcpu_get_tsc_khz(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu);
int edge_kvm_facade_vcpu_set_tsc_khz(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
    uint32_t frequency_khz);
int edge_kvm_facade_vcpu_setup_mce(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
    uint64_t capability);
int edge_kvm_facade_vcpu_set_mce(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
    const edge_kvm_x86_mce_t *machine_check);
int edge_kvm_facade_vcpu_set_signal_mask(edge_kvm_facade_t *facade,
                                         edge_kvm_handle_t vcpu,
                                         uint64_t mask);
int edge_kvm_facade_get_supported_cpuid(
    edge_kvm_facade_t *facade, edge_kvm_cpuid_entry2_t *entries,
    uint32_t capacity, uint32_t *count);
int edge_kvm_facade_vcpu_set_cpuid(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
    const edge_kvm_cpuid_entry2_t *entries, uint32_t count);
int edge_kvm_facade_vcpu_get_cpuid(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
    edge_kvm_cpuid_entry2_t *entries, uint32_t capacity, uint32_t *count);
int edge_kvm_facade_vm_set_memory_region(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vm,
    const edge_kvm_userspace_memory_region_t *region);
int edge_kvm_facade_vm_coalesced_mmio(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vm,
    const edge_kvm_coalesced_mmio_zone_t *zone, uint8_t unregister);
int edge_kvm_facade_vm_dirty_log_page_count(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vm, uint32_t slot,
    uint32_t *page_count);
int edge_kvm_facade_vm_get_dirty_log(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vm, uint32_t slot,
    uint32_t first_page, uint32_t page_count, uint64_t *bitmap,
    uint32_t bitmap_words);
int edge_kvm_facade_vm_enable_cap(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vm,
    const edge_kvm_enable_cap_t *capability);
int edge_kvm_facade_vm_clear_dirty_log(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vm, uint32_t slot,
    uint32_t first_page, uint32_t page_count, const uint64_t *bitmap,
    uint32_t bitmap_words);
int edge_kvm_facade_descriptor_retain(edge_kvm_facade_t *facade,
                                      edge_kvm_descriptor_kind_t kind,
                                      edge_kvm_handle_t handle);
int edge_kvm_facade_descriptor_release(edge_kvm_facade_t *facade,
                                       edge_kvm_descriptor_kind_t kind,
                                       edge_kvm_handle_t handle);

#endif
