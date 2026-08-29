/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_EDGE_KVM_OBJECT_H
#define EDGEOS_KERNEL_EDGE_KVM_OBJECT_H

#include <stdint.h>

#define EDGE_KVM_API_VERSION 12u
#define EDGE_KVM_OBJECT_MAX_VMS 16u
#define EDGE_KVM_OBJECT_MAX_VCPUS 256u
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

typedef struct edge_kvm_backend_ops {
    void *context;
    int (*vm_create)(void *context, uint32_t machine_type,
                     uint64_t *backend_cookie);
    void (*vm_destroy)(void *context, uint64_t backend_cookie);
    int (*vcpu_create)(void *context, uint64_t vm_cookie, uint32_t vcpu_id,
                       uint64_t *backend_cookie);
    void (*vcpu_destroy)(void *context, uint64_t vcpu_cookie);
    int (*memory_region_set)(void *context, uint64_t vm_cookie,
                             const edge_kvm_memory_region_t *region);
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
} edge_kvm_vcpu_object_t;

typedef struct edge_kvm_object_table {
    uint32_t next_generation;
    uint32_t active_vm_count;
    uint32_t active_vcpu_count;
    uint32_t reserved;
    edge_kvm_backend_ops_t backend;
    edge_kvm_vm_object_t vms[EDGE_KVM_OBJECT_MAX_VMS];
    edge_kvm_vcpu_object_t vcpus[EDGE_KVM_OBJECT_MAX_VCPUS];
} edge_kvm_object_table_t;

typedef struct edge_kvm_vm_snapshot {
    uint32_t machine_type;
    uint32_t descriptor_references;
    uint32_t vcpu_count;
    uint32_t memory_slot_count;
    uint64_t backend_cookie;
} edge_kvm_vm_snapshot_t;

typedef struct edge_kvm_vcpu_snapshot {
    uint32_t vcpu_id;
    uint32_t descriptor_references;
    edge_kvm_handle_t vm;
    uint64_t backend_cookie;
} edge_kvm_vcpu_snapshot_t;

/* Callers must serialize mutations of one table. */
int edge_kvm_object_table_init(edge_kvm_object_table_t *table,
                               const edge_kvm_backend_ops_t *backend);
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

#endif
