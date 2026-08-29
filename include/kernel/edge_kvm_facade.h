/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_EDGE_KVM_FACADE_H
#define EDGEOS_KERNEL_EDGE_KVM_FACADE_H

#include <stdint.h>

#include "kernel/edge_kvm_capability.h"
#include "kernel/edge_kvm_object.h"

typedef enum edge_kvm_descriptor_kind {
    EDGE_KVM_DESCRIPTOR_VM = 1,
    EDGE_KVM_DESCRIPTOR_VCPU,
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
int edge_kvm_facade_descriptor_retain(edge_kvm_facade_t *facade,
                                      edge_kvm_descriptor_kind_t kind,
                                      edge_kvm_handle_t handle);
int edge_kvm_facade_descriptor_release(edge_kvm_facade_t *facade,
                                       edge_kvm_descriptor_kind_t kind,
                                       edge_kvm_handle_t handle);

#endif
