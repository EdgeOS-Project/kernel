/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_EDGE_KVM_RUNTIME_H
#define EDGEOS_KERNEL_EDGE_KVM_RUNTIME_H

#include <stdint.h>

#include "kernel/edge_kvm_facade.h"
#include "kernel/ioctl_runtime.h"

typedef enum kernel_edge_kvm_file_kind {
    KERNEL_EDGE_KVM_FILE_SYSTEM = 1,
    KERNEL_EDGE_KVM_FILE_VM,
    KERNEL_EDGE_KVM_FILE_VCPU,
    KERNEL_EDGE_KVM_FILE_DEVICE,
} kernel_edge_kvm_file_kind_t;

typedef struct kernel_edge_kvm_file {
    kernel_edge_kvm_file_kind_t kind;
    edge_kvm_handle_t handle;
} kernel_edge_kvm_file_t;

typedef struct kernel_edge_kvm_descriptor_backend_ops {
    int (*install)(void *context, kernel_edge_kvm_file_kind_t kind,
                   edge_kvm_handle_t handle);
    int (*resolve)(void *context, int32_t descriptor,
                   kernel_edge_kvm_file_t *file);
    int (*install_stats)(void *context,
                         kernel_edge_kvm_file_kind_t source_kind,
                         edge_kvm_handle_t handle);
    int (*install_guest_memfd)(void *context, uint64_t size);
    int (*close)(void *context, int32_t descriptor);
} kernel_edge_kvm_descriptor_backend_ops_t;

int kernel_edge_kvm_descriptor_backend_register(
    const kernel_edge_kvm_descriptor_backend_ops_t *ops, void *context);
int kernel_edge_kvm_descriptor_runtime_initialize(void);
int kernel_edge_kvm_backend_register(
    const edge_kvm_backend_ops_t *backend,
    const edge_kvm_capability_table_t *capabilities);
int64_t kernel_edge_kvm_ioctl(const kernel_ioctl_request_t *request);
int kernel_edge_kvm_vcpu_mmap_page(edge_kvm_handle_t handle,
                                   uint32_t page_index,
                                   uint64_t *physical_address);
int kernel_edge_kvm_descriptor_retain(kernel_edge_kvm_file_kind_t kind,
                                      edge_kvm_handle_t handle);
int kernel_edge_kvm_descriptor_release(kernel_edge_kvm_file_kind_t kind,
                                       edge_kvm_handle_t handle);
int64_t kernel_edge_kvm_stats_read(kernel_edge_kvm_file_kind_t source_kind,
                                   edge_kvm_handle_t handle,
                                   uint64_t offset, void *buffer,
                                   uint32_t length);

#endif
