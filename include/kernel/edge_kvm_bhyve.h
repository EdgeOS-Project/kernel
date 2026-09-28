/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_EDGE_KVM_BHYVE_H
#define EDGEOS_KERNEL_EDGE_KVM_BHYVE_H

#include <stdint.h>

/* Register the architecture bhyve backend behind the EdgeOS KVM facade. */
int edge_kvm_bhyve_x86_register(void);
int edge_kvm_bhyve_arm64_register(void);

/* Resolve an Edge KVM VM backend cookie to the native bhyve VM object. */
void *edge_kvm_bhyve_x86_native_vm(uint64_t vm_cookie);

/* Validate an IOVA mapping against a registered bhyve guest memory slot. */
int edge_kvm_bhyve_x86_validate_dma_mapping(uint64_t vm_cookie,
                                            uint64_t iova,
                                            uint64_t userspace_address,
                                            uint64_t size,
                                            uint32_t flags);

#endif
