/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_EDGE_KVM_CAPABILITY_H
#define EDGEOS_KERNEL_EDGE_KVM_CAPABILITY_H

#include <stdint.h>

#define EDGE_KVM_CAPABILITY_RECORD_MAX 64u

typedef struct edge_kvm_capability_record {
    uint32_t capability;
    int32_t value;
} edge_kvm_capability_record_t;

typedef struct edge_kvm_capability_table {
    uint8_t frozen;
    uint8_t reserved[3];
    uint32_t count;
    edge_kvm_capability_record_t records[EDGE_KVM_CAPABILITY_RECORD_MAX];
} edge_kvm_capability_table_t;

void edge_kvm_capability_table_init(edge_kvm_capability_table_t *table);
int edge_kvm_capability_set(edge_kvm_capability_table_t *table,
                            uint32_t capability, int32_t value);
void edge_kvm_capability_freeze(edge_kvm_capability_table_t *table);
int32_t edge_kvm_capability_query(const edge_kvm_capability_table_t *table,
                                  uint32_t capability);

#endif
