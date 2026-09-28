/* SPDX-License-Identifier: MPL-2.0 */
/* Conservative KVM capability publication for backend feature probes. */

#include "kernel/edge_kvm_capability.h"
#include "kernel/linux_errno.h"
#include "string.h"

void edge_kvm_capability_table_init(edge_kvm_capability_table_t *table) {
    if (table) memset(table, 0, sizeof(*table));
}

int edge_kvm_capability_set(edge_kvm_capability_table_t *table,
                            uint32_t capability, int32_t value) {
    if (!table || value <= 0) return -EDGE_LINUX_EINVAL;
    if (table->frozen) return -EDGE_LINUX_EBUSY;

    for (uint32_t index = 0; index < table->count; ++index) {
        if (table->records[index].capability != capability) continue;
        table->records[index].value = value;
        return 0;
    }
    if (table->count >= EDGE_KVM_CAPABILITY_RECORD_MAX)
        return -EDGE_LINUX_ENOSPC;
    table->records[table->count].capability = capability;
    table->records[table->count].value = value;
    ++table->count;
    return 0;
}

void edge_kvm_capability_freeze(edge_kvm_capability_table_t *table) {
    if (table) table->frozen = 1u;
}

int32_t edge_kvm_capability_query(const edge_kvm_capability_table_t *table,
                                  uint32_t capability) {
    if (!table) return 0;
    for (uint32_t index = 0; index < table->count; ++index) {
        if (table->records[index].capability == capability)
            return table->records[index].value;
    }
    return 0;
}
