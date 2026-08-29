/* SPDX-License-Identifier: MPL-2.0 */
/* ABI layout and conservative capability policy regression tests. */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "kernel/edge_kvm_abi.h"
#include "kernel/edge_kvm_capability.h"
#include "kernel/linux_errno.h"

_Static_assert(sizeof(edge_kvm_userspace_memory_region_t) == 32,
               "KVM memory region ABI size changed");
_Static_assert(offsetof(edge_kvm_userspace_memory_region_t,
                        guest_physical_address) == 8,
               "KVM memory region guest address offset changed");
_Static_assert(offsetof(edge_kvm_userspace_memory_region_t,
                        userspace_address) == 24,
               "KVM memory region userspace address offset changed");
_Static_assert(EDGE_KVM_IOCTL_GET_API_VERSION == 0x0000ae00u,
               "KVM API version request changed");
_Static_assert(EDGE_KVM_IOCTL_CREATE_VM == 0x0000ae01u,
               "KVM create VM request changed");
_Static_assert(EDGE_KVM_IOCTL_CHECK_EXTENSION == 0x0000ae03u,
               "KVM extension request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_VCPU_MMAP_SIZE == 0x0000ae04u,
               "KVM vCPU mmap request changed");
_Static_assert(EDGE_KVM_IOCTL_CREATE_VCPU == 0x0000ae41u,
               "KVM create vCPU request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_USER_MEMORY_REGION == 0x4020ae46u,
               "KVM memory region request changed");
_Static_assert(EDGE_KVM_IOCTL_RUN == 0x0000ae80u,
               "KVM run request changed");

int main(void) {
    edge_kvm_capability_table_t table;

    edge_kvm_capability_table_init(&table);
    assert(edge_kvm_capability_query(&table, EDGE_KVM_CAP_USER_MEMORY) == 0);
    assert(edge_kvm_capability_set(
               &table, EDGE_KVM_CAP_USER_MEMORY, 1) == 0);
    assert(edge_kvm_capability_set(
               &table, EDGE_KVM_CAP_NR_MEMSLOTS, 64) == 0);
    assert(edge_kvm_capability_set(
               &table, EDGE_KVM_CAP_NR_MEMSLOTS, 32) == 0);
    assert(table.count == 2);
    assert(edge_kvm_capability_query(
               &table, EDGE_KVM_CAP_USER_MEMORY) == 1);
    assert(edge_kvm_capability_query(
               &table, EDGE_KVM_CAP_NR_MEMSLOTS) == 32);
    assert(edge_kvm_capability_query(&table, 0xffffffffu) == 0);
    assert(edge_kvm_capability_set(
               &table, EDGE_KVM_CAP_IRQCHIP, 0) == -EDGE_LINUX_EINVAL);

    edge_kvm_capability_freeze(&table);
    assert(edge_kvm_capability_set(
               &table, EDGE_KVM_CAP_IRQCHIP, 1) == -EDGE_LINUX_EBUSY);
    assert(edge_kvm_capability_query(&table, EDGE_KVM_CAP_IRQCHIP) == 0);

    edge_kvm_capability_table_init(&table);
    for (uint32_t index = 0; index < EDGE_KVM_CAPABILITY_RECORD_MAX; ++index)
        assert(edge_kvm_capability_set(&table, 0x1000u + index, 1) == 0);
    assert(edge_kvm_capability_set(&table, 0x2000u, 1) ==
           -EDGE_LINUX_ENOSPC);

    puts("edge_kvm_abi_unit: PASS");
    return 0;
}
