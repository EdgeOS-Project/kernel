/* SPDX-License-Identifier: MPL-2.0 */
/* Hypervisor identification for the FreeBSD driver bridge. */

#include <sys/kernel.h>
#include <sys/systm.h>

#if defined(__x86_64__)
#include <machine/cpufunc.h>
#endif

static void
bsd_hypervisor_identify(void *argument __unused)
{
#if defined(__x86_64__)
    unsigned int registers[4];

    do_cpuid(1, registers);
    if ((registers[2] & (1u << 31)) == 0) {
        vm_guest = VM_GUEST_NO;
        return;
    }

    do_cpuid(0x40000000u, registers);
    if (registers[1] == 0x7263694du &&
        registers[2] == 0x666f736fu &&
        registers[3] == 0x76482074u)
        vm_guest = VM_GUEST_HV;
    else
        vm_guest = VM_GUEST_VM;
#else
    vm_guest = VM_GUEST_NO;
#endif
}

SYSINIT(edgeos_hypervisor_identify, SI_SUB_VM, SI_ORDER_FIRST,
    bsd_hypervisor_identify, NULL);
