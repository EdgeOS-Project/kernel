/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS ARM64 Linux signal-return trampoline.
 * Copyright (c) EdgeOS Contributors.
 *
 * Linux AArch64 does not require applications to provide SA_RESTORER. The
 * kernel supplies an executable return sequence and places its address in
 * x30 when entering a handler. Keep that mechanism in architecture code:
 * shared signal policy stores the userspace action but must not interpret an
 * unused AArch64 sa_restorer field as a function pointer.
 */

#include <stdint.h>

#include "arch/arm64/signal.h"
#include "mm/arch_vm.h"

#define ARM64_LINUX_SYS_RT_SIGRETURN 139u

int edgeos_arm64_signal_trampoline_install(uint64_t address_space) {
    uint32_t *page;

    if (!address_space) return -1;
    page = (uint32_t *)arch_vm_alloc_page();
    if (!page) return -1;

    /* mov x8, #__NR_rt_sigreturn; svc #0; brk #0 */
    page[0] = 0xd2800008u | (ARM64_LINUX_SYS_RT_SIGRETURN << 5);
    page[1] = 0xd4000001u;
    page[2] = 0xd4200000u;
    arch_vm_sync_loaded_page(page, 1);

    if (arch_vm_map_user_page(
            address_space, EDGEOS_ARM64_SIGNAL_TRAMPOLINE_ADDRESS,
            (uint64_t)(uintptr_t)page,
            ARCH_VM_PROT_READ | ARCH_VM_PROT_EXEC) < 0) {
        arch_vm_free_page(page);
        return -1;
    }
    return 0;
}

uint64_t edgeos_arm64_signal_trampoline_address(void) {
    return EDGEOS_ARM64_SIGNAL_TRAMPOLINE_ADDRESS;
}
