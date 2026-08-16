/* SPDX-License-Identifier: MPL-2.0 */
/* EFI runtime mapping and call bridge for x86_64 and ARM64. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/bus_dma.h"
#include "compat/freebsd/machine/efi.h"
#include <sys/errno.h>
#include <sys/efi.h>

static volatile uint32_t g_efi_map_active;
int print_efirt_faults = 1;
u_long cnt_efirt_faults;

void *
efi_phys_to_kva(vm_paddr_t physical_address)
{
    void *virtual_address = 0;

    if (bsd_bus_dma_virtual_address(physical_address, 1,
        &virtual_address) != 0)
        return 0;
    return virtual_address;
}

bool
efi_create_1t1_map(struct efi_md *map, int descriptor_count,
    int descriptor_size)
{
    struct efi_md *descriptor;

    if (!map || descriptor_count <= 0 ||
        descriptor_size < (int)sizeof(*map))
        return false;
    for (int index = 0; index < descriptor_count; ++index) {
        uint64_t length;
        void *mapping;

        descriptor = (struct efi_md *)((uint8_t *)map +
            (size_t)index * (size_t)descriptor_size);
        if ((descriptor->md_attr & EFI_MD_ATTR_RT) == 0)
            continue;
        if (descriptor->md_pages == 0 ||
            descriptor->md_pages > UINT64_MAX / EFI_PAGE_SIZE)
            return false;
        length = descriptor->md_pages * EFI_PAGE_SIZE;
        if (descriptor->md_phys > UINT64_MAX - (length - 1u) ||
            (descriptor->md_virt != 0 &&
             descriptor->md_virt != descriptor->md_phys) ||
            length > SIZE_MAX ||
            bsd_bus_dma_virtual_address(descriptor->md_phys,
                (size_t)length, &mapping) != 0 || !mapping)
            return false;
    }
    __atomic_store_n(&g_efi_map_active, 1u, __ATOMIC_RELEASE);
    return true;
}

void
efi_destroy_1t1_map(void)
{
    __atomic_store_n(&g_efi_map_active, 0u, __ATOMIC_RELEASE);
}

int
efi_arch_enter(void)
{
    if (__atomic_load_n(&g_efi_map_active, __ATOMIC_ACQUIRE) == 0)
        return ENXIO;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    return 0;
}

void
efi_arch_leave(void)
{
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

int
efi_rt_arch_call(struct efirt_callinfo *call)
{
    if (!call || call->ec_fptr == 0 || call->ec_argcnt > 5)
        return EINVAL;
    switch (call->ec_argcnt) {
    case 0:
        call->ec_efi_status =
            ((register_t EFIABI_ATTR (*)(void))call->ec_fptr)();
        break;
    case 1:
        call->ec_efi_status =
            ((register_t EFIABI_ATTR (*)(register_t))call->ec_fptr)(
                call->ec_arg1);
        break;
    case 2:
        call->ec_efi_status =
            ((register_t EFIABI_ATTR (*)(register_t, register_t))
                call->ec_fptr)(call->ec_arg1, call->ec_arg2);
        break;
    case 3:
        call->ec_efi_status =
            ((register_t EFIABI_ATTR (*)(register_t, register_t,
                register_t))call->ec_fptr)(call->ec_arg1,
                call->ec_arg2, call->ec_arg3);
        break;
    case 4:
        call->ec_efi_status =
            ((register_t EFIABI_ATTR (*)(register_t, register_t,
                register_t, register_t))call->ec_fptr)(call->ec_arg1,
                call->ec_arg2, call->ec_arg3, call->ec_arg4);
        break;
    default:
        call->ec_efi_status =
            ((register_t EFIABI_ATTR (*)(register_t, register_t,
                register_t, register_t, register_t))call->ec_fptr)(
                call->ec_arg1, call->ec_arg2, call->ec_arg3,
                call->ec_arg4, call->ec_arg5);
        break;
    }
    return 0;
}
