/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS host glue for the pinned FreeBSD ARM64 VMM implementation. */

#include <stdbool.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/callout.h>
#include <sys/mutex.h>

#include <arm64/vmm/arm64.h>
#include <arm64/vmm/vmm_handlers.h>
#include <machine/hypervisor.h>

volatile uint32_t edgeos_arm64_booted_from_el2;

bool
has_hyp(void)
{
    return __atomic_load_n(&edgeos_arm64_booted_from_el2,
        __ATOMIC_ACQUIRE) != 0;
}

bool
in_vhe(void)
{
    uint64_t current_el;

    __asm__ __volatile__("mrs %0, CurrentEL" : "=r"(current_el));
    return (current_el & UINT64_C(0xc)) == UINT64_C(0x8);
}

uint64_t
vmm_read_reg(uint64_t reg)
{
    if (in_vhe())
        return vmm_vhe_read_reg(reg);
    return vmm_call_hyp(HYP_READ_REGISTER, reg);
}

uint64_t
vmm_enter_guest(struct hyp *hyp, struct hypctx *hypctx)
{
    if (in_vhe())
        return vmm_vhe_enter_guest(hyp, hypctx);
    return vmm_call_hyp(HYP_ENTER_GUEST, hyp->el2_addr, hypctx->el2_addr);
}

void
vmm_clean_s2_tlbi(void)
{
    if (in_vhe())
        vmm_vhe_clean_s2_tlbi();
    else
        (void)vmm_call_hyp(HYP_CLEAN_S2_TLBI);
}

void
vmm_s2_tlbi_range(uint64_t vttbr, vm_offset_t start, vm_offset_t end,
    bool final_only)
{
    if (in_vhe())
        vmm_vhe_s2_tlbi_range(vttbr, start, end, final_only);
    else
        (void)vmm_call_hyp(HYP_S2_TLBI_RANGE, vttbr, start, end,
            final_only);
}

void
vmm_s2_tlbi_all(uint64_t vttbr)
{
    if (in_vhe())
        vmm_vhe_s2_tlbi_all(vttbr);
    else
        (void)vmm_call_hyp(HYP_S2_TLBI_ALL, vttbr);
}
