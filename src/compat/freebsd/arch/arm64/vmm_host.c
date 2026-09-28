/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS host glue for the pinned FreeBSD ARM64 VMM implementation. */

#include <stdbool.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/callout.h>
#include <sys/mutex.h>

#include <arm64/vmm/arm64.h>
#include <arm64/vmm/vmm_handlers.h>
#include <arm64/vmm/io/vtimer.h>
#include <machine/cpufunc.h>
#include <machine/hypervisor.h>

volatile uint32_t edgeos_arm64_booted_from_el2;

void edge_bhyve_upstream_vtimer_vmcleanup(struct hyp *hyp);

struct edge_host_timer_state {
    register_t daif;
    uint64_t cval;
    uint64_t ctl;
};

static void
edge_host_timer_save(struct edge_host_timer_state *state)
{
    state->daif = intr_disable();
    __asm__ __volatile__("mrs %0, cntv_cval_el0" : "=r"(state->cval));
    __asm__ __volatile__("mrs %0, cntv_ctl_el0" : "=r"(state->ctl));
}

static void
edge_host_timer_restore(const struct edge_host_timer_state *state)
{
    __asm__ __volatile__("msr cntv_cval_el0, %0" : : "r"(state->cval));
    __asm__ __volatile__("msr cntv_ctl_el0, %0" : : "r"(state->ctl));
    __asm__ __volatile__("isb" ::: "memory");
    intr_restore(state->daif);
}

void
vtimer_vmcleanup(struct hyp *hyp)
{
    struct edge_host_timer_state host_timer;

    /* Upstream cleanup may disable CNTV after the last vCPU exits. */
    edge_host_timer_save(&host_timer);
    edge_bhyve_upstream_vtimer_vmcleanup(hyp);
    edge_host_timer_restore(&host_timer);
}

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
    struct edge_host_timer_state host_timer;
    uint64_t result;

    /* The host scheduler and guest share CNTV on EdgeOS. */
    edge_host_timer_save(&host_timer);
    if (in_vhe())
        result = vmm_vhe_enter_guest(hyp, hypctx);
    else
        result = vmm_call_hyp(HYP_ENTER_GUEST, hyp->el2_addr,
            hypctx->el2_addr);
    /* Restore the host deadline before host interrupts can run. */
    edge_host_timer_restore(&host_timer);
    return result;
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
