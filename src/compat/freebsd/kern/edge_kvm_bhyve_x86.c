/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS-owned KVM object adapter for the imported FreeBSD bhyve core. */

#include <stdint.h>

#include "arch/x86_64/fpu.h"
#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/cpu.h"
#include "compat/freebsd/sys/conf.h"
#include "compat/freebsd/sys/mutex.h"
#include "compat/freebsd/sys/sglist.h"
#include "compat/freebsd/vm/vm.h"
#include "compat/freebsd/vm/vm_object.h"
#include "compat/freebsd/vm/vm_pager.h"
#include "kernel/edge_kvm_abi.h"
#include "kernel/edge_kvm_bhyve.h"
#include "kernel/edge_vfio_runtime.h"
#include "kernel/edge_vfio_bhyve.h"
#include "kernel/edge_kvm_capability.h"
#include "kernel/eventfd.h"
#include "kernel/edge_kvm_object.h"
#include "kernel/edge_kvm_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/mm_runtime.h"
#include "kernel/process_runtime.h"
#include "kernel/signal_runtime.h"
#include "mm/arch_vm.h"
#include "sys/process.h"
#include "sys/boottime.h"
#include "sys/scheduler.h"

#include <sys/param.h>
#include <sys/callout.h>
#include <sys/mman.h>
#include <sys/smp.h>
#include <sys/time.h>
#include <x86/psl.h>
#include <x86/specialreg.h>
#include <dev/ic/i8253reg.h>
#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_dev.h>
#include <dev/vmm/vmm_vm.h>
#include <machine/smp.h>
#include <machine/cpufunc.h>
#include <machine/vmm_instruction_emul.h>
#include <machine/clock.h>
#include <machine/cputypes.h>
#include <machine/fpu.h>
#include <machine/md_var.h>
#include <machine/vmm.h>
#include <amd64/vmm/x86.h>
#include <amd64/vmm/vmm_host.h>
#include <amd64/vmm/vmm_lapic.h>
#include <amd64/vmm/io/vatpit.h>
#include <amd64/vmm/io/vatpic.h>
#include <amd64/vmm/io/vioapic.h>
#include <amd64/vmm/io/vlapic.h>
#include <amd64/vmm/io/vlapic_priv.h>
#include <amd64/vmm/amd/vmcb.h>
#include <amd64/vmm/amd/svm.h>
#include <amd64/vmm/amd/svm_msr.h>
#include <amd64/vmm/amd/svm_softc.h>
#include <amd64/vmm/intel/vmx.h>
#include <amd64/vmm/intel/vmx_msr.h>
#include <amd64/vmm/vmm_util.h>

struct vlapic;
struct pcpu;
struct svm_regctx;
struct trapframe;
void nmi_register_handler(int (*handler)(struct trapframe *));
uint64_t vlapic_get_apicbase(struct vlapic *vlapic);
int vlapic_set_apicbase(struct vlapic *vlapic, uint64_t value);
uint64_t vlapic_get_cr8(struct vlapic *vlapic);
void vlapic_set_cr8(struct vlapic *vlapic, uint64_t value);

#define EDGE_KVM_BHYVE_MAX_SLOTS VM_MAXSYSMEM
#define EDGE_KVM_BHYVE_MAX_MSRS EDGE_KVM_MAX_MSR_ENTRIES
#define EDGE_KVM_BHYVE_MAX_IOEVENTFDS 256u
#define EDGE_KVM_BHYVE_MAX_IRQFDS 256u
#define EDGE_KVM_BHYVE_MAX_VFIO_DEVICES EDGE_KVM_OBJECT_MAX_DEVICES
#define EDGE_KVM_BHYVE_MAX_VFIO_FILES EDGE_VFIO_MAX_GROUPS
#define EDGE_KVM_BHYVE_PAGE_CHUNK_CAPACITY 2048u
#define EDGE_KVM_BHYVE_MCE_FEATURES \
    (EDGE_KVM_X86_MCE_CTL_PRESENT | EDGE_KVM_X86_MCE_SER_PRESENT)
#define EDGE_KVM_BHYVE_MSR_MCG_CAP UINT32_C(0x00000179)
#define EDGE_KVM_BHYVE_MSR_MCG_STATUS UINT32_C(0x0000017a)
#define EDGE_KVM_BHYVE_MSR_MCG_CTL UINT32_C(0x0000017b)
#define EDGE_KVM_BHYVE_MSR_MC0_CTL UINT32_C(0x00000400)
#define EDGE_KVM_BHYVE_MSR_MC_BANK_STRIDE 4u
#define EDGE_KVM_BHYVE_MSR_IA32_FEATURE_CONTROL UINT32_C(0x0000003a)
#define EDGE_KVM_BHYVE_MSR_IA32_BIOS_SIGN_ID UINT32_C(0x0000008b)
#define EDGE_KVM_BHYVE_MSR_IA32_MISC_FEATURES_ENABLES UINT32_C(0x00000140)
#define EDGE_KVM_BHYVE_MSR_IA32_PERF_CAPABILITIES UINT32_C(0x00000345)
#define EDGE_KVM_BHYVE_MSR_TSC_AUX UINT32_C(0xc0000103)
#define EDGE_KVM_BHYVE_MSR_AMD64_LS_CFG UINT32_C(0xc0011020)
#define EDGE_KVM_BHYVE_MSR_AMD_PERF_LEGACY_FIRST UINT32_C(0xc0010000)
#define EDGE_KVM_BHYVE_MSR_AMD_PERF_LEGACY_LAST UINT32_C(0xc0010007)
#define EDGE_KVM_BHYVE_MSR_AMD_PERF_EXT_FIRST UINT32_C(0xc0010200)
#define EDGE_KVM_BHYVE_MSR_AMD_PERF_EXT_LAST UINT32_C(0xc001020b)
#define EDGE_KVM_BHYVE_MSR_AMD_NB_CFG UINT32_C(0xc001001f)
#define EDGE_KVM_BHYVE_MSR_AMD_HWCR UINT32_C(0xc0010015)
#define EDGE_KVM_BHYVE_MSR_AMD_PATCH_LOADER UINT32_C(0xc0010020)
#define EDGE_KVM_BHYVE_MSR_AMD_MMIO_CONF_BASE UINT32_C(0xc0010058)
#define EDGE_KVM_BHYVE_MSR_AMD_TSEG_ADDR UINT32_C(0xc0010112)
#define EDGE_KVM_BHYVE_MSR_AMD_TSEG_MASK UINT32_C(0xc0010113)
#define EDGE_KVM_BHYVE_MSR_AMD_HSAVE_PA UINT32_C(0xc0010117)
#define EDGE_KVM_BHYVE_MSR_AMD_DC_CFG UINT32_C(0xc0011022)
#define EDGE_KVM_BHYVE_MSR_AMD_TW_CFG UINT32_C(0xc0011023)
#define EDGE_KVM_BHYVE_MSR_AMD_BU_CFG2 UINT32_C(0xc001102a)
#define EDGE_KVM_BHYVE_MSR_AMD_F15H_EX_CFG UINT32_C(0xc001102c)
#define EDGE_KVM_BHYVE_MSR_AMD_DE_CFG UINT32_C(0xc0011029)

typedef struct edge_kvm_bhyve_page_chunk {
    struct edge_kvm_bhyve_page_chunk *next;
    uint32_t count;
    uint32_t reserved;
    uint64_t pages[EDGE_KVM_BHYVE_PAGE_CHUNK_CAPACITY];
} edge_kvm_bhyve_page_chunk_t;

typedef struct edge_kvm_bhyve_memory_slot {
    uint8_t active;
    uint8_t reserved[7];
    uint64_t guest_physical_address;
    uint64_t userspace_address;
    uint64_t memory_size;
    edge_kvm_bhyve_page_chunk_t *page_chunks;
    uint32_t page_count;
    uint32_t flags;
} edge_kvm_bhyve_memory_slot_t;

typedef struct edge_kvm_bhyve_coalesced_zone {
    uint8_t active;
    uint8_t reserved[7];
    edge_kvm_coalesced_mmio_zone_t zone;
} edge_kvm_bhyve_coalesced_zone_t;

typedef struct edge_kvm_bhyve_ioeventfd {
    uint8_t active;
    uint8_t reserved[3];
    edge_kvm_ioeventfd_registration_t registration;
} edge_kvm_bhyve_ioeventfd_t;

struct edge_kvm_bhyve_vm;

typedef struct edge_kvm_bhyve_irqfd {
    uint8_t active;
    uint8_t reserved[3];
    edge_kvm_irqfd_registration_t registration;
    struct edge_kvm_bhyve_vm *vm;
} edge_kvm_bhyve_irqfd_t;

typedef struct edge_bhyve_atpic_layout {
    bool ready;
    int icw_num;
    int rd_cmd_reg;
    bool aeoi;
    bool poll;
    bool rotate;
    bool sfn;
    int irq_base;
    uint8_t request;
    uint8_t service;
    uint8_t mask;
    uint8_t smm;
    int acnt[8];
    int lowprio;
    bool intr_raised;
} edge_bhyve_atpic_layout_t;

typedef struct edge_bhyve_vatpic_layout {
    struct vm *vm;
    struct mtx mtx;
    edge_bhyve_atpic_layout_t atpic[2];
    uint8_t elc[2];
} edge_bhyve_vatpic_layout_t;

typedef struct edge_bhyve_vioapic_layout {
    struct vm *vm;
    struct mtx mtx;
    uint32_t id;
    uint32_t ioregsel;
    struct {
        uint64_t reg;
        int acnt;
    } rtbl[32];
} edge_bhyve_vioapic_layout_t;

struct edge_bhyve_vatpit_layout;

typedef struct edge_bhyve_pit_callout_arg_layout {
    struct edge_bhyve_vatpit_layout *vatpit;
    int channel_num;
} edge_bhyve_pit_callout_arg_layout_t;

typedef struct edge_bhyve_pit_channel_layout {
    int mode;
    uint16_t initial;
    struct bintime now_bt;
    uint8_t cr[2];
    uint8_t ol[2];
    bool slatched;
    uint8_t status;
    int crbyte;
    int olbyte;
    int frbyte;
    struct callout callout;
    struct bintime callout_bt;
    edge_bhyve_pit_callout_arg_layout_t callout_arg;
} edge_bhyve_pit_channel_layout_t;

typedef struct edge_bhyve_vatpit_layout {
    struct vm *vm;
    struct mtx mtx;
    struct bintime freq_bt;
    edge_bhyve_pit_channel_layout_t channel[3];
} edge_bhyve_vatpit_layout_t;

typedef struct edge_kvm_bhyve_vm {
    struct vm *vm;
    uint64_t tss_address;
    uint64_t identity_map_address;
    uint8_t tss_address_set;
    uint8_t identity_map_address_set;
    uint8_t irqchip_created;
    uint8_t pit_created;
    uint32_t route_count;
    edge_kvm_irq_routing_entry_t routes[EDGE_KVM_MAX_IRQ_ROUTES];
    uint8_t irq_levels[EDGE_KVM_MAX_IRQ_ROUTES];
    edge_kvm_pit_state2_t pit_shadow;
    uint64_t clock_base_ns;
    uint64_t clock_host_ns;
    edge_kvm_bhyve_ioeventfd_t ioeventfds[
        EDGE_KVM_BHYVE_MAX_IOEVENTFDS];
    edge_kvm_bhyve_irqfd_t irqfds[EDGE_KVM_BHYVE_MAX_IRQFDS];
    edge_kvm_bhyve_memory_slot_t slots[EDGE_KVM_BHYVE_MAX_SLOTS];
    edge_kvm_bhyve_coalesced_zone_t
        coalesced_zones[EDGE_KVM_MAX_COALESCED_MMIO_ZONES];
    void *coalesced_mmio_page;
    volatile uint8_t coalesced_mmio_lock;
} edge_kvm_bhyve_vm_t;

void *
edge_kvm_bhyve_x86_native_vm(uint64_t vm_cookie)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)vm_cookie;
    return backend_vm ? backend_vm->vm : 0;
}

int
edge_kvm_bhyve_x86_validate_dma_mapping(uint64_t vm_cookie, uint64_t iova,
    uint64_t userspace_address, uint64_t size, uint32_t flags)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)vm_cookie;

    if (!backend_vm || size == 0 || iova > UINT64_MAX - size ||
        userspace_address > UINT64_MAX - size)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < EDGE_KVM_BHYVE_MAX_SLOTS; ++index) {
        const edge_kvm_bhyve_memory_slot_t *slot = &backend_vm->slots[index];
        uint64_t offset;

        if (!slot->active || iova < slot->guest_physical_address)
            continue;
        offset = iova - slot->guest_physical_address;
        if (offset > slot->memory_size || size > slot->memory_size - offset)
            continue;
        if (userspace_address != slot->userspace_address + offset)
            return -EDGE_LINUX_EINVAL;
        if ((flags & EDGE_VFIO_DMA_MAP_FLAG_WRITE) != 0 &&
            (slot->flags & EDGE_KVM_MEMORY_READONLY) != 0)
            return -EDGE_LINUX_EPERM;
        return 0;
    }
    return -EDGE_LINUX_ENOENT;
}

typedef struct edge_kvm_bhyve_vcpu {
    struct vcpu *vcpu;
    edge_kvm_bhyve_vm_t *vm;
    void *run_pages[EDGE_KVM_VCPU_MMAP_PAGES];
    edge_kvm_cpuid_entry2_t cpuid_entries[EDGE_KVM_MAX_CPUID_ENTRIES];
    uint32_t cpuid_count;
    edge_kvm_msr_entry_t msr_entries[EDGE_KVM_BHYVE_MAX_MSRS];
    uint32_t msr_count;
    uint32_t mp_state;
    uint32_t guest_debug_control;
    uint8_t guest_debug_registers_saved;
    edge_kvm_debugregs_t guest_debug_saved_registers;
    uint32_t tsc_frequency_khz;
    uint64_t mce_capability;
    uint64_t signal_mask;
    uint8_t signal_mask_active;
    edge_kvm_vcpu_events_t event_state;
    uint8_t pending_io_in;
    uint8_t pending_io_size;
    uint8_t pending_mmio_read;
    uint8_t pending_mmio_opcode;
    uint8_t pending_string_in;
    uint8_t pending_string_count;
    uint8_t invpcid_enabled;
    uint8_t startup_reset_pending;
    uint8_t startup_sipi_pending;
    volatile uint64_t startup_sequence;
    struct callout immediate_exit_callout;
    edge_kvm_run_t *volatile active_run;
    task_t *volatile active_task;
} edge_kvm_bhyve_vcpu_t;

static void
edge_kvm_bhyve_immediate_exit_poll(void *argument)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu = argument;
    edge_kvm_run_t *run;
    task_t *task;
    uint64_t pending;

    run = __atomic_load_n(&backend_vcpu->active_run, __ATOMIC_ACQUIRE);
    if (!run)
        return;
    task = __atomic_load_n(&backend_vcpu->active_task, __ATOMIC_ACQUIRE);
    pending = task ?
        (__atomic_load_n(&task->signal_pending, __ATOMIC_ACQUIRE) |
         __atomic_load_n(&task->signal_shared_pending, __ATOMIC_ACQUIRE)) &
        ~__atomic_load_n(&task->sigmask, __ATOMIC_ACQUIRE) : 0;
    if (__atomic_load_n(&run->immediate_exit, __ATOMIC_ACQUIRE) != 0 ||
        pending != 0 ||
        (task && __atomic_load_n(
            &task->need_resched, __ATOMIC_ACQUIRE) != 0)) {
        vcpu_lock(backend_vcpu->vcpu);
        backend_vcpu->vcpu->reqidle = 1;
        vcpu_notify_event_locked(backend_vcpu->vcpu);
        vcpu_unlock(backend_vcpu->vcpu);
        return;
    }
    if (__atomic_load_n(&backend_vcpu->active_run, __ATOMIC_ACQUIRE) == run)
        (void)callout_reset_sbt(&backend_vcpu->immediate_exit_callout,
            SBT_1MS, 0, edge_kvm_bhyve_immediate_exit_poll,
            backend_vcpu, C_HARDCLOCK | C_DIRECT_EXEC);
}

static int
edge_kvm_bhyve_task_signal_pending(const task_t *task)
{
    uint64_t pending;

    if (!task)
        return 0;
    pending = __atomic_load_n(&task->signal_pending, __ATOMIC_ACQUIRE) |
        __atomic_load_n(&task->signal_shared_pending, __ATOMIC_ACQUIRE);
    return (pending &
        ~__atomic_load_n(&task->sigmask, __ATOMIC_ACQUIRE)) != 0;
}

static void
edge_kvm_bhyve_signal_notify(void *argument)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu = argument;
    edge_kvm_run_t *run;
    task_t *task;

    if (!backend_vcpu)
        return;
    run = __atomic_load_n(&backend_vcpu->active_run, __ATOMIC_ACQUIRE);
    task = __atomic_load_n(&backend_vcpu->active_task, __ATOMIC_ACQUIRE);
    if (!run || (!run->immediate_exit &&
        !edge_kvm_bhyve_task_signal_pending(task)))
        return;
    vcpu_lock(backend_vcpu->vcpu);
    backend_vcpu->vcpu->reqidle = 1;
    vcpu_notify_event_locked(backend_vcpu->vcpu);
    vcpu_unlock(backend_vcpu->vcpu);
}

static const uint32_t edge_kvm_bhyve_msr_indices[] = {
    UINT32_C(0x00000010), UINT32_C(0x00000174),
    UINT32_C(0x00000175), UINT32_C(0x00000176),
    UINT32_C(0x00000277), UINT32_C(0xc0000081),
    UINT32_C(0xc0000082), UINT32_C(0xc0000083),
    UINT32_C(0xc0000084), UINT32_C(0xc0000102),
    EDGE_KVM_BHYVE_MSR_TSC_AUX,
};

static int
edge_kvm_bhyve_get_mce_cap_supported(void *context, uint64_t *capability)
{
    (void)context;
    if (!capability)
        return -EDGE_LINUX_EINVAL;
    *capability = EDGE_KVM_BHYVE_MCE_FEATURES;
    return 0;
}

#define EDGE_KVM_RUN_IO_DATA_OFFSET 2048u

static uint64_t
edge_kvm_bhyve_monotonic_ns(void)
{
    struct timespec now;

    getnanouptime(&now);
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) +
        (uint64_t)now.tv_nsec;
}

static void edge_kvm_bhyve_irqfd_notify(void *context, int event_id);

static void
edge_kvm_bhyve_irqfd_release(edge_kvm_bhyve_irqfd_t *irqfd)
{
    if (!irqfd || !irqfd->active)
        return;
    (void)kernel_eventfd_observer_unregister(
        irqfd->registration.event_id, edge_kvm_bhyve_irqfd_notify, irqfd);
    kernel_eventfd_release(irqfd->registration.event_id);
    if (irqfd->registration.resample_event_id >= 0)
        kernel_eventfd_release(irqfd->registration.resample_event_id);
    memset(irqfd, 0, sizeof(*irqfd));
}

/* FreeBSD defines this in vmm_dev.c, which EdgeOS intentionally excludes. */
u_int vm_maxcpu;

static volatile uint32_t g_bhyve_vm_sequence;
static uint8_t g_bhyve_initialized;
static edge_kvm_bhyve_vcpu_t
    *g_bhyve_vcpus[EDGE_KVM_OBJECT_MAX_VCPUS];

typedef struct edge_kvm_bhyve_vfio_device {
    uint8_t active;
    uint8_t reserved[7];
    uint64_t vm_cookie;
    int32_t descriptors[EDGE_KVM_BHYVE_MAX_VFIO_FILES];
    uint32_t descriptor_count;
} edge_kvm_bhyve_vfio_device_t;
static edge_kvm_bhyve_vfio_device_t
    g_bhyve_vfio_devices[EDGE_KVM_BHYVE_MAX_VFIO_DEVICES];

int edge_bhyve_upstream_x86_emulate_cpuid(
    struct vcpu *vcpu, uint64_t *rax, uint64_t *rbx,
    uint64_t *rcx, uint64_t *rdx);
static void edge_kvm_bhyve_mask_cpuid(edge_kvm_cpuid_entry2_t *entry);
void edge_bhyve_upstream_svm_launch(
    uint64_t pa, struct svm_regctx *gctx, struct pcpu *host_gs_base);
int edge_bhyve_upstream_vmx_rdmsr(
    struct vmx_vcpu *vcpu, u_int number, uint64_t *value, bool *return_user);
int edge_bhyve_upstream_vmx_wrmsr(
    struct vmx_vcpu *vcpu, u_int number, uint64_t value, bool *return_user);
int edge_bhyve_upstream_svm_rdmsr(
    struct svm_vcpu *vcpu, u_int number, uint64_t *value, bool *return_user);
int edge_bhyve_upstream_svm_wrmsr(
    struct svm_vcpu *vcpu, u_int number, uint64_t value, bool *return_user);

void
svm_launch(uint64_t pa, struct svm_regctx *gctx, struct pcpu *pcpu)
{
    uint64_t host_gs_base = rdmsr(MSR_GSBASE);

    (void)pcpu;
    edge_bhyve_upstream_svm_launch(pa, gctx,
        (struct pcpu *)(uintptr_t)host_gs_base);
}

int
edge_kvm_bhyve_vlapic_set_apicbase(struct vlapic *vlapic, uint64_t value)
{
    uint64_t address;
    uint64_t current;
    enum x2apic_state state;
    int error;

    if (!vlapic ||
        (value & (APICBASE_RESERVED & ~APICBASE_BSP)) != 0)
        return 22;
    current = vlapic_get_apicbase(vlapic);
    value = (value & ~APICBASE_BSP) | (current & APICBASE_BSP);
    if ((value & APICBASE_X2APIC) != 0 &&
        (value & APICBASE_ENABLED) == 0) {
        value |= APICBASE_ENABLED | DEFAULT_APIC_BASE;
    }
    address = value & APICBASE_ADDRESS;
    if (address != 0 && address != DEFAULT_APIC_BASE)
        return 22;
    state = (value & APICBASE_X2APIC) != 0 ?
        X2APIC_ENABLED : X2APIC_DISABLED;
    error = vm_set_x2apic_state(vlapic->vcpu, state);
    if (error != 0)
        return error;
    vlapic->msr_apicbase = value;
    return 0;
}

static edge_kvm_bhyve_vcpu_t *
edge_kvm_bhyve_find_vcpu(struct vcpu *vcpu)
{
    for (uint32_t index = 0; index < EDGE_KVM_OBJECT_MAX_VCPUS; ++index) {
        if (g_bhyve_vcpus[index] && g_bhyve_vcpus[index]->vcpu == vcpu)
            return g_bhyve_vcpus[index];
    }
    return 0;
}

bool
edge_kvm_bhyve_mem_allocated(struct vcpu *vcpu, vm_paddr_t gpa)
{
    struct vm_mem *memory;

    if (!vcpu)
        return false;
    memory = vm_mem(vcpu_vm(vcpu));
    for (int index = 0; index < VM_MAX_MEMMAPS; ++index) {
        const struct vm_mem_map *mapping = &memory->mem_maps[index];

        if (mapping->len == 0 || gpa < mapping->gpa ||
            gpa >= mapping->gpa + mapping->len)
            continue;
        /*
         * EdgeOS wires every KVM memory slot before a vCPU can run.  A nested
         * fault inside a read-only slot is therefore a guest write and must
         * take bhyve's instruction-emulation exit so QEMU receives KVM MMIO,
         * while writable RAM faults stay on bhyve's paging path.
         */
        return (mapping->prot & VM_PROT_WRITE) != 0;
    }
    return false;
}

int
x86_emulate_cpuid(struct vcpu *vcpu, uint64_t *rax, uint64_t *rbx,
    uint64_t *rcx, uint64_t *rdx)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        edge_kvm_bhyve_find_vcpu(vcpu);
    uint32_t function = (uint32_t)*rax;
    uint32_t index = (uint32_t)*rcx;

    if (backend_vcpu && backend_vcpu->cpuid_count != 0) {
        for (uint32_t entry_index = 0;
             entry_index < backend_vcpu->cpuid_count; ++entry_index) {
            const edge_kvm_cpuid_entry2_t *entry =
                &backend_vcpu->cpuid_entries[entry_index];

            if (entry->function != function)
                continue;
            if ((entry->flags & EDGE_KVM_CPUID_FLAG_SIGNIFICANT_INDEX) &&
                entry->index != index)
                continue;
            *rax = entry->eax;
            *rbx = entry->ebx;
            *rcx = entry->ecx;
            *rdx = entry->edx;
            if (function == UINT32_C(0x00000001))
                *rbx = (*rbx & UINT32_C(0x00ffffff)) |
                    ((uint64_t)vcpu_vcpuid(vcpu) << 24);
            else if (function == UINT32_C(0x0000000b) ||
                     function == UINT32_C(0x0000001f))
                *rdx = (uint32_t)vcpu_vcpuid(vcpu);
            else if (function == UINT32_C(0x8000001e))
                *rax = (uint32_t)vcpu_vcpuid(vcpu);
            return 1;
        }
    }
    if (function == UINT32_C(0x00000015) &&
        tsc_freq >= UINT64_C(1000000)) {
        uint64_t ratio = (tsc_freq + UINT64_C(500000)) /
            UINT64_C(1000000);

        if (ratio <= UINT32_MAX) {
            *rax = 1;
            *rbx = ratio;
            *rcx = UINT32_C(1000000);
            *rdx = 0;
            return 1;
        }
    }
    if (function == UINT32_C(0x00000016) &&
        tsc_freq >= UINT64_C(1000000)) {
        uint64_t frequency_mhz = (tsc_freq + UINT64_C(500000)) /
            UINT64_C(1000000);

        if (frequency_mhz <= UINT16_MAX) {
            *rax = frequency_mhz;
            *rbx = frequency_mhz;
            *rcx = UINT32_C(100);
            *rdx = 0;
            return 1;
        }
    }
    int handled = edge_bhyve_upstream_x86_emulate_cpuid(
        vcpu, rax, rbx, rcx, rdx);

    if (handled) {
        edge_kvm_cpuid_entry2_t entry = {
            .function = function,
            .index = index,
            .eax = (uint32_t)*rax,
            .ebx = (uint32_t)*rbx,
            .ecx = (uint32_t)*rcx,
            .edx = (uint32_t)*rdx,
        };

        edge_kvm_bhyve_mask_cpuid(&entry);
        *rax = entry.eax;
        *rbx = entry.ebx;
        *rcx = entry.ecx;
        *rdx = entry.edx;
        if (backend_vcpu && function == UINT32_C(0x00000001))
            *rbx = (*rbx & UINT32_C(0x00ffffff)) |
                ((uint64_t)vcpu_vcpuid(vcpu) << 24);
        else if (backend_vcpu &&
                 (function == UINT32_C(0x0000000b) ||
                  function == UINT32_C(0x0000001f)))
            *rdx = (uint32_t)vcpu_vcpuid(vcpu);
        else if (backend_vcpu && function == UINT32_C(0x8000001e))
            *rax = (uint32_t)vcpu_vcpuid(vcpu);
    }
    return handled;
}

static void
edge_kvm_bhyve_mask_cpuid(edge_kvm_cpuid_entry2_t *entry)
{
    const struct xsave_limits *limits = vmm_get_xsave_limits();

    if (entry->function == UINT32_C(0x00000001)) {
        /*
         * VMX and TSC-deadline mode are not implemented by this backend.
         * The latter must be hidden from userspace-supplied CPUID as well as
         * the upstream fallback or a guest can stop the periodic LAPIC timer
         * and program an unhandled IA32_TSC_DEADLINE MSR.
         */
        entry->ecx &= ~((UINT32_C(1) << 5) | (UINT32_C(1) << 24));
        entry->ecx |= UINT32_C(1) << 31;
    } else if (entry->function == UINT32_C(0x00000007) &&
        entry->index == 0) {
        /*
         * SPEC_CTRL, PRED_CMD, ARCH_CAPABILITIES, and CORE_CAPABILITIES
         * are not virtualized by the current bhyve backend.
         */
        entry->edx &= ~((UINT32_C(1) << 26) |
            (UINT32_C(1) << 27) | (UINT32_C(1) << 29) |
            (UINT32_C(1) << 30) | (UINT32_C(1) << 31));
        if ((limits->xcr0_allowed & XFEATURE_MPX) != XFEATURE_MPX)
            entry->ebx &= ~(UINT32_C(1) << 14);
    } else if (entry->function == UINT32_C(0x00000007) &&
        entry->index == 2) {
        entry->edx &= ~UINT32_C(0x1f);
    } else if (entry->function == UINT32_C(0x0000000d)) {
        if (!limits->xsave_enabled) {
            entry->eax = 0;
            entry->ebx = 0;
            entry->ecx = 0;
            entry->edx = 0;
        } else if (entry->index == 0) {
            entry->eax &= (uint32_t)limits->xcr0_allowed;
            entry->edx &= (uint32_t)(limits->xcr0_allowed >> 32);
            if (entry->ecx > limits->xsave_max_size)
                entry->ecx = limits->xsave_max_size;
        } else if (entry->index == 1) {
            entry->eax &= CPUID_EXTSTATE_XSAVEOPT;
            entry->ebx = 0;
            entry->ecx = 0;
            entry->edx = 0;
        } else if (entry->index > 1 &&
            (entry->index >= 64 ||
             (limits->xcr0_allowed &
              (UINT64_C(1) << entry->index)) == 0)) {
            entry->eax = 0;
            entry->ebx = 0;
            entry->ecx = 0;
            entry->edx = 0;
        }
    } else if (entry->function == UINT32_C(0x80000001)) {
        entry->ecx &= ~(UINT32_C(1) << 2);
    } else if (entry->function == UINT32_C(0x80000007)) {
        /*
         * The backend currently exposes the legacy architectural MCE banks,
         * but not AMD overflow recovery, SUCCOR, or scalable MCA interrupt
         * configuration. Keep Linux from touching the associated AMD-only
         * recovery MSRs until those facilities are virtualized.
         */
        entry->ebx &= ~((UINT32_C(1) << 0) |
            (UINT32_C(1) << 1) | (UINT32_C(1) << 3));
    } else if (entry->function == UINT32_C(0x80000008)) {
        entry->ebx &= ~((UINT32_C(1) << 12) |
            (UINT32_C(1) << 14) | (UINT32_C(1) << 15) |
            (UINT32_C(1) << 17) | (UINT32_C(1) << 24) |
            (UINT32_C(1) << 25) | (UINT32_C(1) << 28));
    } else if (entry->function == UINT32_C(0x80000021)) {
        entry->eax &= ~((UINT32_C(1) << 8) |
            (UINT32_C(1) << 27) | (UINT32_C(1) << 28));
    }
}

static void
edge_kvm_bhyve_append_cpuid(edge_kvm_cpuid_entry2_t *entries,
    uint32_t capacity, uint32_t *count, uint32_t function,
    uint32_t index, uint32_t flags)
{
    unsigned int registers[4];
    edge_kvm_cpuid_entry2_t entry = {
        .function = function,
        .index = index,
        .flags = flags,
    };

    cpuid_count(function, index, registers);
    entry.eax = registers[0];
    entry.ebx = registers[1];
    entry.ecx = registers[2];
    entry.edx = registers[3];
    if (function == UINT32_C(0x00000015) &&
        (entry.eax == 0 || entry.ebx == 0 || entry.ecx == 0) &&
        tsc_freq >= UINT64_C(1000000)) {
        uint64_t ratio = (tsc_freq + UINT64_C(500000)) /
            UINT64_C(1000000);

        if (ratio <= UINT32_MAX) {
            entry.eax = 1;
            entry.ebx = (uint32_t)ratio;
            entry.ecx = UINT32_C(1000000);
            entry.edx = 0;
        }
    } else if (function == UINT32_C(0x00000016) &&
        entry.eax == 0 && tsc_freq >= UINT64_C(1000000)) {
        uint64_t frequency_mhz = (tsc_freq + UINT64_C(500000)) /
            UINT64_C(1000000);

        if (frequency_mhz <= UINT16_MAX) {
            entry.eax = (uint32_t)frequency_mhz;
            entry.ebx = (uint32_t)frequency_mhz;
            entry.ecx = UINT32_C(100);
            entry.edx = 0;
        }
    }
    edge_kvm_bhyve_mask_cpuid(&entry);
    if (*count < capacity)
        entries[*count] = entry;
    ++*count;
}

static void
edge_kvm_bhyve_append_indexed_cpuid(edge_kvm_cpuid_entry2_t *entries,
    uint32_t capacity, uint32_t *count, uint32_t function)
{
    unsigned int registers[4];
    uint32_t limit = 0;

    if (function == UINT32_C(0x00000004) ||
        function == UINT32_C(0x8000001d)) {
        limit = 31;
        for (uint32_t index = 0; index <= limit; ++index) {
            cpuid_count(function, index, registers);
            edge_kvm_bhyve_append_cpuid(entries, capacity, count,
                function, index, EDGE_KVM_CPUID_FLAG_SIGNIFICANT_INDEX);
            if ((registers[0] & 0x1fu) == 0)
                break;
        }
    } else if (function == UINT32_C(0x00000007)) {
        cpuid_count(function, 0, registers);
        limit = registers[0] < 31 ? registers[0] : 31;
        for (uint32_t index = 0; index <= limit; ++index)
            edge_kvm_bhyve_append_cpuid(entries, capacity, count,
                function, index, EDGE_KVM_CPUID_FLAG_SIGNIFICANT_INDEX);
    } else if (function == UINT32_C(0x0000000b) ||
               function == UINT32_C(0x0000001f)) {
        for (uint32_t index = 0; index < 32; ++index) {
            cpuid_count(function, index, registers);
            edge_kvm_bhyve_append_cpuid(entries, capacity, count,
                function, index, EDGE_KVM_CPUID_FLAG_SIGNIFICANT_INDEX);
            if (registers[1] == 0)
                break;
        }
    } else if (function == UINT32_C(0x0000000d)) {
        for (uint32_t index = 0; index < 64; ++index) {
            cpuid_count(function, index, registers);
            if (index < 2 || registers[0] || registers[1] ||
                registers[2] || registers[3])
                edge_kvm_bhyve_append_cpuid(entries, capacity, count,
                    function, index,
                    EDGE_KVM_CPUID_FLAG_SIGNIFICANT_INDEX);
        }
    }
}

static int
edge_kvm_bhyve_get_supported_cpuid(void *context,
    edge_kvm_cpuid_entry2_t *entries, uint32_t capacity, uint32_t *count)
{
    static const uint32_t basic_leaves[] = {
        0x00000000, 0x00000001, 0x00000002, 0x00000003,
        0x00000004, 0x00000006, 0x00000007, 0x0000000a,
        0x0000000b, 0x0000000d, 0x0000000f, 0x00000010,
        0x00000015, 0x00000016,
    };
    static const uint32_t extended_leaves[] = {
        0x80000000, 0x80000001, 0x80000002, 0x80000003,
        0x80000004, 0x80000006, 0x80000007, 0x80000008,
        0x8000001d, 0x8000001e,
    };

    (void)context;
    if (!count || (capacity != 0 && !entries))
        return -EDGE_LINUX_EINVAL;
    *count = 0;
    for (uint32_t index = 0;
         index < sizeof(basic_leaves) / sizeof(basic_leaves[0]); ++index) {
        uint32_t leaf = basic_leaves[index];

        if (leaf > cpu_high)
            continue;
        if (leaf == 4 || leaf == 7 || leaf == 0x0b || leaf == 0x0d)
            edge_kvm_bhyve_append_indexed_cpuid(
                entries, capacity, count, leaf);
        else
            edge_kvm_bhyve_append_cpuid(entries, capacity, count,
                leaf, 0, 0);
    }
    for (uint32_t index = 0;
         index < sizeof(extended_leaves) / sizeof(extended_leaves[0]);
         ++index) {
        uint32_t leaf = extended_leaves[index];

        if (leaf > cpu_exthigh)
            continue;
        if (leaf == UINT32_C(0x8000001d))
            edge_kvm_bhyve_append_indexed_cpuid(
                entries, capacity, count, leaf);
        else
            edge_kvm_bhyve_append_cpuid(entries, capacity, count,
                leaf, 0, 0);
    }
    if (*count + 2u <= EDGE_KVM_MAX_CPUID_ENTRIES) {
        edge_kvm_cpuid_entry2_t signature = {
            .function = UINT32_C(0x40000000),
            .eax = UINT32_C(0x40000001),
            .ebx = UINT32_C(0x4b4d564b),
            .ecx = UINT32_C(0x564b4d56),
            .edx = UINT32_C(0x0000004d),
        };
        edge_kvm_cpuid_entry2_t features = {
            .function = UINT32_C(0x40000001),
        };

        if (*count < capacity)
            entries[*count] = signature;
        ++*count;
        if (*count < capacity)
            entries[*count] = features;
        ++*count;
    }
    return *count <= EDGE_KVM_MAX_CPUID_ENTRIES ? 0 :
        -EDGE_LINUX_E2BIG;
}

static int
edge_kvm_bhyve_get_msr_index_list(void *context, uint32_t *indices,
    uint32_t capacity, uint32_t *count)
{
    uint32_t supported = (uint32_t)(sizeof(edge_kvm_bhyve_msr_indices) /
        sizeof(edge_kvm_bhyve_msr_indices[0]));

    (void)context;
    if (!count || (capacity != 0 && !indices))
        return -EDGE_LINUX_EINVAL;
    *count = supported;
    if (capacity > supported)
        capacity = supported;
    if (capacity != 0)
        memcpy(indices, edge_kvm_bhyve_msr_indices,
            (size_t)capacity * sizeof(indices[0]));
    return 0;
}

static int
edge_kvm_bhyve_get_msr_feature_index_list(void *context,
    uint32_t *indices, uint32_t capacity, uint32_t *count)
{
    uint32_t supported;

    (void)context;
    if (!count || (capacity != 0 && !indices))
        return -EDGE_LINUX_EINVAL;
    supported = cpu_vendor_id == CPU_VENDOR_AMD ||
        cpu_vendor_id == CPU_VENDOR_HYGON ? 1u : 0u;
    *count = supported;
    if (capacity != 0 && supported != 0)
        indices[0] = EDGE_KVM_BHYVE_MSR_AMD_DE_CFG;
    return 0;
}

static int
edge_kvm_bhyve_get_msr_features(void *context,
    edge_kvm_msr_entry_t *entries, uint32_t count)
{
    (void)context;
    if (count != 0 && !entries)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < count; ++index) {
        if ((cpu_vendor_id != CPU_VENDOR_AMD &&
             cpu_vendor_id != CPU_VENDOR_HYGON) ||
            entries[index].index != EDGE_KVM_BHYVE_MSR_AMD_DE_CFG)
            return (int)index;
        /* No DE_CFG feature bit is promised until bhyve virtualizes it. */
        entries[index].data = 0;
    }
    return (int)count;
}

static int
edge_kvm_bhyve_device_create(void *context, uint64_t vm_cookie,
    uint32_t type, uint32_t flags, uint64_t *device_cookie)
{
    (void)context;
    if (!vm_cookie || !device_cookie || type != EDGE_KVM_DEVICE_VFIO)
        return -EDGE_LINUX_ENODEV;
    if (flags == EDGE_KVM_CREATE_DEVICE_TEST) {
        *device_cookie = 0;
        return 0;
    }
    if (flags != 0)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0;
         index < EDGE_KVM_BHYVE_MAX_VFIO_DEVICES; ++index) {
        edge_kvm_bhyve_vfio_device_t *device =
            &g_bhyve_vfio_devices[index];
        if (device->active)
            continue;
        memset(device, 0, sizeof(*device));
        device->active = 1;
        device->vm_cookie = vm_cookie;
        *device_cookie = (uint64_t)(uintptr_t)device;
        return 0;
    }
    return -EDGE_LINUX_ENOSPC;
}

static void
edge_kvm_bhyve_device_destroy(void *context, uint64_t device_cookie)
{
    edge_kvm_bhyve_vfio_device_t *device =
        (edge_kvm_bhyve_vfio_device_t *)(uintptr_t)device_cookie;

    (void)context;
    if (!device || !device->active)
        return;
    while (device->descriptor_count != 0) {
        int32_t descriptor =
            device->descriptors[--device->descriptor_count];
        (void)kernel_edge_vfio_unbind_descriptor(
            descriptor, device->vm_cookie);
    }
    memset(device, 0, sizeof(*device));
}

static int
edge_kvm_bhyve_device_has_attr(void *context, uint64_t device_cookie,
    const edge_kvm_device_attr_t *attribute)
{
    edge_kvm_bhyve_vfio_device_t *device =
        (edge_kvm_bhyve_vfio_device_t *)(uintptr_t)device_cookie;

    (void)context;
    if (!device || !device->active || !attribute)
        return -EDGE_LINUX_EBADF;
    return attribute->group == EDGE_KVM_DEVICE_VFIO_FILE_GROUP &&
        (attribute->attribute == EDGE_KVM_DEVICE_VFIO_FILE_ADD ||
         attribute->attribute == EDGE_KVM_DEVICE_VFIO_FILE_DEL) ?
        0 : -EDGE_LINUX_ENXIO;
}

static int
edge_kvm_bhyve_device_set_attr(void *context, uint64_t device_cookie,
    const edge_kvm_device_attr_t *attribute, const void *value,
    uint32_t value_size)
{
    edge_kvm_bhyve_vfio_device_t *device =
        (edge_kvm_bhyve_vfio_device_t *)(uintptr_t)device_cookie;
    int32_t descriptor;
    int status;

    status = edge_kvm_bhyve_device_has_attr(
        context, device_cookie, attribute);
    if (status < 0)
        return status;
    if (!value || value_size != sizeof(descriptor))
        return -EDGE_LINUX_EINVAL;
    memcpy(&descriptor, value, sizeof(descriptor));
    for (uint32_t index = 0; index < device->descriptor_count; ++index) {
        if (device->descriptors[index] != descriptor)
            continue;
        if (attribute->attribute == EDGE_KVM_DEVICE_VFIO_FILE_ADD)
            return 0;
        status = kernel_edge_vfio_unbind_descriptor(
            descriptor, device->vm_cookie);
        if (status < 0)
            return status;
        device->descriptors[index] =
            device->descriptors[--device->descriptor_count];
        return 0;
    }
    if (attribute->attribute == EDGE_KVM_DEVICE_VFIO_FILE_DEL)
        return -EDGE_LINUX_ENOENT;
    if (device->descriptor_count == EDGE_KVM_BHYVE_MAX_VFIO_FILES)
        return -EDGE_LINUX_ENOSPC;
    status = kernel_edge_vfio_bind_descriptor(
        descriptor, device->vm_cookie);
    if (status < 0)
        return status;
    device->descriptors[device->descriptor_count++] = descriptor;
    return 0;
}

static int
edge_kvm_bhyve_device_get_attr(void *context, uint64_t device_cookie,
    const edge_kvm_device_attr_t *attribute, void *value,
    uint32_t value_size)
{
    (void)context;
    (void)device_cookie;
    (void)attribute;
    (void)value;
    (void)value_size;
    return -EDGE_LINUX_ENXIO;
}

static int
edge_kvm_bhyve_error(int error)
{
    switch (error) {
    case 0:
        return 0;
    case 2:
        return -EDGE_LINUX_ENOENT;
    case 12:
        return -EDGE_LINUX_ENOMEM;
    case 14:
        return -EDGE_LINUX_EFAULT;
    case 16:
        return -EDGE_LINUX_EBUSY;
    case 17:
        return -EDGE_LINUX_EEXIST;
    case 22:
        return -EDGE_LINUX_EINVAL;
    case 28:
        return -EDGE_LINUX_ENOSPC;
    default:
        return -EDGE_LINUX_EIO;
    }
}

static void
edge_kvm_bhyve_name(char name[VM_MAX_NAMELEN + 1])
{
    static const char digits[] = "0123456789abcdef";
    uint32_t value = __atomic_add_fetch(&g_bhyve_vm_sequence, 1u,
        __ATOMIC_RELAXED);
    const char prefix[] = "edge-kvm-";
    uint32_t position = 0;

    for (; position < sizeof(prefix) - 1u; ++position)
        name[position] = prefix[position];
    for (int shift = 28; shift >= 0; shift -= 4)
        name[position++] = digits[(value >> shift) & 0xfu];
    name[position] = 0;
}

static void
edge_kvm_bhyve_release_pages(edge_kvm_bhyve_memory_slot_t *slot)
{
    edge_kvm_bhyve_page_chunk_t *chunk;

    if (!slot)
        return;
    chunk = slot->page_chunks;
    while (chunk) {
        edge_kvm_bhyve_page_chunk_t *next = chunk->next;

        for (uint32_t page = 0; page < chunk->count; ++page)
            arch_vm_free_page((void *)(uintptr_t)chunk->pages[page]);
        bsd_kfree(chunk);
        chunk = next;
    }
    slot->page_chunks = 0;
    slot->page_count = 0;
}

static int
edge_kvm_bhyve_build_object(const edge_kvm_memory_region_t *region,
    vm_object_t *object_out, edge_kvm_bhyve_page_chunk_t **chunks_out,
    uint32_t *page_count_out)
{
    task_t *task = process_current_task();
    task_t *memory = task ? process_vm_task(task) : 0;
    struct sglist *sg;
    vm_object_t object;
    edge_kvm_bhyve_page_chunk_t *chunks = 0;
    edge_kvm_bhyve_page_chunk_t *tail = 0;
    uint64_t page_count64;
    uint32_t protection = ARCH_VM_PROT_READ;
    uint32_t page_count;
    uint32_t max_segments;
    int error = 0;

    if (!memory || !memory->cr3 || !object_out || !chunks_out ||
        !page_count_out)
        return -EDGE_LINUX_EFAULT;
    *page_count_out = 0;
    if ((region->flags & EDGE_KVM_MEMORY_READONLY) == 0)
        protection |= ARCH_VM_PROT_WRITE;
    page_count64 = region->memory_size / EDGE_KVM_PAGE_SIZE;
    if (page_count64 == 0 || page_count64 > UINT32_MAX)
        return -EDGE_LINUX_EINVAL;
    page_count = (uint32_t)page_count64;
    max_segments = page_count > UINT16_MAX ? UINT16_MAX : page_count;
    sg = sglist_alloc((int)max_segments, BSD_M_WAITOK);
    if (!sg) {
        bsd_printf("edge-kvm: memory metadata allocation failed "
            "pages=%u segments=%u\n", page_count, max_segments);
        return -EDGE_LINUX_ENOMEM;
    }
    for (uint32_t page = 0; page < page_count; ++page) {
        uint64_t user_address = region->userspace_address +
            (uint64_t)page * EDGE_KVM_PAGE_SIZE;
        uint64_t physical_address;

        if (kernel_mm_resolve_user_page(memory->cr3, user_address,
                protection) <= 0 ||
            arch_vm_translate(memory->cr3, user_address,
                &physical_address, 0) < 0) {
            bsd_printf("edge-kvm: user page resolution failed "
                "page=%u address=%#lx\n", page, user_address);
            error = -EDGE_LINUX_EFAULT;
            break;
        }
        physical_address &= ~(uint64_t)(EDGE_KVM_PAGE_SIZE - 1u);
        if (arch_vm_retain_page((void *)(uintptr_t)physical_address) < 0) {
            bsd_printf("edge-kvm: page retention failed page=%u "
                "physical=%#lx\n", page, physical_address);
            error = -EDGE_LINUX_EFAULT;
            break;
        }
        if (!tail || tail->count == EDGE_KVM_BHYVE_PAGE_CHUNK_CAPACITY) {
            edge_kvm_bhyve_page_chunk_t *chunk = bsd_kmalloc(
                sizeof(*chunk), BSD_M_WAITOK | BSD_M_ZERO);

            if (!chunk) {
                bsd_printf("edge-kvm: page chunk allocation failed "
                    "page=%u\n", page);
                arch_vm_free_page((void *)(uintptr_t)physical_address);
                error = -EDGE_LINUX_ENOMEM;
                break;
            }
            if (tail)
                tail->next = chunk;
            else
                chunks = chunk;
            tail = chunk;
        }
        tail->pages[tail->count++] = physical_address;
        if (sglist_append_phys(sg, physical_address,
                EDGE_KVM_PAGE_SIZE) != 0) {
            bsd_printf("edge-kvm: scatter/gather capacity exhausted "
                "page=%u segments=%u\n", page, sg->sg_nseg);
            arch_vm_free_page((void *)(uintptr_t)physical_address);
            --tail->count;
            error = -EDGE_LINUX_ENOSPC;
            break;
        }
        *page_count_out = page + 1u;
    }
    if (error < 0) {
        edge_kvm_bhyve_memory_slot_t failed = {
            .page_chunks = chunks,
            .page_count = *page_count_out,
        };

        edge_kvm_bhyve_release_pages(&failed);
        sglist_free(sg);
        *page_count_out = 0;
        return error;
    }
    object = vm_pager_allocate(OBJT_SG, sg, region->memory_size,
        protection, 0, 0);
    if (!object) {
        bsd_printf("edge-kvm: guest memory object allocation failed "
            "pages=%u segments=%u\n", page_count, sg->sg_nseg);
        edge_kvm_bhyve_memory_slot_t failed = {
            .page_chunks = chunks,
            .page_count = page_count,
        };

        edge_kvm_bhyve_release_pages(&failed);
        sglist_free(sg);
        *page_count_out = 0;
        return -EDGE_LINUX_ENOMEM;
    }
    *object_out = object;
    *chunks_out = chunks;
    return 0;
}

static int
edge_kvm_bhyve_vm_create(void *context, uint32_t machine_type,
    uint64_t *backend_cookie)
{
    edge_kvm_bhyve_vm_t *backend_vm;
    char name[VM_MAX_NAMELEN + 1];
    int error;

    (void)context;
    if (!backend_cookie || machine_type != 0)
        return -EDGE_LINUX_EINVAL;
    backend_vm = bsd_kmalloc(sizeof(*backend_vm),
        BSD_M_WAITOK | BSD_M_ZERO);
    if (!backend_vm)
        return -EDGE_LINUX_ENOMEM;
    edge_kvm_bhyve_name(name);
    error = vm_create(name, &backend_vm->vm);
    if (error != 0) {
        bsd_kfree(backend_vm);
        return edge_kvm_bhyve_error(error);
    }
    backend_vm->coalesced_mmio_page = arch_vm_alloc_page();
    if (!backend_vm->coalesced_mmio_page) {
        vm_destroy(backend_vm->vm);
        bsd_kfree(backend_vm);
        return -EDGE_LINUX_ENOMEM;
    }
    memset(backend_vm->coalesced_mmio_page, 0, EDGE_KVM_PAGE_SIZE);
    backend_vm->clock_host_ns = edge_kvm_bhyve_monotonic_ns();
    *backend_cookie = (uint64_t)(uintptr_t)backend_vm;
    return 0;
}

static void
edge_kvm_bhyve_vm_destroy(void *context, uint64_t backend_cookie)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)backend_cookie;

    (void)context;
    if (!backend_vm)
        return;
    for (uint32_t index = 0; index < EDGE_KVM_BHYVE_MAX_IOEVENTFDS;
         ++index) {
        if (backend_vm->ioeventfds[index].active)
            kernel_eventfd_release(
                backend_vm->ioeventfds[index].registration.event_id);
    }
    for (uint32_t index = 0; index < EDGE_KVM_BHYVE_MAX_IRQFDS; ++index)
        edge_kvm_bhyve_irqfd_release(&backend_vm->irqfds[index]);
    vm_destroy(backend_vm->vm);
    for (uint32_t slot = 0; slot < EDGE_KVM_BHYVE_MAX_SLOTS; ++slot)
        edge_kvm_bhyve_release_pages(&backend_vm->slots[slot]);
    arch_vm_free_page(backend_vm->coalesced_mmio_page);
    bsd_kfree(backend_vm);
}

static void
edge_kvm_bhyve_coalesced_lock(edge_kvm_bhyve_vm_t *backend_vm)
{
    while (__atomic_test_and_set(&backend_vm->coalesced_mmio_lock,
        __ATOMIC_ACQUIRE))
        __asm__ __volatile__("pause" ::: "memory");
}

static void
edge_kvm_bhyve_coalesced_unlock(edge_kvm_bhyve_vm_t *backend_vm)
{
    __atomic_clear(&backend_vm->coalesced_mmio_lock, __ATOMIC_RELEASE);
}

static int
edge_kvm_bhyve_vm_coalesced_mmio(void *context, uint64_t backend_cookie,
    const edge_kvm_coalesced_mmio_zone_t *zone, uint8_t unregister)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)backend_cookie;
    int empty = -1;

    (void)context;
    if (!backend_vm || !zone || !zone->size || zone->pio ||
        zone->address > UINT64_MAX - zone->size)
        return -EDGE_LINUX_EINVAL;
    edge_kvm_bhyve_coalesced_lock(backend_vm);
    for (uint32_t index = 0;
         index < EDGE_KVM_MAX_COALESCED_MMIO_ZONES; ++index) {
        edge_kvm_bhyve_coalesced_zone_t *entry =
            &backend_vm->coalesced_zones[index];

        if (!entry->active) {
            if (empty < 0)
                empty = (int)index;
            continue;
        }
        if (entry->zone.address == zone->address &&
            entry->zone.size == zone->size &&
            entry->zone.pio == zone->pio) {
            if (!unregister) {
                edge_kvm_bhyve_coalesced_unlock(backend_vm);
                return -EDGE_LINUX_EEXIST;
            }
            memset(entry, 0, sizeof(*entry));
            edge_kvm_bhyve_coalesced_unlock(backend_vm);
            return 0;
        }
    }
    if (unregister) {
        edge_kvm_bhyve_coalesced_unlock(backend_vm);
        return -EDGE_LINUX_ENOENT;
    }
    if (empty < 0) {
        edge_kvm_bhyve_coalesced_unlock(backend_vm);
        return -EDGE_LINUX_ENOSPC;
    }
    backend_vm->coalesced_zones[empty].active = 1;
    backend_vm->coalesced_zones[empty].zone = *zone;
    edge_kvm_bhyve_coalesced_unlock(backend_vm);
    return 0;
}

static int
edge_kvm_bhyve_coalesced_mmio_write(edge_kvm_bhyve_vm_t *backend_vm,
    uint64_t address, uint64_t value, uint32_t length)
{
    edge_kvm_coalesced_mmio_ring_t *ring;
    uint32_t first;
    uint32_t last;
    uint32_t next;
    int matched = 0;

    if (!backend_vm || !backend_vm->coalesced_mmio_page ||
        !length || length > 8)
        return 0;
    edge_kvm_bhyve_coalesced_lock(backend_vm);
    for (uint32_t index = 0;
         index < EDGE_KVM_MAX_COALESCED_MMIO_ZONES; ++index) {
        const edge_kvm_bhyve_coalesced_zone_t *entry =
            &backend_vm->coalesced_zones[index];
        uint64_t offset;

        if (!entry->active || address < entry->zone.address)
            continue;
        offset = address - entry->zone.address;
        if (offset <= entry->zone.size &&
            length <= entry->zone.size - offset) {
            matched = 1;
            break;
        }
    }
    if (!matched) {
        edge_kvm_bhyve_coalesced_unlock(backend_vm);
        return 0;
    }
    ring = backend_vm->coalesced_mmio_page;
    first = __atomic_load_n(&ring->first, __ATOMIC_ACQUIRE);
    last = __atomic_load_n(&ring->last, __ATOMIC_RELAXED);
    next = (last + 1u) % EDGE_KVM_COALESCED_MMIO_MAX;
    if (next == first) {
        edge_kvm_bhyve_coalesced_unlock(backend_vm);
        return 0;
    }
    ring->entries[last].physical_address = address;
    ring->entries[last].length = length;
    ring->entries[last].pio = 0;
    memcpy(ring->entries[last].data, &value, length);
    __atomic_store_n(&ring->last, next, __ATOMIC_RELEASE);
    edge_kvm_bhyve_coalesced_unlock(backend_vm);
    return 1;
}

static int
edge_kvm_bhyve_ioeventfd_key_matches(
    const edge_kvm_ioeventfd_registration_t *left,
    const edge_kvm_ioeventfd_registration_t *right)
{
    uint32_t key_flags = EDGE_KVM_IOEVENTFD_FLAG_DATAMATCH |
        EDGE_KVM_IOEVENTFD_FLAG_PIO;

    return left->address == right->address &&
        left->length == right->length &&
        (left->flags & key_flags) == (right->flags & key_flags) &&
        ((left->flags & EDGE_KVM_IOEVENTFD_FLAG_DATAMATCH) == 0 ||
         left->datamatch == right->datamatch);
}

static int
edge_kvm_bhyve_vm_ioeventfd(void *context, uint64_t backend_cookie,
    const edge_kvm_ioeventfd_registration_t *event)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)backend_cookie;
    edge_kvm_bhyve_ioeventfd_t *free_entry = 0;

    (void)context;
    if (!backend_vm || !event)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < EDGE_KVM_BHYVE_MAX_IOEVENTFDS;
         ++index) {
        edge_kvm_bhyve_ioeventfd_t *entry =
            &backend_vm->ioeventfds[index];

        if (!entry->active) {
            if (!free_entry)
                free_entry = entry;
            continue;
        }
        if (!edge_kvm_bhyve_ioeventfd_key_matches(
                &entry->registration, event))
            continue;
        if ((event->flags & EDGE_KVM_IOEVENTFD_FLAG_DEASSIGN) == 0)
            return -EDGE_LINUX_EEXIST;
        kernel_eventfd_release(entry->registration.event_id);
        memset(entry, 0, sizeof(*entry));
        return 0;
    }
    if ((event->flags & EDGE_KVM_IOEVENTFD_FLAG_DEASSIGN) != 0)
        return -EDGE_LINUX_ENOENT;
    if (!free_entry)
        return -EDGE_LINUX_ENOSPC;
    free_entry->registration = *event;
    free_entry->active = 1u;
    return 0;
}

static int
edge_kvm_bhyve_vm_set_tss_address(void *context, uint64_t backend_cookie,
    uint64_t address)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)backend_cookie;

    (void)context;
    if (!backend_vm || (address & (EDGE_KVM_PAGE_SIZE - 1)) != 0 ||
        address > UINT32_MAX)
        return -EDGE_LINUX_EINVAL;
    backend_vm->tss_address = address;
    backend_vm->tss_address_set = 1;
    return 0;
}

static int
edge_kvm_bhyve_vm_set_identity_map_address(void *context,
    uint64_t backend_cookie, uint64_t address)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)backend_cookie;

    (void)context;
    if (!backend_vm || (address & (EDGE_KVM_PAGE_SIZE - 1)) != 0)
        return -EDGE_LINUX_EINVAL;
    backend_vm->identity_map_address = address;
    backend_vm->identity_map_address_set = 1;
    return 0;
}

static int
edge_kvm_bhyve_vm_create_irqchip(void *context, uint64_t backend_cookie)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)backend_cookie;

    (void)context;
    if (!backend_vm || !vm_ioapic(backend_vm->vm) ||
        !vm_atpic(backend_vm->vm))
        return -EDGE_LINUX_ENODEV;
    if (backend_vm->irqchip_created)
        return -EDGE_LINUX_EEXIST;
    backend_vm->irqchip_created = 1;
    return 0;
}

static int
edge_kvm_bhyve_apply_irq_route(edge_kvm_bhyve_vm_t *backend_vm,
    const edge_kvm_irq_routing_entry_t *entry, bool asserted)
{
    int irq;

    if (entry->type == EDGE_KVM_IRQ_ROUTING_MSI) {
        uint64_t address;

        if (!asserted)
            return 0;
        address = ((uint64_t)entry->u.msi.address_hi << 32) |
            entry->u.msi.address_lo;
        return edge_kvm_bhyve_error(lapic_intr_msi(
            backend_vm->vm, address, entry->u.msi.data));
    }
    if (entry->u.irqchip.irqchip == EDGE_KVM_IRQCHIP_IOAPIC) {
        if (asserted)
            return edge_kvm_bhyve_error(vioapic_assert_irq(
                backend_vm->vm, (int)entry->u.irqchip.pin));
        return edge_kvm_bhyve_error(vioapic_deassert_irq(
            backend_vm->vm, (int)entry->u.irqchip.pin));
    }
    irq = (int)entry->u.irqchip.pin;
    if (entry->u.irqchip.irqchip == EDGE_KVM_IRQCHIP_PIC_SLAVE)
        irq += 8;
    if (asserted)
        return edge_kvm_bhyve_error(vatpic_assert_irq(
            backend_vm->vm, irq));
    return edge_kvm_bhyve_error(vatpic_deassert_irq(
        backend_vm->vm, irq));
}

static int
edge_kvm_bhyve_vm_set_gsi_routing(void *context, uint64_t backend_cookie,
    const edge_kvm_irq_routing_entry_t *entries, uint32_t count)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)backend_cookie;
    int error;

    (void)context;
    if (!backend_vm || count > EDGE_KVM_MAX_IRQ_ROUTES ||
        (count != 0 && !entries))
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < backend_vm->route_count; ++index) {
        const edge_kvm_irq_routing_entry_t *entry =
            &backend_vm->routes[index];

        if (!backend_vm->irq_levels[entry->gsi])
            continue;
        error = edge_kvm_bhyve_apply_irq_route(backend_vm, entry, false);
        if (error < 0)
            return error;
    }
    if (count != 0)
        memcpy(backend_vm->routes, entries,
            (uint64_t)count * sizeof(entries[0]));
    backend_vm->route_count = count;
    for (uint32_t index = 0; index < count; ++index) {
        const edge_kvm_irq_routing_entry_t *entry =
            &backend_vm->routes[index];

        if (!backend_vm->irq_levels[entry->gsi])
            continue;
        error = edge_kvm_bhyve_apply_irq_route(backend_vm, entry, true);
        if (error < 0)
            return error;
    }
    return 0;
}

static int
edge_kvm_bhyve_vm_set_irq_line(void *context, uint64_t backend_cookie,
    edge_kvm_irq_level_t *level)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)backend_cookie;
    bool asserted;
    int error;

    (void)context;
    if (!backend_vm || !level || level->irq >= EDGE_KVM_MAX_IRQ_ROUTES ||
        level->level > 1)
        return -EDGE_LINUX_EINVAL;
    asserted = level->level != 0;
    if (backend_vm->irq_levels[level->irq] == asserted)
        return 0;
    for (uint32_t index = 0; index < backend_vm->route_count; ++index) {
        const edge_kvm_irq_routing_entry_t *entry =
            &backend_vm->routes[index];

        if (entry->gsi != level->irq)
            continue;
        error = edge_kvm_bhyve_apply_irq_route(
            backend_vm, entry, asserted);
        if (error < 0)
            return error;
    }
    backend_vm->irq_levels[level->irq] = asserted;
    level->level = asserted;
    return 0;
}

static void
edge_kvm_bhyve_irqfd_notify(void *context, int event_id)
{
    edge_kvm_bhyve_irqfd_t *irqfd = context;
    edge_kvm_irq_level_t level;
    uint64_t value;

    if (!irqfd || !irqfd->active ||
        irqfd->registration.event_id != event_id ||
        kernel_eventfd_consume_value(event_id, &value) < 0)
        return;
    level.irq = irqfd->registration.gsi;
    level.level = 1;
    if (edge_kvm_bhyve_vm_set_irq_line(
            0, (uint64_t)(uintptr_t)irqfd->vm, &level) < 0)
        return;
    level.level = 0;
    (void)edge_kvm_bhyve_vm_set_irq_line(
        0, (uint64_t)(uintptr_t)irqfd->vm, &level);
}

static int
edge_kvm_bhyve_vm_irqfd(void *context, uint64_t backend_cookie,
    const edge_kvm_irqfd_registration_t *registration)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)backend_cookie;
    edge_kvm_bhyve_irqfd_t *free_irqfd = 0;
    int error;

    (void)context;
    if (!backend_vm || !registration)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < EDGE_KVM_BHYVE_MAX_IRQFDS; ++index) {
        edge_kvm_bhyve_irqfd_t *irqfd = &backend_vm->irqfds[index];

        if (!irqfd->active) {
            if (!free_irqfd) free_irqfd = irqfd;
            continue;
        }
        if (irqfd->registration.event_id != registration->event_id ||
            irqfd->registration.gsi != registration->gsi)
            continue;
        if ((registration->flags & EDGE_KVM_IRQFD_FLAG_DEASSIGN) == 0)
            return -EDGE_LINUX_EEXIST;
        edge_kvm_bhyve_irqfd_release(irqfd);
        return 0;
    }
    if ((registration->flags & EDGE_KVM_IRQFD_FLAG_DEASSIGN) != 0)
        return -EDGE_LINUX_ENOENT;
    if (!free_irqfd)
        return -EDGE_LINUX_ENOSPC;
    free_irqfd->registration = *registration;
    free_irqfd->vm = backend_vm;
    free_irqfd->active = 1u;
    error = kernel_eventfd_observer_register(
        registration->event_id, edge_kvm_bhyve_irqfd_notify, free_irqfd);
    if (error < 0) {
        memset(free_irqfd, 0, sizeof(*free_irqfd));
        return error;
    }
    return 0;
}

static int
edge_kvm_bhyve_vm_signal_msi(void *context, uint64_t backend_cookie,
    const edge_kvm_msi_t *message)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)backend_cookie;
    uint64_t address;
    int error;

    (void)context;
    if (!backend_vm || !message)
        return -EDGE_LINUX_EINVAL;
    address = ((uint64_t)message->address_hi << 32) |
        message->address_lo;
    error = lapic_intr_msi(backend_vm->vm, address, message->data);
    return error == 0 ? 1 : edge_kvm_bhyve_error(error);
}

static int
edge_kvm_bhyve_vm_get_irqchip(void *context, uint64_t backend_cookie,
    edge_kvm_irqchip_t *state)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)backend_cookie;

    (void)context;
    if (!backend_vm || !state || !backend_vm->irqchip_created)
        return -EDGE_LINUX_EINVAL;
    if (state->chip_id == EDGE_KVM_IRQCHIP_PIC_MASTER ||
        state->chip_id == EDGE_KVM_IRQCHIP_PIC_SLAVE) {
        edge_bhyve_vatpic_layout_t *vatpic =
            (edge_bhyve_vatpic_layout_t *)vm_atpic(backend_vm->vm);
        edge_bhyve_atpic_layout_t *atpic;
        edge_kvm_pic_state_t *pic = &state->chip.pic;
        uint32_t chip = state->chip_id;

        memset(state->chip.padding, 0, sizeof(state->chip.padding));
        mtx_lock_spin(&vatpic->mtx);
        atpic = &vatpic->atpic[chip];
        for (uint32_t pin = 0; pin < 8; ++pin) {
            if (atpic->acnt[pin] > 0)
                pic->last_irr |= (uint8_t)(1u << pin);
        }
        pic->irr = atpic->request;
        pic->imr = atpic->mask;
        pic->isr = atpic->service;
        pic->priority_add = atpic->ready ?
            (uint8_t)((atpic->lowprio + 1) & 7) : 0;
        pic->irq_base = (uint8_t)atpic->irq_base;
        pic->read_reg_select = (uint8_t)atpic->rd_cmd_reg;
        pic->poll = atpic->poll;
        pic->special_mask = atpic->smm;
        pic->init_state = (uint8_t)atpic->icw_num;
        pic->auto_eoi = atpic->aeoi;
        pic->rotate_on_auto_eoi = atpic->rotate;
        pic->special_fully_nested_mode = atpic->sfn;
        pic->init4 = atpic->ready;
        pic->elcr = vatpic->elc[chip];
        pic->elcr_mask = chip == EDGE_KVM_IRQCHIP_PIC_MASTER ?
            UINT8_C(0xf8) : UINT8_C(0xde);
        mtx_unlock_spin(&vatpic->mtx);
        return 0;
    }
    if (state->chip_id == EDGE_KVM_IRQCHIP_IOAPIC) {
        edge_bhyve_vioapic_layout_t *vioapic =
            (edge_bhyve_vioapic_layout_t *)vm_ioapic(backend_vm->vm);
        edge_kvm_ioapic_state_t *ioapic = &state->chip.ioapic;

        memset(state->chip.padding, 0, sizeof(state->chip.padding));
        mtx_lock_spin(&vioapic->mtx);
        ioapic->base_address = UINT64_C(0xfec00000);
        ioapic->ioregsel = vioapic->ioregsel;
        ioapic->id = vioapic->id;
        for (uint32_t pin = 0; pin < 24; ++pin) {
            ioapic->redirtbl[pin] = vioapic->rtbl[pin].reg;
            if (vioapic->rtbl[pin].acnt > 0)
                ioapic->irr |= UINT32_C(1) << pin;
        }
        mtx_unlock_spin(&vioapic->mtx);
        return 0;
    }
    return -EDGE_LINUX_EINVAL;
}

static int
edge_kvm_bhyve_vm_set_irqchip(void *context, uint64_t backend_cookie,
    const edge_kvm_irqchip_t *state)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)backend_cookie;

    (void)context;
    if (!backend_vm || !state || !backend_vm->irqchip_created)
        return -EDGE_LINUX_EINVAL;
    if (state->chip_id == EDGE_KVM_IRQCHIP_PIC_MASTER ||
        state->chip_id == EDGE_KVM_IRQCHIP_PIC_SLAVE) {
        edge_bhyve_vatpic_layout_t *vatpic =
            (edge_bhyve_vatpic_layout_t *)vm_atpic(backend_vm->vm);
        edge_bhyve_atpic_layout_t *atpic;
        const edge_kvm_pic_state_t *pic = &state->chip.pic;
        uint32_t chip = state->chip_id;

        mtx_lock_spin(&vatpic->mtx);
        atpic = &vatpic->atpic[chip];
        atpic->ready = pic->init4 != 0 || pic->irq_base != 0;
        atpic->icw_num = pic->init_state;
        atpic->rd_cmd_reg = pic->read_reg_select;
        atpic->aeoi = pic->auto_eoi != 0;
        atpic->poll = pic->poll != 0;
        atpic->rotate = pic->rotate_on_auto_eoi != 0;
        atpic->sfn = pic->special_fully_nested_mode != 0;
        atpic->irq_base = pic->irq_base;
        atpic->request = pic->irr;
        atpic->service = pic->isr;
        atpic->mask = pic->imr;
        atpic->smm = pic->special_mask;
        for (uint32_t pin = 0; pin < 8; ++pin)
            atpic->acnt[pin] = (pic->last_irr >> pin) & 1u;
        atpic->lowprio = (pic->priority_add + 7u) & 7u;
        atpic->intr_raised = false;
        vatpic->elc[chip] = pic->elcr;
        mtx_unlock_spin(&vatpic->mtx);
        return 0;
    }
    if (state->chip_id == EDGE_KVM_IRQCHIP_IOAPIC) {
        edge_bhyve_vioapic_layout_t *vioapic =
            (edge_bhyve_vioapic_layout_t *)vm_ioapic(backend_vm->vm);
        const edge_kvm_ioapic_state_t *ioapic = &state->chip.ioapic;

        if (ioapic->base_address != UINT64_C(0xfec00000))
            return -EDGE_LINUX_EINVAL;
        mtx_lock_spin(&vioapic->mtx);
        vioapic->ioregsel = ioapic->ioregsel;
        vioapic->id = ioapic->id;
        for (uint32_t pin = 0; pin < 24; ++pin) {
            vioapic->rtbl[pin].reg = ioapic->redirtbl[pin];
            vioapic->rtbl[pin].acnt = (ioapic->irr >> pin) & 1u;
        }
        mtx_unlock_spin(&vioapic->mtx);
        return 0;
    }
    return -EDGE_LINUX_EINVAL;
}

static int64_t
edge_kvm_bhyve_bintime_ns(const struct bintime *time)
{
    __uint128_t fraction;

    fraction = (__uint128_t)time->frac * UINT64_C(1000000000);
    return time->sec * INT64_C(1000000000) +
        (int64_t)(fraction >> 64);
}

static uint32_t
edge_kvm_bhyve_pit_count(edge_bhyve_vatpit_layout_t *vatpit,
    edge_bhyve_pit_channel_layout_t *channel)
{
    struct bintime delta;
    uint64_t ticks;

    if (channel->initial == 0)
        return UINT32_C(0x10000);
    binuptime(&delta);
    bintime_sub(&delta, &channel->now_bt);
    ticks = (uint64_t)delta.sec * UINT64_C(1193182);
    if (vatpit->freq_bt.frac != 0)
        ticks += delta.frac / vatpit->freq_bt.frac;
    return channel->initial - ticks % channel->initial;
}

static int
edge_kvm_bhyve_vm_get_pit(void *context, uint64_t backend_cookie,
    edge_kvm_pit_state2_t *state)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)backend_cookie;
    edge_bhyve_vatpit_layout_t *vatpit;

    (void)context;
    if (!backend_vm || !state || !backend_vm->pit_created)
        return -EDGE_LINUX_EINVAL;
    vatpit = (edge_bhyve_vatpit_layout_t *)vm_atpit(backend_vm->vm);
    *state = backend_vm->pit_shadow;
    mtx_lock_spin(&vatpit->mtx);
    for (uint32_t index = 0; index < 3; ++index) {
        edge_bhyve_pit_channel_layout_t *channel =
            &vatpit->channel[index];
        edge_kvm_pit_channel_state_t *output = &state->channels[index];

        output->count = edge_kvm_bhyve_pit_count(vatpit, channel);
        output->latched_count = (uint16_t)
            ((uint16_t)channel->ol[0] << 8 | channel->ol[1]);
        output->count_latched = (uint8_t)channel->olbyte;
        output->status_latched = channel->slatched;
        output->status = channel->status;
        output->read_state = (uint8_t)channel->frbyte;
        output->write_state = (uint8_t)channel->crbyte;
        output->write_latch = channel->cr[0];
        if (channel->initial != 0) {
            output->rw_mode = 3;
            output->mode = (uint8_t)((channel->mode >> 1) & 7);
            output->count_load_time =
                edge_kvm_bhyve_bintime_ns(&channel->now_bt);
        }
    }
    mtx_unlock_spin(&vatpit->mtx);
    return 0;
}

static int
edge_kvm_bhyve_vm_set_pit(void *context, uint64_t backend_cookie,
    const edge_kvm_pit_state2_t *state)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)backend_cookie;
    edge_bhyve_vatpit_layout_t *vatpit;

    (void)context;
    if (!backend_vm || !state || !backend_vm->pit_created)
        return -EDGE_LINUX_EINVAL;
    vatpit = (edge_bhyve_vatpit_layout_t *)vm_atpit(backend_vm->vm);
    for (uint32_t index = 0; index < 3; ++index) {
        const edge_kvm_pit_channel_state_t *input =
            &state->channels[index];
        uint32_t command;
        uint32_t value;

        if (input->rw_mode == 0)
            continue;
        if (input->bcd > 1 || input->rw_mode > 3 || input->mode > 5)
            return -EDGE_LINUX_EINVAL;
        command = (index << 6) | (input->rw_mode << 4) |
            (input->mode << 1) | input->bcd;
        if (vatpit_handler(backend_vm->vm, false, TIMER_MODE, 1,
                &command) != 0)
            return -EDGE_LINUX_EINVAL;
        if (input->rw_mode == 1 || input->rw_mode == 3) {
            value = input->count & UINT32_C(0xff);
            if (vatpit_handler(backend_vm->vm, false,
                    TIMER_CNTR0 + (int)index, 1, &value) != 0)
                return -EDGE_LINUX_EINVAL;
        }
        if (input->rw_mode == 2 || input->rw_mode == 3) {
            value = (input->count >> 8) & UINT32_C(0xff);
            if (vatpit_handler(backend_vm->vm, false,
                    TIMER_CNTR0 + (int)index, 1, &value) != 0)
                return -EDGE_LINUX_EINVAL;
        }
    }
    backend_vm->pit_shadow = *state;
    mtx_lock_spin(&vatpit->mtx);
    for (uint32_t index = 0; index < 3; ++index) {
        edge_bhyve_pit_channel_layout_t *channel =
            &vatpit->channel[index];
        const edge_kvm_pit_channel_state_t *input =
            &state->channels[index];

        channel->ol[0] = (uint8_t)(input->latched_count >> 8);
        channel->ol[1] = (uint8_t)input->latched_count;
        channel->olbyte = input->count_latched;
        channel->slatched = input->status_latched != 0;
        channel->status = input->status;
        channel->frbyte = input->read_state;
        channel->crbyte = input->write_state;
        channel->cr[0] = input->write_latch;
    }
    mtx_unlock_spin(&vatpit->mtx);
    return 0;
}

static int
edge_kvm_bhyve_vm_create_pit(void *context, uint64_t backend_cookie,
    const edge_kvm_pit_config_t *config)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)backend_cookie;

    (void)context;
    if (!backend_vm || !config || !vm_atpit(backend_vm->vm) ||
        (config->flags & ~UINT32_C(1)) != 0)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < 15; ++index) {
        if (config->padding[index] != 0)
            return -EDGE_LINUX_EINVAL;
    }
    if (backend_vm->pit_created)
        return -EDGE_LINUX_EEXIST;
    memset(&backend_vm->pit_shadow, 0, sizeof(backend_vm->pit_shadow));
    for (uint32_t index = 0; index < 3; ++index) {
        backend_vm->pit_shadow.channels[index].count = UINT32_C(0x10000);
        backend_vm->pit_shadow.channels[index].mode = UINT8_MAX;
        backend_vm->pit_shadow.channels[index].gate = 1;
    }
    backend_vm->pit_created = 1;
    return 0;
}

static int
edge_kvm_bhyve_vm_get_clock(void *context, uint64_t backend_cookie,
    edge_kvm_clock_data_t *state)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)backend_cookie;
    uint64_t now;

    (void)context;
    if (!backend_vm || !state)
        return -EDGE_LINUX_EINVAL;
    now = edge_kvm_bhyve_monotonic_ns();
    memset(state, 0, sizeof(*state));
    state->clock = backend_vm->clock_base_ns +
        (now - backend_vm->clock_host_ns);
    return 0;
}

static int
edge_kvm_bhyve_vm_set_clock(void *context, uint64_t backend_cookie,
    const edge_kvm_clock_data_t *state)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)backend_cookie;

    (void)context;
    if (!backend_vm || !state ||
        (state->flags & ~EDGE_KVM_CLOCK_VALID_FLAGS) != 0)
        return -EDGE_LINUX_EINVAL;
    backend_vm->clock_base_ns = state->clock;
    backend_vm->clock_host_ns = edge_kvm_bhyve_monotonic_ns();
    return 0;
}

static int
edge_kvm_bhyve_vcpu_reset_state(struct vcpu *vcpu)
{
    static const enum vm_reg_name data_segments[] = {
        VM_REG_GUEST_DS, VM_REG_GUEST_ES, VM_REG_GUEST_FS,
        VM_REG_GUEST_GS, VM_REG_GUEST_SS,
    };
    struct seg_desc code = {
        .base = UINT64_C(0xffff0000),
        .limit = UINT32_C(0xffff),
        .access = UINT32_C(0x9b),
    };
    struct seg_desc data = {
        .limit = UINT32_C(0xffff),
        .access = UINT32_C(0x93),
    };
    struct seg_desc task = {
        .limit = UINT32_C(0xffff),
        .access = UINT32_C(0x8b),
    };
    struct seg_desc unusable = {
        .access = UINT32_C(0x10000),
    };
    struct seg_desc table = {
        .limit = UINT32_C(0xffff),
    };
    int error;

    error = vm_set_register(vcpu, VM_REG_GUEST_RIP, UINT64_C(0xfff0));
    if (error == 0)
        error = vm_set_register(vcpu, VM_REG_GUEST_RFLAGS, 2);
    if (error == 0)
        error = vm_set_register(vcpu, VM_REG_GUEST_CR0,
            UINT64_C(0x60000010));
    if (error == 0)
        error = vm_set_register(vcpu, VM_REG_GUEST_CS, UINT64_C(0xf000));
    if (error == 0)
        error = vm_set_seg_desc(vcpu, VM_REG_GUEST_CS, &code);
    for (uint32_t index = 0; error == 0 &&
         index < sizeof(data_segments) / sizeof(data_segments[0]); ++index) {
        error = vm_set_register(vcpu, data_segments[index], 0);
        if (error == 0)
            error = vm_set_seg_desc(vcpu, data_segments[index], &data);
    }
    if (error == 0)
        error = vm_set_register(vcpu, VM_REG_GUEST_TR, 0);
    if (error == 0)
        error = vm_set_seg_desc(vcpu, VM_REG_GUEST_TR, &task);
    if (error == 0)
        error = vm_set_register(vcpu, VM_REG_GUEST_LDTR, 0);
    if (error == 0)
        error = vm_set_seg_desc(vcpu, VM_REG_GUEST_LDTR, &unusable);
    if (error == 0)
        error = vm_set_seg_desc(vcpu, VM_REG_GUEST_GDTR, &table);
    if (error == 0)
        error = vm_set_seg_desc(vcpu, VM_REG_GUEST_IDTR, &table);
    return error;
}

void
edge_bhyve_kvm_startup_event(struct vm *vm, const cpuset_t *targets,
    uint32_t mode, uint8_t vector)
{
    if (!vm || !targets)
        return;
    for (uint32_t index = 0; index < EDGE_KVM_OBJECT_MAX_VCPUS; ++index) {
        edge_kvm_bhyve_vcpu_t *target = g_bhyve_vcpus[index];
        uint32_t target_id;
        int error = 0;

        if (!target || target->vm->vm != vm)
            continue;
        target_id = (uint32_t)vcpu_vcpuid(target->vcpu);
        if (!CPU_ISSET((int)target_id, targets))
            continue;
        if (mode == APIC_DELMODE_INIT) {
            __atomic_store_n(
                &target->startup_reset_pending, 1, __ATOMIC_RELEASE);
            target->mp_state = EDGE_KVM_MP_STATE_INIT_RECEIVED;
        } else if (mode == APIC_DELMODE_STARTUP) {
            target->event_state.sipi_vector = vector;
            __atomic_store_n(
                &target->startup_sipi_pending, 1, __ATOMIC_RELEASE);
            target->mp_state = EDGE_KVM_MP_STATE_RUNNABLE;
        }
        if (error == 0) {
            __atomic_add_fetch(
                &target->startup_sequence, 1, __ATOMIC_RELEASE);
            kernel_runtime_notify_sequence(&target->startup_sequence);
            vcpu_lock(target->vcpu);
            target->vcpu->reqidle = 1;
            vcpu_notify_event_locked(target->vcpu);
            vcpu_unlock(target->vcpu);
        }
    }
}

static int
edge_kvm_bhyve_vcpu_create(void *context, uint64_t vm_cookie,
    uint32_t vcpu_id, uint64_t *backend_cookie)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)vm_cookie;
    edge_kvm_bhyve_vcpu_t *backend_vcpu;
    struct vcpu *vcpu;
    bool invpcid_enabled = vmm_is_svm();
    int error;

    (void)context;
    if (!backend_vm || !backend_cookie || vcpu_id >= vm_maxcpu)
        return -EDGE_LINUX_EINVAL;
    vcpu = vm_alloc_vcpu(backend_vm->vm, (int)vcpu_id);
    if (!vcpu)
        return -EDGE_LINUX_ENOMEM;
    error = vm_activate_cpu(vcpu);
    if (error != 0)
        return edge_kvm_bhyve_error(error);
    error = edge_kvm_bhyve_vcpu_reset_state(vcpu);
    if (error != 0)
        return edge_kvm_bhyve_error(error);
    error = edge_kvm_bhyve_vlapic_set_apicbase(vm_lapic(vcpu),
        DEFAULT_APIC_BASE | APICBASE_ENABLED |
        (vcpu_id == 0 ? APICBASE_BSP : 0));
    if (error != 0)
        return edge_kvm_bhyve_error(error);
    if (!vmm_is_svm()) {
        error = vm_set_capability(vcpu, VM_CAP_UNRESTRICTED_GUEST, 1);
        if (error != 0)
            return edge_kvm_bhyve_error(error);
        if ((cpu_feature2 & CPUID2_HV) == 0 &&
            vm_get_capability(vcpu, VM_CAP_ENABLE_INVPCID, &error) == 0) {
            error = vm_set_capability(vcpu, VM_CAP_ENABLE_INVPCID, 1);
            if (error != 0)
                return edge_kvm_bhyve_error(error);
            invpcid_enabled = true;
        }
    }
    error = vm_set_capability(vcpu, VM_CAP_HALT_EXIT, 1);
    if (error != 0)
        return edge_kvm_bhyve_error(error);
    error = vm_set_capability(vcpu, VM_CAP_IPI_EXIT, 1);
    if (error != 0)
        return edge_kvm_bhyve_error(error);
    backend_vcpu = bsd_kmalloc(sizeof(*backend_vcpu),
        BSD_M_WAITOK | BSD_M_ZERO);
    if (!backend_vcpu)
        return -EDGE_LINUX_ENOMEM;
    backend_vcpu->vcpu = vcpu;
    backend_vcpu->vm = backend_vm;
    backend_vcpu->invpcid_enabled = invpcid_enabled;
    callout_init(&backend_vcpu->immediate_exit_callout, 1);
    backend_vcpu->mp_state = vcpu_id == 0 ?
        EDGE_KVM_MP_STATE_RUNNABLE : EDGE_KVM_MP_STATE_UNINITIALIZED;
    if (vcpu_id != 0) {
        cpuset_t waiting;

        CPU_SETOF((int)vcpu_id, &waiting);
        vm_await_start(backend_vm->vm, &waiting);
    }
    for (uint32_t page = 0; page < EDGE_KVM_VCPU_MMAP_PAGES; ++page) {
        if (page == EDGE_KVM_X86_COALESCED_MMIO_PAGE_OFFSET) {
            backend_vcpu->run_pages[page] =
                backend_vm->coalesced_mmio_page;
            continue;
        }
        backend_vcpu->run_pages[page] = arch_vm_alloc_page();
        if (!backend_vcpu->run_pages[page]) {
            for (uint32_t rollback = 0; rollback < page; ++rollback) {
                if (rollback != EDGE_KVM_X86_COALESCED_MMIO_PAGE_OFFSET)
                    arch_vm_free_page(backend_vcpu->run_pages[rollback]);
            }
            bsd_kfree(backend_vcpu);
            return -EDGE_LINUX_ENOMEM;
        }
        memset(backend_vcpu->run_pages[page], 0, EDGE_KVM_PAGE_SIZE);
    }
    for (uint32_t index = 0; index < EDGE_KVM_OBJECT_MAX_VCPUS; ++index) {
        if (!g_bhyve_vcpus[index]) {
            g_bhyve_vcpus[index] = backend_vcpu;
            *backend_cookie = (uint64_t)(uintptr_t)backend_vcpu;
            return 0;
        }
    }
    for (uint32_t page = 0; page < EDGE_KVM_VCPU_MMAP_PAGES; ++page) {
        if (page != EDGE_KVM_X86_COALESCED_MMIO_PAGE_OFFSET)
            arch_vm_free_page(backend_vcpu->run_pages[page]);
    }
    bsd_kfree(backend_vcpu);
    return -EDGE_LINUX_ENOSPC;
}

static void
edge_kvm_bhyve_vcpu_destroy(void *context, uint64_t backend_cookie)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;

    /* The imported VM owns vCPUs and releases them during vm_destroy(). */
    (void)context;
    if (!backend_vcpu)
        return;
    __atomic_store_n(&backend_vcpu->active_run, 0, __ATOMIC_RELEASE);
    (void)callout_drain(&backend_vcpu->immediate_exit_callout);
    for (uint32_t index = 0; index < EDGE_KVM_OBJECT_MAX_VCPUS; ++index) {
        if (g_bhyve_vcpus[index] == backend_vcpu) {
            g_bhyve_vcpus[index] = 0;
            break;
        }
    }
    for (uint32_t page = 0; page < EDGE_KVM_VCPU_MMAP_PAGES; ++page) {
        if (page != EDGE_KVM_X86_COALESCED_MMIO_PAGE_OFFSET &&
            backend_vcpu->run_pages[page])
            arch_vm_free_page(backend_vcpu->run_pages[page]);
    }
    bsd_kfree(backend_vcpu);
}

static int
edge_kvm_bhyve_vcpu_set_cpuid(void *context, uint64_t backend_cookie,
    const edge_kvm_cpuid_entry2_t *entries, uint32_t count)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;

    (void)context;
    if (!backend_vcpu || count > EDGE_KVM_MAX_CPUID_ENTRIES ||
        (count != 0 && !entries))
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < count; ++index) {
        if (entries[index].flags &
            ~(EDGE_KVM_CPUID_FLAG_SIGNIFICANT_INDEX |
              EDGE_KVM_CPUID_FLAG_STATEFUL_FUNC |
              EDGE_KVM_CPUID_FLAG_STATE_READ_NEXT))
            return -EDGE_LINUX_EINVAL;
    }
    for (uint32_t index = 0; index < count; ++index) {
        backend_vcpu->cpuid_entries[index] = entries[index];
        edge_kvm_bhyve_mask_cpuid(&backend_vcpu->cpuid_entries[index]);
        if (!backend_vcpu->invpcid_enabled &&
            backend_vcpu->cpuid_entries[index].function ==
                UINT32_C(0x00000007) &&
            backend_vcpu->cpuid_entries[index].index == 0)
            backend_vcpu->cpuid_entries[index].ebx &=
                ~CPUID_STDEXT_INVPCID;
    }
    backend_vcpu->cpuid_count = count;
    return 0;
}

static int
edge_kvm_bhyve_vcpu_get_cpuid(void *context, uint64_t backend_cookie,
    edge_kvm_cpuid_entry2_t *entries, uint32_t capacity, uint32_t *count)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    uint32_t copied;

    (void)context;
    if (!backend_vcpu || !count || (capacity != 0 && !entries) ||
        capacity > EDGE_KVM_MAX_CPUID_ENTRIES)
        return -EDGE_LINUX_EINVAL;
    *count = backend_vcpu->cpuid_count;
    copied = capacity < backend_vcpu->cpuid_count ?
        capacity : backend_vcpu->cpuid_count;
    for (uint32_t index = 0; index < copied; ++index)
        entries[index] = backend_vcpu->cpuid_entries[index];
    return 0;
}

static int
edge_kvm_bhyve_vcpu_get_mp_state(void *context, uint64_t backend_cookie,
    edge_kvm_mp_state_t *state)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;

    (void)context;
    if (!backend_vcpu || !state)
        return -EDGE_LINUX_EINVAL;
    state->mp_state = backend_vcpu->mp_state;
    return 0;
}

static int
edge_kvm_bhyve_vcpu_set_mp_state(void *context, uint64_t backend_cookie,
    const edge_kvm_mp_state_t *state)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    struct vm *vm;
    cpuset_t target;

    (void)context;
    if (!backend_vcpu || !state ||
        state->mp_state > EDGE_KVM_MP_STATE_LOAD)
        return -EDGE_LINUX_EINVAL;
    vm = vcpu_vm(backend_vcpu->vcpu);
    CPU_SETOF(vcpu_vcpuid(backend_vcpu->vcpu), &target);
    if (state->mp_state == EDGE_KVM_MP_STATE_UNINITIALIZED ||
        state->mp_state == EDGE_KVM_MP_STATE_INIT_RECEIVED) {
        vm_await_start(vm, &target);
    } else if (state->mp_state == EDGE_KVM_MP_STATE_RUNNABLE ||
               state->mp_state == EDGE_KVM_MP_STATE_SIPI_RECEIVED ||
               state->mp_state == EDGE_KVM_MP_STATE_OPERATING ||
               state->mp_state == EDGE_KVM_MP_STATE_LOAD) {
        (void)vm_start_cpus(vm, &target);
        if (state->mp_state == EDGE_KVM_MP_STATE_SIPI_RECEIVED) {
            uint64_t vector = backend_vcpu->event_state.sipi_vector & 0xffu;
            struct seg_desc descriptor = {
                .base = vector << 12,
                .limit = UINT32_C(0xffff),
                .access = UINT32_C(0x9b),
            };
            int error = vm_set_register(
                backend_vcpu->vcpu, VM_REG_GUEST_CS, vector << 8);

            if (error == 0)
                error = vm_set_seg_desc(
                    backend_vcpu->vcpu, VM_REG_GUEST_CS, &descriptor);
            if (error == 0)
                error = vm_set_register(
                    backend_vcpu->vcpu, VM_REG_GUEST_RIP, 0);
            if (error != 0)
                return edge_kvm_bhyve_error(error);
        }
    }
    backend_vcpu->mp_state = state->mp_state;
    if (state->mp_state != EDGE_KVM_MP_STATE_UNINITIALIZED &&
        state->mp_state != EDGE_KVM_MP_STATE_INIT_RECEIVED) {
        __atomic_add_fetch(
            &backend_vcpu->startup_sequence, 1, __ATOMIC_RELEASE);
        kernel_runtime_notify_sequence(&backend_vcpu->startup_sequence);
    }
    return 0;
}

static int
edge_kvm_bhyve_vcpu_get_events(void *context, uint64_t backend_cookie,
    edge_kvm_vcpu_events_t *events)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    struct vcpu *vcpu;
    uint64_t interrupt_shadow = 0;
    int error;

    (void)context;
    if (!backend_vcpu || !events)
        return -EDGE_LINUX_EINVAL;
    vcpu = backend_vcpu->vcpu;
    *events = backend_vcpu->event_state;
    events->flags = EDGE_KVM_VCPUEVENT_VALID_NMI_PENDING |
                    EDGE_KVM_VCPUEVENT_VALID_SIPI_VECTOR |
                    EDGE_KVM_VCPUEVENT_VALID_SHADOW |
                    EDGE_KVM_VCPUEVENT_VALID_PAYLOAD;
    events->exception.injected = vcpu->exception_pending != 0;
    events->exception.pending = vcpu->exception_pending != 0;
    events->exception.number = (uint8_t)vcpu->exc_vector;
    events->exception.has_error_code = vcpu->exc_errcode_valid != 0;
    events->exception.error_code = vcpu->exc_errcode;
    events->nmi.pending = vm_nmi_pending(vcpu) != 0;
    events->interrupt.injected = vm_extint_pending(vcpu) != 0;
    error = vm_get_register(
        vcpu, VM_REG_GUEST_INTR_SHADOW, &interrupt_shadow);
    if (error != 0)
        return edge_kvm_bhyve_error(error);
    events->interrupt.shadow = interrupt_shadow != 0;
    return 0;
}

static int
edge_kvm_bhyve_vcpu_set_events(void *context, uint64_t backend_cookie,
    const edge_kvm_vcpu_events_t *events)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    struct vcpu *vcpu;

    (void)context;
    if (!backend_vcpu || !events ||
        (events->flags & ~EDGE_KVM_VCPUEVENT_VALID_MASK) != 0 ||
        events->exception.injected > 1 || events->exception.pending > 1 ||
        events->exception.has_error_code > 1 ||
        events->interrupt.injected > 1 ||
        events->interrupt.soft > 1 || events->interrupt.shadow > 1 ||
        events->nmi.injected > 1 || events->nmi.pending > 1 ||
        events->exception_has_payload > 1 ||
        events->smi.smm || events->smi.pending ||
        events->smi.smm_inside_nmi || events->smi.latched_init)
        return -EDGE_LINUX_EINVAL;
    if ((events->exception.injected || events->exception.pending) &&
        events->exception.number >= 32)
        return -EDGE_LINUX_EINVAL;
    if (events->interrupt.injected && events->interrupt.number < 16)
        return -EDGE_LINUX_EINVAL;
    if (events->nmi.padding)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < sizeof(events->reserved); ++index) {
        if (events->reserved[index] != 0)
            return -EDGE_LINUX_EINVAL;
    }
    vcpu = backend_vcpu->vcpu;
    vcpu->exception_pending =
        events->exception.injected || events->exception.pending;
    vcpu->exc_vector = events->exception.number;
    vcpu->exc_errcode_valid = events->exception.has_error_code;
    vcpu->exc_errcode = events->exception.error_code;
    vcpu->nmi_pending = events->nmi.injected || events->nmi.pending;
    vcpu->extint_pending = events->interrupt.injected;
    {
        int error = vm_set_register(vcpu, VM_REG_GUEST_INTR_SHADOW,
            events->interrupt.shadow != 0);

        if (error != 0)
            return edge_kvm_bhyve_error(error);
    }
    if (events->exception_has_payload &&
        events->exception.number == 14) {
        int error = vm_set_register(
            vcpu, VM_REG_GUEST_CR2, events->exception_payload);

        if (error != 0)
            return edge_kvm_bhyve_error(error);
    }
    backend_vcpu->event_state = *events;
    return 0;
}

static int
edge_kvm_bhyve_vcpu_mmap_page(void *context, uint64_t backend_cookie,
    uint32_t page_index, uint64_t *physical_address)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;

    (void)context;
    if (!backend_vcpu || !physical_address ||
        page_index >= EDGE_KVM_VCPU_MMAP_PAGES ||
        !backend_vcpu->run_pages[page_index])
        return -EDGE_LINUX_EINVAL;
    *physical_address =
        (uint64_t)(uintptr_t)backend_vcpu->run_pages[page_index];
    return 0;
}

static int
edge_kvm_bhyve_vcpu_get_regs(void *context, uint64_t backend_cookie,
    edge_kvm_regs_t *registers)
{
    static const enum vm_reg_name names[] = {
        VM_REG_GUEST_RAX, VM_REG_GUEST_RBX, VM_REG_GUEST_RCX,
        VM_REG_GUEST_RDX, VM_REG_GUEST_RSI, VM_REG_GUEST_RDI,
        VM_REG_GUEST_RSP, VM_REG_GUEST_RBP, VM_REG_GUEST_R8,
        VM_REG_GUEST_R9, VM_REG_GUEST_R10, VM_REG_GUEST_R11,
        VM_REG_GUEST_R12, VM_REG_GUEST_R13, VM_REG_GUEST_R14,
        VM_REG_GUEST_R15, VM_REG_GUEST_RIP, VM_REG_GUEST_RFLAGS,
    };
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    uint64_t *values = (uint64_t *)registers;

    (void)context;
    if (!backend_vcpu || !registers)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < sizeof(names) / sizeof(names[0]);
         ++index) {
        int error = vm_get_register(backend_vcpu->vcpu, names[index],
            &values[index]);
        if (error != 0)
            return edge_kvm_bhyve_error(error);
    }
    /*
     * bhyve leaves the hardware RIP at an instruction which caused a
     * userspace exit and records the resume address in nextrip.  Linux KVM
     * exposes the architectural resume RIP after a completed exit, and QEMU
     * may synchronize and write that state back before re-entering KVM.
     */
    registers->rip = backend_vcpu->vcpu->nextrip;
    return 0;
}

static int
edge_kvm_bhyve_vcpu_set_regs(void *context, uint64_t backend_cookie,
    const edge_kvm_regs_t *registers)
{
    static const enum vm_reg_name names[] = {
        VM_REG_GUEST_RAX, VM_REG_GUEST_RBX, VM_REG_GUEST_RCX,
        VM_REG_GUEST_RDX, VM_REG_GUEST_RSI, VM_REG_GUEST_RDI,
        VM_REG_GUEST_RSP, VM_REG_GUEST_RBP, VM_REG_GUEST_R8,
        VM_REG_GUEST_R9, VM_REG_GUEST_R10, VM_REG_GUEST_R11,
        VM_REG_GUEST_R12, VM_REG_GUEST_R13, VM_REG_GUEST_R14,
        VM_REG_GUEST_R15, VM_REG_GUEST_RIP, VM_REG_GUEST_RFLAGS,
    };
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    const uint64_t *values = (const uint64_t *)registers;

    (void)context;
    if (!backend_vcpu || !registers)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < sizeof(names) / sizeof(names[0]);
         ++index) {
        int error = vm_set_register(backend_vcpu->vcpu, names[index],
            values[index]);
        if (error != 0)
            return edge_kvm_bhyve_error(error);
    }
    backend_vcpu->vcpu->nextrip = registers->rip;
    return 0;
}

static int
edge_kvm_bhyve_get_segment(struct vcpu *vcpu, enum vm_reg_name name,
    edge_kvm_segment_t *segment)
{
    struct seg_desc descriptor;
    uint64_t selector;
    int error;

    error = vm_get_register(vcpu, name, &selector);
    if (error != 0)
        return error;
    error = vm_get_seg_desc(vcpu, name, &descriptor);
    if (error != 0)
        return error;
    memset(segment, 0, sizeof(*segment));
    segment->base = descriptor.base;
    segment->limit = descriptor.limit;
    segment->selector = (uint16_t)selector;
    segment->type = descriptor.access & 0xfu;
    segment->s = (descriptor.access >> 4) & 1u;
    segment->dpl = (descriptor.access >> 5) & 3u;
    segment->present = (descriptor.access >> 7) & 1u;
    segment->avl = (descriptor.access >> 12) & 1u;
    segment->l = (descriptor.access >> 13) & 1u;
    segment->db = (descriptor.access >> 14) & 1u;
    segment->g = (descriptor.access >> 15) & 1u;
    segment->unusable = (descriptor.access >> 16) & 1u;
    return 0;
}

static int
edge_kvm_bhyve_set_segment(struct vcpu *vcpu, enum vm_reg_name name,
    const edge_kvm_segment_t *segment)
{
    struct seg_desc descriptor = {
        .base = segment->base,
        .limit = segment->limit,
        .access = ((uint32_t)segment->type & 0xfu) |
            (((uint32_t)segment->s & 1u) << 4) |
            (((uint32_t)segment->dpl & 3u) << 5) |
            (((uint32_t)segment->present & 1u) << 7) |
            (((uint32_t)segment->avl & 1u) << 12) |
            (((uint32_t)segment->l & 1u) << 13) |
            (((uint32_t)segment->db & 1u) << 14) |
            (((uint32_t)segment->g & 1u) << 15) |
            (((uint32_t)segment->unusable & 1u) << 16),
    };
    int error = vm_set_register(vcpu, name, segment->selector);

    if (error != 0)
        return error;
    return vm_set_seg_desc(vcpu, name, &descriptor);
}

static int
edge_kvm_bhyve_vcpu_get_sregs(void *context, uint64_t backend_cookie,
    edge_kvm_sregs_t *registers)
{
    static const enum vm_reg_name segment_names[] = {
        VM_REG_GUEST_CS, VM_REG_GUEST_DS, VM_REG_GUEST_ES,
        VM_REG_GUEST_FS, VM_REG_GUEST_GS, VM_REG_GUEST_SS,
        VM_REG_GUEST_TR, VM_REG_GUEST_LDTR,
    };
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    edge_kvm_segment_t *segments;
    struct seg_desc descriptor;
    int error;

    (void)context;
    if (!backend_vcpu || !registers)
        return -EDGE_LINUX_EINVAL;
    memset(registers, 0, sizeof(*registers));
    segments = &registers->cs;
    for (uint32_t index = 0;
         index < sizeof(segment_names) / sizeof(segment_names[0]); ++index) {
        error = edge_kvm_bhyve_get_segment(
            backend_vcpu->vcpu, segment_names[index], &segments[index]);
        if (error != 0)
            return edge_kvm_bhyve_error(error);
    }
    error = vm_get_seg_desc(backend_vcpu->vcpu, VM_REG_GUEST_GDTR,
        &descriptor);
    if (error != 0)
        return edge_kvm_bhyve_error(error);
    registers->gdt.base = descriptor.base;
    registers->gdt.limit = (uint16_t)descriptor.limit;
    error = vm_get_seg_desc(backend_vcpu->vcpu, VM_REG_GUEST_IDTR,
        &descriptor);
    if (error != 0)
        return edge_kvm_bhyve_error(error);
    registers->idt.base = descriptor.base;
    registers->idt.limit = (uint16_t)descriptor.limit;
    error = vm_get_register(backend_vcpu->vcpu, VM_REG_GUEST_CR0,
        &registers->cr0);
    if (error == 0)
        error = vm_get_register(backend_vcpu->vcpu, VM_REG_GUEST_CR2,
            &registers->cr2);
    if (error == 0)
        error = vm_get_register(backend_vcpu->vcpu, VM_REG_GUEST_CR3,
            &registers->cr3);
    if (error == 0)
        error = vm_get_register(backend_vcpu->vcpu, VM_REG_GUEST_CR4,
            &registers->cr4);
    if (error == 0)
        error = vm_get_register(backend_vcpu->vcpu, VM_REG_GUEST_EFER,
            &registers->efer);
    if (error != 0)
        return edge_kvm_bhyve_error(error);
    registers->cr8 = vlapic_get_cr8(vm_lapic(backend_vcpu->vcpu));
    registers->apic_base =
        vlapic_get_apicbase(vm_lapic(backend_vcpu->vcpu));
    return 0;
}

static int
edge_kvm_bhyve_vcpu_set_sregs(void *context, uint64_t backend_cookie,
    const edge_kvm_sregs_t *registers)
{
    static const enum vm_reg_name segment_names[] = {
        VM_REG_GUEST_CS, VM_REG_GUEST_DS, VM_REG_GUEST_ES,
        VM_REG_GUEST_FS, VM_REG_GUEST_GS, VM_REG_GUEST_SS,
        VM_REG_GUEST_TR, VM_REG_GUEST_LDTR,
    };
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    const edge_kvm_segment_t *segments;
    struct seg_desc descriptor;
    int error;

    (void)context;
    if (!backend_vcpu || !registers)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < 4; ++index) {
        if (registers->interrupt_bitmap[index] != 0)
            return -EDGE_LINUX_EINVAL;
    }
    segments = &registers->cs;
    for (uint32_t index = 0;
         index < sizeof(segment_names) / sizeof(segment_names[0]); ++index) {
        error = edge_kvm_bhyve_set_segment(
            backend_vcpu->vcpu, segment_names[index], &segments[index]);
        if (error != 0)
            return edge_kvm_bhyve_error(error);
    }
    descriptor = (struct seg_desc) {
        .base = registers->gdt.base,
        .limit = registers->gdt.limit,
    };
    error = vm_set_seg_desc(backend_vcpu->vcpu, VM_REG_GUEST_GDTR,
        &descriptor);
    if (error != 0)
        return edge_kvm_bhyve_error(error);
    descriptor = (struct seg_desc) {
        .base = registers->idt.base,
        .limit = registers->idt.limit,
    };
    error = vm_set_seg_desc(backend_vcpu->vcpu, VM_REG_GUEST_IDTR,
        &descriptor);
    if (error != 0)
        return edge_kvm_bhyve_error(error);
    error = vm_set_register(backend_vcpu->vcpu, VM_REG_GUEST_CR3,
        registers->cr3);
    if (error == 0)
        error = vm_set_register(backend_vcpu->vcpu, VM_REG_GUEST_CR4,
            registers->cr4);
    if (error == 0)
        error = vm_set_register(backend_vcpu->vcpu, VM_REG_GUEST_EFER,
            registers->efer);
    if (error == 0)
        error = vm_set_register(backend_vcpu->vcpu, VM_REG_GUEST_CR0,
            registers->cr0);
    if (error == 0)
        error = vm_set_register(backend_vcpu->vcpu, VM_REG_GUEST_CR2,
            registers->cr2);
    if (error != 0)
        return edge_kvm_bhyve_error(error);
    if (registers->cr8 > 15)
        return -EDGE_LINUX_EINVAL;
    vlapic_set_cr8(vm_lapic(backend_vcpu->vcpu), registers->cr8);
    error = edge_kvm_bhyve_vlapic_set_apicbase(
        vm_lapic(backend_vcpu->vcpu),
        registers->apic_base);
    return edge_kvm_bhyve_error(error);
}

static int
edge_kvm_bhyve_vcpu_get_fpu(void *context, uint64_t backend_cookie,
    edge_kvm_fpu_t *state)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    struct savefpu *save;

    (void)context;
    if (!backend_vcpu || !state || !backend_vcpu->vcpu->guestfpu)
        return -EDGE_LINUX_EINVAL;
    save = backend_vcpu->vcpu->guestfpu;
    memset(state, 0, sizeof(*state));
    memcpy(state->fpr, save->sv_fp, sizeof(state->fpr));
    state->fcw = save->sv_env.en_cw;
    state->fsw = save->sv_env.en_sw;
    state->ftwx = save->sv_env.en_tw;
    state->last_opcode = save->sv_env.en_opcode;
    state->last_ip = save->sv_env.en_rip;
    state->last_dp = save->sv_env.en_rdp;
    memcpy(state->xmm, save->sv_xmm, sizeof(state->xmm));
    state->mxcsr = save->sv_env.en_mxcsr;
    return 0;
}

static int
edge_kvm_bhyve_vcpu_get_sregs2(void *context, uint64_t backend_cookie,
    edge_kvm_sregs2_t *registers)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    edge_kvm_sregs_t legacy;
    int error;

    if (!backend_vcpu || !registers)
        return -EDGE_LINUX_EINVAL;
    memset(&legacy, 0, sizeof(legacy));
    error = edge_kvm_bhyve_vcpu_get_sregs(
        context, backend_cookie, &legacy);
    if (error < 0)
        return error;
    memset(registers, 0, sizeof(*registers));
    _Static_assert(__builtin_offsetof(edge_kvm_sregs_t,
        interrupt_bitmap) == __builtin_offsetof(edge_kvm_sregs2_t, flags),
        "KVM SREGS and SREGS2 common prefix");
    memcpy(registers, &legacy,
        __builtin_offsetof(edge_kvm_sregs2_t, flags));
    if ((registers->cr0 & (UINT64_C(1) << 31)) != 0 &&
        (registers->cr4 & (UINT64_C(1) << 5)) != 0 &&
        (registers->efer & (UINT64_C(1) << 10)) == 0) {
        for (uint32_t index = 0; index < 4; ++index) {
            error = vm_get_register(backend_vcpu->vcpu,
                (enum vm_reg_name)(VM_REG_GUEST_PDPTE0 + index),
                &registers->pdptrs[index]);
            if (error != 0)
                return edge_kvm_bhyve_error(error);
        }
        registers->flags = EDGE_KVM_SREGS2_PDPTRS_VALID;
    }
    return 0;
}

static int
edge_kvm_bhyve_vcpu_set_sregs2(void *context, uint64_t backend_cookie,
    const edge_kvm_sregs2_t *registers)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    edge_kvm_sregs_t legacy;
    int error;

    if (!backend_vcpu || !registers)
        return -EDGE_LINUX_EINVAL;
    memset(&legacy, 0, sizeof(legacy));
    memcpy(&legacy, registers,
        __builtin_offsetof(edge_kvm_sregs2_t, flags));
    error = edge_kvm_bhyve_vcpu_set_sregs(
        context, backend_cookie, &legacy);
    if (error < 0)
        return error;
    if ((registers->flags & EDGE_KVM_SREGS2_PDPTRS_VALID) != 0) {
        for (uint32_t index = 0; index < 4; ++index) {
            error = vm_set_register(backend_vcpu->vcpu,
                (enum vm_reg_name)(VM_REG_GUEST_PDPTE0 + index),
                registers->pdptrs[index]);
            if (error != 0)
                return edge_kvm_bhyve_error(error);
        }
    }
    return 0;
}

static int
edge_kvm_bhyve_vcpu_set_fpu(void *context, uint64_t backend_cookie,
    const edge_kvm_fpu_t *state)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    struct savefpu *save;

    (void)context;
    if (!backend_vcpu || !state || !backend_vcpu->vcpu->guestfpu ||
        state->padding1 != 0 || state->padding2 != 0)
        return -EDGE_LINUX_EINVAL;
    save = backend_vcpu->vcpu->guestfpu;
    memcpy(save->sv_fp, state->fpr, sizeof(state->fpr));
    save->sv_env.en_cw = state->fcw;
    save->sv_env.en_sw = state->fsw;
    save->sv_env.en_tw = state->ftwx;
    save->sv_env.en_zero = 0;
    save->sv_env.en_opcode = state->last_opcode;
    save->sv_env.en_rip = state->last_ip;
    save->sv_env.en_rdp = state->last_dp;
    memcpy(save->sv_xmm, state->xmm, sizeof(state->xmm));
    save->sv_env.en_mxcsr = state->mxcsr;
    return 0;
}

static int
edge_kvm_bhyve_vcpu_get_lapic(void *context, uint64_t backend_cookie,
    edge_kvm_lapic_state_t *state)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    struct vlapic *vlapic;
    uint64_t current_count = 0;
    bool return_to_userspace = false;
    int mmio_access;

    (void)context;
    if (!backend_vcpu || !state)
        return -EDGE_LINUX_EINVAL;
    vlapic = vm_lapic(backend_vcpu->vcpu);
    if (!vlapic || !vlapic->apic_page)
        return -EDGE_LINUX_ENODEV;
    _Static_assert(sizeof(struct LAPIC) == sizeof(*state),
        "bhyve and KVM local APIC page size");
    memcpy(state->registers, vlapic->apic_page, sizeof(*state));
    mmio_access = (vlapic_get_apicbase(vlapic) & APICBASE_X2APIC) == 0;
    (void)vlapic_read(vlapic, mmio_access, APIC_OFFSET_TIMER_CCR,
        &current_count, &return_to_userspace);
    memcpy(&state->registers[APIC_OFFSET_TIMER_CCR], &current_count,
        sizeof(uint32_t));
    return 0;
}

static int
edge_kvm_bhyve_vcpu_set_lapic(void *context, uint64_t backend_cookie,
    const edge_kvm_lapic_state_t *state)
{
    static const uint32_t lvt_offsets[] = {
        APIC_OFFSET_CMCI_LVT, APIC_OFFSET_TIMER_LVT,
        APIC_OFFSET_THERM_LVT, APIC_OFFSET_PERF_LVT,
        APIC_OFFSET_LINT0_LVT, APIC_OFFSET_LINT1_LVT,
        APIC_OFFSET_ERROR_LVT,
    };
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    struct vlapic *vlapic;
    struct LAPIC *lapic;
    uint32_t *isr;
    uint32_t initial_count;
    uint32_t current_count;

    (void)context;
    if (!backend_vcpu || !state)
        return -EDGE_LINUX_EINVAL;
    vlapic = vm_lapic(backend_vcpu->vcpu);
    if (!vlapic || !vlapic->apic_page)
        return -EDGE_LINUX_ENODEV;
    lapic = vlapic->apic_page;
    memcpy(lapic, state->registers, sizeof(*state));

    memset(vlapic->isrvec_stk, 0, sizeof(vlapic->isrvec_stk));
    vlapic->isrvec_stk_top = 0;
    isr = &lapic->isr0;
    for (uint32_t vector = 0; vector < 256; ++vector) {
        uint32_t word = (vector / 32u) * 4u;

        if ((isr[word] & (UINT32_C(1) << (vector % 32u))) == 0)
            continue;
        if (vlapic->isrvec_stk_top + 1 >= ISRVEC_STK_SIZE)
            return -EDGE_LINUX_EINVAL;
        vlapic->isrvec_stk[++vlapic->isrvec_stk_top] =
            (uint8_t)vector;
    }
    vlapic_svr_write_handler(vlapic);
    for (uint32_t index = 0;
         index < sizeof(lvt_offsets) / sizeof(lvt_offsets[0]); ++index)
        vlapic_lvt_write_handler(vlapic, lvt_offsets[index]);
    vlapic_sync_tpr(vlapic);

    initial_count = lapic->icr_timer;
    current_count = lapic->ccr_timer;
    vlapic_dcr_write_handler(vlapic);
    if (initial_count != 0 && current_count < initial_count)
        lapic->icr_timer = current_count;
    vlapic_icrtmr_write_handler(vlapic);
    lapic->icr_timer = initial_count;
    vlapic->timer_period_bt = vlapic->timer_freq_bt;
    bintime_mul(&vlapic->timer_period_bt, initial_count);
    return 0;
}

static int
edge_kvm_bhyve_vcpu_get_debugregs(void *context, uint64_t backend_cookie,
    edge_kvm_debugregs_t *state)
{
    static const enum vm_reg_name names[] = {
        VM_REG_GUEST_DR0, VM_REG_GUEST_DR1, VM_REG_GUEST_DR2,
        VM_REG_GUEST_DR3, VM_REG_GUEST_DR6, VM_REG_GUEST_DR7,
    };
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    uint64_t *values;
    int error;

    (void)context;
    if (!backend_vcpu || !state)
        return -EDGE_LINUX_EINVAL;
    memset(state, 0, sizeof(*state));
    values = &state->db[0];
    for (uint32_t index = 0;
         index < sizeof(names) / sizeof(names[0]); ++index) {
        error = vm_get_register(
            backend_vcpu->vcpu, names[index], &values[index]);
        if (error != 0)
            return edge_kvm_bhyve_error(error);
    }
    return 0;
}

static int
edge_kvm_bhyve_vcpu_set_debugregs(void *context, uint64_t backend_cookie,
    const edge_kvm_debugregs_t *state)
{
    static const enum vm_reg_name names[] = {
        VM_REG_GUEST_DR0, VM_REG_GUEST_DR1, VM_REG_GUEST_DR2,
        VM_REG_GUEST_DR3, VM_REG_GUEST_DR6, VM_REG_GUEST_DR7,
    };
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    const uint64_t *values;
    int error;

    (void)context;
    if (!backend_vcpu || !state)
        return -EDGE_LINUX_EINVAL;
    values = &state->db[0];
    for (uint32_t index = 0;
         index < sizeof(names) / sizeof(names[0]); ++index) {
        error = vm_set_register(
            backend_vcpu->vcpu, names[index], values[index]);
        if (error != 0)
            return edge_kvm_bhyve_error(error);
    }
    return 0;
}

static int
edge_kvm_bhyve_vcpu_set_guest_debug(void *context, uint64_t backend_cookie,
    const edge_kvm_guest_debug_x86_t *state)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    const uint32_t allowed = EDGE_KVM_GUESTDBG_ENABLE |
        EDGE_KVM_GUESTDBG_SINGLESTEP | EDGE_KVM_GUESTDBG_USE_SW_BP |
        EDGE_KVM_GUESTDBG_USE_HW_BP | EDGE_KVM_GUESTDBG_INJECT_DB |
        EDGE_KVM_GUESTDBG_INJECT_BP | EDGE_KVM_GUESTDBG_BLOCKIRQ;
    uint32_t control;
    edge_kvm_debugregs_t current_registers;
    edge_kvm_debugregs_t desired_registers;
    int old_capabilities[4];
    int capability_names[4] = {
        0, VM_CAP_BPT_EXIT,
        VM_CAP_MASK_HWINTR, VM_CAP_DB_EXIT,
    };
    int desired_capabilities[4];
    int step_capability;
    int error;

    (void)context;
    if (!backend_vcpu || !state)
        return -EDGE_LINUX_EINVAL;
    control = state->control;
    if ((control & ~allowed) != 0 ||
        ((control & ~EDGE_KVM_GUESTDBG_ENABLE) != 0 &&
         (control & EDGE_KVM_GUESTDBG_ENABLE) == 0) ||
        (control & (EDGE_KVM_GUESTDBG_INJECT_DB |
                    EDGE_KVM_GUESTDBG_INJECT_BP)) ==
            (EDGE_KVM_GUESTDBG_INJECT_DB |
             EDGE_KVM_GUESTDBG_INJECT_BP))
        return -EDGE_LINUX_EINVAL;

    step_capability = vmm_is_svm() ?
        VM_CAP_RFLAGS_TF : VM_CAP_MTRAP_EXIT;
    capability_names[0] = step_capability;
    desired_capabilities[0] =
        (control & EDGE_KVM_GUESTDBG_SINGLESTEP) != 0;
    desired_capabilities[1] =
        (control & EDGE_KVM_GUESTDBG_USE_SW_BP) != 0;
    desired_capabilities[2] =
        (control & EDGE_KVM_GUESTDBG_BLOCKIRQ) != 0;
    desired_capabilities[3] =
        (control & EDGE_KVM_GUESTDBG_USE_HW_BP) != 0 ||
        (vmm_is_svm() &&
         (control & EDGE_KVM_GUESTDBG_SINGLESTEP) != 0);
    for (uint32_t index = 0; index < 4; ++index) {
        error = vm_get_capability(backend_vcpu->vcpu,
            capability_names[index], &old_capabilities[index]);
        if (error != 0)
            return edge_kvm_bhyve_error(error);
    }
    error = edge_kvm_bhyve_vcpu_get_debugregs(
        context, backend_cookie, &current_registers);
    if (error < 0)
        return error;
    desired_registers = current_registers;
    if ((control & EDGE_KVM_GUESTDBG_USE_HW_BP) != 0) {
        memcpy(desired_registers.db, state->debug_registers,
            sizeof(desired_registers.db));
        desired_registers.dr6 = state->debug_registers[6];
        desired_registers.dr7 = state->debug_registers[7];
    } else if (backend_vcpu->guest_debug_registers_saved) {
        desired_registers = backend_vcpu->guest_debug_saved_registers;
    }
    error = edge_kvm_bhyve_vcpu_set_debugregs(
        context, backend_cookie, &desired_registers);
    if (error < 0) {
        (void)edge_kvm_bhyve_vcpu_set_debugregs(
            context, backend_cookie, &current_registers);
        return error;
    }
    for (uint32_t index = 0; index < 4; ++index) {
        error = vm_set_capability(backend_vcpu->vcpu,
            capability_names[index], desired_capabilities[index]);
        if (error == 0)
            continue;
        while (index > 0) {
            --index;
            (void)vm_set_capability(backend_vcpu->vcpu,
                capability_names[index], old_capabilities[index]);
        }
        (void)edge_kvm_bhyve_vcpu_set_debugregs(
            context, backend_cookie, &current_registers);
        return edge_kvm_bhyve_error(error);
    }
    if ((control & EDGE_KVM_GUESTDBG_INJECT_DB) != 0)
        error = vm_inject_exception(backend_vcpu->vcpu, IDT_DB, 0, 0, 0);
    else if ((control & EDGE_KVM_GUESTDBG_INJECT_BP) != 0)
        error = vm_inject_exception(backend_vcpu->vcpu, IDT_BP, 0, 0, 0);
    if (error != 0) {
        for (uint32_t index = 0; index < 4; ++index)
            (void)vm_set_capability(backend_vcpu->vcpu,
                capability_names[index], old_capabilities[index]);
        (void)edge_kvm_bhyve_vcpu_set_debugregs(
            context, backend_cookie, &current_registers);
        return edge_kvm_bhyve_error(error);
    }
    if ((control & EDGE_KVM_GUESTDBG_USE_HW_BP) != 0 &&
        !backend_vcpu->guest_debug_registers_saved) {
        backend_vcpu->guest_debug_saved_registers = current_registers;
        backend_vcpu->guest_debug_registers_saved = 1;
    } else if ((control & EDGE_KVM_GUESTDBG_USE_HW_BP) == 0) {
        backend_vcpu->guest_debug_registers_saved = 0;
        memset(&backend_vcpu->guest_debug_saved_registers, 0,
            sizeof(backend_vcpu->guest_debug_saved_registers));
    }
    backend_vcpu->guest_debug_control = control;
    return 0;
}

static int
edge_kvm_bhyve_vcpu_get_xcrs(void *context, uint64_t backend_cookie,
    edge_kvm_xcrs_t *state)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;

    (void)context;
    if (!backend_vcpu || !state)
        return -EDGE_LINUX_EINVAL;
    memset(state, 0, sizeof(*state));
    state->nr_xcrs = 1;
    state->xcrs[0].xcr = 0;
    state->xcrs[0].value = backend_vcpu->vcpu->guest_xcr0;
    return 0;
}

static int
edge_kvm_bhyve_vcpu_set_xcrs(void *context, uint64_t backend_cookie,
    const edge_kvm_xcrs_t *state)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    const struct xsave_limits *limits;
    uint64_t value;

    (void)context;
    if (!backend_vcpu || !state)
        return -EDGE_LINUX_EINVAL;
    if (state->nr_xcrs == 0)
        return 0;
    value = state->xcrs[0].value;
    limits = vmm_get_xsave_limits();
    if (!limits->xsave_enabled || (value & UINT64_C(1)) == 0 ||
        (value & ~limits->xcr0_allowed) != 0 ||
        ((value & (UINT64_C(1) << 2)) != 0 &&
         (value & (UINT64_C(1) << 1)) == 0) ||
        (((value >> 3) & UINT64_C(3)) != 0 &&
         ((value >> 3) & UINT64_C(3)) != UINT64_C(3)) ||
        (((value >> 5) & UINT64_C(7)) != 0 &&
         (((value >> 5) & UINT64_C(7)) != UINT64_C(7) ||
          (value & (UINT64_C(1) << 2)) == 0)))
        return -EDGE_LINUX_EINVAL;
    backend_vcpu->vcpu->guest_xcr0 = value;
    return 0;
}

static uint64_t
edge_kvm_bhyve_xsave_load_u64(const uint8_t *bytes)
{
    uint64_t value;

    memcpy(&value, bytes, sizeof(value));
    return value;
}

static uint32_t
edge_kvm_bhyve_xsave_load_u32(const uint8_t *bytes)
{
    uint32_t value;

    memcpy(&value, bytes, sizeof(value));
    return value;
}

static void
edge_kvm_bhyve_xsave_store_u64(uint8_t *bytes, uint64_t value)
{
    memcpy(bytes, &value, sizeof(value));
}

static int
edge_kvm_bhyve_vcpu_get_xsave(void *context, uint64_t backend_cookie,
    edge_kvm_xsave_t *state)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    const struct xsave_limits *limits;

    (void)context;
    if (!backend_vcpu || !state || !backend_vcpu->vcpu->guestfpu)
        return -EDGE_LINUX_EINVAL;
    limits = vmm_get_xsave_limits();
    if (!limits->xsave_enabled ||
        limits->xsave_max_size > EDGE_KVM_XSAVE_SIZE)
        return -EDGE_LINUX_EOPNOTSUPP;
    memset(state, 0, sizeof(*state));
    memcpy(state->region, backend_vcpu->vcpu->guestfpu,
        limits->xsave_max_size);
    edge_kvm_bhyve_xsave_store_u64(
        state->region + EDGE_KVM_XSAVE_XCR0_OFFSET,
        limits->xcr0_allowed);
    return 0;
}

static int
edge_kvm_bhyve_vcpu_set_xsave(void *context, uint64_t backend_cookie,
    const edge_kvm_xsave_t *state)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    const struct xsave_limits *limits;
    uint64_t reserved = 0;
    uint64_t xcomp_bv;
    uint64_t xstate_bv;
    uint32_t mxcsr;
    uint32_t mxcsr_mask;

    (void)context;
    if (!backend_vcpu || !state || !backend_vcpu->vcpu->guestfpu)
        return -EDGE_LINUX_EINVAL;
    limits = vmm_get_xsave_limits();
    if (!limits->xsave_enabled ||
        limits->xsave_max_size > EDGE_KVM_XSAVE_SIZE)
        return -EDGE_LINUX_EOPNOTSUPP;
    xstate_bv = edge_kvm_bhyve_xsave_load_u64(
        state->region + EDGE_KVM_XSAVE_HEADER_OFFSET);
    xcomp_bv = edge_kvm_bhyve_xsave_load_u64(
        state->region + EDGE_KVM_XSAVE_HEADER_OFFSET + sizeof(uint64_t));
    for (uint32_t index = 0; index < EDGE_KVM_XSAVE_RESERVED_SIZE;
         index += sizeof(uint64_t)) {
        reserved |= edge_kvm_bhyve_xsave_load_u64(
            state->region + EDGE_KVM_XSAVE_RESERVED_OFFSET + index);
    }
    mxcsr = edge_kvm_bhyve_xsave_load_u32(state->region + 24u);
    mxcsr_mask = backend_vcpu->vcpu->guestfpu->sv_env.en_mxcsr_mask;
    if (mxcsr_mask == 0)
        mxcsr_mask = 0xffbfu;
    if ((xstate_bv & ~limits->xcr0_allowed) != 0 || xcomp_bv != 0 ||
        reserved != 0 || (mxcsr & ~mxcsr_mask) != 0)
        return -EDGE_LINUX_EINVAL;
    memcpy(backend_vcpu->vcpu->guestfpu, state->region,
        limits->xsave_max_size);
    return 0;
}

static edge_kvm_msr_entry_t *
edge_kvm_bhyve_find_msr(edge_kvm_bhyve_vcpu_t *backend_vcpu,
    uint32_t index)
{
    for (uint32_t slot = 0; slot < backend_vcpu->msr_count; ++slot) {
        if (backend_vcpu->msr_entries[slot].index == index)
            return &backend_vcpu->msr_entries[slot];
    }
    return 0;
}

static int
edge_kvm_bhyve_store_msr(edge_kvm_bhyve_vcpu_t *backend_vcpu,
    uint32_t index, uint64_t value)
{
    edge_kvm_msr_entry_t *stored =
        edge_kvm_bhyve_find_msr(backend_vcpu, index);

    if (!stored) {
        if (backend_vcpu->msr_count == EDGE_KVM_BHYVE_MAX_MSRS)
            return -EDGE_LINUX_ENOSPC;
        stored = &backend_vcpu->msr_entries[backend_vcpu->msr_count++];
        stored->index = index;
        stored->reserved = 0;
    }
    stored->data = value;
    return 0;
}

static bool
edge_kvm_bhyve_is_amd_performance_msr(uint32_t index)
{
    return (index >= EDGE_KVM_BHYVE_MSR_AMD_PERF_LEGACY_FIRST &&
            index <= EDGE_KVM_BHYVE_MSR_AMD_PERF_LEGACY_LAST) ||
        (index >= EDGE_KVM_BHYVE_MSR_AMD_PERF_EXT_FIRST &&
         index <= EDGE_KVM_BHYVE_MSR_AMD_PERF_EXT_LAST);
}

static bool
edge_kvm_bhyve_is_amd_state_msr(uint32_t index)
{
    return edge_kvm_bhyve_is_amd_performance_msr(index) ||
        index == EDGE_KVM_BHYVE_MSR_AMD_HWCR ||
        index == EDGE_KVM_BHYVE_MSR_AMD_DE_CFG;
}

static bool
edge_kvm_bhyve_is_amd_zero_msr(uint32_t index)
{
    switch (index) {
    case EDGE_KVM_BHYVE_MSR_AMD_NB_CFG:
    case EDGE_KVM_BHYVE_MSR_AMD_PATCH_LOADER:
    case EDGE_KVM_BHYVE_MSR_AMD_MMIO_CONF_BASE:
    case EDGE_KVM_BHYVE_MSR_AMD_TSEG_ADDR:
    case EDGE_KVM_BHYVE_MSR_AMD_TSEG_MASK:
    case EDGE_KVM_BHYVE_MSR_AMD_HSAVE_PA:
    case EDGE_KVM_BHYVE_MSR_AMD_DC_CFG:
    case EDGE_KVM_BHYVE_MSR_AMD_TW_CFG:
    case EDGE_KVM_BHYVE_MSR_AMD_BU_CFG2:
    case EDGE_KVM_BHYVE_MSR_AMD_F15H_EX_CFG:
        return true;
    default:
        return false;
    }
}

static bool
edge_kvm_bhyve_is_mce_msr(const edge_kvm_bhyve_vcpu_t *backend_vcpu,
    uint32_t index)
{
    uint32_t bank_count =
        (uint32_t)(backend_vcpu->mce_capability &
                   EDGE_KVM_X86_MCE_BANK_COUNT_MASK);

    if (backend_vcpu->mce_capability == 0)
        return false;
    if (index == EDGE_KVM_BHYVE_MSR_MCG_CAP ||
        index == EDGE_KVM_BHYVE_MSR_MCG_STATUS)
        return true;
    if (index == EDGE_KVM_BHYVE_MSR_MCG_CTL)
        return (backend_vcpu->mce_capability &
                EDGE_KVM_X86_MCE_CTL_PRESENT) != 0;
    return index >= EDGE_KVM_BHYVE_MSR_MC0_CTL &&
        index < EDGE_KVM_BHYVE_MSR_MC0_CTL +
                    bank_count * EDGE_KVM_BHYVE_MSR_MC_BANK_STRIDE;
}

static int
edge_kvm_bhyve_mce_rdmsr(struct vcpu *vcpu, uint32_t index,
    uint64_t *value, bool *return_user)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu = edge_kvm_bhyve_find_vcpu(vcpu);
    edge_kvm_msr_entry_t *stored;

    if (!backend_vcpu || !edge_kvm_bhyve_is_mce_msr(backend_vcpu, index))
        return -1;
    stored = edge_kvm_bhyve_find_msr(backend_vcpu, index);
    *value = stored ? stored->data : 0;
    *return_user = false;
    return 0;
}

static int
edge_kvm_bhyve_mce_wrmsr(struct vcpu *vcpu, uint32_t index,
    uint64_t value, bool *return_user)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu = edge_kvm_bhyve_find_vcpu(vcpu);
    int status;

    if (!backend_vcpu || !edge_kvm_bhyve_is_mce_msr(backend_vcpu, index))
        return -1;
    if (index != EDGE_KVM_BHYVE_MSR_MCG_CAP) {
        status = edge_kvm_bhyve_store_msr(backend_vcpu, index, value);
        if (status < 0)
            return EDGE_LINUX_ENOSPC;
    }
    *return_user = false;
    return 0;
}

static int
edge_kvm_bhyve_compat_rdmsr(uint32_t index, uint64_t *value,
    bool *return_user)
{
    if (index != EDGE_KVM_BHYVE_MSR_IA32_BIOS_SIGN_ID)
        return -1;
    /*
     * Linux probes the microcode signature during early boot even when the
     * exposed CPU is AMD. KVM completes the absent value as zero; bhyve
     * otherwise returns this probe to userspace as an unknown MSR.
     */
    *value = 0;
    *return_user = false;
    return 0;
}

static int
edge_kvm_bhyve_compat_wrmsr(uint32_t index, bool *return_user)
{
    if (index != EDGE_KVM_BHYVE_MSR_IA32_BIOS_SIGN_ID)
        return -1;
    /*
     * Intel guests clear IA32_BIOS_SIGN_ID before CPUID refreshes the
     * microcode signature. Linux KVM accepts guest writes without changing
     * the userspace-configured revision, so the bhyve backend must consume
     * the write instead of returning an unknown-MSR exit to QEMU.
     */
    *return_user = false;
    return 0;
}

static int
edge_kvm_bhyve_faulting_rdmsr(struct vcpu *vcpu, uint32_t index,
    bool *return_user)
{
    if (index != EDGE_KVM_BHYVE_MSR_AMD64_LS_CFG)
        return -1;
    /*
     * AMD LS_CFG is family-specific and is not enumerated by CPUID. Linux
     * probes it with rdmsr_safe(); inject the architectural #GP used by KVM
     * when the virtual CPU does not implement this MSR.
     */
    vm_inject_gp(vcpu);
    *return_user = false;
    return 0;
}

int
vmx_rdmsr(struct vmx_vcpu *vcpu, u_int number, uint64_t *value,
    bool *return_user)
{
    if (number == EDGE_KVM_BHYVE_MSR_IA32_FEATURE_CONTROL) {
        /*
         * Linux reads this MSR before enabling VMX.  Match the KVM
         * contract for an Intel vCPU whose VMX operation is locked on and
         * permitted outside SMX.
         */
        *value = IA32_FEATURE_CONTROL_LOCK | IA32_FEATURE_CONTROL_VMX_EN;
        *return_user = false;
        return 0;
    }
    if (number == EDGE_KVM_BHYVE_MSR_IA32_MISC_FEATURES_ENABLES) {
        /* No optional miscellaneous CPU features are enabled by KVM. */
        *value = 0;
        *return_user = false;
        return 0;
    }
    if (number == EDGE_KVM_BHYVE_MSR_IA32_PERF_CAPABILITIES) {
        *value = 0;
        *return_user = false;
        return 0;
    }
    if (edge_kvm_bhyve_compat_rdmsr(number, value, return_user) == 0)
        return 0;
    if (edge_kvm_bhyve_mce_rdmsr(
            vcpu->vcpu, number, value, return_user) == 0)
        return 0;
    if (edge_kvm_bhyve_faulting_rdmsr(
            vcpu->vcpu, number, return_user) == 0)
        return 0;
    return edge_bhyve_upstream_vmx_rdmsr(
        vcpu, number, value, return_user);
}

int
vmx_wrmsr(struct vmx_vcpu *vcpu, u_int number, uint64_t value,
    bool *return_user)
{
    if (number == EDGE_KVM_BHYVE_MSR_IA32_MISC_FEATURES_ENABLES &&
        value == 0) {
        *return_user = false;
        return 0;
    }
    if (edge_kvm_bhyve_compat_wrmsr(number, return_user) == 0)
        return 0;
    if (edge_kvm_bhyve_mce_wrmsr(
            vcpu->vcpu, number, value, return_user) == 0)
        return 0;
    return edge_bhyve_upstream_vmx_wrmsr(
        vcpu, number, value, return_user);
}

int
svm_rdmsr(struct svm_vcpu *vcpu, u_int number, uint64_t *value,
    bool *return_user)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu;
    edge_kvm_msr_entry_t *stored;

    if (number == EDGE_KVM_BHYVE_MSR_TSC_AUX) {
        backend_vcpu = edge_kvm_bhyve_find_vcpu(vcpu->vcpu);
        if (!backend_vcpu)
            return -1;
        stored = edge_kvm_bhyve_find_msr(backend_vcpu, number);
        *value = stored ? stored->data : 0;
        *return_user = false;
        return 0;
    }
    if (edge_kvm_bhyve_is_amd_state_msr(number)) {
        backend_vcpu = edge_kvm_bhyve_find_vcpu(vcpu->vcpu);
        if (!backend_vcpu)
            return -1;
        stored = edge_kvm_bhyve_find_msr(backend_vcpu, number);
        *value = stored ? stored->data : 0;
        *return_user = false;
        return 0;
    }
    if (edge_kvm_bhyve_is_amd_zero_msr(number)) {
        *value = 0;
        *return_user = false;
        return 0;
    }
    if (edge_kvm_bhyve_compat_rdmsr(number, value, return_user) == 0)
        return 0;
    if (edge_kvm_bhyve_mce_rdmsr(
            vcpu->vcpu, number, value, return_user) == 0)
        return 0;
    if (edge_kvm_bhyve_faulting_rdmsr(
            vcpu->vcpu, number, return_user) == 0)
        return 0;
    return edge_bhyve_upstream_svm_rdmsr(
        vcpu, number, value, return_user);
}

int
svm_wrmsr(struct svm_vcpu *vcpu, u_int number, uint64_t value,
    bool *return_user)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu;

    if (edge_kvm_bhyve_compat_wrmsr(number, return_user) == 0)
        return 0;

    if (number == EDGE_KVM_BHYVE_MSR_TSC_AUX) {
        backend_vcpu = edge_kvm_bhyve_find_vcpu(vcpu->vcpu);
        if (!backend_vcpu ||
            edge_kvm_bhyve_store_msr(backend_vcpu, number, value) < 0)
            return EDGE_LINUX_ENOSPC;
        *return_user = false;
        return 0;
    }
    if (edge_kvm_bhyve_is_amd_state_msr(number)) {
        backend_vcpu = edge_kvm_bhyve_find_vcpu(vcpu->vcpu);
        if (!backend_vcpu ||
            edge_kvm_bhyve_store_msr(backend_vcpu, number, value) < 0)
            return EDGE_LINUX_ENOSPC;
        *return_user = false;
        return 0;
    }
    if (edge_kvm_bhyve_is_amd_zero_msr(number)) {
        *return_user = false;
        return 0;
    }
    if (edge_kvm_bhyve_mce_wrmsr(
            vcpu->vcpu, number, value, return_user) == 0)
        return 0;
    return edge_bhyve_upstream_svm_wrmsr(
        vcpu, number, value, return_user);
}

static void
edge_kvm_bhyve_apply_mtrr(struct vm_mtrr *mtrr, uint32_t index,
    uint64_t value)
{
    if (index == MSR_MTRRdefType ||
        (index >= MSR_MTRR4kBase && index <= MSR_MTRR4kBase + 7) ||
        (index >= MSR_MTRR16kBase && index <= MSR_MTRR16kBase + 1) ||
        index == MSR_MTRR64kBase ||
        (index >= MSR_MTRRVarBase &&
         index < MSR_MTRRVarBase + VMM_MTRR_VAR_MAX * 2u))
        (void)vm_wrmtrr(mtrr, index, value);
}

static void
edge_kvm_bhyve_apply_msr(edge_kvm_bhyve_vcpu_t *backend_vcpu,
    uint32_t index, uint64_t value)
{
    if (vmm_is_svm()) {
        struct svm_vcpu *svm_vcpu = backend_vcpu->vcpu->cookie;
        struct vmcb_state *state = svm_get_vmcb_state(svm_vcpu);

        edge_kvm_bhyve_apply_mtrr(&svm_vcpu->mtrr, index, value);

        switch (index) {
        case UINT32_C(0x00000174): state->sysenter_cs = value; break;
        case UINT32_C(0x00000175): state->sysenter_esp = value; break;
        case UINT32_C(0x00000176): state->sysenter_eip = value; break;
        case UINT32_C(0x00000277): state->g_pat = value; break;
        case UINT32_C(0xc0000081): state->star = value; break;
        case UINT32_C(0xc0000082): state->lstar = value; break;
        case UINT32_C(0xc0000083): state->cstar = value; break;
        case UINT32_C(0xc0000084): state->sfmask = value; break;
        case UINT32_C(0xc0000102): state->kernelgsbase = value; break;
        default: break;
        }
        svm_set_dirty(svm_vcpu, VMCB_CACHE_CR | VMCB_CACHE_I);
    } else if (vmm_is_intel()) {
        struct vmx_vcpu *vmx_vcpu = backend_vcpu->vcpu->cookie;

        edge_kvm_bhyve_apply_mtrr(&vmx_vcpu->mtrr, index, value);

        switch (index) {
        case UINT32_C(0x00000277):
            vmx_vcpu->guest_msrs[IDX_MSR_PAT] = value;
            break;
        case UINT32_C(0xc0000081):
            vmx_vcpu->guest_msrs[IDX_MSR_STAR] = value;
            break;
        case UINT32_C(0xc0000082):
            vmx_vcpu->guest_msrs[IDX_MSR_LSTAR] = value;
            break;
        case UINT32_C(0xc0000083):
            vmx_vcpu->guest_msrs[IDX_MSR_CSTAR] = value;
            break;
        case UINT32_C(0xc0000084):
            vmx_vcpu->guest_msrs[IDX_MSR_SF_MASK] = value;
            break;
        case UINT32_C(0xc0000102):
            vmx_vcpu->guest_msrs[IDX_MSR_KGSBASE] = value;
            break;
        default: break;
        }
    }
}

static int
edge_kvm_bhyve_vcpu_set_msrs(void *context, uint64_t backend_cookie,
    const edge_kvm_msr_entry_t *entries, uint32_t count)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;

    (void)context;
    if (!backend_vcpu || (count != 0 && !entries))
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < count; ++index) {
        if (entries[index].reserved != 0)
            return (int)index;
        if (edge_kvm_bhyve_store_msr(backend_vcpu,
                entries[index].index, entries[index].data) < 0)
            return (int)index;
        edge_kvm_bhyve_apply_msr(backend_vcpu, entries[index].index,
            entries[index].data);
    }
    return (int)count;
}

static int64_t
edge_kvm_bhyve_vcpu_get_tsc_khz(void *context, uint64_t backend_cookie)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    uint64_t frequency_khz;

    (void)context;
    if (!backend_vcpu)
        return -EDGE_LINUX_EINVAL;
    frequency_khz = tsc_freq / UINT64_C(1000);
    if (frequency_khz == 0 || frequency_khz > UINT32_MAX)
        return -EDGE_LINUX_EIO;
    return (int64_t)frequency_khz;
}

static int
edge_kvm_bhyve_vcpu_set_tsc_khz(void *context, uint64_t backend_cookie,
    uint32_t frequency_khz)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    uint64_t host_frequency_khz;

    (void)context;
    if (!backend_vcpu)
        return -EDGE_LINUX_EINVAL;
    host_frequency_khz = tsc_freq / UINT64_C(1000);
    if (host_frequency_khz == 0 || host_frequency_khz > UINT32_MAX)
        return -EDGE_LINUX_EIO;
    if (frequency_khz != 0 && frequency_khz != (uint32_t)host_frequency_khz)
        return -EDGE_LINUX_EOPNOTSUPP;
    backend_vcpu->tsc_frequency_khz = (uint32_t)host_frequency_khz;
    return 0;
}

static int
edge_kvm_bhyve_vcpu_setup_mce(void *context, uint64_t backend_cookie,
    uint64_t capability)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;

    (void)context;
    if (!backend_vcpu ||
        (capability & ~(EDGE_KVM_BHYVE_MCE_FEATURES |
                        EDGE_KVM_X86_MCE_BANK_COUNT_MASK)) != 0 ||
        (capability & EDGE_KVM_X86_MCE_BANK_COUNT_MASK) == 0 ||
        (capability & EDGE_KVM_X86_MCE_BANK_COUNT_MASK) >
            EDGE_KVM_X86_MCE_MAX_BANKS)
        return -EDGE_LINUX_EINVAL;
    backend_vcpu->mce_capability = capability;
    if (edge_kvm_bhyve_store_msr(backend_vcpu,
            EDGE_KVM_BHYVE_MSR_MCG_CAP, capability) < 0 ||
        edge_kvm_bhyve_store_msr(backend_vcpu,
            EDGE_KVM_BHYVE_MSR_MCG_STATUS, 0) < 0 ||
        ((capability & EDGE_KVM_X86_MCE_CTL_PRESENT) != 0 &&
         edge_kvm_bhyve_store_msr(backend_vcpu,
            EDGE_KVM_BHYVE_MSR_MCG_CTL, 0) < 0)) {
        backend_vcpu->mce_capability = 0;
        return -EDGE_LINUX_ENOSPC;
    }
    return 0;
}

static int
edge_kvm_bhyve_vcpu_set_mce(void *context, uint64_t backend_cookie,
    const edge_kvm_x86_mce_t *machine_check)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    edge_kvm_msr_entry_t *stored;
    uint64_t previous_mcg_status;
    uint64_t previous_bank_status;
    uint32_t bank_count;
    uint32_t bank_base;
    int error;

    (void)context;
    if (!backend_vcpu || !machine_check ||
        (machine_check->status & EDGE_KVM_X86_MCE_STATUS_VALID) == 0)
        return -EDGE_LINUX_EINVAL;
    bank_count = (uint32_t)(backend_vcpu->mce_capability &
                            EDGE_KVM_X86_MCE_BANK_COUNT_MASK);
    if (machine_check->bank >= bank_count)
        return -EDGE_LINUX_EINVAL;
    bank_base = EDGE_KVM_BHYVE_MSR_MC0_CTL +
        (uint32_t)machine_check->bank * EDGE_KVM_BHYVE_MSR_MC_BANK_STRIDE;
    stored = edge_kvm_bhyve_find_msr(
        backend_vcpu, bank_base + 1u);
    previous_bank_status = stored ? stored->data : 0;
    if ((machine_check->status & EDGE_KVM_X86_MCE_STATUS_UNCORRECTED) == 0 &&
        (previous_bank_status & (EDGE_KVM_X86_MCE_STATUS_VALID |
                                 EDGE_KVM_X86_MCE_STATUS_UNCORRECTED)) ==
            (EDGE_KVM_X86_MCE_STATUS_VALID |
             EDGE_KVM_X86_MCE_STATUS_UNCORRECTED))
        return 0;
    stored = edge_kvm_bhyve_find_msr(
        backend_vcpu, EDGE_KVM_BHYVE_MSR_MCG_STATUS);
    previous_mcg_status = stored ? stored->data : 0;
    if (edge_kvm_bhyve_store_msr(
            backend_vcpu, bank_base + 1u, machine_check->status) < 0 ||
        edge_kvm_bhyve_store_msr(
            backend_vcpu, bank_base + 2u, machine_check->address) < 0 ||
        edge_kvm_bhyve_store_msr(
            backend_vcpu, bank_base + 3u,
            machine_check->miscellaneous) < 0 ||
        edge_kvm_bhyve_store_msr(
            backend_vcpu, EDGE_KVM_BHYVE_MSR_MCG_STATUS,
            machine_check->mcg_status) < 0)
        return -EDGE_LINUX_ENOSPC;
    if ((machine_check->status & EDGE_KVM_X86_MCE_STATUS_UNCORRECTED) == 0)
        return 0;
    if ((previous_mcg_status & EDGE_KVM_X86_MCG_STATUS_IN_PROGRESS) != 0) {
        error = vm_suspend(backend_vcpu->vm->vm, VM_SUSPEND_TRIPLEFAULT);
        return error == 0 ? 0 : edge_kvm_bhyve_error(error);
    }
    error = vm_inject_exception(backend_vcpu->vcpu, IDT_MC, 0, 0, 0);
    return error == 0 ? 0 : edge_kvm_bhyve_error(error);
}

static int
edge_kvm_bhyve_vcpu_set_signal_mask(void *context, uint64_t backend_cookie,
    uint64_t mask)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;

    (void)context;
    if (!backend_vcpu)
        return -EDGE_LINUX_EINVAL;
    backend_vcpu->signal_mask = mask;
    backend_vcpu->signal_mask_active = 1u;
    return 0;
}

static int
edge_kvm_bhyve_vcpu_get_msrs(void *context, uint64_t backend_cookie,
    edge_kvm_msr_entry_t *entries, uint32_t count)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;

    (void)context;
    if (!backend_vcpu || (count != 0 && !entries))
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < count; ++index) {
        edge_kvm_msr_entry_t *stored;

        if (entries[index].reserved != 0)
            return (int)index;
        stored = edge_kvm_bhyve_find_msr(backend_vcpu,
            entries[index].index);
        entries[index].data = stored ? stored->data : 0;
    }
    return (int)count;
}

static int
edge_kvm_bhyve_complete_io(edge_kvm_bhyve_vcpu_t *backend_vcpu,
    edge_kvm_run_t *run)
{
    uint64_t rax;
    uint32_t value = 0;
    uint64_t mask;
    int error;

    if (!backend_vcpu->pending_io_in)
        return 0;
    memcpy(&value, (uint8_t *)run + EDGE_KVM_RUN_IO_DATA_OFFSET,
        backend_vcpu->pending_io_size);
    error = vm_get_register(backend_vcpu->vcpu, VM_REG_GUEST_RAX, &rax);
    if (error != 0)
        return edge_kvm_bhyve_error(error);
    mask = backend_vcpu->pending_io_size == 4 ? UINT32_MAX :
        ((UINT64_C(1) << (backend_vcpu->pending_io_size * 8u)) - 1u);
    rax = (rax & ~mask) | ((uint64_t)value & mask);
    error = vm_set_register(backend_vcpu->vcpu, VM_REG_GUEST_RAX, rax);
    if (error != 0)
        return edge_kvm_bhyve_error(error);
    backend_vcpu->pending_io_in = 0;
    backend_vcpu->pending_io_size = 0;
    return 0;
}

static int
edge_kvm_bhyve_transfer_string_io(edge_kvm_bhyve_vcpu_t *backend_vcpu,
    struct vm_inout_str *string_io, uint8_t *data, uint32_t iterations,
    bool input)
{
    struct vm_copyinfo copyinfo[2];
    enum vm_reg_name index_register = input ?
        VM_REG_GUEST_RDI : VM_REG_GUEST_RSI;
    uint64_t address_mask = vie_size2mask(string_io->addrsize);
    uint64_t index = string_io->index & address_mask;
    uint64_t count = string_io->count & address_mask;
    int protection = input ? PROT_WRITE : PROT_READ;
    int error;

    if (string_io->addrsize != 2 && string_io->addrsize != 4 &&
        string_io->addrsize != 8)
        return -EDGE_LINUX_EINVAL;
    if (iterations > count)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t iteration = 0; iteration < iterations; ++iteration) {
        uint64_t linear_address;
        int fault = 0;

        if (vie_calculate_gla(string_io->paging.cpu_mode,
            string_io->seg_name, &string_io->seg_desc, index,
            string_io->inout.bytes, string_io->addrsize, protection,
            &linear_address) != 0) {
            vm_inject_gp(backend_vcpu->vcpu);
            return 1;
        }
        error = vm_copy_setup(backend_vcpu->vcpu, &string_io->paging,
            linear_address, string_io->inout.bytes, protection, copyinfo,
            2, &fault);
        if (error != 0)
            return edge_kvm_bhyve_error(error);
        if (fault != 0) {
            vm_copy_teardown(copyinfo, 2);
            return 1;
        }
        if (vie_alignment_check(string_io->paging.cpl,
            string_io->inout.bytes, string_io->cr0, string_io->rflags,
            linear_address) != 0) {
            vm_copy_teardown(copyinfo, 2);
            vm_inject_ac(backend_vcpu->vcpu, 0);
            return 1;
        }
        if (input) {
            vm_copyout(data + iteration * string_io->inout.bytes,
                copyinfo, string_io->inout.bytes);
        } else {
            vm_copyin(copyinfo,
                data + iteration * string_io->inout.bytes,
                string_io->inout.bytes);
        }
        vm_copy_teardown(copyinfo, 2);
        if ((string_io->rflags & PSL_D) != 0)
            index -= string_io->inout.bytes;
        else
            index += string_io->inout.bytes;
        --count;
    }
    error = vie_update_register(backend_vcpu->vcpu, index_register,
        index, string_io->addrsize);
    if (error == 0 && string_io->inout.rep)
        error = vie_update_register(backend_vcpu->vcpu,
            VM_REG_GUEST_RCX, count, string_io->addrsize);
    if (error != 0)
        return edge_kvm_bhyve_error(error);
    if (count != 0)
        backend_vcpu->vcpu->nextrip =
            vm_exitinfo(backend_vcpu->vcpu)->rip;
    return 0;
}

static int
edge_kvm_bhyve_complete_string_io(edge_kvm_bhyve_vcpu_t *backend_vcpu,
    edge_kvm_run_t *run)
{
    struct vm_exit *vm_exit;
    int error;

    if (!backend_vcpu->pending_string_in)
        return 0;
    vm_exit = vm_exitinfo(backend_vcpu->vcpu);
    error = edge_kvm_bhyve_transfer_string_io(backend_vcpu,
        &vm_exit->u.inout_str,
        (uint8_t *)run + EDGE_KVM_RUN_IO_DATA_OFFSET,
        backend_vcpu->pending_string_count, true);
    backend_vcpu->pending_string_in = 0;
    backend_vcpu->pending_string_count = 0;
    return error;
}

typedef struct edge_kvm_bhyve_mmio_context {
    edge_kvm_run_t *run;
    edge_kvm_bhyve_vcpu_t *backend_vcpu;
    uint8_t completing_read;
    uint8_t read_requested;
    uint8_t write_seen;
    uint8_t coalesced_write;
} edge_kvm_bhyve_mmio_context_t;

static int
edge_kvm_bhyve_mmio_read(struct vcpu *vcpu, uint64_t gpa,
    uint64_t *value, int size, void *argument)
{
    edge_kvm_bhyve_mmio_context_t *context = argument;

    (void)vcpu;
    if (!context || !context->run || !value || size <= 0 || size > 8)
        return 22;
    context->run->exit_reason = EDGE_KVM_EXIT_MMIO;
    context->run->exit.mmio.physical_address = gpa;
    context->run->exit.mmio.length = (uint32_t)size;
    context->run->exit.mmio.is_write = 0;
    if (!context->completing_read) {
        context->read_requested = 1;
        return 11;
    }
    *value = 0;
    memcpy(value, context->run->exit.mmio.data, (size_t)size);
    return 0;
}

static int
edge_kvm_bhyve_mmio_write(struct vcpu *vcpu, uint64_t gpa,
    uint64_t value, int size, void *argument)
{
    edge_kvm_bhyve_mmio_context_t *context = argument;

    (void)vcpu;
    if (!context || !context->run || !context->backend_vcpu ||
        size <= 0 || size > 8)
        return 22;
    if (edge_kvm_bhyve_coalesced_mmio_write(
            context->backend_vcpu->vm, gpa, value,
            (uint32_t)size) > 0) {
        context->write_seen = 1;
        context->coalesced_write = 1;
        return 0;
    }
    context->run->exit_reason = EDGE_KVM_EXIT_MMIO;
    context->run->exit.mmio.physical_address = gpa;
    context->run->exit.mmio.length = (uint32_t)size;
    context->run->exit.mmio.is_write = 1;
    memcpy(context->run->exit.mmio.data, &value, (size_t)size);
    context->write_seen = 1;
    return 0;
}

static int
edge_kvm_bhyve_complete_mmio(edge_kvm_bhyve_vcpu_t *backend_vcpu,
    edge_kvm_run_t *run)
{
    struct vm_exit *vm_exit;
    edge_kvm_bhyve_mmio_context_t context = {
        .run = run,
        .backend_vcpu = backend_vcpu,
        .completing_read = 1,
    };
    int error;

    if (!backend_vcpu->pending_mmio_read)
        return 0;
    if (backend_vcpu->pending_mmio_opcode == UINT8_C(0xa0)) {
        uint64_t rax;
        int register_error = vm_get_register(
            backend_vcpu->vcpu, VM_REG_GUEST_RAX, &rax);

        if (register_error != 0)
            return edge_kvm_bhyve_error(register_error);
        rax = (rax & ~UINT64_C(0xff)) | run->exit.mmio.data[0];
        register_error = vm_set_register(
            backend_vcpu->vcpu, VM_REG_GUEST_RAX, rax);
        if (register_error != 0)
            return edge_kvm_bhyve_error(register_error);
        backend_vcpu->pending_mmio_read = 0;
        backend_vcpu->pending_mmio_opcode = 0;
        return 0;
    }
    vm_exit = vm_exitinfo(backend_vcpu->vcpu);
    error = vmm_emulate_instruction(backend_vcpu->vcpu,
        vm_exit->u.inst_emul.gpa, &vm_exit->u.inst_emul.vie,
        &vm_exit->u.inst_emul.paging, edge_kvm_bhyve_mmio_read,
        edge_kvm_bhyve_mmio_write, &context);
    if (error != 0)
        return edge_kvm_bhyve_error(error);
    backend_vcpu->pending_mmio_read = 0;
    return 0;
}

static int
edge_kvm_bhyve_moffset8_exit(edge_kvm_bhyve_vcpu_t *backend_vcpu,
    struct vm_exit *vm_exit, edge_kvm_run_t *run)
{
    struct vie *vie = &vm_exit->u.inst_emul.vie;
    uint32_t opcode_offset = 0;
    uint32_t address_size;
    bool address_override = false;
    uint8_t opcode;

    while (opcode_offset < vie->num_valid) {
        uint8_t byte = vie->inst[opcode_offset];

        if (byte == UINT8_C(0x67)) {
            address_override = true;
        } else if (byte != UINT8_C(0x66) && byte != UINT8_C(0xf0) &&
                   byte != UINT8_C(0xf2) && byte != UINT8_C(0xf3) &&
                   byte != UINT8_C(0x26) && byte != UINT8_C(0x2e) &&
                   byte != UINT8_C(0x36) && byte != UINT8_C(0x3e) &&
                   byte != UINT8_C(0x64) && byte != UINT8_C(0x65)) {
            break;
        }
        ++opcode_offset;
    }
    if (opcode_offset >= vie->num_valid)
        return 0;
    opcode = vie->inst[opcode_offset];
    if (opcode != UINT8_C(0xa0) && opcode != UINT8_C(0xa2))
        return 0;
    if (vm_exit->u.inst_emul.paging.cpu_mode == CPU_MODE_64BIT) {
        address_size = address_override ? 4u : 8u;
    } else {
        address_size = vm_exit->u.inst_emul.cs_d ? 4u : 2u;
        if (address_override)
            address_size = address_size == 4u ? 2u : 4u;
    }
    backend_vcpu->vcpu->nextrip = vm_exit->rip + opcode_offset + 1u +
        address_size;
    run->exit_reason = EDGE_KVM_EXIT_MMIO;
    run->exit.mmio.physical_address = vm_exit->u.inst_emul.gpa;
    run->exit.mmio.length = 1;
    run->exit.mmio.is_write = opcode == UINT8_C(0xa2);
    if (opcode == UINT8_C(0xa2)) {
        uint64_t rax;
        int error = vm_get_register(
            backend_vcpu->vcpu, VM_REG_GUEST_RAX, &rax);

        if (error != 0)
            return edge_kvm_bhyve_error(error);
        if (edge_kvm_bhyve_coalesced_mmio_write(
                backend_vcpu->vm, vm_exit->u.inst_emul.gpa,
                rax & UINT64_C(0xff), 1) > 0)
            return 2;
        run->exit.mmio.data[0] = (uint8_t)rax;
    } else {
        backend_vcpu->pending_mmio_read = 1;
        backend_vcpu->pending_mmio_opcode = opcode;
    }
    return 1;
}

static int
edge_kvm_bhyve_finish_vcpu_ioctl(struct vcpu *vcpu, int result)
{
    int error = vcpu_set_state(vcpu, VCPU_IDLE, false);

    return error == 0 ? result : edge_kvm_bhyve_error(error);
}

static int
edge_kvm_bhyve_signal_pioeventfd(edge_kvm_bhyve_vcpu_t *backend_vcpu,
    uint16_t port, uint32_t length, uint32_t value)
{
    edge_kvm_bhyve_vm_t *backend_vm = backend_vcpu->vm;
    uint64_t mask = length == 4 ? UINT32_MAX :
        ((UINT64_C(1) << (length * 8u)) - 1u);

    for (uint32_t index = 0; index < EDGE_KVM_BHYVE_MAX_IOEVENTFDS;
         ++index) {
        const edge_kvm_bhyve_ioeventfd_t *entry =
            &backend_vm->ioeventfds[index];
        const edge_kvm_ioeventfd_registration_t *registration =
            &entry->registration;
        int64_t result;

        if (!entry->active ||
            (registration->flags & EDGE_KVM_IOEVENTFD_FLAG_PIO) == 0 ||
            registration->address != port ||
            (registration->length != 0 &&
             registration->length != length) ||
            ((registration->flags & EDGE_KVM_IOEVENTFD_FLAG_DATAMATCH) != 0 &&
             (registration->datamatch & mask) != ((uint64_t)value & mask)))
            continue;
        result = kernel_eventfd_write_value(
            registration->event_id, 1, 1u);
        return result < 0 ? (int)result : 1;
    }
    return 0;
}

static int
edge_kvm_bhyve_vcpu_run_inner(void *context, uint64_t backend_cookie,
    edge_kvm_run_t *run)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    struct vm_exit *vm_exit;
    uint32_t io_value;
    int error;

    (void)context;
    if (!backend_vcpu || !run)
        return -EDGE_LINUX_EINVAL;
    if (run->immediate_exit ||
        edge_kvm_bhyve_task_signal_pending(process_current_task()))
        return -EDGE_LINUX_EINTR;
    error = edge_kvm_bhyve_complete_io(backend_vcpu, run);
    if (error < 0)
        return error;
    error = edge_kvm_bhyve_complete_string_io(backend_vcpu, run);
    if (error < 0)
        return error;
    error = edge_kvm_bhyve_complete_mmio(backend_vcpu, run);
    if (error < 0)
        return error;
    memset(&run->exit, 0, sizeof(run->exit));
    run->exit_reason = EDGE_KVM_EXIT_UNKNOWN;
    run->ready_for_interrupt_injection = 0;
    run->if_flag = 0;

    if (backend_vcpu->mp_state == EDGE_KVM_MP_STATE_UNINITIALIZED ||
        backend_vcpu->mp_state == EDGE_KVM_MP_STATE_INIT_RECEIVED) {
        uint64_t observed = __atomic_load_n(
            &backend_vcpu->startup_sequence, __ATOMIC_ACQUIRE);
        uint64_t deadline = boottime_monotonic_us() + UINT64_C(10000);

        (void)kernel_runtime_wait_sequence(
            &backend_vcpu->startup_sequence, observed, deadline);
        return -EDGE_LINUX_EINTR;
    }
    if (__atomic_exchange_n(
            &backend_vcpu->startup_sipi_pending, 0,
            __ATOMIC_ACQ_REL) != 0) {
        uint64_t vector = backend_vcpu->event_state.sipi_vector & 0xffu;
        struct seg_desc descriptor = {
            .base = vector << 12,
            .limit = UINT32_C(0xffff),
            .access = UINT32_C(0x9b),
        };

        if (__atomic_exchange_n(
                &backend_vcpu->startup_reset_pending, 0,
                __ATOMIC_ACQ_REL) != 0)
            error = edge_kvm_bhyve_vcpu_reset_state(backend_vcpu->vcpu);
        else
            error = 0;
        if (error == 0)
            error = vm_set_register(
                backend_vcpu->vcpu, VM_REG_GUEST_CS, vector << 8);
        if (error == 0)
            error = vm_set_seg_desc(
                backend_vcpu->vcpu, VM_REG_GUEST_CS, &descriptor);
        if (error == 0)
            error = vm_set_register(
                backend_vcpu->vcpu, VM_REG_GUEST_RIP, 0);
        if (error != 0)
            return edge_kvm_bhyve_error(error);
    }
    if (backend_vcpu->mp_state == EDGE_KVM_MP_STATE_HALTED)
        backend_vcpu->mp_state = EDGE_KVM_MP_STATE_RUNNABLE;

run_guest:
    if (process_current_task() &&
        __atomic_load_n(&process_current_task()->need_resched,
            __ATOMIC_ACQUIRE) != 0)
        return -EDGE_LINUX_EINTR;
    __atomic_store_n(&backend_vcpu->active_task,
        process_current_task(), __ATOMIC_RELEASE);
    __atomic_store_n(&backend_vcpu->active_run, run, __ATOMIC_RELEASE);
    if (process_current_task_interrupt_notifier_set(
            edge_kvm_bhyve_signal_notify, backend_vcpu) < 0) {
        __atomic_store_n(&backend_vcpu->active_run, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&backend_vcpu->active_task, 0, __ATOMIC_RELEASE);
        return -EDGE_LINUX_ESRCH;
    }
    edge_kvm_bhyve_signal_notify(backend_vcpu);
    (void)callout_reset_sbt(&backend_vcpu->immediate_exit_callout,
        SBT_1MS, 0, edge_kvm_bhyve_immediate_exit_poll,
        backend_vcpu, C_HARDCLOCK | C_DIRECT_EXEC);
    error = vcpu_set_state(backend_vcpu->vcpu, VCPU_FROZEN, true);
    if (error != 0) {
        process_current_task_interrupt_notifier_clear(
            edge_kvm_bhyve_signal_notify, backend_vcpu);
        __atomic_store_n(&backend_vcpu->active_run, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&backend_vcpu->active_task, 0, __ATOMIC_RELEASE);
        (void)callout_stop(&backend_vcpu->immediate_exit_callout);
        return edge_kvm_bhyve_error(error);
    }
    error = vm_run(backend_vcpu->vcpu);
    process_current_task_interrupt_notifier_clear(
        edge_kvm_bhyve_signal_notify, backend_vcpu);
    __atomic_store_n(&backend_vcpu->active_run, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&backend_vcpu->active_task, 0, __ATOMIC_RELEASE);
    (void)callout_stop(&backend_vcpu->immediate_exit_callout);
    if (error != 0) {
        return edge_kvm_bhyve_finish_vcpu_ioctl(
            backend_vcpu->vcpu, edge_kvm_bhyve_error(error));
    }
    vm_exit = vm_exitinfo(backend_vcpu->vcpu);
    switch (vm_exit->exitcode) {
    case VM_EXITCODE_REQIDLE:
        return edge_kvm_bhyve_finish_vcpu_ioctl(
            backend_vcpu->vcpu, -EDGE_LINUX_EINTR);
    case VM_EXITCODE_DB:
    case VM_EXITCODE_BPT:
    case VM_EXITCODE_MTRAP:
        run->exit_reason = EDGE_KVM_EXIT_DEBUG;
        run->exit.debug.exception = vm_exit->exitcode == VM_EXITCODE_BPT ?
            IDT_BP : IDT_DB;
        run->exit.debug.program_counter = vm_exit->rip;
        if (vm_exit->exitcode == VM_EXITCODE_MTRAP ||
            (backend_vcpu->guest_debug_control &
             EDGE_KVM_GUESTDBG_SINGLESTEP) != 0)
            run->exit.debug.dr6 = UINT64_C(1) << 14;
        else if (!vmm_is_svm() && vm_exit->exitcode == VM_EXITCODE_DB)
            run->exit.debug.dr6 = vm_exit->u.dbg.dr6;
        else
            (void)vm_get_register(backend_vcpu->vcpu,
                VM_REG_GUEST_DR6, &run->exit.debug.dr6);
        (void)vm_get_register(backend_vcpu->vcpu,
            VM_REG_GUEST_DR7, &run->exit.debug.dr7);
        return edge_kvm_bhyve_finish_vcpu_ioctl(
            backend_vcpu->vcpu, 0);
    case VM_EXITCODE_INOUT:
        if (!vm_exit->u.inout.in) {
            error = edge_kvm_bhyve_signal_pioeventfd(
                backend_vcpu, vm_exit->u.inout.port,
                (uint32_t)vm_exit->u.inout.bytes,
                vm_exit->u.inout.eax);
            if (error < 0)
                return edge_kvm_bhyve_finish_vcpu_ioctl(
                    backend_vcpu->vcpu, error);
            if (error > 0) {
                error = edge_kvm_bhyve_finish_vcpu_ioctl(
                    backend_vcpu->vcpu, 0);
                if (error < 0)
                    return error;
                goto run_guest;
            }
        }
        run->exit_reason = EDGE_KVM_EXIT_IO;
        run->exit.io.direction = vm_exit->u.inout.in ?
            EDGE_KVM_EXIT_IO_IN : EDGE_KVM_EXIT_IO_OUT;
        run->exit.io.size = (uint8_t)vm_exit->u.inout.bytes;
        run->exit.io.port = vm_exit->u.inout.port;
        run->exit.io.count = 1;
        run->exit.io.data_offset = EDGE_KVM_RUN_IO_DATA_OFFSET;
        if (vm_exit->u.inout.in) {
            backend_vcpu->pending_io_in = 1;
            backend_vcpu->pending_io_size =
                (uint8_t)vm_exit->u.inout.bytes;
        } else {
            io_value = vm_exit->u.inout.eax;
            memcpy((uint8_t *)run + EDGE_KVM_RUN_IO_DATA_OFFSET,
                &io_value, vm_exit->u.inout.bytes);
        }
        return edge_kvm_bhyve_finish_vcpu_ioctl(
            backend_vcpu->vcpu, 0);
    case VM_EXITCODE_INOUT_STR:
        {
            struct vm_inout_str *string_io = &vm_exit->u.inout_str;
            uint64_t count = string_io->count &
                vie_size2mask(string_io->addrsize);
            uint32_t iterations = (uint32_t)(count > 16 ? 16 : count);

            if (iterations == 0 ||
                (string_io->inout.bytes != 1 &&
                 string_io->inout.bytes != 2 &&
                 string_io->inout.bytes != 4)) {
                run->exit_reason = EDGE_KVM_EXIT_INTERNAL_ERROR;
                run->exit.internal.suberror =
                    EDGE_KVM_INTERNAL_ERROR_EMULATION;
                run->exit.internal.data_count = 2;
                run->exit.internal.data[0] = VM_EXITCODE_INOUT_STR;
                run->exit.internal.data[1] = vm_exit->rip;
                return edge_kvm_bhyve_finish_vcpu_ioctl(
                    backend_vcpu->vcpu, 0);
            }
            run->exit_reason = EDGE_KVM_EXIT_IO;
            run->exit.io.direction = string_io->inout.in ?
                EDGE_KVM_EXIT_IO_IN : EDGE_KVM_EXIT_IO_OUT;
            run->exit.io.size = (uint8_t)string_io->inout.bytes;
            run->exit.io.port = string_io->inout.port;
            run->exit.io.count = iterations;
            run->exit.io.data_offset = EDGE_KVM_RUN_IO_DATA_OFFSET;
            if (string_io->inout.in) {
                backend_vcpu->pending_string_in = 1;
                backend_vcpu->pending_string_count = (uint8_t)iterations;
            } else {
                error = edge_kvm_bhyve_transfer_string_io(backend_vcpu,
                    string_io,
                    (uint8_t *)run + EDGE_KVM_RUN_IO_DATA_OFFSET,
                    iterations, false);
                if (error < 0)
                    return edge_kvm_bhyve_finish_vcpu_ioctl(
                        backend_vcpu->vcpu, error);
                if (error > 0) {
                    error = edge_kvm_bhyve_finish_vcpu_ioctl(
                        backend_vcpu->vcpu, 0);
                    if (error < 0)
                        return error;
                    goto run_guest;
                }
            }
        }
        return edge_kvm_bhyve_finish_vcpu_ioctl(
            backend_vcpu->vcpu, 0);
    case VM_EXITCODE_RDMSR:
    case VM_EXITCODE_WRMSR:
        /*
         * KVM injects #GP for an unknown MSR unless userspace MSR exits
         * were explicitly enabled.  QEMU relies on this for rdmsr_safe()
         * probes during Linux CPU initialization.
         */
        vm_inject_gp(backend_vcpu->vcpu);
        error = edge_kvm_bhyve_finish_vcpu_ioctl(
            backend_vcpu->vcpu, 0);
        if (error < 0)
            return error;
        goto run_guest;
    case VM_EXITCODE_HLT:
        backend_vcpu->mp_state = EDGE_KVM_MP_STATE_HALTED;
        run->exit_reason = EDGE_KVM_EXIT_HLT;
        return edge_kvm_bhyve_finish_vcpu_ioctl(
            backend_vcpu->vcpu, 0);
    case VM_EXITCODE_SUSPENDED:
        if (vm_exit->u.suspended.how == VM_SUSPEND_HALT) {
            run->exit_reason = EDGE_KVM_EXIT_HLT;
        } else if (vm_exit->u.suspended.how == VM_SUSPEND_TRIPLEFAULT) {
            run->exit_reason = EDGE_KVM_EXIT_SHUTDOWN;
        } else {
            run->exit_reason = EDGE_KVM_EXIT_SYSTEM_EVENT;
            run->exit.system_event.type =
                vm_exit->u.suspended.how == VM_SUSPEND_RESET ?
                EDGE_KVM_SYSTEM_EVENT_RESET :
                EDGE_KVM_SYSTEM_EVENT_SHUTDOWN;
        }
        return edge_kvm_bhyve_finish_vcpu_ioctl(
            backend_vcpu->vcpu, 0);
    case VM_EXITCODE_INST_EMUL:
        {
            edge_kvm_bhyve_mmio_context_t context = {
                .run = run,
                .backend_vcpu = backend_vcpu,
            };

            error = edge_kvm_bhyve_moffset8_exit(
                backend_vcpu, vm_exit, run);
            if (error < 0)
                return edge_kvm_bhyve_finish_vcpu_ioctl(
                    backend_vcpu->vcpu, error);
            if (error > 1) {
                error = edge_kvm_bhyve_finish_vcpu_ioctl(
                    backend_vcpu->vcpu, 0);
                if (error < 0)
                    return error;
                goto run_guest;
            }
            if (error > 0)
                return edge_kvm_bhyve_finish_vcpu_ioctl(
                    backend_vcpu->vcpu, 0);
            error = vmm_emulate_instruction(backend_vcpu->vcpu,
                vm_exit->u.inst_emul.gpa, &vm_exit->u.inst_emul.vie,
                &vm_exit->u.inst_emul.paging,
                edge_kvm_bhyve_mmio_read,
                edge_kvm_bhyve_mmio_write, &context);
            if (error == 11 && context.read_requested) {
                backend_vcpu->pending_mmio_read = 1;
            } else if (error != 0 ||
                       (!context.read_requested && !context.write_seen)) {
                run->exit_reason = EDGE_KVM_EXIT_INTERNAL_ERROR;
                run->exit.internal.suberror =
                    EDGE_KVM_INTERNAL_ERROR_EMULATION;
                run->exit.internal.data_count = 2;
                run->exit.internal.data[0] = vm_exit->u.inst_emul.gpa;
                    run->exit.internal.data[1] = vm_exit->rip;
            }
            if (context.coalesced_write) {
                error = edge_kvm_bhyve_finish_vcpu_ioctl(
                    backend_vcpu->vcpu, 0);
                if (error < 0)
                    return error;
                goto run_guest;
            }
        }
        return edge_kvm_bhyve_finish_vcpu_ioctl(
            backend_vcpu->vcpu, 0);
    default:
        run->exit_reason = EDGE_KVM_EXIT_INTERNAL_ERROR;
        run->exit.internal.suberror = EDGE_KVM_INTERNAL_ERROR_EMULATION;
        run->exit.internal.data_count = 2;
        run->exit.internal.data[0] = (uint64_t)vm_exit->exitcode;
        run->exit.internal.data[1] = vm_exit->rip;
        return edge_kvm_bhyve_finish_vcpu_ioctl(
            backend_vcpu->vcpu, 0);
    }
}

static int
edge_kvm_bhyve_vcpu_run(void *context, uint64_t backend_cookie,
    edge_kvm_run_t *run)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)backend_cookie;
    task_t *current_task;
    uint64_t host_cr0;
    uint64_t host_fs_base;
    uint64_t host_tsc_aux = 0;
    uint64_t saved_affinity = 0;
    uint64_t run_affinity = 0;
    uint64_t available;
    uint64_t previous_mask = 0;
    edge_kvm_msr_entry_t *guest_tsc_aux;
    bool host_fpu_active;
    bool swap_tsc_aux;
    bool task_pinned = false;
    int result;

    if (!backend_vcpu)
        return -EDGE_LINUX_EINVAL;
    current_task = process_current_task();
    if (current_task && !current_task->is_idle) {
        uint32_t ordinal;

        saved_affinity = __atomic_load_n(
            &current_task->scheduler.affinity_mask, __ATOMIC_ACQUIRE);
        available = saved_affinity & scheduler_online_cpu_mask();
        if (available == 0)
            available = scheduler_online_cpu_mask();
        ordinal = (uint32_t)vcpu_vcpuid(backend_vcpu->vcpu) %
            (uint32_t)__builtin_popcountll(available);
        for (uint32_t cpu = 0; cpu < 64; ++cpu) {
            uint64_t bit = UINT64_C(1) << cpu;

            if ((available & bit) == 0)
                continue;
            if (ordinal-- == 0) {
                run_affinity = bit;
                break;
            }
        }
        if (run_affinity != 0 && run_affinity != saved_affinity) {
            __atomic_store_n(&current_task->scheduler.affinity_mask,
                run_affinity, __ATOMIC_RELEASE);
            task_pinned = true;
            if ((run_affinity &
                 (UINT64_C(1) << edge_smp_current_cpu())) == 0) {
                __atomic_store_n(
                    &current_task->need_resched, 1, __ATOMIC_RELEASE);
                scheduler_yield();
            }
        }
    }
    /*
     * FreeBSD runs the kernel with a zero FS base and programs that value in
     * the VMX host-state area.  EdgeOS preserves the calling Linux process TLS
     * base across syscalls, so restore it after every guest transition.
     */
    host_fs_base = rdmsr(MSR_FSBASE);
    host_cr0 = rcr0();
    host_fpu_active = current_task && (host_cr0 & CR0_TS) == 0;
    if (host_fpu_active) {
        x86_fpu_save_state(
            current_task->xsave_region, current_task->fxsave_region);
    }
    swap_tsc_aux = vmm_is_svm();
    guest_tsc_aux = edge_kvm_bhyve_find_msr(
        backend_vcpu, EDGE_KVM_BHYVE_MSR_TSC_AUX);
    if (!backend_vcpu->signal_mask_active) {
        if (swap_tsc_aux) {
            host_tsc_aux = rdmsr(EDGE_KVM_BHYVE_MSR_TSC_AUX);
            wrmsr(EDGE_KVM_BHYVE_MSR_TSC_AUX,
                guest_tsc_aux ? guest_tsc_aux->data : 0);
        }
        result = edge_kvm_bhyve_vcpu_run_inner(
            context, backend_cookie, run);
        if (swap_tsc_aux)
            wrmsr(EDGE_KVM_BHYVE_MSR_TSC_AUX, host_tsc_aux);
        load_cr0(host_cr0);
        if (host_fpu_active) {
            x86_fpu_restore_state(
                current_task->xsave_region, current_task->fxsave_region);
        }
        wrmsr(MSR_FSBASE, host_fs_base);
        if (task_pinned) {
            __atomic_store_n(&current_task->scheduler.affinity_mask,
                saved_affinity, __ATOMIC_RELEASE);
        }
        if (current_task && !current_task->is_idle &&
            __atomic_load_n(&current_task->need_resched,
                __ATOMIC_ACQUIRE) != 0)
            scheduler_yield();
        return result;
    }
    if (kernel_current_signal_mask_get(&previous_mask) < 0 ||
        kernel_current_signal_mask_set(backend_vcpu->signal_mask) < 0) {
        return -EDGE_LINUX_ESRCH;
    }
    if (swap_tsc_aux) {
        host_tsc_aux = rdmsr(EDGE_KVM_BHYVE_MSR_TSC_AUX);
        wrmsr(EDGE_KVM_BHYVE_MSR_TSC_AUX,
            guest_tsc_aux ? guest_tsc_aux->data : 0);
    }
    result = edge_kvm_bhyve_vcpu_run_inner(context, backend_cookie, run);
    if (swap_tsc_aux)
        wrmsr(EDGE_KVM_BHYVE_MSR_TSC_AUX, host_tsc_aux);
    load_cr0(host_cr0);
    if (host_fpu_active) {
        x86_fpu_restore_state(
            current_task->xsave_region, current_task->fxsave_region);
    }
    wrmsr(MSR_FSBASE, host_fs_base);
    if (task_pinned) {
        __atomic_store_n(&current_task->scheduler.affinity_mask,
            saved_affinity, __ATOMIC_RELEASE);
    }
    if (kernel_current_signal_mask_set(previous_mask) < 0 && result >= 0)
        result = -EDGE_LINUX_ESRCH;
    if (current_task && !current_task->is_idle &&
        __atomic_load_n(&current_task->need_resched,
            __ATOMIC_ACQUIRE) != 0)
        scheduler_yield();
    return result;
}

static int
edge_kvm_bhyve_memory_region_set(void *context, uint64_t vm_cookie,
    const edge_kvm_memory_region_t *region)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)vm_cookie;
    edge_kvm_bhyve_memory_slot_t replacement = {0};
    edge_kvm_bhyve_memory_slot_t previous;
    struct vm_mem_seg *segment;
    vm_object_t previous_object = 0;
    vm_object_t object = 0;
    int vm_protection;
    int rollback_error;
    int error = 0;

    (void)context;
    if (!backend_vm || !region || region->slot >= EDGE_KVM_BHYVE_MAX_SLOTS)
        return -EDGE_LINUX_EINVAL;
    if (region->memory_size != 0) {
        error = edge_kvm_bhyve_build_object(region, &object,
            &replacement.page_chunks, &replacement.page_count);
        if (error < 0)
            return error;
        replacement.active = 1u;
        replacement.guest_physical_address =
            region->guest_physical_address;
        replacement.userspace_address = region->userspace_address;
        replacement.memory_size = region->memory_size;
        replacement.flags = region->flags;
    }

    previous = backend_vm->slots[region->slot];
    vm_xlock_memsegs(backend_vm->vm);
    segment = &vm_mem(backend_vm->vm)->mem_segs[region->slot];
    if (previous.active) {
        previous_object = segment->object;
        error = vm_munmap_memseg(backend_vm->vm,
            previous.guest_physical_address, previous.memory_size);
        if (error != 0)
            goto out_unlock;
        segment->len = 0;
        segment->sysmem = false;
        segment->object = 0;
    }
    if (replacement.active) {
        segment->len = region->memory_size;
        segment->sysmem = true;
        segment->object = object;
        vm_protection = VM_PROT_READ | VM_PROT_EXECUTE;
        if ((region->flags & EDGE_KVM_MEMORY_READONLY) == 0)
            vm_protection |= VM_PROT_WRITE;
        error = vm_mmap_memseg(backend_vm->vm,
            region->guest_physical_address, (int)region->slot, 0,
            region->memory_size, vm_protection, VM_MEMMAP_F_WIRED);
        if (error != 0) {
            segment->len = 0;
            segment->sysmem = false;
            segment->object = 0;
            vm_object_deallocate(object);
            object = 0;
            if (previous.active) {
                int previous_protection = VM_PROT_READ | VM_PROT_EXECUTE;

                if ((previous.flags & EDGE_KVM_MEMORY_READONLY) == 0)
                    previous_protection |= VM_PROT_WRITE;
                segment->len = previous.memory_size;
                segment->sysmem = true;
                segment->object = previous_object;
                rollback_error = vm_mmap_memseg(backend_vm->vm,
                    previous.guest_physical_address, (int)region->slot,
                    0, previous.memory_size, previous_protection,
                    VM_MEMMAP_F_WIRED);
                if (rollback_error != 0)
                    error = rollback_error;
            }
            goto out_unlock;
        }
        object = 0;
    }
    backend_vm->slots[region->slot] = replacement;
    if (previous_object)
        vm_object_deallocate(previous_object);

out_unlock:
    vm_unlock_memsegs(backend_vm->vm);
    if (error != 0) {
        if (object)
            vm_object_deallocate(object);
        edge_kvm_bhyve_release_pages(&replacement);
        return edge_kvm_bhyve_error(error);
    }
    edge_kvm_bhyve_release_pages(&previous);
    return 0;
}

static int
edge_kvm_bhyve_vcpu_pre_fault_memory(void *context, uint64_t vcpu_cookie,
    edge_kvm_pre_fault_memory_t *request)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)vcpu_cookie;
    uint32_t processed = 0;

    (void)context;
    if (!backend_vcpu || !backend_vcpu->vm || !backend_vcpu->vm->vm ||
        !request)
        return -EDGE_LINUX_EINVAL;
    vm_xlock_memsegs(backend_vcpu->vm->vm);
    while (request->size != 0 && processed < 1024u) {
        void *cookie = 0;
        void *mapping = vm_gpa_hold_global(backend_vcpu->vm->vm,
            request->guest_physical_address, EDGE_KVM_PAGE_SIZE,
            VM_PROT_READ, &cookie);

        if (!mapping)
            break;
        vm_gpa_release(cookie);
        request->guest_physical_address += EDGE_KVM_PAGE_SIZE;
        request->size -= EDGE_KVM_PAGE_SIZE;
        ++processed;
    }
    vm_unlock_memsegs(backend_vcpu->vm->vm);
    return processed != 0 ? 0 : -EDGE_LINUX_ENOENT;
}

static int
edge_kvm_bhyve_vcpu_translate(void *context, uint64_t vcpu_cookie,
    edge_kvm_translation_t *translation)
{
    edge_kvm_bhyve_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_vcpu_t *)(uintptr_t)vcpu_cookie;
    struct vm_guest_paging paging;
    struct seg_desc cs;
    uint64_t cr0;
    uint64_t cr4;
    uint64_t efer;
    uint64_t gpa = UINT64_MAX;
    int error;
    int guest_fault = 0;

    (void)context;
    if (!backend_vcpu || !backend_vcpu->vcpu || !translation)
        return -EDGE_LINUX_EINVAL;
    error = vm_get_register(backend_vcpu->vcpu, VM_REG_GUEST_CR0, &cr0);
    if (error == 0)
        error = vm_get_register(backend_vcpu->vcpu, VM_REG_GUEST_CR3,
            &paging.cr3);
    if (error == 0)
        error = vm_get_register(backend_vcpu->vcpu, VM_REG_GUEST_CR4, &cr4);
    if (error == 0)
        error = vm_get_register(backend_vcpu->vcpu, VM_REG_GUEST_EFER, &efer);
    if (error == 0)
        error = vm_get_seg_desc(backend_vcpu->vcpu, VM_REG_GUEST_CS, &cs);
    if (error != 0)
        return edge_kvm_bhyve_error(error);

    paging.cpl = 0;
    if ((efer & EFER_LMA) != 0)
        paging.cpu_mode = (cs.access & (1u << 13)) != 0 ?
            CPU_MODE_64BIT : CPU_MODE_COMPATIBILITY;
    else if ((cr0 & CR0_PE) != 0)
        paging.cpu_mode = CPU_MODE_PROTECTED;
    else
        paging.cpu_mode = CPU_MODE_REAL;

    if ((cr0 & CR0_PG) == 0)
        paging.paging_mode = PAGING_MODE_FLAT;
    else if ((cr4 & CR4_PAE) == 0)
        paging.paging_mode = PAGING_MODE_32;
    else if ((efer & EFER_LME) != 0)
        paging.paging_mode = (cr4 & CR4_LA57) != 0 ?
            PAGING_MODE_64_LA57 : PAGING_MODE_64;
    else
        paging.paging_mode = PAGING_MODE_PAE;

    error = vm_gla2gpa_nofault(backend_vcpu->vcpu, &paging,
        translation->linear_address, VM_PROT_READ, &gpa, &guest_fault);
    translation->physical_address =
        error == 0 && !guest_fault ? gpa : UINT64_MAX;
    translation->valid = error == 0 && !guest_fault;
    translation->writeable = 1;
    translation->usermode = 0;
    return 0;
}

static int
edge_kvm_bhyve_memory_dirty_log_get(void *context, uint64_t vm_cookie,
    uint32_t slot_index, uint32_t first_page, uint32_t page_count,
    uint64_t *bitmap, uint32_t bitmap_words, uint8_t clear)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)vm_cookie;
    edge_kvm_bhyve_memory_slot_t *slot;
    pmap_t pmap;
    uint64_t start;
    int error;

    (void)context;
    if (!backend_vm || !bitmap || slot_index >= EDGE_KVM_BHYVE_MAX_SLOTS)
        return -EDGE_LINUX_EINVAL;
    slot = &backend_vm->slots[slot_index];
    if (!slot->active ||
        (slot->flags & EDGE_KVM_MEMORY_LOG_DIRTY_PAGES) == 0 ||
        first_page > slot->page_count ||
        page_count > slot->page_count - first_page)
        return -EDGE_LINUX_EINVAL;
    start = slot->guest_physical_address +
        (uint64_t)first_page * PAGE_SIZE;
    pmap = vmspace_pmap(vm_vmspace(backend_vm->vm));
    error = edgeos_pmap_get_dirty(
        pmap, start, page_count, bitmap, bitmap_words, clear != 0);
    return error == 0 ? 0 : edge_kvm_bhyve_error(error);
}

static int
edge_kvm_bhyve_memory_dirty_log_clear(void *context, uint64_t vm_cookie,
    uint32_t slot_index, uint32_t first_page, uint32_t page_count,
    const uint64_t *bitmap, uint32_t bitmap_words)
{
    edge_kvm_bhyve_vm_t *backend_vm =
        (edge_kvm_bhyve_vm_t *)(uintptr_t)vm_cookie;
    edge_kvm_bhyve_memory_slot_t *slot;
    uint64_t start;
    int error;

    (void)context;
    if (!backend_vm || !bitmap || slot_index >= EDGE_KVM_BHYVE_MAX_SLOTS)
        return -EDGE_LINUX_EINVAL;
    slot = &backend_vm->slots[slot_index];
    if (!slot->active ||
        (slot->flags & EDGE_KVM_MEMORY_LOG_DIRTY_PAGES) == 0 ||
        first_page > slot->page_count ||
        page_count > slot->page_count - first_page)
        return -EDGE_LINUX_EINVAL;
    start = slot->guest_physical_address +
        (uint64_t)first_page * PAGE_SIZE;
    error = edgeos_pmap_clear_dirty(
        vmspace_pmap(vm_vmspace(backend_vm->vm)), start, page_count,
        bitmap, bitmap_words);
    return error == 0 ? 0 : edge_kvm_bhyve_error(error);
}

int
edge_kvm_bhyve_x86_register(void)
{
    edge_kvm_backend_ops_t backend = {
        .get_supported_cpuid = edge_kvm_bhyve_get_supported_cpuid,
        .get_msr_index_list = edge_kvm_bhyve_get_msr_index_list,
        .get_msr_feature_index_list =
            edge_kvm_bhyve_get_msr_feature_index_list,
        .get_msr_features = edge_kvm_bhyve_get_msr_features,
        .get_mce_cap_supported = edge_kvm_bhyve_get_mce_cap_supported,
        .vm_create = edge_kvm_bhyve_vm_create,
        .vm_destroy = edge_kvm_bhyve_vm_destroy,
        .vm_set_tss_address = edge_kvm_bhyve_vm_set_tss_address,
        .vm_set_identity_map_address =
            edge_kvm_bhyve_vm_set_identity_map_address,
        .vm_create_irqchip = edge_kvm_bhyve_vm_create_irqchip,
        .vm_set_gsi_routing = edge_kvm_bhyve_vm_set_gsi_routing,
        .vm_set_irq_line = edge_kvm_bhyve_vm_set_irq_line,
        .vm_signal_msi = edge_kvm_bhyve_vm_signal_msi,
        .vm_get_irqchip = edge_kvm_bhyve_vm_get_irqchip,
        .vm_set_irqchip = edge_kvm_bhyve_vm_set_irqchip,
        .vm_create_pit = edge_kvm_bhyve_vm_create_pit,
        .vm_get_pit = edge_kvm_bhyve_vm_get_pit,
        .vm_set_pit = edge_kvm_bhyve_vm_set_pit,
        .vm_get_clock = edge_kvm_bhyve_vm_get_clock,
        .vm_set_clock = edge_kvm_bhyve_vm_set_clock,
        .vm_coalesced_mmio = edge_kvm_bhyve_vm_coalesced_mmio,
        .vm_ioeventfd = edge_kvm_bhyve_vm_ioeventfd,
        .vm_irqfd = edge_kvm_bhyve_vm_irqfd,
        .vcpu_create = edge_kvm_bhyve_vcpu_create,
        .vcpu_destroy = edge_kvm_bhyve_vcpu_destroy,
        .vcpu_run = edge_kvm_bhyve_vcpu_run,
        .vcpu_pre_fault_memory = edge_kvm_bhyve_vcpu_pre_fault_memory,
        .vcpu_translate = edge_kvm_bhyve_vcpu_translate,
        .vcpu_get_regs = edge_kvm_bhyve_vcpu_get_regs,
        .vcpu_set_regs = edge_kvm_bhyve_vcpu_set_regs,
        .vcpu_get_sregs = edge_kvm_bhyve_vcpu_get_sregs,
        .vcpu_set_sregs = edge_kvm_bhyve_vcpu_set_sregs,
        .vcpu_get_sregs2 = edge_kvm_bhyve_vcpu_get_sregs2,
        .vcpu_set_sregs2 = edge_kvm_bhyve_vcpu_set_sregs2,
        .vcpu_get_fpu = edge_kvm_bhyve_vcpu_get_fpu,
        .vcpu_set_fpu = edge_kvm_bhyve_vcpu_set_fpu,
        .vcpu_get_lapic = edge_kvm_bhyve_vcpu_get_lapic,
        .vcpu_set_lapic = edge_kvm_bhyve_vcpu_set_lapic,
        .vcpu_get_debugregs = edge_kvm_bhyve_vcpu_get_debugregs,
        .vcpu_set_debugregs = edge_kvm_bhyve_vcpu_set_debugregs,
        .vcpu_set_guest_debug = edge_kvm_bhyve_vcpu_set_guest_debug,
        .vcpu_get_xcrs = edge_kvm_bhyve_vcpu_get_xcrs,
        .vcpu_set_xcrs = edge_kvm_bhyve_vcpu_set_xcrs,
        .vcpu_get_xsave = edge_kvm_bhyve_vcpu_get_xsave,
        .vcpu_set_xsave = edge_kvm_bhyve_vcpu_set_xsave,
        .vcpu_get_msrs = edge_kvm_bhyve_vcpu_get_msrs,
        .vcpu_set_msrs = edge_kvm_bhyve_vcpu_set_msrs,
        .vcpu_get_mp_state = edge_kvm_bhyve_vcpu_get_mp_state,
        .vcpu_set_mp_state = edge_kvm_bhyve_vcpu_set_mp_state,
        .vcpu_get_events = edge_kvm_bhyve_vcpu_get_events,
        .vcpu_set_events = edge_kvm_bhyve_vcpu_set_events,
        .vcpu_get_tsc_khz = edge_kvm_bhyve_vcpu_get_tsc_khz,
        .vcpu_set_tsc_khz = edge_kvm_bhyve_vcpu_set_tsc_khz,
        .vcpu_setup_mce = edge_kvm_bhyve_vcpu_setup_mce,
        .vcpu_set_mce = edge_kvm_bhyve_vcpu_set_mce,
        .vcpu_set_signal_mask = edge_kvm_bhyve_vcpu_set_signal_mask,
        .vcpu_set_cpuid = edge_kvm_bhyve_vcpu_set_cpuid,
        .vcpu_get_cpuid = edge_kvm_bhyve_vcpu_get_cpuid,
        .vcpu_mmap_page = edge_kvm_bhyve_vcpu_mmap_page,
        .device_create = edge_kvm_bhyve_device_create,
        .device_destroy = edge_kvm_bhyve_device_destroy,
        .device_set_attr = edge_kvm_bhyve_device_set_attr,
        .device_get_attr = edge_kvm_bhyve_device_get_attr,
        .device_has_attr = edge_kvm_bhyve_device_has_attr,
        .memory_region_set = edge_kvm_bhyve_memory_region_set,
        .memory_dirty_log_get = edge_kvm_bhyve_memory_dirty_log_get,
        .memory_dirty_log_clear = edge_kvm_bhyve_memory_dirty_log_clear,
    };
    edge_kvm_capability_table_t capabilities;
    int error;

    if (g_bhyve_initialized)
        return -EDGE_LINUX_EBUSY;
    error = bsd_cpu_runtime_refresh_topology();
    if (error != 0)
        return edge_kvm_bhyve_error(error);
    vm_maxcpu = mp_ncpus > 0 ? (u_int)mp_ncpus : 1u;
    if (vm_maxcpu > VM_MAXCPU)
        vm_maxcpu = VM_MAXCPU;
    error = vmm_modinit();
    if (error != 0)
        return edge_kvm_bhyve_error(error);
    error = edge_vfio_bhyve_x86_register();
    if (error != 0)
        return error;

    edge_kvm_capability_table_init(&capabilities);
    if (edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_IRQCHIP, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_IRQ_ROUTING, EDGE_KVM_MAX_IRQ_ROUTES) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_IRQ_INJECT_STATUS, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_PIT2, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_IRQFD, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_PIT_STATE2, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_ADJUST_CLOCK, EDGE_KVM_CLOCK_VALID_FLAGS) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_SET_TSS_ADDR, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_USER_MEMORY, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_USER_MEMORY2, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_PRE_FAULT_MEMORY, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_COALESCED_MMIO,
            EDGE_KVM_X86_COALESCED_MMIO_PAGE_OFFSET) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_EXT_CPUID, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_NR_VCPUS, (int32_t)vm_maxcpu) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_MAX_VCPUS, (int32_t)vm_maxcpu) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_NR_MEMSLOTS, EDGE_KVM_BHYVE_MAX_SLOTS) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_DESTROY_MEMORY_REGION_WORKS, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_JOIN_MEMORY_REGIONS_WORKS, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_MP_STATE, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_VCPU_EVENTS, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_INTERNAL_ERROR_DATA, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_IOEVENTFD, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_SET_IDENTITY_MAP_ADDR, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_IOEVENTFD_ANY_LENGTH, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_SIGNAL_MSI, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_MCE, EDGE_KVM_X86_MCE_MAX_BANKS) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_TSC_CONTROL, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_GET_TSC_KHZ, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_SET_GUEST_DEBUG, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_DEBUGREGS, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_X86_ROBUST_SINGLESTEP, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_XSAVE, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_XCRS, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_XSAVE2, EDGE_KVM_XSAVE_SIZE) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_IMMEDIATE_EXIT, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2,
            EDGE_KVM_DIRTY_LOG_MANUAL_SUPPORTED_FLAGS) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_READONLY_MEMORY, 1) < 0) {
        (void)vmm_modcleanup();
        return -EDGE_LINUX_ENOSPC;
    }
    if ((cpu_vendor_id == CPU_VENDOR_AMD ||
         cpu_vendor_id == CPU_VENDOR_HYGON) &&
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_GET_MSR_FEATURES, 1) < 0) {
        (void)vmm_modcleanup();
        return -EDGE_LINUX_ENOSPC;
    }
    error = kernel_edge_kvm_backend_register(&backend, &capabilities);
    if (error < 0) {
        (void)vmm_modcleanup();
        return error;
    }
    g_bhyve_initialized = 1u;
    return 0;
}
