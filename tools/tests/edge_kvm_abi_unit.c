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
_Static_assert(sizeof(edge_kvm_userspace_memory_region2_t) == 160,
               "KVM memory region2 ABI size changed");
_Static_assert(offsetof(edge_kvm_userspace_memory_region2_t,
                        guest_memfd_offset) == 32,
               "KVM memory region2 guest memfd offset changed");
_Static_assert(EDGE_KVM_MEMORY_GUEST_MEMFD == 0x4u,
               "KVM guest memfd memory flag changed");
_Static_assert(EDGE_KVM_IOCTL_GET_API_VERSION == 0x0000ae00u,
               "KVM API version request changed");
_Static_assert(EDGE_KVM_IOCTL_CREATE_VM == 0x0000ae01u,
               "KVM create VM request changed");
_Static_assert(EDGE_KVM_IOCTL_CHECK_EXTENSION == 0x0000ae03u,
               "KVM extension request changed");
_Static_assert(EDGE_KVM_CAP_JOIN_MEMORY_REGIONS_WORKS == 0x1eu,
               "KVM join-memory-regions capability number changed");
_Static_assert(EDGE_KVM_CAP_DESTROY_MEMORY_REGION_WORKS == 0x15u,
               "KVM destroy-memory-region capability number changed");
_Static_assert(EDGE_KVM_CAP_SET_GUEST_DEBUG == 0x17u,
               "KVM guest-debug capability number changed");
_Static_assert(EDGE_KVM_CAP_IOEVENTFD_ANY_LENGTH == 0x7au,
               "KVM ioeventfd-any-length capability number changed");
_Static_assert(EDGE_KVM_CAP_USER_MEMORY2 == 0xe7u,
               "KVM user-memory2 capability number changed");
_Static_assert(EDGE_KVM_CAP_PRE_FAULT_MEMORY == 0xecu,
               "KVM memory-prefault capability number changed");
_Static_assert(EDGE_KVM_CAP_GET_MSR_FEATURES == 0x99u,
               "KVM feature-MSR capability number changed");
_Static_assert(EDGE_KVM_REG_ARM_PSCI_VERSION == UINT64_C(0x6030000000140000),
               "KVM ARM PSCI version register changed");
_Static_assert(EDGE_KVM_REG_ARM64_SPSR(4) == UINT64_C(0x6030000000100050),
               "KVM ARM SPSR register indexing changed");
_Static_assert(EDGE_KVM_CAP_SET_IDENTITY_MAP_ADDR == 0x25u,
               "KVM identity-map capability number changed");
_Static_assert(EDGE_KVM_IOCTL_GET_VCPU_MMAP_SIZE == 0x0000ae04u,
               "KVM vCPU mmap request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_SUPPORTED_CPUID == 0xc008ae05u,
               "KVM supported CPUID request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_EMULATED_CPUID == 0xc008ae09u,
               "KVM emulated CPUID request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_MSR_INDEX_LIST == 0xc004ae02u,
               "KVM MSR index list request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_MSR_FEATURE_INDEX_LIST == 0xc004ae0au,
               "KVM MSR feature index request changed");
_Static_assert(EDGE_KVM_IOCTL_CREATE_VCPU == 0x0000ae41u,
               "KVM create vCPU request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_USER_MEMORY_REGION == 0x4020ae46u,
               "KVM memory region request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_USER_MEMORY_REGION2 == 0x40a0ae49u,
               "KVM memory region2 request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_NR_MMU_PAGES == 0x0000ae44u,
               "KVM MMU page count request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_NR_MMU_PAGES == 0x0000ae45u,
               "KVM MMU page query request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_TSS_ADDR == 0x0000ae47u,
               "KVM TSS address request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_IDENTITY_MAP_ADDR == 0x4008ae48u,
               "KVM identity map request changed");
_Static_assert(EDGE_KVM_IOCTL_CREATE_IRQCHIP == 0x0000ae60u,
               "KVM irqchip request changed");
_Static_assert(EDGE_KVM_IOCTL_CREATE_PIT == 0x0000ae64u,
               "KVM legacy PIT creation request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_PIT == 0xc048ae65u,
               "KVM legacy PIT read request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_PIT == 0x8048ae66u,
               "KVM legacy PIT write request changed");
_Static_assert(EDGE_KVM_IOCTL_REGISTER_COALESCED_MMIO == 0x4010ae67u,
               "KVM coalesced MMIO registration request changed");
_Static_assert(EDGE_KVM_IOCTL_UNREGISTER_COALESCED_MMIO == 0x4010ae68u,
               "KVM coalesced MMIO removal request changed");
_Static_assert(EDGE_KVM_CAP_COALESCED_MMIO == 0x0fu,
               "KVM coalesced MMIO capability number changed");
_Static_assert(sizeof(edge_kvm_coalesced_mmio_t) == 24,
               "KVM coalesced MMIO entry size changed");
_Static_assert(EDGE_KVM_COALESCED_MMIO_MAX == 170,
               "KVM coalesced MMIO ring capacity changed");
_Static_assert(EDGE_KVM_X86_COALESCED_MMIO_PAGE_OFFSET == 2,
               "x86 KVM coalesced MMIO page offset changed");
_Static_assert(EDGE_KVM_ARM64_COALESCED_MMIO_PAGE_OFFSET == 1,
               "ARM64 KVM coalesced MMIO page offset changed");
_Static_assert(EDGE_KVM_IOCTL_REINJECT_CONTROL == 0x0000ae71u,
               "KVM reinjection control request changed");
_Static_assert(EDGE_KVM_IOCTL_CREATE_PIT2 == 0x4040ae77u,
               "KVM PIT request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_BOOT_CPU_ID == 0x0000ae78u,
               "KVM boot CPU request changed");
_Static_assert(sizeof(edge_kvm_ioeventfd_t) == 64,
               "KVM ioeventfd size changed");
_Static_assert(EDGE_KVM_IOCTL_IOEVENTFD == 0x4040ae79u,
               "KVM ioeventfd request changed");
_Static_assert(EDGE_KVM_IOCTL_XEN_HVM_CONFIG == 0x4038ae7au,
               "KVM Xen configuration request changed");
_Static_assert(sizeof(edge_kvm_msi_t) == 32,
               "KVM MSI message size changed");
_Static_assert(EDGE_KVM_IOCTL_SIGNAL_MSI == 0x4020aea5u,
               "KVM signal MSI request changed");
_Static_assert(sizeof(edge_kvm_irqfd_t) == 32,
               "KVM irqfd size changed");
_Static_assert(EDGE_KVM_IOCTL_IRQFD == 0x4020ae76u,
               "KVM irqfd request changed");
_Static_assert(EDGE_KVM_IOCTL_X86_GET_MCE_CAP_SUPPORTED == 0x8008ae9du,
               "KVM get MCE capability request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_SIGNAL_MASK == 0x4004ae8bu,
               "KVM set signal mask request changed");
_Static_assert(EDGE_KVM_CAP_SIGNAL_MSI == 0x4du,
               "KVM signal MSI capability number changed");
_Static_assert(EDGE_KVM_CAP_DEBUGREGS == 0x32u,
               "KVM debug-register capability number changed");
_Static_assert(EDGE_KVM_CAP_X86_ROBUST_SINGLESTEP == 0x33u,
               "KVM robust-single-step capability number changed");
_Static_assert(EDGE_KVM_CAP_XCRS == 0x38u,
               "KVM XCR capability number changed");
_Static_assert(sizeof(edge_kvm_pit_config_t) == 64,
               "KVM PIT configuration size changed");
_Static_assert(EDGE_KVM_IOCTL_RUN == 0x0000ae80u,
               "KVM run request changed");
_Static_assert(EDGE_KVM_IOCTL_TRANSLATE == 0xc018ae85u,
               "KVM translation request changed");
_Static_assert(EDGE_KVM_IOCTL_INTERRUPT == 0x4004ae86u,
               "KVM interrupt request changed");
_Static_assert(EDGE_KVM_IOCTL_NMI == 0x0000ae9au,
               "KVM NMI request changed");
_Static_assert(EDGE_KVM_IOCTL_TPR_ACCESS_REPORTING == 0xc028ae92u,
               "KVM TPR access request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_GUEST_DEBUG_X86 == 0x4048ae9bu,
               "KVM x86 guest debug request changed");
_Static_assert(EDGE_KVM_EXIT_DEBUG == 4,
               "KVM debug exit reason changed");
_Static_assert(sizeof(edge_kvm_run_debug_x86_t) == 32,
               "KVM x86 debug exit size changed");
_Static_assert(EDGE_KVM_GUESTDBG_ENABLE == 0x00000001u,
               "KVM guest-debug enable flag changed");
_Static_assert(EDGE_KVM_GUESTDBG_SINGLESTEP == 0x00000002u,
               "KVM guest-debug single-step flag changed");
_Static_assert(EDGE_KVM_GUESTDBG_USE_SW_BP == 0x00010000u,
               "KVM guest-debug software-breakpoint flag changed");
_Static_assert(EDGE_KVM_GUESTDBG_BLOCKIRQ == 0x00100000u,
               "KVM guest-debug interrupt-blocking flag changed");
_Static_assert(EDGE_KVM_IOCTL_SET_GUEST_DEBUG_ARM64 == 0x4208ae9bu,
               "KVM ARM64 guest debug request changed");
_Static_assert(sizeof(edge_kvm_regs_t) == 144,
               "KVM general register size changed");
_Static_assert(EDGE_KVM_IOCTL_GET_REGS == 0x8090ae81u,
               "KVM get registers request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_REGS == 0x4090ae82u,
               "KVM set registers request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_SREGS == 0x8138ae83u,
               "KVM get special registers request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_SREGS == 0x4138ae84u,
               "KVM set special registers request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_SREGS2 == 0x8140aeccu,
               "KVM get SREGS2 request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_SREGS2 == 0x4140aecdu,
               "KVM set SREGS2 request changed");
_Static_assert(sizeof(edge_kvm_sregs2_t) == 320,
               "KVM SREGS2 size changed");
_Static_assert(offsetof(edge_kvm_sregs2_t, flags) == 280,
               "KVM SREGS2 flags offset changed");
_Static_assert(offsetof(edge_kvm_sregs2_t, pdptrs) == 288,
               "KVM SREGS2 PDPTR offset changed");
_Static_assert(EDGE_KVM_IOCTL_GET_LAPIC == 0x8400ae8eu,
               "KVM get local APIC request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_LAPIC == 0x4400ae8fu,
               "KVM set local APIC request changed");
_Static_assert(EDGE_KVM_IOCTL_IRQ_LINE == 0x4008ae61u,
               "KVM IRQ line request changed");
_Static_assert(EDGE_KVM_IOCTL_IRQ_LINE_STATUS == 0xc008ae67u,
               "KVM IRQ line status request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_GSI_ROUTING == 0x4008ae6au,
               "KVM GSI routing request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_IRQCHIP == 0xc208ae62u,
               "KVM get IRQ chip request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_IRQCHIP == 0x8208ae63u,
               "KVM set IRQ chip request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_PIT2 == 0x8070ae9fu,
               "KVM get PIT2 request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_PIT2 == 0x4070aea0u,
               "KVM set PIT2 request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_CLOCK == 0x4030ae7bu,
               "KVM set clock request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_CLOCK == 0x8030ae7cu,
               "KVM get clock request changed");
_Static_assert(sizeof(edge_kvm_irq_level_t) == 8,
               "KVM IRQ level size changed");
_Static_assert(sizeof(edge_kvm_irq_routing_entry_t) == 48,
               "KVM IRQ route entry size changed");
_Static_assert(sizeof(edge_kvm_irqchip_t) == 520,
               "KVM IRQ chip size changed");
_Static_assert(sizeof(edge_kvm_pit_state2_t) == 112,
               "KVM PIT2 state size changed");
_Static_assert(EDGE_KVM_IOCTL_GET_DEBUGREGS == 0x8080aea1u,
               "KVM get debug registers request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_DEBUGREGS == 0x4080aea2u,
               "KVM set debug registers request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_XCRS == 0x8188aea6u,
               "KVM get XCR array request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_XCRS == 0x4188aea7u,
               "KVM set XCR array request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_XSAVE == 0x9000aea4u,
               "KVM get XSAVE request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_XSAVE == 0x5000aea5u,
               "KVM set XSAVE request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_XSAVE2 == 0x9000aecfu,
               "KVM get XSAVE2 request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_STATS_FD == 0x0000aeceu,
               "KVM statistics descriptor request changed");
_Static_assert(sizeof(edge_kvm_debugregs_t) == 128,
               "KVM debug register state size changed");
_Static_assert(sizeof(edge_kvm_xcrs_t) == 392,
               "KVM XCR array size changed");
_Static_assert(sizeof(edge_kvm_xsave_t) == 4096,
               "KVM XSAVE state size changed");
_Static_assert(sizeof(edge_kvm_lapic_state_t) == 1024,
               "KVM local APIC state size changed");
_Static_assert(EDGE_KVM_IOCTL_GET_MSRS == 0xc008ae88u,
               "KVM get MSRs request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_MSRS == 0x4008ae89u,
               "KVM set MSRs request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_MP_STATE == 0x8004ae98u,
               "KVM get MP state request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_MP_STATE == 0x4004ae99u,
               "KVM set MP state request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_VCPU_EVENTS == 0x8040ae9fu,
               "KVM get vCPU events request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_VCPU_EVENTS == 0x4040aea0u,
               "KVM set vCPU events request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_VAPIC_ADDR == 0x4008ae93u,
               "KVM set VAPIC address request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_TSC_KHZ == 0x0000aea2u,
               "KVM set TSC frequency request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_TSC_KHZ == 0x0000aea3u,
               "KVM get TSC frequency request changed");
_Static_assert(EDGE_KVM_IOCTL_KVMCLOCK_CTRL == 0x0000aeadU,
               "KVM clock control request changed");
_Static_assert(EDGE_KVM_IOCTL_SMI == 0x0000aeb7u,
               "KVM SMI request changed");
_Static_assert(EDGE_KVM_IOCTL_MEMORY_ENCRYPT_OP == 0xc008aebau,
               "KVM memory encryption operation request changed");
_Static_assert(EDGE_KVM_IOCTL_MEMORY_ENCRYPT_REG_REGION == 0x8010aebbu,
               "KVM encrypted region registration request changed");
_Static_assert(EDGE_KVM_IOCTL_MEMORY_ENCRYPT_UNREG_REGION == 0x8010aebcu,
               "KVM encrypted region removal request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_NESTED_STATE == 0xc080aebeu,
               "KVM nested state read request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_NESTED_STATE == 0x4080aebfu,
               "KVM nested state write request changed");
_Static_assert(EDGE_KVM_IOCTL_CLEAR_DIRTY_LOG == 0xc018aec0u,
               "KVM clear dirty log request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_SUPPORTED_HV_CPUID == 0xc008aec1u,
               "KVM Hyper-V CPUID request changed");
_Static_assert(EDGE_KVM_IOCTL_ARM_VCPU_FINALIZE == 0x4004aec2u,
               "KVM ARM64 vCPU finalize request changed");
_Static_assert(EDGE_KVM_IOCTL_X86_SET_MSR_FILTER == 0x4188aec6u,
               "KVM MSR filter request changed");
_Static_assert(EDGE_KVM_IOCTL_RESET_DIRTY_RINGS == 0x0000aec7u,
               "KVM dirty ring reset request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_MEMORY_ATTRIBUTES == 0x4020aed2u,
               "KVM memory attributes request changed");
_Static_assert(EDGE_KVM_IOCTL_CREATE_GUEST_MEMFD == 0xc040aed4u,
               "KVM guest memfd request changed");
_Static_assert(EDGE_KVM_IOCTL_PRE_FAULT_MEMORY == 0xc040aed5u,
               "KVM memory prefault request changed");
_Static_assert(EDGE_KVM_IOCTL_X86_SETUP_MCE == 0x4008ae9cu,
               "KVM machine-check setup request changed");
_Static_assert(EDGE_KVM_IOCTL_X86_SET_MCE == 0x4040ae9eu,
               "KVM machine-check injection request changed");
_Static_assert(sizeof(edge_kvm_x86_mce_t) == 64,
               "KVM machine-check record size changed");
_Static_assert(EDGE_KVM_IOCTL_SET_CPUID2 == 0x4008ae90u,
               "KVM set CPUID request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_CPUID == 0x4008ae8au,
               "KVM legacy set CPUID request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_CPUID2 == 0xc008ae91u,
               "KVM get CPUID request changed");
_Static_assert(EDGE_KVM_IOCTL_ENABLE_CAP == 0x4068aea3u,
               "KVM enable-capability request changed");
_Static_assert(EDGE_KVM_IOCTL_DIRTY_TLB == 0x4010aeaau,
               "KVM dirty-TLB request changed");
_Static_assert(EDGE_KVM_IOCTL_ARM_SET_DEVICE_ADDR == 0x4010aeabu,
               "KVM ARM device-address request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_PMU_EVENT_FILTER_X86 == 0x4020aeb2u,
               "KVM x86 PMU filter request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_PMU_EVENT_FILTER_ARM64 == 0x4008aeb2u,
               "KVM ARM64 PMU filter request changed");
_Static_assert(EDGE_KVM_IOCTL_ARM_MTE_COPY_TAGS == 0x8030aeb4u,
               "KVM ARM MTE request changed");
_Static_assert(EDGE_KVM_IOCTL_ARM_SET_COUNTER_OFFSET == 0x4010aeb5u,
               "KVM ARM counter-offset request changed");
_Static_assert(EDGE_KVM_IOCTL_ARM_GET_REG_WRITABLE_MASKS == 0x8040aeb6u,
               "KVM ARM writable-mask request changed");
_Static_assert(EDGE_KVM_IOCTL_HYPERV_EVENTFD == 0x4018aebdu,
               "KVM Hyper-V eventfd request changed");
_Static_assert(EDGE_KVM_IOCTL_XEN_HVM_GET_ATTR == 0xc048aec8u,
               "KVM Xen VM attribute read request changed");
_Static_assert(EDGE_KVM_IOCTL_XEN_HVM_SET_ATTR == 0x4048aec9u,
               "KVM Xen VM attribute write request changed");
_Static_assert(EDGE_KVM_IOCTL_XEN_VCPU_GET_ATTR == 0xc048aecau,
               "KVM Xen vCPU attribute read request changed");
_Static_assert(EDGE_KVM_IOCTL_XEN_VCPU_SET_ATTR == 0x4048aecbu,
               "KVM Xen vCPU attribute write request changed");
_Static_assert(EDGE_KVM_IOCTL_XEN_HVM_EVTCHN_SEND == 0x400caed0u,
               "KVM Xen event-channel request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_ONE_REG == 0x4010aeabu,
               "KVM get one register request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_ONE_REG == 0x4010aeacu,
               "KVM set one register request changed");
_Static_assert(EDGE_KVM_IOCTL_ARM_VCPU_INIT == 0x4020aeaeu,
               "KVM ARM vCPU initialization request changed");
_Static_assert(EDGE_KVM_IOCTL_ARM_PREFERRED_TARGET == 0x8020aeafu,
               "KVM ARM preferred target request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_REG_LIST == 0xc008aeb0u,
               "KVM register-list request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_DIRTY_LOG == 0x4010ae42u,
               "KVM dirty-log request changed");
_Static_assert(sizeof(edge_kvm_dirty_log_t) == 16,
               "KVM dirty-log descriptor size changed");
_Static_assert(EDGE_KVM_IOCTL_CREATE_DEVICE == 0xc00caee0u,
               "KVM device creation request changed");
_Static_assert(EDGE_KVM_IOCTL_SET_DEVICE_ATTR == 0x4018aee1u,
               "KVM set device attribute request changed");
_Static_assert(EDGE_KVM_IOCTL_GET_DEVICE_ATTR == 0x4018aee2u,
               "KVM get device attribute request changed");
_Static_assert(EDGE_KVM_IOCTL_HAS_DEVICE_ATTR == 0x4018aee3u,
               "KVM has device attribute request changed");
_Static_assert(EDGE_KVM_REG_ARM64_X(0) == UINT64_C(0x6030000000100000),
               "KVM ARM64 X0 identifier changed");
_Static_assert(EDGE_KVM_REG_ARM64_LR == UINT64_C(0x603000000010003c),
               "KVM ARM64 link-register identifier changed");
_Static_assert(EDGE_KVM_REG_ARM64_PC == UINT64_C(0x6030000000100040),
               "KVM ARM64 program-counter identifier changed");
_Static_assert(EDGE_KVM_REG_ARM64_V(0) == UINT64_C(0x6040000000100054),
               "KVM ARM64 vector-register identifier changed");
_Static_assert(EDGE_KVM_REG_ARM64_V(1) == UINT64_C(0x6040000000100058),
               "KVM ARM64 vector-register indexing changed");
_Static_assert(sizeof(edge_kvm_cpuid_entry2_t) == 40,
               "KVM CPUID entry size changed");
_Static_assert(sizeof(edge_kvm_cpuid2_t) == 8,
               "KVM CPUID header size changed");
_Static_assert(sizeof(edge_kvm_msr_entry_t) == 16,
               "KVM MSR entry size changed");
_Static_assert(offsetof(edge_kvm_msr_entry_t, data) == 8,
               "KVM MSR data offset changed");
_Static_assert(sizeof(edge_kvm_msrs_t) == 8,
               "KVM MSR array header size changed");
_Static_assert(sizeof(edge_kvm_msr_list_t) == 4,
               "KVM MSR index list header size changed");
_Static_assert(sizeof(edge_kvm_mp_state_t) == 4,
               "KVM MP state size changed");
_Static_assert(sizeof(edge_kvm_vcpu_events_t) == 64,
               "KVM vCPU events size changed");
_Static_assert(offsetof(edge_kvm_vcpu_events_t, exception_payload) == 56,
               "KVM exception payload offset changed");

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
