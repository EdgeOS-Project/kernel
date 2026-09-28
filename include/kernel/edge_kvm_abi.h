/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_EDGE_KVM_ABI_H
#define EDGEOS_KERNEL_EDGE_KVM_ABI_H

#include <stdint.h>

/* Linux-compatible ioctl encoding, independently implemented for EdgeOS. */
#define EDGE_LINUX_IOC_NR_BITS 8u
#define EDGE_LINUX_IOC_TYPE_BITS 8u
#define EDGE_LINUX_IOC_SIZE_BITS 14u
#define EDGE_LINUX_IOC_NR_SHIFT 0u
#define EDGE_LINUX_IOC_TYPE_SHIFT \
    (EDGE_LINUX_IOC_NR_SHIFT + EDGE_LINUX_IOC_NR_BITS)
#define EDGE_LINUX_IOC_SIZE_SHIFT \
    (EDGE_LINUX_IOC_TYPE_SHIFT + EDGE_LINUX_IOC_TYPE_BITS)
#define EDGE_LINUX_IOC_DIR_SHIFT \
    (EDGE_LINUX_IOC_SIZE_SHIFT + EDGE_LINUX_IOC_SIZE_BITS)
#define EDGE_LINUX_IOC_NONE 0u
#define EDGE_LINUX_IOC_WRITE 1u
#define EDGE_LINUX_IOC_READ 2u
#define EDGE_LINUX_IOC(direction, type, number, size) \
    (((uint32_t)(direction) << EDGE_LINUX_IOC_DIR_SHIFT) | \
     ((uint32_t)(size) << EDGE_LINUX_IOC_SIZE_SHIFT) | \
     ((uint32_t)(type) << EDGE_LINUX_IOC_TYPE_SHIFT) | \
     ((uint32_t)(number) << EDGE_LINUX_IOC_NR_SHIFT))
#define EDGE_LINUX_IO(type, number) \
    EDGE_LINUX_IOC(EDGE_LINUX_IOC_NONE, type, number, 0u)
#define EDGE_LINUX_IOW(type, number, data_type) \
    EDGE_LINUX_IOC(EDGE_LINUX_IOC_WRITE, type, number, sizeof(data_type))
#define EDGE_LINUX_IOR(type, number, data_type) \
    EDGE_LINUX_IOC(EDGE_LINUX_IOC_READ, type, number, sizeof(data_type))
#define EDGE_LINUX_IOWR(type, number, data_type) \
    EDGE_LINUX_IOC(EDGE_LINUX_IOC_READ | EDGE_LINUX_IOC_WRITE, type, number, \
                   sizeof(data_type))

#define EDGE_KVM_IOCTL_TYPE 0xaeu
#define EDGE_KVM_IOCTL_GET_API_VERSION \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x00u)
#define EDGE_KVM_IOCTL_CREATE_VM \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x01u)
#define EDGE_KVM_IOCTL_CHECK_EXTENSION \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x03u)
#define EDGE_KVM_IOCTL_GET_VCPU_MMAP_SIZE \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x04u)
#define EDGE_KVM_IOCTL_GET_SUPPORTED_CPUID \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0x05u, edge_kvm_cpuid2_t)
#define EDGE_KVM_IOCTL_GET_EMULATED_CPUID \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0x09u, edge_kvm_cpuid2_t)
#define EDGE_KVM_IOCTL_GET_MSR_INDEX_LIST \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0x02u, edge_kvm_msr_list_t)
#define EDGE_KVM_IOCTL_GET_MSR_FEATURE_INDEX_LIST \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0x0au, edge_kvm_msr_list_t)
#define EDGE_KVM_IOCTL_CREATE_VCPU \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x41u)
#define EDGE_KVM_IOCTL_GET_DIRTY_LOG \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x42u, edge_kvm_dirty_log_t)
#define EDGE_KVM_IOCTL_SET_NR_MMU_PAGES \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x44u)
#define EDGE_KVM_IOCTL_GET_NR_MMU_PAGES \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x45u)
#define EDGE_KVM_IOCTL_SET_USER_MEMORY_REGION \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x46u, \
                   edge_kvm_userspace_memory_region_t)
#define EDGE_KVM_IOCTL_SET_USER_MEMORY_REGION2 \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x49u, \
                   edge_kvm_userspace_memory_region2_t)
#define EDGE_KVM_IOCTL_SET_TSS_ADDR \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x47u)
#define EDGE_KVM_IOCTL_SET_IDENTITY_MAP_ADDR \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x48u, uint64_t)
#define EDGE_KVM_IOCTL_CREATE_IRQCHIP \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x60u)
#define EDGE_KVM_IOCTL_CREATE_PIT \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x64u)
#define EDGE_KVM_IOCTL_GET_PIT \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0x65u, edge_kvm_pit_state_t)
#define EDGE_KVM_IOCTL_SET_PIT \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0x66u, edge_kvm_pit_state_t)
#define EDGE_KVM_IOCTL_IRQ_LINE \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x61u, edge_kvm_irq_level_t)
#define EDGE_KVM_IOCTL_IRQ_LINE_STATUS \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0x67u, edge_kvm_irq_level_t)
#define EDGE_KVM_IOCTL_REGISTER_COALESCED_MMIO \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x67u, \
                   edge_kvm_coalesced_mmio_zone_t)
#define EDGE_KVM_IOCTL_UNREGISTER_COALESCED_MMIO \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x68u, \
                   edge_kvm_coalesced_mmio_zone_t)
#define EDGE_KVM_IOCTL_GET_IRQCHIP \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0x62u, edge_kvm_irqchip_t)
#define EDGE_KVM_IOCTL_SET_IRQCHIP \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0x63u, edge_kvm_irqchip_t)
#define EDGE_KVM_IOCTL_SET_GSI_ROUTING \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x6au, edge_kvm_irq_routing_t)
#define EDGE_KVM_IOCTL_REINJECT_CONTROL \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x71u)
#define EDGE_KVM_IOCTL_CREATE_PIT2 \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x77u, edge_kvm_pit_config_t)
#define EDGE_KVM_IOCTL_SET_BOOT_CPU_ID \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x78u)
#define EDGE_KVM_IOCTL_IRQFD \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x76u, edge_kvm_irqfd_t)
#define EDGE_KVM_IOCTL_IOEVENTFD \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x79u, edge_kvm_ioeventfd_t)
#define EDGE_KVM_IOCTL_XEN_HVM_CONFIG \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x7au, edge_kvm_xen_hvm_config_t)
#define EDGE_KVM_IOCTL_SET_CLOCK \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x7bu, edge_kvm_clock_data_t)
#define EDGE_KVM_IOCTL_GET_CLOCK \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0x7cu, edge_kvm_clock_data_t)
#define EDGE_KVM_IOCTL_GET_PIT2 \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0x9fu, edge_kvm_pit_state2_t)
#define EDGE_KVM_IOCTL_SET_PIT2 \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xa0u, edge_kvm_pit_state2_t)
#define EDGE_KVM_IOCTL_SIGNAL_MSI \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xa5u, edge_kvm_msi_t)
#define EDGE_KVM_IOCTL_RUN \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x80u)
#define EDGE_KVM_IOCTL_TRANSLATE \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0x85u, edge_kvm_translation_t)
#define EDGE_KVM_IOCTL_INTERRUPT \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x86u, edge_kvm_interrupt_t)
#define EDGE_KVM_IOCTL_GET_REGS \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0x81u, edge_kvm_regs_t)
#define EDGE_KVM_IOCTL_SET_REGS \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x82u, edge_kvm_regs_t)
#define EDGE_KVM_IOCTL_GET_SREGS \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0x83u, edge_kvm_sregs_t)
#define EDGE_KVM_IOCTL_SET_SREGS \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x84u, edge_kvm_sregs_t)
#define EDGE_KVM_IOCTL_GET_FPU \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0x8cu, edge_kvm_fpu_t)
#define EDGE_KVM_IOCTL_SET_FPU \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x8du, edge_kvm_fpu_t)
#define EDGE_KVM_IOCTL_GET_LAPIC \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0x8eu, edge_kvm_lapic_state_t)
#define EDGE_KVM_IOCTL_SET_LAPIC \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x8fu, edge_kvm_lapic_state_t)
#define EDGE_KVM_IOCTL_SET_VAPIC_ADDR \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x93u, edge_kvm_vapic_addr_t)
#define EDGE_KVM_IOCTL_TPR_ACCESS_REPORTING \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0x92u, \
                    edge_kvm_tpr_access_control_t)
#define EDGE_KVM_IOCTL_NMI EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x9au)
#define EDGE_KVM_IOCTL_SET_GUEST_DEBUG_X86 \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x9bu, edge_kvm_guest_debug_x86_t)
#define EDGE_KVM_IOCTL_SET_GUEST_DEBUG_ARM64 \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x9bu, edge_kvm_guest_debug_arm64_t)
#define EDGE_KVM_IOCTL_GET_DEBUGREGS \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0xa1u, edge_kvm_debugregs_t)
#define EDGE_KVM_IOCTL_SET_DEBUGREGS \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xa2u, edge_kvm_debugregs_t)
#define EDGE_KVM_IOCTL_GET_XCRS \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0xa6u, edge_kvm_xcrs_t)
#define EDGE_KVM_IOCTL_SET_XCRS \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xa7u, edge_kvm_xcrs_t)
#define EDGE_KVM_IOCTL_GET_XSAVE \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0xa4u, edge_kvm_xsave_t)
#define EDGE_KVM_IOCTL_SET_XSAVE \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xa5u, edge_kvm_xsave_t)
#define EDGE_KVM_IOCTL_GET_XSAVE2 \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0xcfu, edge_kvm_xsave_t)
#define EDGE_KVM_IOCTL_GET_STATS_FD \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0xceu)
#define EDGE_KVM_IOCTL_GET_MSRS \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0x88u, edge_kvm_msrs_t)
#define EDGE_KVM_IOCTL_SET_SIGNAL_MASK \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x8bu, edge_kvm_signal_mask_t)
#define EDGE_KVM_IOCTL_SET_MSRS \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x89u, edge_kvm_msrs_t)
#define EDGE_KVM_IOCTL_GET_MP_STATE \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0x98u, edge_kvm_mp_state_t)
#define EDGE_KVM_IOCTL_SET_MP_STATE \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x99u, edge_kvm_mp_state_t)
#define EDGE_KVM_IOCTL_GET_VCPU_EVENTS \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0x9fu, edge_kvm_vcpu_events_t)
#define EDGE_KVM_IOCTL_SET_VCPU_EVENTS \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xa0u, edge_kvm_vcpu_events_t)
#define EDGE_KVM_IOCTL_GET_SREGS2 \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0xccu, edge_kvm_sregs2_t)
#define EDGE_KVM_IOCTL_SET_SREGS2 \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xcdu, edge_kvm_sregs2_t)
#define EDGE_KVM_IOCTL_SET_TSC_KHZ \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0xa2u)
#define EDGE_KVM_IOCTL_GET_TSC_KHZ \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0xa3u)
#define EDGE_KVM_IOCTL_KVMCLOCK_CTRL \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0xadu)
#define EDGE_KVM_IOCTL_SMI EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0xb7u)
#define EDGE_KVM_IOCTL_MEMORY_ENCRYPT_OP \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0xbau, uint64_t)
#define EDGE_KVM_IOCTL_MEMORY_ENCRYPT_REG_REGION \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0xbbu, edge_kvm_enc_region_t)
#define EDGE_KVM_IOCTL_MEMORY_ENCRYPT_UNREG_REGION \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0xbcu, edge_kvm_enc_region_t)
#define EDGE_KVM_IOCTL_GET_NESTED_STATE \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0xbeu, edge_kvm_nested_state_t)
#define EDGE_KVM_IOCTL_SET_NESTED_STATE \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xbfu, edge_kvm_nested_state_t)
#define EDGE_KVM_IOCTL_CLEAR_DIRTY_LOG \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0xc0u, edge_kvm_clear_dirty_log_t)
#define EDGE_KVM_IOCTL_GET_SUPPORTED_HV_CPUID \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0xc1u, edge_kvm_cpuid2_t)
#define EDGE_KVM_IOCTL_ARM_VCPU_FINALIZE \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xc2u, int32_t)
#define EDGE_KVM_IOCTL_X86_SET_MSR_FILTER \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xc6u, edge_kvm_msr_filter_t)
#define EDGE_KVM_IOCTL_XEN_HVM_GET_ATTR \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0xc8u, edge_kvm_xen_attr_t)
#define EDGE_KVM_IOCTL_XEN_HVM_SET_ATTR \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xc9u, edge_kvm_xen_attr_t)
#define EDGE_KVM_IOCTL_XEN_VCPU_GET_ATTR \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0xcau, edge_kvm_xen_attr_t)
#define EDGE_KVM_IOCTL_XEN_VCPU_SET_ATTR \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xcbu, edge_kvm_xen_attr_t)
#define EDGE_KVM_IOCTL_XEN_HVM_EVTCHN_SEND \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xd0u, edge_kvm_xen_evtchn_t)
#define EDGE_KVM_IOCTL_RESET_DIRTY_RINGS \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0xc7u)
#define EDGE_KVM_IOCTL_X86_SETUP_MCE \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x9cu, uint64_t)
#define EDGE_KVM_IOCTL_X86_GET_MCE_CAP_SUPPORTED \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0x9du, uint64_t)
#define EDGE_KVM_IOCTL_X86_SET_MCE \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x9eu, edge_kvm_x86_mce_t)
#define EDGE_KVM_IOCTL_SET_CPUID2 \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x90u, edge_kvm_cpuid2_t)
#define EDGE_KVM_IOCTL_SET_CPUID \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x8au, edge_kvm_cpuid_t)
#define EDGE_KVM_IOCTL_GET_CPUID2 \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0x91u, edge_kvm_cpuid2_t)
#define EDGE_KVM_IOCTL_ENABLE_CAP \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xa3u, edge_kvm_enable_cap_t)
#define EDGE_KVM_IOCTL_DIRTY_TLB \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xaau, edge_kvm_dirty_tlb_t)
#define EDGE_KVM_IOCTL_ARM_SET_DEVICE_ADDR \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xabu, edge_kvm_arm_device_addr_t)
#define EDGE_KVM_IOCTL_SET_PMU_EVENT_FILTER_X86 \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xb2u, edge_kvm_pmu_event_filter_x86_t)
#define EDGE_KVM_IOCTL_SET_PMU_EVENT_FILTER_ARM64 \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xb2u, edge_kvm_pmu_event_filter_arm64_t)
#define EDGE_KVM_IOCTL_ARM_MTE_COPY_TAGS \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0xb4u, edge_kvm_arm_copy_mte_tags_t)
#define EDGE_KVM_IOCTL_ARM_SET_COUNTER_OFFSET \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xb5u, edge_kvm_arm_counter_offset_t)
#define EDGE_KVM_IOCTL_ARM_GET_REG_WRITABLE_MASKS \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0xb6u, edge_kvm_reg_mask_range_t)
#define EDGE_KVM_IOCTL_HYPERV_EVENTFD \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xbdu, edge_kvm_hyperv_eventfd_t)
#define EDGE_KVM_IOCTL_GET_ONE_REG \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xabu, edge_kvm_one_reg_t)
#define EDGE_KVM_IOCTL_SET_ONE_REG \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xacu, edge_kvm_one_reg_t)
#define EDGE_KVM_IOCTL_ARM_VCPU_INIT \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xaeu, edge_kvm_vcpu_init_t)
#define EDGE_KVM_IOCTL_ARM_PREFERRED_TARGET \
    EDGE_LINUX_IOR(EDGE_KVM_IOCTL_TYPE, 0xafu, edge_kvm_vcpu_init_t)
#define EDGE_KVM_IOCTL_GET_REG_LIST \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0xb0u, edge_kvm_reg_list_t)
#define EDGE_KVM_IOCTL_CREATE_DEVICE \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0xe0u, edge_kvm_create_device_t)
#define EDGE_KVM_IOCTL_SET_DEVICE_ATTR \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xe1u, edge_kvm_device_attr_t)
#define EDGE_KVM_IOCTL_GET_DEVICE_ATTR \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xe2u, edge_kvm_device_attr_t)
#define EDGE_KVM_IOCTL_HAS_DEVICE_ATTR \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xe3u, edge_kvm_device_attr_t)
#define EDGE_KVM_IOCTL_SET_MEMORY_ATTRIBUTES \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0xd2u, \
                   edge_kvm_memory_attributes_t)
#define EDGE_KVM_IOCTL_CREATE_GUEST_MEMFD \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0xd4u, \
                    edge_kvm_create_guest_memfd_t)
#define EDGE_KVM_IOCTL_PRE_FAULT_MEMORY \
    EDGE_LINUX_IOWR(EDGE_KVM_IOCTL_TYPE, 0xd5u, \
                    edge_kvm_pre_fault_memory_t)

#define EDGE_KVM_VCPU_MMAP_PAGES 3u
#define EDGE_KVM_COALESCED_MMIO_PAGE_SIZE 4096u
#define EDGE_KVM_X86_COALESCED_MMIO_PAGE_OFFSET 2u
#define EDGE_KVM_ARM64_COALESCED_MMIO_PAGE_OFFSET 1u
#define EDGE_KVM_MAX_COALESCED_MMIO_ZONES 64u
#define EDGE_KVM_MAX_CPUID_ENTRIES 256u
#define EDGE_KVM_MAX_MSR_ENTRIES 256u
#define EDGE_KVM_MAX_REG_ENTRIES 512u
#define EDGE_KVM_STATS_NAME_SIZE 48u
#define EDGE_KVM_STATS_TYPE_CUMULATIVE UINT32_C(0x00000000)
#define EDGE_KVM_STATS_TYPE_INSTANT UINT32_C(0x00000001)
#define EDGE_KVM_STATS_UNIT_NONE UINT32_C(0x00000000)
#define EDGE_KVM_STATS_BASE_POW10 UINT32_C(0x00000000)
#define EDGE_KVM_CPUID_FLAG_SIGNIFICANT_INDEX 1u
#define EDGE_KVM_CPUID_FLAG_STATEFUL_FUNC 2u
#define EDGE_KVM_CPUID_FLAG_STATE_READ_NEXT 4u

typedef struct edge_kvm_stats_header {
    uint32_t flags;
    uint32_t name_size;
    uint32_t descriptor_count;
    uint32_t id_offset;
    uint32_t descriptor_offset;
    uint32_t data_offset;
} edge_kvm_stats_header_t;

typedef struct edge_kvm_stats_descriptor {
    uint32_t flags;
    int16_t exponent;
    uint16_t size;
    uint32_t offset;
    uint32_t bucket_size;
} edge_kvm_stats_descriptor_t;

_Static_assert(sizeof(edge_kvm_stats_header_t) == 24,
               "KVM statistics header size");
_Static_assert(sizeof(edge_kvm_stats_descriptor_t) == 16,
               "KVM statistics descriptor size");

enum edge_kvm_exit_reason {
    EDGE_KVM_EXIT_UNKNOWN = 0,
    EDGE_KVM_EXIT_IO = 2,
    EDGE_KVM_EXIT_DEBUG = 4,
    EDGE_KVM_EXIT_HLT = 5,
    EDGE_KVM_EXIT_MMIO = 6,
    EDGE_KVM_EXIT_SHUTDOWN = 8,
    EDGE_KVM_EXIT_FAIL_ENTRY = 9,
    EDGE_KVM_EXIT_INTR = 10,
    EDGE_KVM_EXIT_INTERNAL_ERROR = 17,
    EDGE_KVM_EXIT_SYSTEM_EVENT = 24,
};

#define EDGE_KVM_EXIT_IO_IN 0u
#define EDGE_KVM_EXIT_IO_OUT 1u
#define EDGE_KVM_INTERNAL_ERROR_EMULATION 1u
#define EDGE_KVM_SYSTEM_EVENT_SHUTDOWN 1u
#define EDGE_KVM_SYSTEM_EVENT_RESET 2u
#define EDGE_KVM_SYSTEM_EVENT_CRASH 3u

typedef struct edge_kvm_run_io {
    uint8_t direction;
    uint8_t size;
    uint16_t port;
    uint32_t count;
    uint64_t data_offset;
} edge_kvm_run_io_t;

typedef struct edge_kvm_run_mmio {
    uint64_t physical_address;
    uint8_t data[8];
    uint32_t length;
    uint8_t is_write;
} edge_kvm_run_mmio_t;

typedef struct edge_kvm_run_debug_x86 {
    uint32_t exception;
    uint32_t padding;
    uint64_t program_counter;
    uint64_t dr6;
    uint64_t dr7;
} edge_kvm_run_debug_x86_t;

typedef struct edge_kvm_run_internal {
    uint32_t suberror;
    uint32_t data_count;
    uint64_t data[16];
} edge_kvm_run_internal_t;

typedef struct edge_kvm_run_system_event {
    uint32_t type;
    uint32_t data_count;
    uint64_t data[16];
} edge_kvm_run_system_event_t;

typedef struct edge_kvm_run {
    uint8_t request_interrupt_window;
    uint8_t immediate_exit;
    uint8_t padding1[6];
    uint32_t exit_reason;
    uint8_t ready_for_interrupt_injection;
    uint8_t if_flag;
    uint16_t flags;
    uint64_t cr8;
    uint64_t apic_base;
    union {
        edge_kvm_run_io_t io;
        edge_kvm_run_mmio_t mmio;
        edge_kvm_run_debug_x86_t debug;
        edge_kvm_run_internal_t internal;
        edge_kvm_run_system_event_t system_event;
        uint8_t reserved[256];
    } exit;
} edge_kvm_run_t;

_Static_assert(__builtin_offsetof(edge_kvm_run_t, exit_reason) == 8,
               "KVM run exit_reason offset");
_Static_assert(__builtin_offsetof(edge_kvm_run_t, exit) == 32,
               "KVM run union offset");
_Static_assert(sizeof(edge_kvm_run_io_t) == 16,
               "KVM run I/O payload size");

typedef struct edge_kvm_userspace_memory_region {
    uint32_t slot;
    uint32_t flags;
    uint64_t guest_physical_address;
    uint64_t memory_size;
    uint64_t userspace_address;
} edge_kvm_userspace_memory_region_t;

typedef struct edge_kvm_userspace_memory_region2 {
    uint32_t slot;
    uint32_t flags;
    uint64_t guest_phys_addr;
    uint64_t memory_size;
    uint64_t userspace_addr;
    uint64_t guest_memfd_offset;
    uint32_t guest_memfd;
    uint32_t pad1;
    uint64_t pad2[14];
} edge_kvm_userspace_memory_region2_t;

#define EDGE_KVM_MEMORY_GUEST_MEMFD UINT32_C(0x00000004)

typedef struct edge_kvm_enable_cap {
    uint32_t capability;
    uint32_t flags;
    uint64_t arguments[4];
    uint8_t padding[64];
} edge_kvm_enable_cap_t;

#define EDGE_KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE UINT64_C(1)
#define EDGE_KVM_DIRTY_LOG_INITIALLY_SET UINT64_C(2)
#define EDGE_KVM_DIRTY_LOG_MANUAL_SUPPORTED_FLAGS \
    EDGE_KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE

typedef struct edge_kvm_dirty_tlb {
    uint64_t bitmap;
    uint32_t dirty_count;
    uint32_t padding;
} edge_kvm_dirty_tlb_t;

typedef struct edge_kvm_arm_device_addr {
    uint64_t id;
    uint64_t address;
} edge_kvm_arm_device_addr_t;

typedef struct edge_kvm_pmu_event_filter_x86 {
    uint32_t action;
    uint32_t event_count;
    uint32_t fixed_counter_bitmap;
    uint32_t flags;
    uint32_t padding[4];
    uint64_t events[];
} edge_kvm_pmu_event_filter_x86_t;

typedef struct edge_kvm_pmu_event_filter_arm64 {
    uint16_t base_event;
    uint16_t event_count;
    uint8_t action;
    uint8_t padding[3];
} edge_kvm_pmu_event_filter_arm64_t;

typedef struct edge_kvm_arm_copy_mte_tags {
    uint64_t guest_ipa;
    uint64_t length;
    uint64_t address;
    uint64_t flags;
    uint64_t reserved[2];
} edge_kvm_arm_copy_mte_tags_t;

typedef struct edge_kvm_arm_counter_offset {
    uint64_t counter_offset;
    uint64_t reserved;
} edge_kvm_arm_counter_offset_t;

typedef struct edge_kvm_reg_mask_range {
    uint64_t address;
    uint32_t range;
    uint32_t reserved[13];
} edge_kvm_reg_mask_range_t;

typedef struct edge_kvm_hyperv_eventfd {
    uint32_t connection_id;
    int32_t descriptor;
    uint32_t flags;
    uint32_t padding[3];
} edge_kvm_hyperv_eventfd_t;

typedef struct edge_kvm_xen_hvm_config {
    uint32_t flags;
    uint32_t msr;
    uint64_t blob_address_32;
    uint64_t blob_address_64;
    uint8_t blob_size_32;
    uint8_t blob_size_64;
    uint8_t padding[30];
} edge_kvm_xen_hvm_config_t;

typedef struct edge_kvm_xen_attr {
    uint16_t type;
    uint16_t padding[3];
    uint64_t value[8];
} edge_kvm_xen_attr_t;

typedef struct edge_kvm_xen_evtchn {
    uint32_t port;
    uint32_t vcpu;
    uint32_t priority;
} edge_kvm_xen_evtchn_t;

typedef struct edge_kvm_dirty_log {
    uint32_t slot;
    uint32_t padding;
    uint64_t dirty_bitmap;
} edge_kvm_dirty_log_t;

typedef struct edge_kvm_clear_dirty_log {
    uint32_t slot;
    uint32_t num_pages;
    uint64_t first_page;
    uint64_t dirty_bitmap;
} edge_kvm_clear_dirty_log_t;

typedef struct edge_kvm_coalesced_mmio_zone {
    uint64_t address;
    uint32_t size;
    uint32_t pio;
} edge_kvm_coalesced_mmio_zone_t;

typedef struct edge_kvm_coalesced_mmio {
    uint64_t physical_address;
    uint32_t length;
    uint32_t pio;
    uint8_t data[8];
} edge_kvm_coalesced_mmio_t;

#define EDGE_KVM_COALESCED_MMIO_MAX \
    ((EDGE_KVM_COALESCED_MMIO_PAGE_SIZE - 2u * sizeof(uint32_t)) / \
     sizeof(edge_kvm_coalesced_mmio_t))

typedef struct edge_kvm_coalesced_mmio_ring {
    uint32_t first;
    uint32_t last;
    edge_kvm_coalesced_mmio_t entries[EDGE_KVM_COALESCED_MMIO_MAX];
} edge_kvm_coalesced_mmio_ring_t;

typedef struct edge_kvm_translation {
    uint64_t linear_address;
    uint64_t physical_address;
    uint8_t valid;
    uint8_t writeable;
    uint8_t usermode;
    uint8_t padding[5];
} edge_kvm_translation_t;

typedef struct edge_kvm_interrupt {
    uint32_t irq;
} edge_kvm_interrupt_t;

typedef struct edge_kvm_tpr_access_control {
    uint32_t enabled;
    uint32_t flags;
    uint32_t reserved[8];
} edge_kvm_tpr_access_control_t;

typedef struct edge_kvm_guest_debug_x86 {
    uint32_t control;
    uint32_t padding;
    uint64_t debug_registers[8];
} edge_kvm_guest_debug_x86_t;

#define EDGE_KVM_GUESTDBG_ENABLE UINT32_C(0x00000001)
#define EDGE_KVM_GUESTDBG_SINGLESTEP UINT32_C(0x00000002)
#define EDGE_KVM_GUESTDBG_USE_SW_BP UINT32_C(0x00010000)
#define EDGE_KVM_GUESTDBG_USE_HW_BP UINT32_C(0x00020000)
#define EDGE_KVM_GUESTDBG_INJECT_DB UINT32_C(0x00040000)
#define EDGE_KVM_GUESTDBG_INJECT_BP UINT32_C(0x00080000)
#define EDGE_KVM_GUESTDBG_BLOCKIRQ UINT32_C(0x00100000)

typedef struct edge_kvm_guest_debug_arm64 {
    uint32_t control;
    uint32_t padding;
    uint64_t breakpoint_controls[16];
    uint64_t breakpoint_values[16];
    uint64_t watchpoint_controls[16];
    uint64_t watchpoint_values[16];
} edge_kvm_guest_debug_arm64_t;

typedef struct edge_kvm_enc_region {
    uint64_t address;
    uint64_t size;
} edge_kvm_enc_region_t;

typedef struct edge_kvm_nested_state {
    uint16_t flags;
    uint16_t format;
    uint32_t size;
    uint8_t header[120];
} edge_kvm_nested_state_t;

typedef struct edge_kvm_msr_filter_range {
    uint32_t flags;
    uint32_t count;
    uint32_t base;
    uint32_t padding;
    uint64_t bitmap;
} edge_kvm_msr_filter_range_t;

typedef struct edge_kvm_msr_filter {
    uint32_t flags;
    uint32_t padding;
    edge_kvm_msr_filter_range_t ranges[16];
} edge_kvm_msr_filter_t;

typedef struct edge_kvm_memory_attributes {
    uint64_t address;
    uint64_t size;
    uint64_t attributes;
    uint64_t flags;
} edge_kvm_memory_attributes_t;

typedef struct edge_kvm_create_guest_memfd {
    uint64_t size;
    uint64_t flags;
    uint64_t reserved[6];
} edge_kvm_create_guest_memfd_t;

typedef struct edge_kvm_pre_fault_memory {
    uint64_t guest_physical_address;
    uint64_t size;
    uint64_t flags;
    uint64_t padding[5];
} edge_kvm_pre_fault_memory_t;

_Static_assert(sizeof(edge_kvm_userspace_memory_region2_t) == 160,
               "KVM memory region2 size");
_Static_assert(sizeof(edge_kvm_clear_dirty_log_t) == 24,
               "KVM clear dirty log size");
_Static_assert(sizeof(edge_kvm_coalesced_mmio_zone_t) == 16,
               "KVM coalesced MMIO zone size");
_Static_assert(sizeof(edge_kvm_coalesced_mmio_t) == 24,
               "KVM coalesced MMIO entry size");
_Static_assert(sizeof(edge_kvm_coalesced_mmio_ring_t) <=
    EDGE_KVM_COALESCED_MMIO_PAGE_SIZE,
               "KVM coalesced MMIO ring page overflow");
_Static_assert(sizeof(edge_kvm_translation_t) == 24,
               "KVM translation size");
_Static_assert(sizeof(edge_kvm_tpr_access_control_t) == 40,
               "KVM TPR access control size");
_Static_assert(sizeof(edge_kvm_guest_debug_x86_t) == 72,
               "KVM x86 guest debug size");
_Static_assert(sizeof(edge_kvm_run_debug_x86_t) == 32,
               "KVM x86 debug exit size");
_Static_assert(sizeof(edge_kvm_guest_debug_arm64_t) == 520,
               "KVM ARM64 guest debug size");
_Static_assert(sizeof(edge_kvm_nested_state_t) == 128,
               "KVM nested state header size");
_Static_assert(sizeof(edge_kvm_msr_filter_t) == 392,
               "KVM MSR filter size");
_Static_assert(sizeof(edge_kvm_create_guest_memfd_t) == 64,
               "KVM guest memfd size");
_Static_assert(sizeof(edge_kvm_pre_fault_memory_t) == 64,
               "KVM prefault memory size");

_Static_assert(sizeof(edge_kvm_dirty_log_t) == 16,
               "KVM dirty log descriptor size");
_Static_assert(EDGE_KVM_IOCTL_GET_DIRTY_LOG == UINT32_C(0x4010ae42),
               "KVM dirty log ioctl encoding");

typedef struct edge_kvm_one_reg {
    uint64_t id;
    uint64_t address;
} edge_kvm_one_reg_t;

typedef struct edge_kvm_vcpu_init {
    uint32_t target;
    uint32_t features[7];
} edge_kvm_vcpu_init_t;

typedef struct edge_kvm_reg_list {
    uint64_t count;
} edge_kvm_reg_list_t;

typedef struct edge_kvm_create_device {
    uint32_t type;
    uint32_t descriptor;
    uint32_t flags;
} edge_kvm_create_device_t;

typedef struct edge_kvm_device_attr {
    uint32_t flags;
    uint32_t group;
    uint64_t attribute;
    uint64_t address;
} edge_kvm_device_attr_t;

_Static_assert(sizeof(edge_kvm_one_reg_t) == 16,
               "KVM one-register descriptor size");
_Static_assert(sizeof(edge_kvm_vcpu_init_t) == 32,
               "KVM ARM vCPU initialization size");
_Static_assert(sizeof(edge_kvm_reg_list_t) == 8,
               "KVM register-list header size");
_Static_assert(sizeof(edge_kvm_create_device_t) == 12,
               "KVM device creation size");
_Static_assert(sizeof(edge_kvm_device_attr_t) == 24,
               "KVM device attribute size");

#define EDGE_KVM_DEVICE_ARM_VGIC_V3 7u
#define EDGE_KVM_DEVICE_VFIO 4u

#define EDGE_KVM_DEVICE_VFIO_FILE_GROUP 1u
#define EDGE_KVM_DEVICE_VFIO_FILE_ADD UINT64_C(1)
#define EDGE_KVM_DEVICE_VFIO_FILE_DEL UINT64_C(2)
#define EDGE_KVM_CREATE_DEVICE_TEST 1u
#define EDGE_KVM_DEVICE_ARM_VGIC_GROUP_ADDRESS 0u
#define EDGE_KVM_DEVICE_ARM_VGIC_GROUP_DIST_REGS 1u
#define EDGE_KVM_DEVICE_ARM_VGIC_GROUP_NR_IRQS 3u
#define EDGE_KVM_DEVICE_ARM_VGIC_GROUP_CONTROL 4u
#define EDGE_KVM_DEVICE_ARM_VGIC_GROUP_REDIST_REGS 5u
#define EDGE_KVM_DEVICE_ARM_VGIC_GROUP_CPU_SYSREGS 6u
#define EDGE_KVM_DEVICE_ARM_VGIC_GROUP_LEVEL_INFO 7u
#define EDGE_KVM_DEVICE_ARM_VGIC_ADDRESS_DIST UINT64_C(2)
#define EDGE_KVM_DEVICE_ARM_VGIC_ADDRESS_REDIST UINT64_C(3)
#define EDGE_KVM_DEVICE_ARM_VGIC_CONTROL_INIT UINT64_C(0)
#define EDGE_KVM_DEVICE_ARM_VGIC_SAVE_PENDING_TABLES UINT64_C(3)

#define EDGE_KVM_ARM_VCPU_POWER_OFF 0u
#define EDGE_KVM_ARM_VCPU_PSCI_0_2 2u
#define EDGE_KVM_ARM_VCPU_FEATURE(feature) (UINT32_C(1) << (feature))

#define EDGE_KVM_REG_ARCH_MASK UINT64_C(0xff00000000000000)
#define EDGE_KVM_REG_SIZE_MASK UINT64_C(0x00f0000000000000)
#define EDGE_KVM_REG_SIZE_SHIFT 52u
#define EDGE_KVM_REG_ARM64 UINT64_C(0x6000000000000000)
#define EDGE_KVM_REG_SIZE_U32 UINT64_C(0x0020000000000000)
#define EDGE_KVM_REG_SIZE_U64 UINT64_C(0x0030000000000000)
#define EDGE_KVM_REG_SIZE_U128 UINT64_C(0x0040000000000000)
#define EDGE_KVM_REG_ARM_CORE UINT64_C(0x0000000000100000)
#define EDGE_KVM_REG_ARM64_SYSREG UINT64_C(0x0000000000130000)
#define EDGE_KVM_REG_ARM_FW UINT64_C(0x0000000000140000)
#define EDGE_KVM_REG_ARM_PSCI_VERSION \
    (EDGE_KVM_REG_ARM64 | EDGE_KVM_REG_SIZE_U64 | EDGE_KVM_REG_ARM_FW)
#define EDGE_KVM_REG_ARM64_SYSREG_ID(op0, op1, crn, crm, op2) \
    (EDGE_KVM_REG_ARM64 | EDGE_KVM_REG_SIZE_U64 | \
     EDGE_KVM_REG_ARM64_SYSREG | ((uint64_t)(op0) << 14) | \
     ((uint64_t)(op1) << 11) | ((uint64_t)(crn) << 7) | \
     ((uint64_t)(crm) << 3) | (uint64_t)(op2))
#define EDGE_KVM_REG_ARM64_MPIDR_EL1 \
    EDGE_KVM_REG_ARM64_SYSREG_ID(3, 0, 0, 0, 5)
#define EDGE_KVM_REG_ARM64_SCTLR_EL1 \
    EDGE_KVM_REG_ARM64_SYSREG_ID(3, 0, 1, 0, 0)
#define EDGE_KVM_REG_ARM64_TTBR0_EL1 \
    EDGE_KVM_REG_ARM64_SYSREG_ID(3, 0, 2, 0, 0)
#define EDGE_KVM_REG_ARM64_TTBR1_EL1 \
    EDGE_KVM_REG_ARM64_SYSREG_ID(3, 0, 2, 0, 1)
#define EDGE_KVM_REG_ARM64_TCR_EL1 \
    EDGE_KVM_REG_ARM64_SYSREG_ID(3, 0, 2, 0, 2)
#define EDGE_KVM_REG_ARM_PTIMER_CTL \
    EDGE_KVM_REG_ARM64_SYSREG_ID(3, 3, 14, 2, 1)
#define EDGE_KVM_REG_ARM_PTIMER_CVAL \
    EDGE_KVM_REG_ARM64_SYSREG_ID(3, 3, 14, 2, 2)
#define EDGE_KVM_REG_ARM_PTIMER_CNT \
    EDGE_KVM_REG_ARM64_SYSREG_ID(3, 3, 14, 0, 1)
#define EDGE_KVM_REG_ARM_TIMER_CTL \
    EDGE_KVM_REG_ARM64_SYSREG_ID(3, 3, 14, 3, 1)
/* Linux published these two virtual timer encodings in swapped form. */
#define EDGE_KVM_REG_ARM_TIMER_CVAL \
    EDGE_KVM_REG_ARM64_SYSREG_ID(3, 3, 14, 0, 2)
#define EDGE_KVM_REG_ARM_TIMER_CNT \
    EDGE_KVM_REG_ARM64_SYSREG_ID(3, 3, 14, 3, 2)
#define EDGE_KVM_REG_ARM64_CORE_BASE \
    (EDGE_KVM_REG_ARM64 | EDGE_KVM_REG_SIZE_U64 | EDGE_KVM_REG_ARM_CORE)
#define EDGE_KVM_REG_ARM64_X(index) \
    (EDGE_KVM_REG_ARM64_CORE_BASE | ((uint64_t)(index) * 2u))
#define EDGE_KVM_REG_ARM64_LR EDGE_KVM_REG_ARM64_X(30u)
#define EDGE_KVM_REG_ARM64_SP \
    (EDGE_KVM_REG_ARM64_CORE_BASE | UINT64_C(0x3e))
#define EDGE_KVM_REG_ARM64_PC \
    (EDGE_KVM_REG_ARM64_CORE_BASE | UINT64_C(0x40))
#define EDGE_KVM_REG_ARM64_PSTATE \
    (EDGE_KVM_REG_ARM64_CORE_BASE | UINT64_C(0x42))
#define EDGE_KVM_REG_ARM64_SP_EL1 \
    (EDGE_KVM_REG_ARM64_CORE_BASE | UINT64_C(0x44))
#define EDGE_KVM_REG_ARM64_ELR_EL1 \
    (EDGE_KVM_REG_ARM64_CORE_BASE | UINT64_C(0x46))
#define EDGE_KVM_REG_ARM64_SPSR(index) \
    (EDGE_KVM_REG_ARM64_CORE_BASE | (UINT64_C(0x48) + \
     ((uint64_t)(index) * 2u)))
#define EDGE_KVM_REG_ARM64_V(index) \
    (EDGE_KVM_REG_ARM64 | EDGE_KVM_REG_SIZE_U128 | \
     EDGE_KVM_REG_ARM_CORE | (UINT64_C(0x54) + \
     ((uint64_t)(index) * 4u)))
#define EDGE_KVM_REG_ARM64_FPSR \
    (EDGE_KVM_REG_ARM64 | EDGE_KVM_REG_SIZE_U32 | \
     EDGE_KVM_REG_ARM_CORE | UINT64_C(0xd4))
#define EDGE_KVM_REG_ARM64_FPCR \
    (EDGE_KVM_REG_ARM64 | EDGE_KVM_REG_SIZE_U32 | \
     EDGE_KVM_REG_ARM_CORE | UINT64_C(0xd5))

_Static_assert(EDGE_KVM_REG_ARM_TIMER_CNT ==
               UINT64_C(0x603000000013df1a),
               "KVM ARM virtual timer count encoding");
_Static_assert(EDGE_KVM_REG_ARM_PTIMER_CNT ==
               UINT64_C(0x603000000013df01),
               "KVM ARM physical timer count encoding");

static inline uint32_t edge_kvm_register_size(uint64_t id) {
    uint64_t shift = (id & EDGE_KVM_REG_SIZE_MASK) >>
        EDGE_KVM_REG_SIZE_SHIFT;

    return shift < 5u ? (uint32_t)(UINT32_C(1) << shift) : 0u;
}

#define EDGE_KVM_IOEVENTFD_FLAG_DATAMATCH UINT32_C(0x01)
#define EDGE_KVM_IOEVENTFD_FLAG_PIO UINT32_C(0x02)
#define EDGE_KVM_IOEVENTFD_FLAG_DEASSIGN UINT32_C(0x04)
#define EDGE_KVM_IOEVENTFD_VALID_FLAGS \
    (EDGE_KVM_IOEVENTFD_FLAG_DATAMATCH | EDGE_KVM_IOEVENTFD_FLAG_PIO | \
     EDGE_KVM_IOEVENTFD_FLAG_DEASSIGN)

typedef struct edge_kvm_ioeventfd {
    uint64_t datamatch;
    uint64_t address;
    uint32_t length;
    int32_t descriptor;
    uint32_t flags;
    uint8_t padding[36];
} edge_kvm_ioeventfd_t;

_Static_assert(sizeof(edge_kvm_ioeventfd_t) == 64,
               "KVM ioeventfd size");

typedef struct edge_kvm_pit_config {
    uint32_t flags;
    uint32_t padding[15];
} edge_kvm_pit_config_t;

#define EDGE_KVM_MAX_IRQ_ROUTES 256u
#define EDGE_KVM_IRQ_ROUTING_IRQCHIP 1u
#define EDGE_KVM_IRQ_ROUTING_MSI 2u
#define EDGE_KVM_MSI_VALID_DEVID 1u
#define EDGE_KVM_IRQCHIP_PIC_MASTER 0u
#define EDGE_KVM_IRQCHIP_PIC_SLAVE 1u
#define EDGE_KVM_IRQCHIP_IOAPIC 2u

typedef struct edge_kvm_irq_level {
    uint32_t irq;
    uint32_t level;
} edge_kvm_irq_level_t;

typedef struct edge_kvm_irq_routing_entry {
    uint32_t gsi;
    uint32_t type;
    uint32_t flags;
    uint32_t padding;
    union {
        struct {
            uint32_t irqchip;
            uint32_t pin;
        } irqchip;
        struct {
            uint32_t address_lo;
            uint32_t address_hi;
            uint32_t data;
            uint32_t devid;
        } msi;
        uint8_t padding[32];
    } u;
} edge_kvm_irq_routing_entry_t;

typedef struct edge_kvm_irq_routing {
    uint32_t nr;
    uint32_t flags;
    edge_kvm_irq_routing_entry_t entries[];
} edge_kvm_irq_routing_t;

typedef struct edge_kvm_msi {
    uint32_t address_lo;
    uint32_t address_hi;
    uint32_t data;
    uint32_t flags;
    uint32_t device_id;
    uint32_t padding[3];
} edge_kvm_msi_t;

#define EDGE_KVM_IRQFD_FLAG_DEASSIGN UINT32_C(0x01)
#define EDGE_KVM_IRQFD_FLAG_RESAMPLE UINT32_C(0x02)
#define EDGE_KVM_IRQFD_VALID_FLAGS \
    (EDGE_KVM_IRQFD_FLAG_DEASSIGN | EDGE_KVM_IRQFD_FLAG_RESAMPLE)

typedef struct edge_kvm_irqfd {
    uint32_t descriptor;
    uint32_t gsi;
    uint32_t flags;
    uint32_t resample_descriptor;
    uint8_t padding[16];
} edge_kvm_irqfd_t;

_Static_assert(sizeof(edge_kvm_irq_level_t) == 8,
               "KVM IRQ level size");
_Static_assert(sizeof(edge_kvm_irq_routing_entry_t) == 48,
               "KVM IRQ route entry size");
_Static_assert(sizeof(edge_kvm_irq_routing_t) == 8,
               "KVM IRQ routing header size");
_Static_assert(sizeof(edge_kvm_msi_t) == 32,
               "KVM MSI message size");
_Static_assert(sizeof(edge_kvm_irqfd_t) == 32,
               "KVM irqfd size");

typedef struct edge_kvm_pic_state {
    uint8_t last_irr;
    uint8_t irr;
    uint8_t imr;
    uint8_t isr;
    uint8_t priority_add;
    uint8_t irq_base;
    uint8_t read_reg_select;
    uint8_t poll;
    uint8_t special_mask;
    uint8_t init_state;
    uint8_t auto_eoi;
    uint8_t rotate_on_auto_eoi;
    uint8_t special_fully_nested_mode;
    uint8_t init4;
    uint8_t elcr;
    uint8_t elcr_mask;
} edge_kvm_pic_state_t;

typedef struct edge_kvm_ioapic_state {
    uint64_t base_address;
    uint32_t ioregsel;
    uint32_t id;
    uint32_t irr;
    uint32_t padding;
    uint64_t redirtbl[24];
} edge_kvm_ioapic_state_t;

typedef struct edge_kvm_irqchip {
    uint32_t chip_id;
    uint32_t padding;
    union {
        edge_kvm_pic_state_t pic;
        edge_kvm_ioapic_state_t ioapic;
        uint8_t padding[512];
    } chip;
} edge_kvm_irqchip_t;

typedef struct edge_kvm_pit_channel_state {
    uint32_t count;
    uint16_t latched_count;
    uint8_t count_latched;
    uint8_t status_latched;
    uint8_t status;
    uint8_t read_state;
    uint8_t write_state;
    uint8_t write_latch;
    uint8_t rw_mode;
    uint8_t mode;
    uint8_t bcd;
    uint8_t gate;
    int64_t count_load_time;
} edge_kvm_pit_channel_state_t;

typedef struct edge_kvm_pit_state {
    edge_kvm_pit_channel_state_t channels[3];
} edge_kvm_pit_state_t;

typedef struct edge_kvm_pit_state2 {
    edge_kvm_pit_channel_state_t channels[3];
    uint32_t flags;
    uint32_t reserved[9];
} edge_kvm_pit_state2_t;

#define EDGE_KVM_CLOCK_VALID_FLAGS UINT32_C(0x0e)

typedef struct edge_kvm_clock_data {
    uint64_t clock;
    uint32_t flags;
    uint32_t padding0;
    uint64_t realtime;
    uint64_t host_tsc;
    uint32_t padding[4];
} edge_kvm_clock_data_t;

_Static_assert(sizeof(edge_kvm_pic_state_t) == 16,
               "KVM PIC state size");
_Static_assert(sizeof(edge_kvm_ioapic_state_t) == 216,
               "KVM IOAPIC state size");
_Static_assert(sizeof(edge_kvm_irqchip_t) == 520,
               "KVM IRQ chip state size");
_Static_assert(sizeof(edge_kvm_pit_channel_state_t) == 24,
               "KVM PIT channel state size");
_Static_assert(sizeof(edge_kvm_pit_state_t) == 72,
               "KVM legacy PIT state size");
_Static_assert(sizeof(edge_kvm_pit_state2_t) == 112,
               "KVM PIT2 state size");
_Static_assert(sizeof(edge_kvm_clock_data_t) == 48,
               "KVM clock data size");

_Static_assert(sizeof(edge_kvm_pit_config_t) == 64,
               "KVM PIT configuration size");

typedef struct edge_kvm_cpuid_entry2 {
    uint32_t function;
    uint32_t index;
    uint32_t flags;
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t padding[3];
} edge_kvm_cpuid_entry2_t;

typedef struct edge_kvm_cpuid_entry {
    uint32_t function;
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t padding;
} edge_kvm_cpuid_entry_t;

typedef struct edge_kvm_cpuid {
    uint32_t nent;
    uint32_t padding;
    edge_kvm_cpuid_entry_t entries[];
} edge_kvm_cpuid_t;

typedef struct edge_kvm_cpuid2 {
    uint32_t nent;
    uint32_t padding;
    edge_kvm_cpuid_entry2_t entries[];
} edge_kvm_cpuid2_t;

_Static_assert(sizeof(edge_kvm_enable_cap_t) == 104,
               "KVM enable-capability size");
_Static_assert(sizeof(edge_kvm_dirty_tlb_t) == 16,
               "KVM dirty-TLB size");
_Static_assert(sizeof(edge_kvm_arm_device_addr_t) == 16,
               "KVM ARM device-address size");
_Static_assert(sizeof(edge_kvm_pmu_event_filter_x86_t) == 32,
               "KVM x86 PMU filter header size");
_Static_assert(sizeof(edge_kvm_pmu_event_filter_arm64_t) == 8,
               "KVM ARM64 PMU filter size");
_Static_assert(sizeof(edge_kvm_arm_copy_mte_tags_t) == 48,
               "KVM ARM MTE copy size");
_Static_assert(sizeof(edge_kvm_arm_counter_offset_t) == 16,
               "KVM ARM counter-offset size");
_Static_assert(sizeof(edge_kvm_reg_mask_range_t) == 64,
               "KVM ARM register-mask range size");
_Static_assert(sizeof(edge_kvm_hyperv_eventfd_t) == 24,
               "KVM Hyper-V eventfd size");
_Static_assert(sizeof(edge_kvm_xen_hvm_config_t) == 56,
               "KVM Xen configuration size");
_Static_assert(sizeof(edge_kvm_xen_attr_t) == 72,
               "KVM Xen attribute size");
_Static_assert(sizeof(edge_kvm_xen_evtchn_t) == 12,
               "KVM Xen event-channel size");
_Static_assert(sizeof(edge_kvm_cpuid_entry_t) == 24,
               "KVM legacy CPUID entry size");
_Static_assert(sizeof(edge_kvm_cpuid_t) == 8,
               "KVM legacy CPUID header size");

_Static_assert(sizeof(edge_kvm_cpuid_entry2_t) == 40,
               "KVM CPUID entry size");
_Static_assert(sizeof(edge_kvm_cpuid2_t) == 8,
               "KVM CPUID header size");

typedef struct edge_kvm_regs {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
    uint64_t rflags;
} edge_kvm_regs_t;

typedef struct edge_kvm_segment {
    uint64_t base;
    uint32_t limit;
    uint16_t selector;
    uint8_t type;
    uint8_t present;
    uint8_t dpl;
    uint8_t db;
    uint8_t s;
    uint8_t l;
    uint8_t g;
    uint8_t avl;
    uint8_t unusable;
    uint8_t padding;
} edge_kvm_segment_t;

typedef struct edge_kvm_dtable {
    uint64_t base;
    uint16_t limit;
    uint16_t padding[3];
} edge_kvm_dtable_t;

typedef struct edge_kvm_sregs {
    edge_kvm_segment_t cs;
    edge_kvm_segment_t ds;
    edge_kvm_segment_t es;
    edge_kvm_segment_t fs;
    edge_kvm_segment_t gs;
    edge_kvm_segment_t ss;
    edge_kvm_segment_t tr;
    edge_kvm_segment_t ldt;
    edge_kvm_dtable_t gdt;
    edge_kvm_dtable_t idt;
    uint64_t cr0;
    uint64_t cr2;
    uint64_t cr3;
    uint64_t cr4;
    uint64_t cr8;
    uint64_t efer;
    uint64_t apic_base;
    uint64_t interrupt_bitmap[4];
} edge_kvm_sregs_t;

_Static_assert(sizeof(edge_kvm_segment_t) == 24,
               "KVM segment size");
_Static_assert(sizeof(edge_kvm_dtable_t) == 16,
               "KVM descriptor table size");
_Static_assert(sizeof(edge_kvm_sregs_t) == 312,
               "KVM special register size");

typedef struct edge_kvm_sregs2 {
    edge_kvm_segment_t cs;
    edge_kvm_segment_t ds;
    edge_kvm_segment_t es;
    edge_kvm_segment_t fs;
    edge_kvm_segment_t gs;
    edge_kvm_segment_t ss;
    edge_kvm_segment_t tr;
    edge_kvm_segment_t ldt;
    edge_kvm_dtable_t gdt;
    edge_kvm_dtable_t idt;
    uint64_t cr0;
    uint64_t cr2;
    uint64_t cr3;
    uint64_t cr4;
    uint64_t cr8;
    uint64_t efer;
    uint64_t apic_base;
    uint64_t flags;
    uint64_t pdptrs[4];
} edge_kvm_sregs2_t;

#define EDGE_KVM_SREGS2_PDPTRS_VALID UINT64_C(1)
#define EDGE_KVM_SREGS2_VALID_FLAGS EDGE_KVM_SREGS2_PDPTRS_VALID

_Static_assert(__builtin_offsetof(edge_kvm_sregs2_t, flags) == 280,
               "KVM SREGS2 flags offset");
_Static_assert(__builtin_offsetof(edge_kvm_sregs2_t, pdptrs) == 288,
               "KVM SREGS2 PDPTR offset");
_Static_assert(sizeof(edge_kvm_sregs2_t) == 320,
               "KVM SREGS2 size");

typedef struct edge_kvm_fpu {
    uint8_t fpr[8][16];
    uint16_t fcw;
    uint16_t fsw;
    uint8_t ftwx;
    uint8_t padding1;
    uint16_t last_opcode;
    uint64_t last_ip;
    uint64_t last_dp;
    uint8_t xmm[16][16];
    uint32_t mxcsr;
    uint32_t padding2;
} edge_kvm_fpu_t;

_Static_assert(sizeof(edge_kvm_fpu_t) == 416,
               "KVM FPU state size");

typedef struct edge_kvm_lapic_state {
    uint8_t registers[1024];
} edge_kvm_lapic_state_t;

typedef struct edge_kvm_vapic_addr {
    uint64_t vapic_addr;
} edge_kvm_vapic_addr_t;

_Static_assert(sizeof(edge_kvm_lapic_state_t) == 1024,
               "KVM local APIC state size");
_Static_assert(sizeof(edge_kvm_vapic_addr_t) == 8,
               "KVM virtual APIC address size");

typedef struct edge_kvm_debugregs {
    uint64_t db[4];
    uint64_t dr6;
    uint64_t dr7;
    uint64_t flags;
    uint64_t reserved[9];
} edge_kvm_debugregs_t;

#define EDGE_KVM_MAX_XCRS 16u

typedef struct edge_kvm_xcr {
    uint32_t xcr;
    uint32_t reserved;
    uint64_t value;
} edge_kvm_xcr_t;

typedef struct edge_kvm_xcrs {
    uint32_t nr_xcrs;
    uint32_t flags;
    edge_kvm_xcr_t xcrs[EDGE_KVM_MAX_XCRS];
    uint64_t padding[16];
} edge_kvm_xcrs_t;

_Static_assert(sizeof(edge_kvm_debugregs_t) == 128,
               "KVM debug register state size");
_Static_assert(sizeof(edge_kvm_xcr_t) == 16,
               "KVM XCR entry size");
_Static_assert(sizeof(edge_kvm_xcrs_t) == 392,
               "KVM XCR array size");

#define EDGE_KVM_XSAVE_SIZE 4096u
#define EDGE_KVM_XSAVE_XCR0_OFFSET 464u
#define EDGE_KVM_XSAVE_HEADER_OFFSET 512u
#define EDGE_KVM_XSAVE_RESERVED_OFFSET 528u
#define EDGE_KVM_XSAVE_RESERVED_SIZE 48u

typedef struct edge_kvm_xsave {
    uint8_t region[EDGE_KVM_XSAVE_SIZE];
} edge_kvm_xsave_t;

_Static_assert(sizeof(edge_kvm_xsave_t) == EDGE_KVM_XSAVE_SIZE,
               "KVM XSAVE state size");

typedef struct edge_kvm_msr_entry {
    uint32_t index;
    uint32_t reserved;
    uint64_t data;
} edge_kvm_msr_entry_t;

typedef struct edge_kvm_msrs {
    uint32_t nmsrs;
    uint32_t padding;
    edge_kvm_msr_entry_t entries[];
} edge_kvm_msrs_t;

typedef struct edge_kvm_signal_mask {
    uint32_t length;
    uint8_t mask[];
} edge_kvm_signal_mask_t;

_Static_assert(sizeof(edge_kvm_signal_mask_t) == 4,
               "KVM signal mask header size");

typedef struct edge_kvm_msr_list {
    uint32_t nmsrs;
    uint32_t indices[];
} edge_kvm_msr_list_t;

_Static_assert(sizeof(edge_kvm_msr_entry_t) == 16,
               "KVM MSR entry size");
_Static_assert(sizeof(edge_kvm_msrs_t) == 8,
               "KVM MSR header size");
_Static_assert(sizeof(edge_kvm_msr_list_t) == 4,
               "KVM MSR list header size");

enum edge_kvm_mp_state_value {
    EDGE_KVM_MP_STATE_RUNNABLE = 0,
    EDGE_KVM_MP_STATE_UNINITIALIZED = 1,
    EDGE_KVM_MP_STATE_INIT_RECEIVED = 2,
    EDGE_KVM_MP_STATE_HALTED = 3,
    EDGE_KVM_MP_STATE_SIPI_RECEIVED = 4,
    EDGE_KVM_MP_STATE_STOPPED = 5,
    EDGE_KVM_MP_STATE_CHECK_STOP = 6,
    EDGE_KVM_MP_STATE_OPERATING = 7,
    EDGE_KVM_MP_STATE_LOAD = 8,
};

typedef struct edge_kvm_mp_state {
    uint32_t mp_state;
} edge_kvm_mp_state_t;

typedef struct edge_kvm_vcpu_events {
    struct {
        uint8_t injected;
        uint8_t number;
        uint8_t has_error_code;
        uint8_t pending;
        uint32_t error_code;
    } exception;
    struct {
        uint8_t injected;
        uint8_t number;
        uint8_t soft;
        uint8_t shadow;
    } interrupt;
    struct {
        uint8_t injected;
        uint8_t pending;
        uint8_t masked;
        uint8_t padding;
    } nmi;
    uint32_t sipi_vector;
    uint32_t flags;
    struct {
        uint8_t smm;
        uint8_t pending;
        uint8_t smm_inside_nmi;
        uint8_t latched_init;
    } smi;
    uint8_t triple_fault;
    uint8_t reserved[26];
    uint8_t exception_has_payload;
    uint64_t exception_payload;
} edge_kvm_vcpu_events_t;

#define EDGE_KVM_VCPUEVENT_VALID_NMI_PENDING UINT32_C(0x01)
#define EDGE_KVM_VCPUEVENT_VALID_SIPI_VECTOR UINT32_C(0x02)
#define EDGE_KVM_VCPUEVENT_VALID_SHADOW UINT32_C(0x04)
#define EDGE_KVM_VCPUEVENT_VALID_SMM UINT32_C(0x08)
#define EDGE_KVM_VCPUEVENT_VALID_PAYLOAD UINT32_C(0x10)
#define EDGE_KVM_VCPUEVENT_VALID_TRIPLE_FAULT UINT32_C(0x20)
#define EDGE_KVM_VCPUEVENT_VALID_MASK UINT32_C(0x3f)

#define EDGE_KVM_X86_MCE_BANK_COUNT_MASK UINT64_C(0xff)
#define EDGE_KVM_X86_MCE_MAX_BANKS 32u
#define EDGE_KVM_X86_MCE_CTL_PRESENT (UINT64_C(1) << 8)
#define EDGE_KVM_X86_MCE_EXTENDED_PRESENT (UINT64_C(1) << 9)
#define EDGE_KVM_X86_MCE_CMCI_PRESENT (UINT64_C(1) << 10)
#define EDGE_KVM_X86_MCE_THRESHOLD_PRESENT (UINT64_C(1) << 11)
#define EDGE_KVM_X86_MCE_SER_PRESENT (UINT64_C(1) << 24)
#define EDGE_KVM_X86_MCE_EMC_PRESENT (UINT64_C(1) << 25)
#define EDGE_KVM_X86_MCE_LMCE_PRESENT (UINT64_C(1) << 27)
#define EDGE_KVM_X86_MCE_VALID_MASK \
    (EDGE_KVM_X86_MCE_BANK_COUNT_MASK | EDGE_KVM_X86_MCE_CTL_PRESENT | \
     EDGE_KVM_X86_MCE_EXTENDED_PRESENT | EDGE_KVM_X86_MCE_CMCI_PRESENT | \
     EDGE_KVM_X86_MCE_THRESHOLD_PRESENT | EDGE_KVM_X86_MCE_SER_PRESENT | \
     EDGE_KVM_X86_MCE_EMC_PRESENT | EDGE_KVM_X86_MCE_LMCE_PRESENT)
#define EDGE_KVM_X86_MCE_STATUS_VALID (UINT64_C(1) << 63)
#define EDGE_KVM_X86_MCE_STATUS_UNCORRECTED (UINT64_C(1) << 61)
#define EDGE_KVM_X86_MCG_STATUS_IN_PROGRESS (UINT64_C(1) << 2)

typedef struct edge_kvm_x86_mce {
    uint64_t status;
    uint64_t address;
    uint64_t miscellaneous;
    uint64_t mcg_status;
    uint8_t bank;
    uint8_t padding1[7];
    uint64_t padding2[3];
} edge_kvm_x86_mce_t;

_Static_assert(sizeof(edge_kvm_x86_mce_t) == 64,
               "KVM x86 machine-check record size");

_Static_assert(sizeof(edge_kvm_mp_state_t) == 4,
               "KVM MP state size");
_Static_assert(sizeof(edge_kvm_vcpu_events_t) == 64,
               "KVM vCPU events size");

/* Capability numbers observed from unmodified QEMU and Linux KVM behavior. */
enum edge_kvm_public_capability {
    EDGE_KVM_CAP_IRQCHIP = 0x00,
    EDGE_KVM_CAP_USER_MEMORY = 0x03,
    EDGE_KVM_CAP_SET_TSS_ADDR = 0x04,
    EDGE_KVM_CAP_EXT_CPUID = 0x07,
    EDGE_KVM_CAP_NR_VCPUS = 0x09,
    EDGE_KVM_CAP_NR_MEMSLOTS = 0x0a,
    EDGE_KVM_CAP_MP_STATE = 0x0e,
    EDGE_KVM_CAP_COALESCED_MMIO = 0x0f,
    EDGE_KVM_CAP_SYNC_MMU = 0x10,
    EDGE_KVM_CAP_DESTROY_MEMORY_REGION_WORKS = 0x15,
    EDGE_KVM_CAP_SET_GUEST_DEBUG = 0x17,
    EDGE_KVM_CAP_JOIN_MEMORY_REGIONS_WORKS = 0x1e,
    EDGE_KVM_CAP_ADJUST_CLOCK = 0x27,
    EDGE_KVM_CAP_MCE = 0x1f,
    EDGE_KVM_CAP_IRQ_ROUTING = 0x19,
    EDGE_KVM_CAP_IRQ_INJECT_STATUS = 0x1a,
    EDGE_KVM_CAP_INTERNAL_ERROR_DATA = 0x28,
    EDGE_KVM_CAP_VCPU_EVENTS = 0x29,
    EDGE_KVM_CAP_TSC_CONTROL = 0x2c,
    EDGE_KVM_CAP_DEBUGREGS = 0x32,
    EDGE_KVM_CAP_X86_ROBUST_SINGLESTEP = 0x33,
    EDGE_KVM_CAP_GET_TSC_KHZ = 0x3d,
    EDGE_KVM_CAP_XSAVE = 0x37,
    EDGE_KVM_CAP_XCRS = 0x38,
    EDGE_KVM_CAP_IRQFD = 0x20,
    EDGE_KVM_CAP_PIT2 = 0x21,
    EDGE_KVM_CAP_PIT_STATE2 = 0x23,
    EDGE_KVM_CAP_IOEVENTFD = 0x24,
    EDGE_KVM_CAP_SET_IDENTITY_MAP_ADDR = 0x25,
    EDGE_KVM_CAP_MAX_VCPUS = 0x42,
    EDGE_KVM_CAP_SIGNAL_MSI = 0x4d,
    EDGE_KVM_CAP_READONLY_MEMORY = 0x51,
    EDGE_KVM_CAP_ARM_PSCI = 0x57,
    EDGE_KVM_CAP_DEVICE_CTRL = 0x59,
    EDGE_KVM_CAP_ARM_PSCI_0_2 = 0x66,
    EDGE_KVM_CAP_IOEVENTFD_ANY_LENGTH = 0x7a,
    EDGE_KVM_CAP_IMMEDIATE_EXIT = 0x88,
    EDGE_KVM_CAP_NESTED_STATE = 0x9d,
    EDGE_KVM_CAP_GET_MSR_FEATURES = 0x99,
    EDGE_KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2 = 0xa8,
    EDGE_KVM_CAP_XSAVE2 = 0xd0,
    EDGE_KVM_CAP_USER_MEMORY2 = 0xe7,
    EDGE_KVM_CAP_PRE_FAULT_MEMORY = 0xec,
};

#endif
