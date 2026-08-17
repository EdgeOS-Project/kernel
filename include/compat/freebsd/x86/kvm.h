/* SPDX-License-Identifier: BSD-2-Clause */
/* KVM paravirtualization feature discovery for imported BSD drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_X86_KVM_H
#define EDGEOS_COMPAT_FREEBSD_X86_KVM_H

#include <stdbool.h>
#include <sys/types.h>
#include <machine/cpufunc.h>

#define KVM_CPUID_SIGNATURE 0x40000000u
#define KVM_CPUID_FEATURES_LEAF 0x40000001u

#define KVM_FEATURE_CLOCKSOURCE 0x00000001u
#define KVM_FEATURE_CLOCKSOURCE2 0x00000008u
#define KVM_FEATURE_MSI_EXT_DEST_ID 0x00008000u
#define KVM_FEATURE_CLOCKSOURCE_STABLE_BIT 0x01000000u

#define KVM_MSR_WALL_CLOCK 0x11u
#define KVM_MSR_SYSTEM_TIME 0x12u
#define KVM_MSR_WALL_CLOCK_NEW 0x4b564d00u
#define KVM_MSR_SYSTEM_TIME_NEW 0x4b564d01u

static inline bool
kvm_cpuid_features_leaf_supported(void)
{
    unsigned int registers[4];

    do_cpuid(KVM_CPUID_SIGNATURE, registers);
    return registers[0] >= KVM_CPUID_FEATURES_LEAF &&
        registers[1] == 0x4b4d564bu &&
        registers[2] == 0x564b4d56u &&
        registers[3] == 0x0000004du;
}

static inline void
kvm_cpuid_get_features(unsigned int *registers)
{
    if (!registers)
        return;
    if (!kvm_cpuid_features_leaf_supported()) {
        registers[0] = 0;
        registers[1] = 0;
        registers[2] = 0;
        registers[3] = 0;
        return;
    }
    do_cpuid(KVM_CPUID_FEATURES_LEAF, registers);
}

#endif
