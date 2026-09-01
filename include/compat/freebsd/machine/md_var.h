/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS x86 CPU state exported to imported FreeBSD drivers. */

#ifndef _MACHINE_MD_VAR_H_
#define _MACHINE_MD_VAR_H_

#include <stdbool.h>
#include <sys/types.h>
#include <machine/specialreg.h>

extern unsigned int cpu_power_eax;
extern unsigned int cpu_power_ecx;
extern unsigned int cpu_id;
extern unsigned int cpu_high;
extern unsigned int cpu_exthigh;
extern unsigned int cpu_feature;
extern unsigned int cpu_feature2;
extern unsigned int cpu_stdext_feature;
extern unsigned int cpu_stdext_feature2;
extern unsigned int cpu_stdext_feature3;
extern unsigned int cpu_stdext_feature4;
extern unsigned int cpu_vendor_id;
extern unsigned int cpu_mon_mwait_edx;
extern unsigned int amd_pminfo;
extern unsigned int amd_feature;
extern unsigned int amd_feature2;
extern unsigned int amd_extended_feature_extensions;
extern unsigned int cpu_procinfo2;
extern uint64_t cpu_ia32_arch_caps;
extern char cpu_vendor[13];
extern int nmi_flush_l1d_sw;
extern int cpu_disable_c2_sleep;
extern int cpu_disable_c3_sleep;
extern long Maxmem;
extern void (*cpu_idle_hook)(sbintime_t);

bool cpu_mwait_usable(void);
void acpi_cpu_c1(void);
void acpi_cpu_idle_mwait(uint32_t hint);
uint64_t cpu_ticks(void);
uint64_t cpu_tickrate(void);
unsigned int cpu_auxmsr(void);
int rdmsr_safe(unsigned int register_id, uint64_t *value);
int wrmsr_safe(unsigned int register_id, uint64_t value);
void identify_cpu1(void);
void identify_cpu2(void);
void hw_ibrs_recalculate(bool all_cpus);
void hw_ssb_recalculate(bool all_cpus);
void amd64_syscall_ret_flush_l1d_recalc(void);
void hw_mds_recalculate(void);
void x86_taa_recalculate(void);
void x86_rngds_mitg_recalculate(bool all_cpus);
void zenbleed_check_and_apply(bool all_cpus);
void printcpuinfo(void);

#define MSR_OP_ANDNOT 0x00000001u
#define MSR_OP_OR 0x00000002u
#define MSR_OP_WRITE 0x00000003u
#define MSR_OP_READ 0x00000004u
#define MSR_OP_SAFE 0x08000000u
#define MSR_OP_LOCAL 0x10000000u
#define MSR_OP_SCHED_ALL 0x20000000u
#define MSR_OP_SCHED_ONE 0x30000000u
#define MSR_OP_RENDEZVOUS_ALL 0x40000000u
#define MSR_OP_RENDEZVOUS_ONE 0x50000000u
#define MSR_OP_CPUID(id) ((unsigned int)(id) << 8)

int x86_msr_op(unsigned int register_id, unsigned int operation,
    uint64_t argument, uint64_t *result);

#endif
