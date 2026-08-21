/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Architecture-independent CPU topology and lifecycle state.
 *
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_SMP_H
#define EDGEOS_KERNEL_SMP_H

#include <stdint.h>

#define EDGE_SMP_MAX_CPUS 256u
#define EDGE_SMP_CAPACITY_SCALE 1024u
#define EDGE_SMP_CALL_MEMORY_BARRIER (1u << 0)
#define EDGE_SMP_CALL_SYNC_CORE (1u << 1)
#define EDGE_SMP_CALL_TLB_FLUSH (1u << 2)
#define EDGE_SMP_CALL_ARCH_MM_REFRESH (1u << 3)
#define EDGE_SMP_CALL_VALID_FLAGS \
    (EDGE_SMP_CALL_MEMORY_BARRIER | EDGE_SMP_CALL_SYNC_CORE | \
     EDGE_SMP_CALL_TLB_FLUSH | EDGE_SMP_CALL_ARCH_MM_REFRESH)
#define EDGE_CPUMASK_WORD_BITS 64u
#define EDGE_CPUMASK_MAX_WORDS \
    ((EDGE_SMP_MAX_CPUS + EDGE_CPUMASK_WORD_BITS - 1u) / \
     EDGE_CPUMASK_WORD_BITS)

typedef struct edge_cpumask {
    uint32_t nbits;
    uint32_t nwords;
    uint64_t bits[EDGE_CPUMASK_MAX_WORDS];
} edge_cpumask_t;

typedef enum edge_cpu_state {
    EDGE_CPU_ABSENT = 0,
    EDGE_CPU_PRESENT,
    EDGE_CPU_STARTING,
    EDGE_CPU_ONLINE,
    EDGE_CPU_DYING,
    EDGE_CPU_OFFLINE,
    EDGE_CPU_FAILED
} edge_cpu_state_t;

typedef struct edge_cpu_topology {
    uint32_t logical_id;
    uint64_t hardware_id;
    uint32_t firmware_id;
    uint32_t package_id;
    uint32_t core_id;
    uint32_t thread_id;
    uint32_t numa_node;
    uint32_t capacity;
    edge_cpu_state_t state;
} edge_cpu_topology_t;

void edge_cpumask_init(edge_cpumask_t *mask, uint32_t nr_cpu_ids);
void edge_cpumask_zero(edge_cpumask_t *mask);
void edge_cpumask_fill(edge_cpumask_t *mask);
int edge_cpumask_set_cpu(edge_cpumask_t *mask, uint32_t cpu);
int edge_cpumask_clear_cpu(edge_cpumask_t *mask, uint32_t cpu);
int edge_cpumask_test_cpu(const edge_cpumask_t *mask, uint32_t cpu);
uint32_t edge_cpumask_weight(const edge_cpumask_t *mask);
uint32_t edge_cpumask_next(const edge_cpumask_t *mask, uint32_t previous);
int edge_cpumask_intersects(const edge_cpumask_t *left,
                            const edge_cpumask_t *right);
void edge_cpumask_and(edge_cpumask_t *destination,
                      const edge_cpumask_t *left,
                      const edge_cpumask_t *right);
void edge_cpumask_or(edge_cpumask_t *destination,
                     const edge_cpumask_t *left,
                     const edge_cpumask_t *right);

void edge_smp_reset(uint64_t boot_hardware_id, uint32_t boot_firmware_id,
                    uint32_t boot_capacity);
int edge_smp_register_cpu(uint64_t hardware_id, uint32_t firmware_id,
                          uint32_t package_id, uint32_t core_id,
                          uint32_t thread_id, uint32_t numa_node,
                          uint32_t capacity);
int edge_smp_find_cpu(uint64_t hardware_id);
int edge_smp_get_cpu(uint32_t logical_id, edge_cpu_topology_t *topology);
int edge_smp_set_state(uint32_t logical_id, edge_cpu_state_t state);
edge_cpu_state_t edge_smp_cpu_state(uint32_t logical_id);
uint32_t edge_smp_nr_cpu_ids(void);
uint32_t edge_smp_present_count(void);
uint32_t edge_smp_online_count(void);
void edge_smp_present_mask(edge_cpumask_t *mask);
void edge_smp_online_mask(edge_cpumask_t *mask);
void edge_smp_sibling_mask(uint32_t logical_id, edge_cpumask_t *mask);
uint64_t edge_smp_online_mask64(void);
uint32_t edge_smp_current_cpu(void);
int edge_smp_reschedule(uint32_t logical_id);
int edge_smp_calls_available(void);
int edge_smp_call(const edge_cpumask_t *mask, uint32_t flags);
void edge_smp_handle_call(uint32_t logical_id);

#endif
