/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS CPU registry and scalable CPU mask unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>

#include "kernel/smp.h"

static int g_failures;
static uint32_t g_current_cpu;
static uint32_t g_sent_calls;
static uint32_t g_executed_calls;
static uint32_t g_executed_flags;
static uint32_t g_callback_calls;
static uint32_t g_vmm_kicks;

static void count_rendezvous(void *argument) {
    uint32_t *value = argument;

    ++g_callback_calls;
    ++*value;
}

uint32_t arch_smp_current_cpu(void) {
    return g_current_cpu;
}

int arch_smp_calls_available(void) {
    return 1;
}

int arch_smp_send_call(uint32_t logical_id) {
    ++g_sent_calls;
    edge_smp_handle_call(logical_id);
    return 0;
}

int arch_smp_send_vmm_kick(uint32_t logical_id) {
    (void)logical_id;
    ++g_vmm_kicks;
    return 0;
}

void arch_smp_execute_call(uint32_t flags) {
    ++g_executed_calls;
    g_executed_flags |= flags;
}

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

static void test_scalable_cpumask(void) {
    edge_cpumask_t left;
    edge_cpumask_t right;
    edge_cpumask_t result;

    edge_cpumask_init(&left, 130u);
    edge_cpumask_init(&right, 130u);
    expect_true("mask spans more than one legacy word", left.nwords == 3u);
    expect_true("set CPU 0", edge_cpumask_set_cpu(&left, 0u) == 0);
    expect_true("set CPU 65", edge_cpumask_set_cpu(&left, 65u) == 0);
    expect_true("set CPU 129", edge_cpumask_set_cpu(&left, 129u) == 0);
    expect_true("reject CPU outside active width",
                edge_cpumask_set_cpu(&left, 130u) != 0);
    expect_true("weight across words", edge_cpumask_weight(&left) == 3u);
    expect_true("iterate first CPU",
                edge_cpumask_next(&left, UINT32_MAX) == 0u);
    expect_true("iterate second word",
                edge_cpumask_next(&left, 0u) == 65u);
    expect_true("iterate final partial word",
                edge_cpumask_next(&left, 65u) == 129u);
    expect_true("iteration terminates at width",
                edge_cpumask_next(&left, 129u) == 130u);

    (void)edge_cpumask_set_cpu(&right, 65u);
    (void)edge_cpumask_set_cpu(&right, 90u);
    expect_true("intersection spans words",
                edge_cpumask_intersects(&left, &right));
    edge_cpumask_and(&result, &left, &right);
    expect_true("and preserves shared CPU only",
                edge_cpumask_weight(&result) == 1u &&
                edge_cpumask_test_cpu(&result, 65u));
    edge_cpumask_or(&result, &left, &right);
    expect_true("or combines active CPUs",
                edge_cpumask_weight(&result) == 4u &&
                edge_cpumask_test_cpu(&result, 90u));
    edge_cpumask_and(&left, &left, &right);
    expect_true("in-place and preserves source bits",
                edge_cpumask_weight(&left) == 1u &&
                edge_cpumask_test_cpu(&left, 65u));
    edge_cpumask_or(&right, &right, &result);
    expect_true("in-place or preserves source bits",
                edge_cpumask_weight(&right) == 4u &&
                edge_cpumask_test_cpu(&right, 129u));
    edge_cpumask_fill(&result);
    expect_true("fill masks unused high bits",
                edge_cpumask_weight(&result) == 130u &&
                result.bits[2] == 3u);
}

static void test_cpu_lifecycle_and_topology(void) {
    edge_cpu_topology_t topology;
    edge_cpumask_t mask;
    int cpu1;
    int cpu2;

    edge_smp_reset(7u, 100u, EDGE_SMP_CAPACITY_SCALE);
    expect_true("boot CPU online", edge_smp_online_count() == 1u);
    cpu1 = edge_smp_register_cpu(8u, 101u, 0u, 0u, 1u, 0u,
                                 EDGE_SMP_CAPACITY_SCALE);
    cpu2 = edge_smp_register_cpu(9u, 102u, 0u, 1u, 0u, 0u, 768u);
    expect_true("logical IDs are stable", cpu1 == 1 && cpu2 == 2);
    expect_true("duplicate hardware ID reuses logical ID",
                edge_smp_register_cpu(8u, 777u, 9u, 9u, 9u, 9u, 1u) == cpu1);
    expect_true("present CPUs include offline siblings",
                edge_smp_present_count() == 3u);
    expect_true("invalid direct online transition rejected",
                edge_smp_set_state((uint32_t)cpu1, EDGE_CPU_ONLINE) != 0);
    expect_true("secondary enters starting state",
                edge_smp_set_state((uint32_t)cpu1, EDGE_CPU_STARTING) == 0);
    expect_true("secondary reports online",
                edge_smp_set_state((uint32_t)cpu1, EDGE_CPU_ONLINE) == 0 &&
                edge_smp_online_count() == 2u);
    expect_true("topology retains heterogeneous capacity",
                edge_smp_get_cpu((uint32_t)cpu2, &topology) == 0 &&
                topology.capacity == 768u && topology.core_id == 1u);
    edge_smp_sibling_mask(0u, &mask);
    expect_true("SMT sibling mask follows package and core",
                edge_cpumask_weight(&mask) == 2u &&
                edge_cpumask_test_cpu(&mask, (uint32_t)cpu1));
    expect_true("legacy online mask remains ABI compatible",
                edge_smp_online_mask64() == 3u);
    expect_true("online CPU enters dying state",
                edge_smp_set_state((uint32_t)cpu1, EDGE_CPU_DYING) == 0);
    expect_true("dying CPU becomes offline",
                edge_smp_set_state((uint32_t)cpu1, EDGE_CPU_OFFLINE) == 0 &&
                edge_smp_online_count() == 1u);
}

static void test_cross_cpu_calls(void) {
    edge_cpumask_t targets;
    uint32_t callback_value = 0u;
    int cpu1;
    int cpu2;

    edge_smp_reset(20u, 200u, EDGE_SMP_CAPACITY_SCALE);
    cpu1 = edge_smp_register_cpu(21u, 201u, 0u, 1u, 0u, 0u,
                                 EDGE_SMP_CAPACITY_SCALE);
    cpu2 = edge_smp_register_cpu(22u, 202u, 0u, 2u, 0u, 0u,
                                 EDGE_SMP_CAPACITY_SCALE);
    expect_true("call targets enter starting state",
                edge_smp_set_state((uint32_t)cpu1, EDGE_CPU_STARTING) == 0 &&
                edge_smp_set_state((uint32_t)cpu2, EDGE_CPU_STARTING) == 0);
    expect_true("call targets enter online state",
                edge_smp_set_state((uint32_t)cpu1, EDGE_CPU_ONLINE) == 0 &&
                edge_smp_set_state((uint32_t)cpu2, EDGE_CPU_ONLINE) == 0);
    edge_smp_online_mask(&targets);
    g_current_cpu = 0u;
    g_sent_calls = 0u;
    g_executed_calls = 0u;
    g_executed_flags = 0u;
    expect_true("shared current CPU follows architecture state",
                edge_smp_current_cpu() == 0u);
    g_current_cpu = 2u;
    expect_true("shared current CPU exposes secondary identity",
                edge_smp_current_cpu() == 2u);
    g_current_cpu = 0u;
    expect_true("memory barrier reaches every online CPU",
                edge_smp_call(&targets, EDGE_SMP_CALL_MEMORY_BARRIER) == 0 &&
                g_sent_calls == 2u && g_executed_calls == 3u &&
                g_executed_flags == EDGE_SMP_CALL_MEMORY_BARRIER);
    expect_true("sync-core call reaches every online CPU",
                edge_smp_call(&targets,
                    EDGE_SMP_CALL_MEMORY_BARRIER |
                    EDGE_SMP_CALL_SYNC_CORE) == 0 &&
                g_sent_calls == 4u && g_executed_calls == 6u &&
                (g_executed_flags & EDGE_SMP_CALL_SYNC_CORE));
    expect_true("TLB flush reaches every online CPU",
                edge_smp_call(&targets, EDGE_SMP_CALL_TLB_FLUSH) == 0 &&
                g_sent_calls == 6u && g_executed_calls == 9u &&
                (g_executed_flags & EDGE_SMP_CALL_TLB_FLUSH));
    expect_true("invalid call flags are rejected",
                edge_smp_call(&targets, 1u << 31) != 0);
    g_callback_calls = 0u;
    expect_true("rendezvous callback reaches every online CPU",
                edge_smp_rendezvous(&targets, count_rendezvous,
                                    &callback_value) == 0 &&
                g_callback_calls == 3u && callback_value == 3u &&
                g_sent_calls == 8u);
    expect_true("rendezvous rejects a missing callback",
                edge_smp_rendezvous(&targets, NULL, NULL) != 0);
}

static void test_vmm_kick_delivery(void) {
    int cpu1;

    edge_smp_reset(30u, 300u, EDGE_SMP_CAPACITY_SCALE);
    cpu1 = edge_smp_register_cpu(31u, 301u, 0u, 1u, 0u, 0u,
                                 EDGE_SMP_CAPACITY_SCALE);
    expect_true("VMM kick target enters starting state",
                edge_smp_set_state((uint32_t)cpu1,
                                   EDGE_CPU_STARTING) == 0);
    expect_true("VMM kick target enters online state",
                edge_smp_set_state((uint32_t)cpu1,
                                   EDGE_CPU_ONLINE) == 0);
    g_vmm_kicks = 0u;
    expect_true("each VMM kick is delivered to the target",
                edge_smp_vmm_kick((uint32_t)cpu1) == 0 &&
                edge_smp_vmm_kick((uint32_t)cpu1) == 0 &&
                g_vmm_kicks == 2u);
}

int main(void) {
    test_scalable_cpumask();
    test_cpu_lifecycle_and_topology();
    test_cross_cpu_calls();
    test_vmm_kick_delivery();
    if (g_failures) return 1;
    puts("smp_unit: PASS");
    return 0;
}
