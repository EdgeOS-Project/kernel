/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Architecture-independent CPU topology and lifecycle state.
 *
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/smp.h"

#include <stdint.h>

uint32_t arch_smp_current_cpu(void);

typedef struct edge_cpu_slot {
    uint64_t hardware_id;
    uint32_t firmware_id;
    uint32_t package_id;
    uint32_t core_id;
    uint32_t thread_id;
    uint32_t numa_node;
    uint32_t capacity;
    volatile uint32_t state;
} edge_cpu_slot_t;

static edge_cpu_slot_t g_cpu_slots[EDGE_SMP_MAX_CPUS];
static volatile uint32_t g_nr_cpu_ids;
static volatile uint8_t g_registration_lock;
static volatile uint64_t g_call_sequence;
static volatile uint64_t g_call_requested[EDGE_SMP_MAX_CPUS];
static volatile uint64_t g_call_completed[EDGE_SMP_MAX_CPUS];
static volatile uint32_t g_call_flags[EDGE_SMP_MAX_CPUS];
static volatile uint64_t g_callback_requested[EDGE_SMP_MAX_CPUS];
static volatile uint64_t g_callback_completed[EDGE_SMP_MAX_CPUS];
static volatile uintptr_t g_callback_function;
static volatile uintptr_t g_callback_argument;
static volatile uint8_t g_callback_lock;

static uint32_t clamp_cpu_count(uint32_t count) {
    if (count == 0) return 1u;
    if (count > EDGE_SMP_MAX_CPUS) return EDGE_SMP_MAX_CPUS;
    return count;
}

static void registration_lock(void) {
    while (__atomic_test_and_set(&g_registration_lock, __ATOMIC_ACQUIRE))
        __asm__ __volatile__("" ::: "memory");
}

static void registration_unlock(void) {
    __atomic_clear(&g_registration_lock, __ATOMIC_RELEASE);
}

static uint64_t last_word_mask(const edge_cpumask_t *mask) {
    uint32_t remainder;

    if (!mask || mask->nwords == 0) return 0;
    remainder = mask->nbits % EDGE_CPUMASK_WORD_BITS;
    if (remainder == 0) return UINT64_MAX;
    return (UINT64_C(1) << remainder) - 1u;
}

void edge_cpumask_init(edge_cpumask_t *mask, uint32_t nr_cpu_ids) {
    if (!mask) return;
    mask->nbits = clamp_cpu_count(nr_cpu_ids);
    mask->nwords = (mask->nbits + EDGE_CPUMASK_WORD_BITS - 1u) /
                   EDGE_CPUMASK_WORD_BITS;
    edge_cpumask_zero(mask);
}

void edge_cpumask_zero(edge_cpumask_t *mask) {
    if (!mask) return;
    for (uint32_t word = 0; word < EDGE_CPUMASK_MAX_WORDS; ++word)
        mask->bits[word] = 0;
}

void edge_cpumask_fill(edge_cpumask_t *mask) {
    if (!mask) return;
    for (uint32_t word = 0; word < mask->nwords; ++word)
        mask->bits[word] = UINT64_MAX;
    for (uint32_t word = mask->nwords; word < EDGE_CPUMASK_MAX_WORDS; ++word)
        mask->bits[word] = 0;
    if (mask->nwords)
        mask->bits[mask->nwords - 1u] &= last_word_mask(mask);
}

int edge_cpumask_set_cpu(edge_cpumask_t *mask, uint32_t cpu) {
    if (!mask || cpu >= mask->nbits) return -1;
    mask->bits[cpu / EDGE_CPUMASK_WORD_BITS] |=
        UINT64_C(1) << (cpu % EDGE_CPUMASK_WORD_BITS);
    return 0;
}

int edge_cpumask_clear_cpu(edge_cpumask_t *mask, uint32_t cpu) {
    if (!mask || cpu >= mask->nbits) return -1;
    mask->bits[cpu / EDGE_CPUMASK_WORD_BITS] &=
        ~(UINT64_C(1) << (cpu % EDGE_CPUMASK_WORD_BITS));
    return 0;
}

int edge_cpumask_test_cpu(const edge_cpumask_t *mask, uint32_t cpu) {
    if (!mask || cpu >= mask->nbits) return 0;
    return (mask->bits[cpu / EDGE_CPUMASK_WORD_BITS] >>
            (cpu % EDGE_CPUMASK_WORD_BITS)) & 1u;
}

uint32_t edge_cpumask_weight(const edge_cpumask_t *mask) {
    uint32_t count = 0;

    if (!mask) return 0;
    for (uint32_t word = 0; word < mask->nwords; ++word)
        count += (uint32_t)__builtin_popcountll(mask->bits[word]);
    return count;
}

uint32_t edge_cpumask_next(const edge_cpumask_t *mask, uint32_t previous) {
    uint32_t cpu = previous == UINT32_MAX ? 0u : previous + 1u;

    if (!mask) return 0;
    for (; cpu < mask->nbits; ++cpu) {
        if (edge_cpumask_test_cpu(mask, cpu)) return cpu;
    }
    return mask->nbits;
}

int edge_cpumask_intersects(const edge_cpumask_t *left,
                            const edge_cpumask_t *right) {
    uint32_t words;

    if (!left || !right) return 0;
    words = left->nwords < right->nwords ? left->nwords : right->nwords;
    for (uint32_t word = 0; word < words; ++word) {
        if (left->bits[word] & right->bits[word]) return 1;
    }
    return 0;
}

void edge_cpumask_and(edge_cpumask_t *destination,
                      const edge_cpumask_t *left,
                      const edge_cpumask_t *right) {
    uint64_t words[EDGE_CPUMASK_MAX_WORDS];
    uint32_t nbits;
    uint32_t nwords;

    if (!destination || !left || !right) return;
    nbits = left->nbits < right->nbits ? left->nbits : right->nbits;
    nwords = (nbits + EDGE_CPUMASK_WORD_BITS - 1u) /
             EDGE_CPUMASK_WORD_BITS;
    for (uint32_t word = 0; word < nwords; ++word)
        words[word] = left->bits[word] & right->bits[word];
    edge_cpumask_init(destination, nbits);
    for (uint32_t word = 0; word < destination->nwords; ++word)
        destination->bits[word] = words[word];
}

void edge_cpumask_or(edge_cpumask_t *destination,
                     const edge_cpumask_t *left,
                     const edge_cpumask_t *right) {
    uint64_t words[EDGE_CPUMASK_MAX_WORDS];
    uint32_t nbits;
    uint32_t nwords;

    if (!destination || !left || !right) return;
    nbits = left->nbits > right->nbits ? left->nbits : right->nbits;
    nwords = (nbits + EDGE_CPUMASK_WORD_BITS - 1u) /
             EDGE_CPUMASK_WORD_BITS;
    for (uint32_t word = 0; word < nwords; ++word) {
        uint64_t left_bits = word < left->nwords ? left->bits[word] : 0;
        uint64_t right_bits = word < right->nwords ? right->bits[word] : 0;

        words[word] = left_bits | right_bits;
    }
    edge_cpumask_init(destination, nbits);
    for (uint32_t word = 0; word < destination->nwords; ++word)
        destination->bits[word] = words[word];
    destination->bits[destination->nwords - 1u] &= last_word_mask(destination);
}

void edge_smp_reset(uint64_t boot_hardware_id, uint32_t boot_firmware_id,
                    uint32_t boot_capacity) {
    for (uint32_t cpu = 0; cpu < EDGE_SMP_MAX_CPUS; ++cpu) {
        g_cpu_slots[cpu].hardware_id = 0;
        g_cpu_slots[cpu].firmware_id = 0;
        g_cpu_slots[cpu].package_id = 0;
        g_cpu_slots[cpu].core_id = cpu;
        g_cpu_slots[cpu].thread_id = 0;
        g_cpu_slots[cpu].numa_node = 0;
        g_cpu_slots[cpu].capacity = EDGE_SMP_CAPACITY_SCALE;
        __atomic_store_n(&g_cpu_slots[cpu].state, EDGE_CPU_ABSENT,
                         __ATOMIC_RELAXED);
        __atomic_store_n(&g_call_requested[cpu], 0u, __ATOMIC_RELAXED);
        __atomic_store_n(&g_call_completed[cpu], 0u, __ATOMIC_RELAXED);
        __atomic_store_n(&g_call_flags[cpu], 0u, __ATOMIC_RELAXED);
        __atomic_store_n(&g_callback_requested[cpu], 0u,
                         __ATOMIC_RELAXED);
        __atomic_store_n(&g_callback_completed[cpu], 0u,
                         __ATOMIC_RELAXED);
    }
    __atomic_store_n(&g_call_sequence, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&g_callback_function, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&g_callback_argument, 0u, __ATOMIC_RELAXED);
    __atomic_clear(&g_callback_lock, __ATOMIC_RELAXED);
    g_registration_lock = 0;
    g_cpu_slots[0].hardware_id = boot_hardware_id;
    g_cpu_slots[0].firmware_id = boot_firmware_id;
    g_cpu_slots[0].capacity = boot_capacity ? boot_capacity :
                              EDGE_SMP_CAPACITY_SCALE;
    __atomic_store_n(&g_cpu_slots[0].state, EDGE_CPU_ONLINE,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&g_nr_cpu_ids, 1u, __ATOMIC_RELEASE);
}

int edge_smp_find_cpu(uint64_t hardware_id) {
    uint32_t count = __atomic_load_n(&g_nr_cpu_ids, __ATOMIC_ACQUIRE);

    for (uint32_t cpu = 0; cpu < count; ++cpu) {
        if (__atomic_load_n(&g_cpu_slots[cpu].state, __ATOMIC_ACQUIRE) !=
                EDGE_CPU_ABSENT &&
            g_cpu_slots[cpu].hardware_id == hardware_id)
            return (int)cpu;
    }
    return -1;
}

int edge_smp_register_cpu(uint64_t hardware_id, uint32_t firmware_id,
                          uint32_t package_id, uint32_t core_id,
                          uint32_t thread_id, uint32_t numa_node,
                          uint32_t capacity) {
    uint32_t logical_id;
    int existing;

    registration_lock();
    existing = edge_smp_find_cpu(hardware_id);
    if (existing >= 0) {
        registration_unlock();
        return existing;
    }
    logical_id = __atomic_load_n(&g_nr_cpu_ids, __ATOMIC_RELAXED);
    if (logical_id >= EDGE_SMP_MAX_CPUS) {
        registration_unlock();
        return -1;
    }
    g_cpu_slots[logical_id].hardware_id = hardware_id;
    g_cpu_slots[logical_id].firmware_id = firmware_id;
    g_cpu_slots[logical_id].package_id = package_id;
    g_cpu_slots[logical_id].core_id = core_id;
    g_cpu_slots[logical_id].thread_id = thread_id;
    g_cpu_slots[logical_id].numa_node = numa_node;
    g_cpu_slots[logical_id].capacity = capacity ? capacity :
                                       EDGE_SMP_CAPACITY_SCALE;
    __atomic_store_n(&g_cpu_slots[logical_id].state, EDGE_CPU_PRESENT,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&g_nr_cpu_ids, logical_id + 1u, __ATOMIC_RELEASE);
    registration_unlock();
    return (int)logical_id;
}

int edge_smp_get_cpu(uint32_t logical_id, edge_cpu_topology_t *topology) {
    edge_cpu_slot_t *slot;
    uint32_t state;

    if (!topology || logical_id >= edge_smp_nr_cpu_ids()) return -1;
    slot = &g_cpu_slots[logical_id];
    state = __atomic_load_n(&slot->state, __ATOMIC_ACQUIRE);
    if (state == EDGE_CPU_ABSENT) return -1;
    topology->logical_id = logical_id;
    topology->hardware_id = slot->hardware_id;
    topology->firmware_id = slot->firmware_id;
    topology->package_id = slot->package_id;
    topology->core_id = slot->core_id;
    topology->thread_id = slot->thread_id;
    topology->numa_node = slot->numa_node;
    topology->capacity = slot->capacity;
    topology->state = (edge_cpu_state_t)state;
    return 0;
}

static int state_transition_valid(edge_cpu_state_t old_state,
                                  edge_cpu_state_t new_state) {
    if (old_state == new_state) return 1;
    switch (old_state) {
    case EDGE_CPU_PRESENT:
    case EDGE_CPU_OFFLINE:
    case EDGE_CPU_FAILED:
        return new_state == EDGE_CPU_STARTING;
    case EDGE_CPU_STARTING:
        return new_state == EDGE_CPU_ONLINE || new_state == EDGE_CPU_FAILED ||
               new_state == EDGE_CPU_OFFLINE;
    case EDGE_CPU_ONLINE:
        return new_state == EDGE_CPU_DYING;
    case EDGE_CPU_DYING:
        return new_state == EDGE_CPU_OFFLINE || new_state == EDGE_CPU_FAILED;
    default:
        return 0;
    }
}

int edge_smp_set_state(uint32_t logical_id, edge_cpu_state_t state) {
    edge_cpu_slot_t *slot;
    uint32_t observed;

    if (logical_id >= edge_smp_nr_cpu_ids() || state == EDGE_CPU_ABSENT)
        return -1;
    slot = &g_cpu_slots[logical_id];
    observed = __atomic_load_n(&slot->state, __ATOMIC_ACQUIRE);
    for (;;) {
        if (!state_transition_valid((edge_cpu_state_t)observed, state))
            return -1;
        if (observed == (uint32_t)state) return 0;
        if (__atomic_compare_exchange_n(&slot->state, &observed,
                (uint32_t)state, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return 0;
    }
}

edge_cpu_state_t edge_smp_cpu_state(uint32_t logical_id) {
    if (logical_id >= edge_smp_nr_cpu_ids()) return EDGE_CPU_ABSENT;
    return (edge_cpu_state_t)__atomic_load_n(&g_cpu_slots[logical_id].state,
                                             __ATOMIC_ACQUIRE);
}

uint32_t edge_smp_nr_cpu_ids(void) {
    return __atomic_load_n(&g_nr_cpu_ids, __ATOMIC_ACQUIRE);
}

static uint32_t count_state(int online_only) {
    uint32_t count = 0;
    uint32_t nr_cpu_ids = edge_smp_nr_cpu_ids();

    for (uint32_t cpu = 0; cpu < nr_cpu_ids; ++cpu) {
        edge_cpu_state_t state = edge_smp_cpu_state(cpu);

        if (online_only ? state == EDGE_CPU_ONLINE : state != EDGE_CPU_ABSENT)
            ++count;
    }
    return count;
}

uint32_t edge_smp_present_count(void) {
    return count_state(0);
}

uint32_t edge_smp_online_count(void) {
    return count_state(1);
}

static void mask_for_state(edge_cpumask_t *mask, int online_only) {
    uint32_t nr_cpu_ids = edge_smp_nr_cpu_ids();

    if (!mask) return;
    edge_cpumask_init(mask, nr_cpu_ids);
    for (uint32_t cpu = 0; cpu < nr_cpu_ids; ++cpu) {
        edge_cpu_state_t state = edge_smp_cpu_state(cpu);

        if (online_only ? state == EDGE_CPU_ONLINE : state != EDGE_CPU_ABSENT)
            (void)edge_cpumask_set_cpu(mask, cpu);
    }
}

void edge_smp_present_mask(edge_cpumask_t *mask) {
    mask_for_state(mask, 0);
}

void edge_smp_online_mask(edge_cpumask_t *mask) {
    mask_for_state(mask, 1);
}

void edge_smp_sibling_mask(uint32_t logical_id, edge_cpumask_t *mask) {
    edge_cpu_topology_t source;
    uint32_t nr_cpu_ids = edge_smp_nr_cpu_ids();

    if (!mask) return;
    edge_cpumask_init(mask, nr_cpu_ids);
    if (edge_smp_get_cpu(logical_id, &source) != 0) return;
    for (uint32_t cpu = 0; cpu < nr_cpu_ids; ++cpu) {
        edge_cpu_topology_t candidate;

        if (edge_smp_get_cpu(cpu, &candidate) == 0 &&
            candidate.package_id == source.package_id &&
            candidate.core_id == source.core_id)
            (void)edge_cpumask_set_cpu(mask, cpu);
    }
}

uint64_t edge_smp_online_mask64(void) {
    edge_cpumask_t mask;

    edge_smp_online_mask(&mask);
    return mask.nwords ? mask.bits[0] : 0;
}

uint32_t edge_smp_current_cpu(void) {
    return arch_smp_current_cpu();
}

__attribute__((weak)) int arch_smp_send_reschedule(uint32_t logical_id) {
    (void)logical_id;
    return -1;
}

int edge_smp_reschedule(uint32_t logical_id) {
    if (edge_smp_cpu_state(logical_id) != EDGE_CPU_ONLINE) return -1;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    return arch_smp_send_reschedule(logical_id);
}

__attribute__((weak)) int arch_smp_send_vmm_kick(uint32_t logical_id) {
    (void)logical_id;
    return -1;
}

int edge_smp_vmm_kick(uint32_t logical_id) {
    if (edge_smp_cpu_state(logical_id) != EDGE_CPU_ONLINE) return -1;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    return arch_smp_send_vmm_kick(logical_id);
}

__attribute__((weak)) uint32_t arch_smp_current_cpu(void) {
    return 0u;
}

__attribute__((weak)) int arch_smp_calls_available(void) {
    return edge_smp_online_count() <= 1u;
}

__attribute__((weak)) int arch_smp_send_call(uint32_t logical_id) {
    (void)logical_id;
    return -1;
}

__attribute__((weak)) void arch_smp_execute_call(uint32_t flags) {
    (void)flags;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

__attribute__((weak)) void arch_smp_call_relax(void) {
    __asm__ __volatile__("" ::: "memory");
}

int edge_smp_calls_available(void) {
    return arch_smp_calls_available();
}

static void publish_call_sequence(uint32_t logical_id, uint64_t sequence) {
    uint64_t observed = __atomic_load_n(&g_call_requested[logical_id],
                                         __ATOMIC_RELAXED);

    while (observed < sequence &&
           !__atomic_compare_exchange_n(&g_call_requested[logical_id],
               &observed, sequence, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED))
        ;
}

void edge_smp_handle_call(uint32_t logical_id) {
    uint64_t requested;
    uint64_t completed;
    uint64_t callback_requested;
    uint64_t callback_completed;
    uint32_t flags;

    if (logical_id >= edge_smp_nr_cpu_ids()) return;
    requested = __atomic_load_n(&g_call_requested[logical_id],
                                __ATOMIC_ACQUIRE);
    completed = __atomic_load_n(&g_call_completed[logical_id],
                                __ATOMIC_RELAXED);
    if (requested <= completed) return;
    /*
     * Flags are cumulative so concurrent publishers cannot consume each
     * other's operation.  Executing a stronger operation on later calls is
     * safe and keeps the interrupt path free of allocation and global locks.
     */
    flags = __atomic_load_n(&g_call_flags[logical_id], __ATOMIC_ACQUIRE);
    arch_smp_execute_call(flags);
    callback_requested = __atomic_load_n(&g_callback_requested[logical_id],
                                         __ATOMIC_ACQUIRE);
    callback_completed = __atomic_load_n(&g_callback_completed[logical_id],
                                         __ATOMIC_RELAXED);
    if (callback_requested > callback_completed) {
        edge_smp_callback_t callback = (edge_smp_callback_t)(uintptr_t)
            __atomic_load_n(&g_callback_function, __ATOMIC_ACQUIRE);
        void *argument = (void *)(uintptr_t)
            __atomic_load_n(&g_callback_argument, __ATOMIC_ACQUIRE);

        if (callback)
            callback(argument);
        __atomic_store_n(&g_callback_completed[logical_id],
                         callback_requested, __ATOMIC_RELEASE);
    }
    __atomic_store_n(&g_call_completed[logical_id], requested,
                     __ATOMIC_RELEASE);
}

void spinlock_contention_relax(void) {
    /*
     * A syscall can wait for a lock while local interrupts are masked.  The
     * lock owner may simultaneously wait for this CPU to complete a TLB or
     * membarrier call.  Service the bounded per-CPU request while waiting so
     * those two dependencies cannot form a cycle.
     */
    edge_smp_handle_call(arch_smp_current_cpu());
    arch_smp_call_relax();
}

int edge_smp_call(const edge_cpumask_t *mask, uint32_t flags) {
    edge_cpumask_t targets;
    edge_cpumask_t online;
    edge_cpumask_t sent;
    uint64_t sequence;
    uint32_t current;
    uint32_t cpu = UINT32_MAX;
    int failed = 0;

    if (!mask || !flags || (flags & ~EDGE_SMP_CALL_VALID_FLAGS)) return -1;
    edge_smp_online_mask(&online);
    edge_cpumask_and(&targets, mask, &online);
    edge_cpumask_init(&sent, targets.nbits);
    if (!edge_cpumask_weight(&targets)) return 0;
    if (edge_smp_online_count() > 1u && !edge_smp_calls_available())
        return -1;

    sequence = __atomic_add_fetch(&g_call_sequence, 1u, __ATOMIC_RELAXED);
    if (!sequence)
        sequence = __atomic_add_fetch(&g_call_sequence, 1u,
                                      __ATOMIC_RELAXED);
    current = arch_smp_current_cpu();
    while ((cpu = edge_cpumask_next(&targets, cpu)) < targets.nbits) {
        if (cpu == current) {
            arch_smp_execute_call(flags);
            continue;
        }
        (void)__atomic_fetch_or(&g_call_flags[cpu], flags, __ATOMIC_RELEASE);
        publish_call_sequence(cpu, sequence);
        if (arch_smp_send_call(cpu) == 0)
            (void)edge_cpumask_set_cpu(&sent, cpu);
        else
            failed = 1;
    }

    cpu = UINT32_MAX;
    while ((cpu = edge_cpumask_next(&sent, cpu)) < sent.nbits) {
        uint32_t spins = 0;

        while (__atomic_load_n(&g_call_completed[cpu], __ATOMIC_ACQUIRE) <
               sequence) {
            /*
             * EdgeOS currently enters native syscalls with local interrupts
             * masked.  Two CPUs may therefore issue membarrier concurrently
             * and wait for each other's call interrupt.  Service this CPU's
             * pending request cooperatively while waiting so the protocol
             * remains live without weakening syscall-entry interrupt rules.
             */
            edge_smp_handle_call(current);
            if (++spins == 100000000u) {
                failed = 1;
                break;
            }
            arch_smp_call_relax();
        }
    }
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    return failed ? -1 : 0;
}

int edge_smp_rendezvous(const edge_cpumask_t *mask,
                        edge_smp_callback_t callback, void *argument) {
    edge_cpumask_t targets;
    edge_cpumask_t online;
    edge_cpumask_t sent;
    uint64_t sequence;
    uint32_t current;
    uint32_t cpu = UINT32_MAX;
    int failed = 0;

    if (!mask || !callback)
        return -1;
    edge_smp_online_mask(&online);
    edge_cpumask_and(&targets, mask, &online);
    edge_cpumask_init(&sent, targets.nbits);
    if (!edge_cpumask_weight(&targets))
        return 0;
    if (edge_smp_online_count() > 1u && !edge_smp_calls_available())
        return -1;

    current = arch_smp_current_cpu();
    while (__atomic_test_and_set(&g_callback_lock, __ATOMIC_ACQUIRE)) {
        edge_smp_handle_call(current);
        arch_smp_call_relax();
    }
    __atomic_store_n(&g_callback_argument, (uintptr_t)argument,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&g_callback_function, (uintptr_t)callback,
                     __ATOMIC_RELEASE);
    sequence = __atomic_add_fetch(&g_call_sequence, 1u, __ATOMIC_RELAXED);
    if (!sequence)
        sequence = __atomic_add_fetch(&g_call_sequence, 1u,
                                      __ATOMIC_RELAXED);

    while ((cpu = edge_cpumask_next(&targets, cpu)) < targets.nbits) {
        if (cpu == current) {
            callback(argument);
            continue;
        }
        __atomic_store_n(&g_callback_requested[cpu], sequence,
                         __ATOMIC_RELEASE);
        publish_call_sequence(cpu, sequence);
        if (arch_smp_send_call(cpu) == 0)
            (void)edge_cpumask_set_cpu(&sent, cpu);
        else
            failed = 1;
    }

    cpu = UINT32_MAX;
    while ((cpu = edge_cpumask_next(&sent, cpu)) < sent.nbits) {
        uint32_t spins = 0;

        while (__atomic_load_n(&g_callback_completed[cpu],
                               __ATOMIC_ACQUIRE) < sequence) {
            edge_smp_handle_call(current);
            if (++spins == 100000000u) {
                failed = 1;
                break;
            }
            arch_smp_call_relax();
        }
    }
    __atomic_store_n(&g_callback_function, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&g_callback_argument, 0u, __ATOMIC_RELAXED);
    __atomic_clear(&g_callback_lock, __ATOMIC_RELEASE);
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    return failed ? -1 : 0;
}
