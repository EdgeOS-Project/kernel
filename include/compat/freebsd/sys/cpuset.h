/* SPDX-License-Identifier: BSD-2-Clause */
/* Compact CPU-set operations for the shared EdgeOS driver runtime. */

#ifndef _SYS_CPUSET_H_
#define _SYS_CPUSET_H_

#include <stdint.h>
#if defined(BSD_BRIDGE_HOST_TEST)
typedef struct _cpuset {
    unsigned long __bits[1];
} cpuset_t;
#else
#include <sys/_cpuset.h>
#endif
#if !defined(BSD_BRIDGE_HOST_TEST)
#include <sys/bitset.h>
#endif

#define BSD_CPUSET_WORD_BITS ((unsigned int)(sizeof(unsigned long) * 8u))
#define BSD_CPUSET_WORDS \
    ((unsigned int)(sizeof(cpuset_t) / sizeof(unsigned long)))

static inline void
bsd_cpuset_zero(volatile cpuset_t *set)
{
    unsigned int index;

    for (index = 0; index < BSD_CPUSET_WORDS; ++index)
        set->__bits[index] = 0;
}

static inline void
bsd_cpuset_fill(volatile cpuset_t *set)
{
    unsigned int index;

    for (index = 0; index < BSD_CPUSET_WORDS; ++index)
        set->__bits[index] = ~0ul;
}

static inline void
bsd_cpuset_set(unsigned int cpu, volatile cpuset_t *set)
{
    if (cpu < sizeof(*set) * 8u)
        set->__bits[cpu / BSD_CPUSET_WORD_BITS] |=
            1ul << (cpu % BSD_CPUSET_WORD_BITS);
}

static inline void
bsd_cpuset_set_atomic(unsigned int cpu, volatile cpuset_t *set)
{
    if (cpu < sizeof(*set) * 8u)
        (void)__atomic_fetch_or(
            &set->__bits[cpu / BSD_CPUSET_WORD_BITS],
            1ul << (cpu % BSD_CPUSET_WORD_BITS), __ATOMIC_RELAXED);
}

static inline void
bsd_cpuset_clear(unsigned int cpu, volatile cpuset_t *set)
{
    if (cpu < sizeof(*set) * 8u)
        set->__bits[cpu / BSD_CPUSET_WORD_BITS] &=
            ~(1ul << (cpu % BSD_CPUSET_WORD_BITS));
}

static inline void
bsd_cpuset_clear_atomic(unsigned int cpu, volatile cpuset_t *set)
{
    if (cpu < sizeof(*set) * 8u)
        (void)__atomic_fetch_and(
            &set->__bits[cpu / BSD_CPUSET_WORD_BITS],
            ~(1ul << (cpu % BSD_CPUSET_WORD_BITS)), __ATOMIC_RELAXED);
}

static inline int
bsd_cpuset_isset(unsigned int cpu, const volatile cpuset_t *set)
{
    if (cpu >= sizeof(*set) * 8u)
        return 0;
    return ((set->__bits[cpu / BSD_CPUSET_WORD_BITS] &
        (1ul << (cpu % BSD_CPUSET_WORD_BITS))) != 0);
}

static inline void
bsd_cpuset_copy(const volatile cpuset_t *source,
    volatile cpuset_t *destination)
{
    unsigned int index;

    for (index = 0; index < BSD_CPUSET_WORDS; ++index)
        destination->__bits[index] = source->__bits[index];
}

static inline void
bsd_cpuset_and(volatile cpuset_t *destination,
    const volatile cpuset_t *left, const volatile cpuset_t *right)
{
    unsigned int index;

    for (index = 0; index < BSD_CPUSET_WORDS; ++index)
        destination->__bits[index] =
            left->__bits[index] & right->__bits[index];
}

static inline void
bsd_cpuset_or(volatile cpuset_t *destination,
    const volatile cpuset_t *left, const volatile cpuset_t *right)
{
    unsigned int index;

    for (index = 0; index < BSD_CPUSET_WORDS; ++index)
        destination->__bits[index] =
            left->__bits[index] | right->__bits[index];
}

static inline void
bsd_cpuset_xor(volatile cpuset_t *destination,
    const volatile cpuset_t *left, const volatile cpuset_t *right)
{
    unsigned int index;

    for (index = 0; index < BSD_CPUSET_WORDS; ++index)
        destination->__bits[index] =
            left->__bits[index] ^ right->__bits[index];
}

static inline void
bsd_cpuset_andnot(volatile cpuset_t *destination,
    const volatile cpuset_t *left, const volatile cpuset_t *right)
{
    unsigned int index;

    for (index = 0; index < BSD_CPUSET_WORDS; ++index)
        destination->__bits[index] =
            left->__bits[index] & ~right->__bits[index];
}

static inline int
bsd_cpuset_compare(const volatile cpuset_t *left,
    const volatile cpuset_t *right)
{
    unsigned int index;

    for (index = 0; index < BSD_CPUSET_WORDS; ++index) {
        if (left->__bits[index] != right->__bits[index])
            return 1;
    }
    return 0;
}

static inline int
bsd_cpuset_empty(const volatile cpuset_t *set)
{
    unsigned int index;

    for (index = 0; index < BSD_CPUSET_WORDS; ++index) {
        if (set->__bits[index] != 0)
            return 0;
    }
    return 1;
}

static inline int
bsd_cpuset_count(const volatile cpuset_t *set)
{
    unsigned int index;
    int count = 0;

    for (index = 0; index < BSD_CPUSET_WORDS; ++index)
        count += __builtin_popcountl(set->__bits[index]);
    return count;
}

static inline int
bsd_cpuset_ffs(const volatile cpuset_t *set)
{
    unsigned int index;

    for (index = 0; index < BSD_CPUSET_WORDS; ++index) {
        if (set->__bits[index] != 0)
            return (int)(index * BSD_CPUSET_WORD_BITS +
                (unsigned int)__builtin_ctzl(set->__bits[index]) + 1u);
    }
    return 0;
}

static inline int
bsd_cpuset_fls(const volatile cpuset_t *set)
{
    unsigned int index = BSD_CPUSET_WORDS;

    while (index != 0) {
        unsigned long word = set->__bits[--index];

        if (word != 0)
            return (int)((index + 1u) * BSD_CPUSET_WORD_BITS -
                (unsigned int)__builtin_clzl(word));
    }
    return 0;
}

static inline uint64_t
bsd_cpuset_low64(const volatile cpuset_t *set)
{
    return (uint64_t)set->__bits[0];
}

#define CPU_ZERO(set) bsd_cpuset_zero((set))
#define CPU_FILL(set) bsd_cpuset_fill((set))
#define CPU_SET(cpu, set) bsd_cpuset_set((unsigned int)(cpu), (set))
#define CPU_CLR(cpu, set) bsd_cpuset_clear((unsigned int)(cpu), (set))
#define CPU_SET_ATOMIC(cpu, set) \
    bsd_cpuset_set_atomic((unsigned int)(cpu), (set))
#define CPU_CLR_ATOMIC(cpu, set) \
    bsd_cpuset_clear_atomic((unsigned int)(cpu), (set))
#define CPU_ISSET(cpu, set) \
    bsd_cpuset_isset((unsigned int)(cpu), (set))
#define CPU_COPY(source, destination) \
    bsd_cpuset_copy((source), (destination))
#define CPU_AND(destination, left, right) \
    bsd_cpuset_and((destination), (left), (right))
#define CPU_OR(destination, left, right) \
    bsd_cpuset_or((destination), (left), (right))
#define CPU_XOR(destination, left, right) \
    bsd_cpuset_xor((destination), (left), (right))
#define CPU_ANDNOT(destination, left, right) \
    bsd_cpuset_andnot((destination), (left), (right))
#define CPU_CMP(left, right) bsd_cpuset_compare((left), (right))
#define CPU_EQUAL(left, right) (CPU_CMP((left), (right)) == 0)
#define CPU_EMPTY(set) bsd_cpuset_empty((set))
#define CPU_COUNT(set) bsd_cpuset_count((set))
#define CPU_FFS(set) bsd_cpuset_ffs((set))
#define CPU_FLS(set) bsd_cpuset_fls((set))
#define CPU_FOREACH_ISSET(cpu, set) \
    for ((cpu) = 0; (cpu) < CPU_SETSIZE; ++(cpu)) \
        if (CPU_ISSET((cpu), (set)))
#define CPU_FOREACH_ISCLR(cpu, set) \
    for ((cpu) = 0; (cpu) < CPU_SETSIZE; ++(cpu)) \
        if (!CPU_ISSET((cpu), (set)))
#define CPU_SETOF(cpu, set) do {                                        \
    CPU_ZERO(set);                                                      \
    CPU_SET((cpu), (set));                                              \
} while (0)

#endif
