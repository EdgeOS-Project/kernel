/* SPDX-License-Identifier: MPL-2.0 */
/* Shared atomics for the EdgeOS FreeBSD driver bridge. */

#ifndef _MACHINE_ATOMIC_H_
#define _MACHINE_ATOMIC_H_

#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
#define EDGE_BSD_BARRIER_STRINGIFY_INNER(option) #option
#define EDGE_BSD_BARRIER_STRINGIFY(option) \
    EDGE_BSD_BARRIER_STRINGIFY_INNER(option)
#define isb() __asm __volatile("isb" : : : "memory")
#define dsb(option) \
    __asm __volatile("dsb " EDGE_BSD_BARRIER_STRINGIFY(option) : : : "memory")
#define dmb(option) \
    __asm __volatile("dmb " EDGE_BSD_BARRIER_STRINGIFY(option) : : : "memory")
#define mb() dmb(sy)
#define wmb() dmb(st)
#define rmb() dmb(ld)
#elif defined(__x86_64__)
#define mb() __asm __volatile("mfence" : : : "memory")
#define wmb() __asm __volatile("sfence" : : : "memory")
#define rmb() __asm __volatile("lfence" : : : "memory")
#else
#error "Unsupported EdgeOS FreeBSD driver bridge architecture"
#endif

#include <sys/types.h>

#define atomic_load_bool(value) \
    __atomic_load_n((const volatile _Bool *)(value), __ATOMIC_RELAXED)
#define atomic_store_bool(value, replacement) \
    __atomic_store_n((volatile _Bool *)(value), (_Bool)(replacement), \
        __ATOMIC_RELAXED)
#define atomic_load_char(value) \
    __atomic_load_n((const volatile u_char *)(value), __ATOMIC_RELAXED)
#define atomic_load_short(value) \
    __atomic_load_n((const volatile u_short *)(value), __ATOMIC_RELAXED)
#define atomic_load_int(value) \
    __atomic_load_n((const volatile u_int *)(value), __ATOMIC_RELAXED)
#define atomic_load_long(value) \
    __atomic_load_n((const volatile u_long *)(value), __ATOMIC_RELAXED)
#define atomic_load_8(value) atomic_load_char(value)
#define atomic_load_16(value) atomic_load_short(value)
#define atomic_load_32(value) atomic_load_int(value)
#define atomic_load_64(value) \
    __atomic_load_n((const volatile uint64_t *)(value), __ATOMIC_RELAXED)

#define atomic_store_char(value, replacement) \
    __atomic_store_n((volatile u_char *)(value), (u_char)(replacement), \
        __ATOMIC_RELAXED)
#define atomic_store_short(value, replacement) \
    __atomic_store_n((volatile u_short *)(value), (u_short)(replacement), \
        __ATOMIC_RELAXED)
#define atomic_store_int(value, replacement) \
    __atomic_store_n((volatile u_int *)(value), (u_int)(replacement), \
        __ATOMIC_RELAXED)
#define atomic_store_long(value, replacement) \
    __atomic_store_n((volatile u_long *)(value), (u_long)(replacement), \
        __ATOMIC_RELAXED)
#define atomic_store_8(value, replacement) \
    atomic_store_char((value), (replacement))
#define atomic_store_16(value, replacement) \
    atomic_store_short((value), (replacement))
#define atomic_store_32(value, replacement) \
    atomic_store_int((value), (replacement))
#define atomic_store_64(value, replacement) \
    __atomic_store_n((volatile uint64_t *)(value), \
        (uint64_t)(replacement), __ATOMIC_RELAXED)

#define atomic_load_ptr(value) \
    __atomic_load_n((value), __ATOMIC_RELAXED)
#define atomic_store_ptr(value, replacement) \
    __atomic_store_n((value), (replacement), __ATOMIC_RELAXED)
#define atomic_interrupt_fence() \
    __asm __volatile(" " : : : "memory")

#define EDGE_BSD_ATOMIC_OPERATIONS(name, type)                            \
static __inline void                                                      \
atomic_set_##name(volatile type *value, type bits)                        \
{                                                                         \
    (void)__atomic_fetch_or(value, bits, __ATOMIC_RELAXED);               \
}                                                                         \
                                                                          \
static __inline void                                                      \
atomic_clear_##name(volatile type *value, type bits)                      \
{                                                                         \
    (void)__atomic_fetch_and(value, (type)~bits, __ATOMIC_RELAXED);       \
}                                                                         \
                                                                          \
static __inline void                                                      \
atomic_add_##name(volatile type *value, type increment)                   \
{                                                                         \
    (void)__atomic_fetch_add(value, increment, __ATOMIC_RELAXED);         \
}                                                                         \
                                                                          \
static __inline void                                                      \
atomic_subtract_##name(volatile type *value, type decrement)              \
{                                                                         \
    (void)__atomic_fetch_sub(value, decrement, __ATOMIC_RELAXED);         \
}                                                                         \
                                                                          \
static __inline type                                                      \
atomic_load_acq_##name(const volatile type *value)                        \
{                                                                         \
    return __atomic_load_n(value, __ATOMIC_ACQUIRE);                      \
}                                                                         \
                                                                          \
static __inline void                                                      \
atomic_store_rel_##name(volatile type *value, type replacement)           \
{                                                                         \
    __atomic_store_n(value, replacement, __ATOMIC_RELEASE);               \
}                                                                         \
                                                                          \
static __inline int                                                       \
atomic_cmpset_##name(volatile type *value, type expected, type desired)    \
{                                                                         \
    return __atomic_compare_exchange_n(value, &expected, desired, 0,      \
        __ATOMIC_RELAXED, __ATOMIC_RELAXED);                              \
}                                                                         \
                                                                          \
static __inline int                                                       \
atomic_cmpset_acq_##name(volatile type *value, type expected,             \
    type desired)                                                         \
{                                                                         \
    return __atomic_compare_exchange_n(value, &expected, desired, 0,      \
        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);                              \
}                                                                         \
                                                                          \
static __inline int                                                       \
atomic_cmpset_rel_##name(volatile type *value, type expected,             \
    type desired)                                                         \
{                                                                         \
    return __atomic_compare_exchange_n(value, &expected, desired, 0,      \
        __ATOMIC_RELEASE, __ATOMIC_RELAXED);                              \
}                                                                         \
                                                                          \
static __inline int                                                       \
atomic_fcmpset_##name(volatile type *value, type *expected, type desired)  \
{                                                                         \
    return __atomic_compare_exchange_n(value, expected, desired, 1,       \
        __ATOMIC_RELAXED, __ATOMIC_RELAXED);                              \
}                                                                         \
                                                                          \
static __inline int                                                       \
atomic_fcmpset_acq_##name(volatile type *value, type *expected,           \
    type desired)                                                         \
{                                                                         \
    return __atomic_compare_exchange_n(value, expected, desired, 1,       \
        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);                              \
}                                                                         \
                                                                          \
static __inline int                                                       \
atomic_fcmpset_rel_##name(volatile type *value, type *expected,           \
    type desired)                                                         \
{                                                                         \
    return __atomic_compare_exchange_n(value, expected, desired, 1,       \
        __ATOMIC_RELEASE, __ATOMIC_RELAXED);                              \
}                                                                         \
                                                                          \
static __inline void                                                      \
atomic_set_acq_##name(volatile type *value, type bits)                    \
{                                                                         \
    (void)__atomic_fetch_or(value, bits, __ATOMIC_ACQUIRE);               \
}                                                                         \
                                                                          \
static __inline void                                                      \
atomic_set_rel_##name(volatile type *value, type bits)                    \
{                                                                         \
    (void)__atomic_fetch_or(value, bits, __ATOMIC_RELEASE);               \
}                                                                         \
                                                                          \
static __inline void                                                      \
atomic_clear_acq_##name(volatile type *value, type bits)                  \
{                                                                         \
    (void)__atomic_fetch_and(value, (type)~bits, __ATOMIC_ACQUIRE);       \
}                                                                         \
                                                                          \
static __inline void                                                      \
atomic_clear_rel_##name(volatile type *value, type bits)                  \
{                                                                         \
    (void)__atomic_fetch_and(value, (type)~bits, __ATOMIC_RELEASE);       \
}                                                                         \
                                                                          \
static __inline void                                                      \
atomic_add_acq_##name(volatile type *value, type increment)               \
{                                                                         \
    (void)__atomic_fetch_add(value, increment, __ATOMIC_ACQUIRE);         \
}                                                                         \
                                                                          \
static __inline void                                                      \
atomic_add_rel_##name(volatile type *value, type increment)               \
{                                                                         \
    (void)__atomic_fetch_add(value, increment, __ATOMIC_RELEASE);         \
}                                                                         \
                                                                          \
static __inline void                                                      \
atomic_subtract_acq_##name(volatile type *value, type decrement)          \
{                                                                         \
    (void)__atomic_fetch_sub(value, decrement, __ATOMIC_ACQUIRE);         \
}                                                                         \
                                                                          \
static __inline void                                                      \
atomic_subtract_rel_##name(volatile type *value, type decrement)          \
{                                                                         \
    (void)__atomic_fetch_sub(value, decrement, __ATOMIC_RELEASE);         \
}

EDGE_BSD_ATOMIC_OPERATIONS(char, u_char)
EDGE_BSD_ATOMIC_OPERATIONS(short, u_short)
EDGE_BSD_ATOMIC_OPERATIONS(int, u_int)
EDGE_BSD_ATOMIC_OPERATIONS(long, u_long)
EDGE_BSD_ATOMIC_OPERATIONS(64, uint64_t)
EDGE_BSD_ATOMIC_OPERATIONS(ptr, uintptr_t)

#undef EDGE_BSD_ATOMIC_OPERATIONS

static __inline u_int
atomic_fetchadd_int(volatile u_int *value, u_int increment)
{
    return __atomic_fetch_add(value, increment, __ATOMIC_RELAXED);
}

static __inline u_long
atomic_fetchadd_long(volatile u_long *value, u_long increment)
{
    return __atomic_fetch_add(value, increment, __ATOMIC_RELAXED);
}

static __inline uint64_t
atomic_fetchadd_64(volatile uint64_t *value, uint64_t increment)
{
    return __atomic_fetch_add(value, increment, __ATOMIC_RELAXED);
}

static __inline uintptr_t
atomic_fetchadd_ptr(volatile uintptr_t *value, uintptr_t increment)
{
    return __atomic_fetch_add(value, increment, __ATOMIC_RELAXED);
}

static __inline u_int
atomic_swap_int(volatile u_int *value, u_int replacement)
{
    return __atomic_exchange_n(value, replacement, __ATOMIC_RELAXED);
}

static __inline u_long
atomic_swap_long(volatile u_long *value, u_long replacement)
{
    return __atomic_exchange_n(value, replacement, __ATOMIC_RELAXED);
}

static __inline uint64_t
atomic_swap_64(volatile uint64_t *value, uint64_t replacement)
{
    return __atomic_exchange_n(value, replacement, __ATOMIC_RELAXED);
}

static __inline uintptr_t
atomic_swap_ptr(volatile uintptr_t *value, uintptr_t replacement)
{
    return __atomic_exchange_n(value, replacement, __ATOMIC_RELAXED);
}

static __inline int
atomic_testandset_int(volatile u_int *value, u_int bit)
{
    u_int mask = (u_int)1 << (bit & 31);
    return (__atomic_fetch_or(value, mask, __ATOMIC_RELAXED) & mask) != 0;
}

#define atomic_testandset_32 atomic_testandset_int
#define atomic_testandclear_32 atomic_testandclear_int

static __inline int
atomic_testandset_long(volatile u_long *value, u_int bit)
{
    u_long mask = (u_long)1 << (bit & 63);
    return (__atomic_fetch_or(value, mask, __ATOMIC_RELAXED) & mask) != 0;
}

static __inline int
atomic_testandclear_int(volatile u_int *value, u_int bit)
{
    u_int mask = (u_int)1 << (bit & 31);
    return (__atomic_fetch_and(value, ~mask, __ATOMIC_RELAXED) & mask) != 0;
}

static __inline int
atomic_testandclear_long(volatile u_long *value, u_int bit)
{
    u_long mask = (u_long)1 << (bit & 63);
    return (__atomic_fetch_and(value, ~mask, __ATOMIC_RELAXED) & mask) != 0;
}

static __inline void
atomic_thread_fence_acq(void)
{
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
}

static __inline void
atomic_thread_fence_rel(void)
{
    __atomic_thread_fence(__ATOMIC_RELEASE);
}

static __inline void
atomic_thread_fence_acq_rel(void)
{
    __atomic_thread_fence(__ATOMIC_ACQ_REL);
}

static __inline void
atomic_thread_fence_seq_cst(void)
{
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

#define atomic_readandclear_int(value) atomic_swap_int((value), 0)
#define atomic_readandclear_long(value) atomic_swap_long((value), 0)
#define atomic_readandclear_64(value) atomic_swap_64((value), 0)
#define atomic_readandclear_ptr(value) atomic_swap_ptr((value), 0)

#define atomic_set_8 atomic_set_char
#define atomic_set_acq_8 atomic_set_acq_char
#define atomic_set_rel_8 atomic_set_rel_char
#define atomic_clear_8 atomic_clear_char
#define atomic_clear_acq_8 atomic_clear_acq_char
#define atomic_clear_rel_8 atomic_clear_rel_char
#define atomic_add_8 atomic_add_char
#define atomic_add_acq_8 atomic_add_acq_char
#define atomic_add_rel_8 atomic_add_rel_char
#define atomic_subtract_8 atomic_subtract_char
#define atomic_subtract_acq_8 atomic_subtract_acq_char
#define atomic_subtract_rel_8 atomic_subtract_rel_char
#define atomic_load_acq_8 atomic_load_acq_char
#define atomic_store_rel_8 atomic_store_rel_char
#define atomic_cmpset_8 atomic_cmpset_char
#define atomic_cmpset_acq_8 atomic_cmpset_acq_char
#define atomic_cmpset_rel_8 atomic_cmpset_rel_char
#define atomic_fcmpset_8 atomic_fcmpset_char
#define atomic_fcmpset_acq_8 atomic_fcmpset_acq_char
#define atomic_fcmpset_rel_8 atomic_fcmpset_rel_char

#define atomic_set_16 atomic_set_short
#define atomic_set_acq_16 atomic_set_acq_short
#define atomic_set_rel_16 atomic_set_rel_short
#define atomic_clear_16 atomic_clear_short
#define atomic_clear_acq_16 atomic_clear_acq_short
#define atomic_clear_rel_16 atomic_clear_rel_short
#define atomic_add_16 atomic_add_short
#define atomic_add_acq_16 atomic_add_acq_short
#define atomic_add_rel_16 atomic_add_rel_short
#define atomic_subtract_16 atomic_subtract_short
#define atomic_subtract_acq_16 atomic_subtract_acq_short
#define atomic_subtract_rel_16 atomic_subtract_rel_short
#define atomic_load_acq_16 atomic_load_acq_short
#define atomic_store_rel_16 atomic_store_rel_short
#define atomic_cmpset_16 atomic_cmpset_short
#define atomic_cmpset_acq_16 atomic_cmpset_acq_short
#define atomic_cmpset_rel_16 atomic_cmpset_rel_short
#define atomic_fcmpset_16 atomic_fcmpset_short
#define atomic_fcmpset_acq_16 atomic_fcmpset_acq_short
#define atomic_fcmpset_rel_16 atomic_fcmpset_rel_short

#define atomic_set_32 atomic_set_int
#define atomic_set_acq_32 atomic_set_acq_int
#define atomic_set_rel_32 atomic_set_rel_int
#define atomic_clear_32 atomic_clear_int
#define atomic_clear_acq_32 atomic_clear_acq_int
#define atomic_clear_rel_32 atomic_clear_rel_int
#define atomic_add_32 atomic_add_int
#define atomic_add_acq_32 atomic_add_acq_int
#define atomic_add_rel_32 atomic_add_rel_int
#define atomic_subtract_32 atomic_subtract_int
#define atomic_subtract_acq_32 atomic_subtract_acq_int
#define atomic_subtract_rel_32 atomic_subtract_rel_int
#define atomic_load_acq_32 atomic_load_acq_int
#define atomic_store_rel_32 atomic_store_rel_int
#define atomic_cmpset_32 atomic_cmpset_int
#define atomic_cmpset_acq_32 atomic_cmpset_acq_int
#define atomic_cmpset_rel_32 atomic_cmpset_rel_int
#define atomic_fcmpset_32 atomic_fcmpset_int
#define atomic_fcmpset_acq_32 atomic_fcmpset_acq_int
#define atomic_fcmpset_rel_32 atomic_fcmpset_rel_int
#define atomic_swap_32 atomic_swap_int
#define atomic_readandclear_32 atomic_readandclear_int
#define atomic_fetchadd_32 atomic_fetchadd_int

#define atomic_load_consume_ptr(value) \
    ((__typeof(*(value)))atomic_load_acq_ptr( \
        (const volatile uintptr_t *)(value)))

#endif
