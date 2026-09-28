#ifndef SYS_SPINLOCK_H
#define SYS_SPINLOCK_H

#include <stdint.h>

typedef struct {
    volatile uint32_t v;
} spinlock_t;

/* The kernel supplies this hook; standalone host tests may leave it absent. */
#if defined(__aarch64__)
extern void spinlock_contention_relax(const volatile uint32_t *value);
#else
extern void spinlock_contention_relax(const volatile uint32_t *value)
    __attribute__((weak));
#endif

static inline void spinlock_init(spinlock_t *l) {
    if (!l) return;
    l->v = 0;
}

static inline void spinlock_relax_value(const volatile uint32_t *value) {
#if defined(EDGEOS_HOST_TEST) || \
    (defined(__STDC_HOSTED__) && __STDC_HOSTED__ == 1)
    (void)value;
    __asm__ __volatile__("" ::: "memory");
#elif defined(__aarch64__)
    spinlock_contention_relax(value);
#else
    (void)value;
    if (spinlock_contention_relax) {
        spinlock_contention_relax(value);
        return;
    }
#if defined(__x86_64__)
    __asm__ __volatile__("pause" ::: "memory");
#endif
#endif
}

static inline void spinlock_relax(void) {
    spinlock_relax_value(0);
}

static inline uint64_t spin_lock_irqsave(spinlock_t *l) {
    uint64_t flags = 0;
#if defined(EDGEOS_HOST_TEST)
    (void)flags;
#elif defined(__x86_64__)
    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
#elif defined(__aarch64__)
    __asm__ __volatile__("mrs %0, daif; msr daifset, #0xf" : "=r"(flags) :: "memory");
#else
#error "spin_lock_irqsave needs an architecture implementation"
#endif
    while (__sync_lock_test_and_set(&l->v, 1)) {
        while (l->v) {
            spinlock_relax_value(&l->v);
        }
    }
    return flags;
}

static inline int spin_trylock_irqsave(spinlock_t *l, uint64_t *flags_out) {
    uint64_t flags = 0;
#if defined(EDGEOS_HOST_TEST)
    (void)flags;
#elif defined(__x86_64__)
    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
#elif defined(__aarch64__)
    __asm__ __volatile__("mrs %0, daif; msr daifset, #0xf" : "=r"(flags) :: "memory");
#else
#error "spin_trylock_irqsave needs an architecture implementation"
#endif
    if (__sync_lock_test_and_set(&l->v, 1)) {
#if defined(EDGEOS_HOST_TEST)
        (void)flags;
#elif defined(__x86_64__)
        if (flags & (1ULL << 9)) __asm__ __volatile__("sti");
#elif defined(__aarch64__)
        __asm__ __volatile__("msr daif, %0" :: "r"(flags) : "memory");
#endif
        if (flags_out) *flags_out = flags;
        return 0;
    }
    if (flags_out) *flags_out = flags;
    return 1;
}

static inline void spin_unlock_irqrestore(spinlock_t *l, uint64_t flags) {
    __sync_lock_release(&l->v);
#if defined(EDGEOS_HOST_TEST)
    (void)flags;
#elif defined(__x86_64__)
    if (flags & (1ULL << 9)) __asm__ __volatile__("sti");
#elif defined(__aarch64__)
    __asm__ __volatile__("msr daif, %0" :: "r"(flags) : "memory");
#else
#error "spin_unlock_irqrestore needs an architecture implementation"
#endif
}

#endif
