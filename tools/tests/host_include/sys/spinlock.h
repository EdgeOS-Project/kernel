#ifndef EDGEOS_HOST_TEST_SPINLOCK_H
#define EDGEOS_HOST_TEST_SPINLOCK_H

#include <stdint.h>

typedef struct {
    volatile uint32_t value;
} spinlock_t;

static inline void spinlock_init(spinlock_t *lock) {
    if (lock) lock->value = 0;
}

static inline uint64_t spin_lock_irqsave(spinlock_t *lock) {
    while (__sync_lock_test_and_set(&lock->value, 1u)) { }
    return 0;
}

static inline void spin_unlock_irqrestore(spinlock_t *lock,
                                          uint64_t flags) {
    (void)flags;
    __sync_lock_release(&lock->value);
}

#endif
