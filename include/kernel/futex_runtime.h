/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS futex runtime interface.
 * Copyright (c) EdgeOS Contributors.
 *
 * Linux futex argument decoding and validation are architecture-independent.
 * Architecture runtimes receive only normalized operations after the common
 * syscall layer has validated the UAPI and converted timeouts to the kernel's
 * monotonic clock.
 */

#ifndef EDGEOS_KERNEL_FUTEX_RUNTIME_H
#define EDGEOS_KERNEL_FUTEX_RUNTIME_H

#include <stdint.h>

#define KERNEL_FUTEX_WAITV_MAX 128u

typedef enum kernel_futex_operation {
    KERNEL_FUTEX_WAIT = 1,
    KERNEL_FUTEX_WAKE,
    KERNEL_FUTEX_REQUEUE,
    KERNEL_FUTEX_COMPARE_REQUEUE,
    KERNEL_FUTEX_WAKE_OPERATION,
    KERNEL_FUTEX_WAIT_VECTOR,
    KERNEL_FUTEX_LOCK_PI,
    KERNEL_FUTEX_TRYLOCK_PI,
    KERNEL_FUTEX_UNLOCK_PI,
    KERNEL_FUTEX_WAIT_REQUEUE_PI,
    KERNEL_FUTEX_COMPARE_REQUEUE_PI,
} kernel_futex_operation_t;

typedef enum kernel_futex_atomic_operation {
    KERNEL_FUTEX_ATOMIC_SET = 0,
    KERNEL_FUTEX_ATOMIC_ADD = 1,
    KERNEL_FUTEX_ATOMIC_OR = 2,
    KERNEL_FUTEX_ATOMIC_AND_NOT = 3,
    KERNEL_FUTEX_ATOMIC_XOR = 4,
} kernel_futex_atomic_operation_t;

typedef enum kernel_futex_comparison {
    KERNEL_FUTEX_COMPARE_EQUAL = 0,
    KERNEL_FUTEX_COMPARE_NOT_EQUAL = 1,
    KERNEL_FUTEX_COMPARE_LESS = 2,
    KERNEL_FUTEX_COMPARE_LESS_EQUAL = 3,
    KERNEL_FUTEX_COMPARE_GREATER = 4,
    KERNEL_FUTEX_COMPARE_GREATER_EQUAL = 5,
} kernel_futex_comparison_t;

typedef struct kernel_futex_wait_entry {
    uint64_t address;
    uint32_t expected_value;
    uint8_t private_futex;
    uint8_t padding[3];
} kernel_futex_wait_entry_t;

typedef struct kernel_futex_request {
    kernel_futex_operation_t operation;
    uint32_t raw_operation;
    uint64_t address;
    uint64_t secondary_address;
    uint64_t deadline_us;
    uint32_t expected_value;
    uint32_t comparison_value;
    uint32_t wake_count;
    uint32_t secondary_count;
    uint32_t bitset;
    int32_t atomic_argument;
    int32_t atomic_comparison_argument;
    kernel_futex_atomic_operation_t atomic_operation;
    kernel_futex_comparison_t atomic_comparison;
    uint16_t waiter_count;
    uint8_t private_futex;
    uint8_t secondary_private_futex;
    uint8_t has_timeout;
    uint8_t robust_unlock;
    uint8_t padding[2];
    void *user_registers;
    kernel_futex_wait_entry_t waiters[KERNEL_FUTEX_WAITV_MAX];
} kernel_futex_request_t;

typedef struct kernel_futex_scratch {
    void *memory;
    uint32_t capacity;
} kernel_futex_scratch_t;

typedef struct kernel_futex_key {
    uint64_t value;
    uintptr_t scope;
} kernel_futex_key_t;

typedef struct kernel_futex_backend_ops {
    int (*resolve_key)(void *context, uint64_t address, int private_futex,
                       kernel_futex_key_t *key);
    int64_t (*wait)(void *context, const kernel_futex_request_t *request);
    int64_t (*wait_vector)(void *context,
                           const kernel_futex_request_t *request);
    uintptr_t (*lock)(void *context);
    void (*unlock)(void *context, uintptr_t lock_state);
    int (*read_word_locked)(void *context, uint64_t address,
                            uint32_t *value);
    int (*compare_exchange_word_locked)(void *context, uint64_t address,
                                        uint32_t *expected,
                                        uint32_t desired);
    int (*wake_locked)(void *context, const kernel_futex_key_t *key,
                       uint32_t maximum, uint32_t bitset);
    int (*requeue_locked)(void *context,
                          const kernel_futex_key_t *source,
                          const kernel_futex_key_t *destination,
                          uint32_t maximum, uint32_t bitset);
    int (*requeue_tid_locked)(void *context,
                              const kernel_futex_key_t *source,
                              const kernel_futex_key_t *destination,
                              int32_t tid);
    int32_t (*current_tid)(void *context);
    int (*waiter_precedes_locked)(void *context, int32_t candidate_tid,
                                  int32_t current_tid);
    int (*prepare_pi_wait_locked)(
        void *context, const kernel_futex_request_t *request,
        const kernel_futex_key_t *key);
    int64_t (*block_pi_wait)(void *context,
                             const kernel_futex_request_t *request);
    int (*wake_tid_locked)(void *context, const kernel_futex_key_t *key,
                           int32_t tid, int result);
    int (*waiter_active_locked)(void *context,
                                const kernel_futex_key_t *key,
                                int32_t tid);
    int (*task_exists_locked)(void *context, int32_t tid);
    void (*recompute_pi_owner_locked)(void *context, int32_t owner_tid,
                                      int32_t donor_tid);
    void (*record_request)(void *context,
                           const kernel_futex_request_t *request);
    void (*record_result)(void *context,
                          const kernel_futex_request_t *request,
                          int64_t result);
} kernel_futex_backend_ops_t;

int kernel_futex_backend_register(
    const kernel_futex_backend_ops_t *ops, void *context);
int64_t kernel_futex_execute(const kernel_futex_request_t *request);
int kernel_futex_async_wait_add(const kernel_futex_request_t *request,
                                uint64_t *wait_id);
int kernel_futex_async_wait_poll(uint64_t wait_id, int32_t *result);
int kernel_futex_async_wait_cancel(uint64_t wait_id);
int kernel_futex_current_scratch(kernel_futex_scratch_t *scratch);
int32_t kernel_futex_atomic_apply(const kernel_futex_request_t *request,
                                  int32_t old_value);
int kernel_futex_atomic_compare(const kernel_futex_request_t *request,
                                int32_t old_value);
void kernel_futex_pi_waiter_cancel_locked(int32_t tid);
int kernel_futex_pi_owner_died_locked(uint64_t address,
                                      int32_t owner_tid,
                                      uint32_t observed_word);
int kernel_futex_pi_requeue_waiter_locked(
    const kernel_futex_key_t *key, int32_t tid);

#endif
