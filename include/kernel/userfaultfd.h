/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux userfaultfd service.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_USERFAULTFD_H
#define EDGEOS_KERNEL_USERFAULTFD_H

#include <stdint.h>

#define KERNEL_UFFD_API 0xAAu

#define KERNEL_UFFD_CLOEXEC        0x00080000u
#define KERNEL_UFFD_NONBLOCK       0x00000800u
#define KERNEL_UFFD_USER_MODE_ONLY 0x00000001u

#define KERNEL_UFFD_REGISTER_MODE_MISSING (1ULL << 0)
#define KERNEL_UFFDIO_MODE_DONTWAKE        (1ULL << 0)

#define KERNEL_UFFD_PAGEFAULT_FLAG_WRITE (1ULL << 0)
#define KERNEL_UFFD_EVENT_PAGEFAULT 0x12u

#define KERNEL_UFFDIO_REGISTER_NUMBER   0x00u
#define KERNEL_UFFDIO_UNREGISTER_NUMBER 0x01u
#define KERNEL_UFFDIO_WAKE_NUMBER       0x02u
#define KERNEL_UFFDIO_COPY_NUMBER       0x03u
#define KERNEL_UFFDIO_ZEROPAGE_NUMBER   0x04u
#define KERNEL_UFFDIO_API_NUMBER        0x3fu

#define KERNEL_UFFD_API_IOCTLS \
    ((1ULL << KERNEL_UFFDIO_REGISTER_NUMBER) | \
     (1ULL << KERNEL_UFFDIO_UNREGISTER_NUMBER) | \
     (1ULL << KERNEL_UFFDIO_API_NUMBER))

#define KERNEL_UFFD_RANGE_IOCTLS \
    ((1ULL << KERNEL_UFFDIO_WAKE_NUMBER) | \
     (1ULL << KERNEL_UFFDIO_COPY_NUMBER) | \
     (1ULL << KERNEL_UFFDIO_ZEROPAGE_NUMBER))

typedef struct kernel_uffdio_api {
    uint64_t api;
    uint64_t features;
    uint64_t ioctls;
} kernel_uffdio_api_t;

typedef struct kernel_uffdio_range {
    uint64_t start;
    uint64_t length;
} kernel_uffdio_range_t;

typedef struct kernel_uffdio_register {
    kernel_uffdio_range_t range;
    uint64_t mode;
    uint64_t ioctls;
} kernel_uffdio_register_t;

typedef struct kernel_uffdio_copy {
    uint64_t destination;
    uint64_t source;
    uint64_t length;
    uint64_t mode;
    int64_t copied;
} kernel_uffdio_copy_t;

typedef struct kernel_uffdio_zeropage {
    kernel_uffdio_range_t range;
    uint64_t mode;
    int64_t zeroed;
} kernel_uffdio_zeropage_t;

typedef struct kernel_userfaultfd_message {
    uint8_t event;
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t reserved3;
    uint64_t flags;
    uint64_t address;
    uint32_t thread_id;
    uint32_t reserved4;
} __attribute__((packed)) kernel_userfaultfd_message_t;

typedef struct kernel_userfaultfd_state {
    uint32_t references;
    uint32_t queued_events;
    uint32_t unresolved_faults;
    uint8_t api_ready;
    uint8_t padding[3];
    uint64_t readiness_sequence;
    uint64_t address_space;
    int32_t owner_pid;
} kernel_userfaultfd_state_t;

typedef int (*kernel_userfaultfd_copy_record_fn)(
    void *context, uint64_t offset, const void *record, uint32_t length);

int kernel_userfaultfd_create(uint64_t address_space, int32_t owner_pid,
                              uint32_t flags);
int kernel_userfaultfd_retain(int context_id);
void kernel_userfaultfd_release(int context_id);
int kernel_userfaultfd_query(int context_id,
                             kernel_userfaultfd_state_t *state);
int kernel_userfaultfd_negotiate(int context_id,
                                 kernel_uffdio_api_t *api);
int kernel_userfaultfd_register(int context_id,
                                kernel_uffdio_register_t *registration);
int kernel_userfaultfd_unregister(int context_id,
                                  const kernel_uffdio_range_t *range);
int kernel_userfaultfd_validate_resolution(
    int context_id, const kernel_uffdio_range_t *range, uint64_t mode,
    uint64_t *address_space);
int kernel_userfaultfd_resolve(int context_id,
                               const kernel_uffdio_range_t *range);
int kernel_userfaultfd_cancel_resolution(
    int context_id, const kernel_uffdio_range_t *range);
int kernel_userfaultfd_missing_fault(
    uint64_t address_space, uint64_t address, int write,
    int *context_id, uint64_t *ticket);
int kernel_userfaultfd_fault_pending(int context_id, uint64_t ticket);
int kernel_userfaultfd_resolution_bypasses_fault(
    uint64_t address_space, uint64_t address);
int64_t kernel_userfaultfd_read(
    int context_id, kernel_userfaultfd_copy_record_fn copy_record,
    void *copy_context, uint64_t length);

#endif
