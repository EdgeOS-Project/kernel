/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux io_uring ring storage and lifetime. */

#ifndef EDGEOS_KERNEL_IO_URING_RUNTIME_H
#define EDGEOS_KERNEL_IO_URING_RUNTIME_H

#include <stdint.h>

#include "kernel/linux_abi.h"

#define KERNEL_IO_URING_MAX_RINGS 64u
#define KERNEL_IO_URING_MAX_SQ_ENTRIES 256u
#define KERNEL_IO_URING_MAX_CQ_ENTRIES 512u
#define KERNEL_IO_URING_PAGE_SIZE 4096u
#define KERNEL_IO_URING_MAX_SQ_RING_PAGES 1u
#define KERNEL_IO_URING_MAX_CQ_RING_PAGES 3u
#define KERNEL_IO_URING_MAX_SQE_PAGES 4u
#define KERNEL_IO_URING_MAX_PENDING 128u
#define KERNEL_IO_URING_MAX_FIXED_FILES 256u
#define KERNEL_IO_URING_MAX_WAIT_REGION_PAGES 64u
#define KERNEL_IO_URING_REGISTERED_RINGS 16u
#define KERNEL_IO_URING_REGISTERED_RING_ALLOC UINT32_MAX
#define KERNEL_IO_URING_REGISTER_FILES_SKIP (-2)

#define KERNEL_IO_URING_OFF_SQ_RING 0x00000000ull
#define KERNEL_IO_URING_OFF_CQ_RING 0x08000000ull
#define KERNEL_IO_URING_OFF_SQES    0x10000000ull
#define KERNEL_IO_URING_OFF_PARAM_REGION 0x20000000ull

typedef struct kernel_io_uring_page {
    void *address;
    uint64_t cookie;
} kernel_io_uring_page_t;

typedef struct kernel_io_uring_page_allocator {
    int (*allocate)(void *context, kernel_io_uring_page_t *page);
    int (*retain)(void *context, const kernel_io_uring_page_t *page);
    void (*release)(void *context, const kernel_io_uring_page_t *page);
    void *context;
} kernel_io_uring_page_allocator_t;

int kernel_io_uring_page_allocator_register(
    const kernel_io_uring_page_allocator_t *allocator);
int kernel_io_uring_create(uint32_t entries,
                           struct edge_linux_io_uring_params *parameters,
                           int32_t *ring_id);
int kernel_io_uring_retain(int32_t ring_id);
void kernel_io_uring_release(int32_t ring_id);
int kernel_io_uring_task_ring_register(int32_t task_id, int32_t ring_id,
                                       uint32_t requested,
                                       uint32_t *assigned);
int kernel_io_uring_task_ring_unregister(int32_t task_id, uint32_t index);
int kernel_io_uring_task_ring_lookup(int32_t task_id, uint32_t index,
                                     int32_t *ring_id);
void kernel_io_uring_task_release(int32_t task_id);
int kernel_io_uring_enable(int32_t ring_id);
int kernel_io_uring_disabled(int32_t ring_id);
int kernel_io_uring_eventfd_register(int32_t ring_id, int32_t event_id,
                                     int asynchronous_only);
int kernel_io_uring_eventfd_unregister(int32_t ring_id);
int kernel_io_uring_region_registered(int32_t ring_id);
int kernel_io_uring_region_register(int32_t ring_id, uint32_t page_count,
                                    int wait_argument);
int kernel_io_uring_region_unregister(int32_t ring_id);
int kernel_io_uring_registered_wait_read(
    int32_t ring_id, uint64_t offset,
    struct edge_linux_io_uring_reg_wait *wait);
int kernel_io_uring_files_register(int32_t ring_id,
                                   const int32_t *descriptors,
                                   uint32_t count);
int kernel_io_uring_files_register_tagged(
    int32_t ring_id, const int32_t *descriptors,
    const uint64_t *tags, uint32_t count);
int kernel_io_uring_files_unregister(int32_t ring_id);
int kernel_io_uring_files_update_validate(int32_t ring_id,
                                          uint32_t offset,
                                          uint32_t count);
int kernel_io_uring_files_update(int32_t ring_id, uint32_t offset,
                                 const int32_t *descriptors,
                                 uint32_t count);
int kernel_io_uring_files_update_tagged(
    int32_t ring_id, uint32_t offset,
    const int32_t *descriptors, const uint64_t *tags,
    uint32_t count);
int kernel_io_uring_fixed_file_materialize(int32_t ring_id,
                                           uint32_t index,
                                           int32_t *descriptor);
int kernel_io_uring_fixed_file_install(int32_t ring_id,
                                       uint32_t index,
                                       uint32_t descriptor_flags,
                                       int32_t *descriptor);
int kernel_io_uring_timeout_add(int32_t ring_id, uint64_t user_data,
                                uint64_t deadline_us,
                                uint32_t completion_target,
                                int32_t expiration_result,
                                int realtime_clock,
                                uint64_t interval_us,
                                uint32_t repeat_count,
                                int multishot);
int kernel_io_uring_timeout_update(int32_t ring_id, uint64_t user_data,
                                   uint64_t value_us, int absolute,
                                   uint64_t monotonic_now_us,
                                   uint64_t realtime_now_us);
int kernel_io_uring_poll_add(int32_t ring_id, uint64_t user_data,
                             int32_t descriptor, uint32_t events,
                             int multishot);
int kernel_io_uring_poll_update(int32_t ring_id, uint64_t old_user_data,
                                int update_events, uint32_t events,
                                int update_user_data,
                                uint64_t new_user_data,
                                int multishot);
int kernel_io_uring_pending_cancel(int32_t ring_id, uint64_t user_data);
uint32_t kernel_io_uring_collect(int32_t ring_id, uint64_t now_us);
int kernel_io_uring_mmap_info(int32_t ring_id, uint64_t offset,
                              uint64_t length, uint32_t *page_count);
int kernel_io_uring_mmap_page(int32_t ring_id, uint64_t offset,
                              uint32_t page_index,
                              kernel_io_uring_page_t *page);
int kernel_io_uring_take_submission(
    int32_t ring_id, struct edge_linux_io_uring_sqe *submission);
int kernel_io_uring_completion_add(int32_t ring_id, uint64_t user_data,
                                   int32_t result, uint32_t flags);
int kernel_io_uring_completion_add_async(int32_t ring_id,
                                         uint64_t user_data,
                                         int32_t result, uint32_t flags);
uint32_t kernel_io_uring_completion_count(int32_t ring_id);
uint32_t kernel_io_uring_completion_capacity(int32_t ring_id);
int kernel_io_uring_wait_deadlines(uint64_t start_us,
                                   uint64_t timeout_us,
                                   int timeout_present,
                                   int absolute_timeout,
                                   uint32_t minimum_wait_us,
                                   uint64_t *minimum_deadline_us,
                                   uint64_t *wait_deadline_us);

#endif
