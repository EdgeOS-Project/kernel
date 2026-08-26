/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux io_uring ring storage and lifetime. */

#ifndef EDGEOS_KERNEL_IO_URING_RUNTIME_H
#define EDGEOS_KERNEL_IO_URING_RUNTIME_H

#include <stdint.h>

#include "kernel/fd_runtime.h"
#include "kernel/futex_runtime.h"
#include "kernel/io_runtime.h"
#include "kernel/linux_abi.h"
#include "kernel/process_runtime.h"

#define KERNEL_IO_URING_MAX_RINGS 64u
#define KERNEL_IO_URING_MAX_SQ_ENTRIES 256u
#define KERNEL_IO_URING_MAX_CQ_ENTRIES 512u
#define KERNEL_IO_URING_PAGE_SIZE 4096u
#define KERNEL_IO_URING_MAX_SQ_RING_PAGES 5u
#define KERNEL_IO_URING_MAX_CQ_RING_PAGES 5u
#define KERNEL_IO_URING_MAX_SQE_PAGES 8u
#define KERNEL_IO_URING_MAX_PENDING 128u
#define KERNEL_IO_URING_MAX_FIXED_FILES 256u
#define KERNEL_IO_URING_MAX_FIXED_BUFFERS 256u
#define KERNEL_IO_URING_INLINE_FIXED_BUFFER_PAGES 64u
#define KERNEL_IO_URING_MAX_PROVIDED_BUFFERS 256u
#define KERNEL_IO_URING_MAX_BUFFER_GROUPS 256u
#define KERNEL_IO_URING_MAX_PBUF_PAGES 256u
#define KERNEL_IO_URING_MAX_WAIT_REGION_PAGES 64u
#define KERNEL_IO_URING_MAX_ZCRX_CONTEXTS 4u
#define KERNEL_IO_URING_MAX_ZCRX_RQ_PAGES 64u
#define KERNEL_IO_URING_MAX_ZCRX_CHUNKS 4096u
#define KERNEL_IO_URING_REGISTERED_RINGS 16u
#define KERNEL_IO_URING_MAX_PERSONALITIES 64u
#define KERNEL_IO_URING_MAX_NAPI_IDS 64u
#define KERNEL_IO_URING_REGISTERED_RING_ALLOC UINT32_MAX
#define KERNEL_IO_URING_REGISTER_FILES_SKIP (-2)

#define KERNEL_IO_URING_OFF_SQ_RING 0x00000000ull
#define KERNEL_IO_URING_OFF_CQ_RING 0x08000000ull
#define KERNEL_IO_URING_OFF_SQES    0x10000000ull
#define KERNEL_IO_URING_OFF_PARAM_REGION 0x20000000ull
#define KERNEL_IO_URING_OFF_ZCRX_REGION 0x30000000ull
#define KERNEL_IO_URING_OFF_ZCRX_SHIFT 16u
#define KERNEL_IO_URING_OFF_PBUF_RING 0x80000000ull
#define KERNEL_IO_URING_OFF_PBUF_SHIFT 16u
#define KERNEL_IO_URING_OFF_MMAP_MASK 0xf8000000ull

typedef struct kernel_io_uring_page {
    void *address;
    uint64_t cookie;
} kernel_io_uring_page_t;

typedef struct kernel_io_uring_page_allocator {
    int (*allocate)(void *context, kernel_io_uring_page_t *page);
    int (*retain)(void *context, const kernel_io_uring_page_t *page);
    int (*pin_user)(void *context, uint64_t address_space,
                    uint64_t user_address,
                    kernel_io_uring_page_t *page);
    void (*release)(void *context, const kernel_io_uring_page_t *page);
    void *(*allocate_metadata_pages)(void *context, uint32_t page_count);
    void (*release_metadata_pages)(void *context, void *address,
                                   uint32_t page_count);
    void *context;
} kernel_io_uring_page_allocator_t;

typedef struct kernel_io_uring_fixed_file_reservation {
    int32_t ring_id;
    uint32_t indices[2];
    uint32_t cookie;
    uint8_t active;
    uint8_t reserved[3];
} kernel_io_uring_fixed_file_reservation_t;

typedef struct kernel_io_uring_selected_buffer {
    uint64_t address;
    uint64_t ring_entry_address;
    uint64_t ring_address_space;
    uint32_t length;
    uint32_t capacity;
    uint16_t id;
    uint16_t group_id;
} kernel_io_uring_selected_buffer_t;

typedef struct kernel_io_uring_pbuf_ring {
    uint64_t address;
    uint64_t address_space;
    uint32_t entries;
    uint32_t head;
    uint32_t minimum_left;
    uint8_t kernel_allocated;
    uint8_t incremental;
    uint8_t reserved[6];
} kernel_io_uring_pbuf_ring_t;

typedef struct kernel_io_uring_napi_state {
    uint32_t busy_poll_to;
    uint8_t prefer_busy_poll;
    uint8_t tracking_mode;
    uint8_t active_id_count;
    uint8_t reserved;
} kernel_io_uring_napi_state_t;

typedef int (*kernel_io_uring_waitid_copy_t)(
    uint64_t address_space, uint64_t user_address,
    const kernel_process_wait_result_t *result, int event_present);

#define KERNEL_IO_URING_CANCEL_ALL       (1u << 0)
#define KERNEL_IO_URING_CANCEL_FD        (1u << 1)
#define KERNEL_IO_URING_CANCEL_ANY       (1u << 2)
#define KERNEL_IO_URING_CANCEL_FD_FIXED  (1u << 3)
#define KERNEL_IO_URING_CANCEL_USERDATA  (1u << 4)
#define KERNEL_IO_URING_CANCEL_OP        (1u << 5)

typedef struct kernel_io_uring_cancel_match {
    uint64_t user_data;
    uint64_t file_description_id;
    uint32_t flags;
    uint8_t opcode;
    uint8_t reserved[3];
} kernel_io_uring_cancel_match_t;

typedef struct kernel_io_uring_worker_request {
    struct edge_linux_io_uring_sqe submission;
    uint64_t sequence;
    int32_t ring_id;
    int32_t descriptor;
} kernel_io_uring_worker_request_t;

int kernel_io_uring_page_allocator_register(
    const kernel_io_uring_page_allocator_t *allocator);
int kernel_io_uring_create(uint32_t entries,
                           struct edge_linux_io_uring_params *parameters,
                           int32_t *ring_id);
int kernel_io_uring_create_for_task(
    uint32_t entries, struct edge_linux_io_uring_params *parameters,
    int32_t *ring_id, int32_t task_id);
int kernel_io_uring_retain(int32_t ring_id);
void kernel_io_uring_release(int32_t ring_id);
int kernel_io_uring_task_ring_register(int32_t task_id, int32_t ring_id,
                                       uint32_t requested,
                                       uint32_t *assigned);
int kernel_io_uring_task_ring_unregister(int32_t task_id, uint32_t index);
int kernel_io_uring_task_ring_lookup(int32_t task_id, uint32_t index,
                                     int32_t *ring_id);
void kernel_io_uring_task_release(int32_t task_id);
int kernel_io_uring_task_restrictions_present(int32_t task_id);
int kernel_io_uring_task_restrictions_register(
    int32_t task_id, uint64_t register_operations,
    const uint64_t submission_operations[2],
    uint8_t submission_flags_allowed,
    uint8_t submission_flags_required,
    int restrict_register_operations,
    int restrict_submission_operations);
int kernel_io_uring_task_restrictions_clone(
    int32_t parent_task_id, int32_t child_task_id);
int kernel_io_uring_enable(int32_t ring_id);
int kernel_io_uring_disabled(int32_t ring_id);
int kernel_io_uring_setup_flags(int32_t ring_id, uint32_t *setup_flags);
int kernel_io_uring_restrictions_register(
    int32_t ring_id, uint64_t register_operations,
    const uint64_t submission_operations[2],
    uint8_t submission_flags_allowed,
    uint8_t submission_flags_required,
    int restrict_register_operations,
    int restrict_submission_operations);
int kernel_io_uring_register_allowed(int32_t ring_id, uint8_t opcode);
int kernel_io_uring_personality_register(
    int32_t ring_id, const linux_credential_state_t *credentials,
    uint16_t *personality_id);
int kernel_io_uring_personality_unregister(
    int32_t ring_id, uint16_t personality_id);
int kernel_io_uring_personality_get(
    int32_t ring_id, uint16_t personality_id,
    linux_credential_state_t *credentials);
int kernel_io_uring_napi_state_get(
    int32_t ring_id, kernel_io_uring_napi_state_t *state);
int kernel_io_uring_napi_configure(
    int32_t ring_id, uint32_t busy_poll_to,
    uint8_t prefer_busy_poll, uint8_t tracking_mode);
int kernel_io_uring_napi_static_add(int32_t ring_id, uint32_t napi_id);
int kernel_io_uring_napi_static_delete(int32_t ring_id, uint32_t napi_id);
int kernel_io_uring_napi_unregister(int32_t ring_id);
int kernel_io_uring_napi_id_register(uint32_t napi_id);
void kernel_io_uring_napi_id_unregister(uint32_t napi_id);
void kernel_io_uring_capabilities(uint64_t *features,
                                  uint64_t *setup_flags);
int kernel_io_uring_eventfd_register(int32_t ring_id, int32_t event_id,
                                     int asynchronous_only);
int kernel_io_uring_eventfd_unregister(int32_t ring_id);
int kernel_io_uring_region_registered(int32_t ring_id);
int kernel_io_uring_region_register(int32_t ring_id, uint32_t page_count,
                                    int wait_argument);
int kernel_io_uring_region_register_user(
    int32_t ring_id, uint64_t address_space, uint64_t user_address,
    uint32_t page_count, int wait_argument);
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
int kernel_io_uring_buffers_register(
    int32_t ring_id, const struct edge_linux_iovec *buffers,
    const uint64_t *tags, uint32_t count);
int kernel_io_uring_buffers_register_user(
    int32_t ring_id, uint64_t address_space,
    const struct edge_linux_iovec *buffers,
    const uint64_t *tags, uint32_t count);
int kernel_io_uring_buffers_unregister(int32_t ring_id);
int kernel_io_uring_buffers_update(
    int32_t ring_id, uint32_t offset,
    const struct edge_linux_iovec *buffers,
    const uint64_t *tags, uint32_t count);
int kernel_io_uring_buffers_update_user(
    int32_t ring_id, uint64_t address_space, uint32_t offset,
    const struct edge_linux_iovec *buffers,
    const uint64_t *tags, uint32_t count);
int kernel_io_uring_buffers_clone(
    int32_t destination_ring_id, int32_t source_ring_id,
    uint32_t source_offset, uint32_t destination_offset,
    uint32_t count, int replace);
int kernel_io_uring_fixed_buffer_validate(
    int32_t ring_id, uint32_t index,
    uint64_t address, uint64_t length);
int kernel_io_uring_fixed_buffer_registered(
    int32_t ring_id, uint32_t index);
int kernel_io_uring_fixed_buffer_copy(
    int32_t ring_id, uint32_t index, uint64_t address,
    void *kernel_buffer, uint64_t length, int to_registered_buffer);
int64_t kernel_io_uring_fixed_buffer_transfer(
    int32_t ring_id, uint32_t index, uint64_t address,
    uint64_t length, int32_t descriptor, uint64_t offset,
    kernel_io_operation_t operation, uint32_t flags,
    void *user_registers);
int kernel_io_uring_provided_buffers_add(
    int32_t ring_id, uint16_t group_id, uint16_t first_buffer_id,
    uint64_t address, uint32_t length, uint32_t count);
int kernel_io_uring_provided_buffers_remove(
    int32_t ring_id, uint16_t group_id, uint32_t count);
int kernel_io_uring_provided_buffer_select(
    int32_t ring_id, uint16_t group_id, uint32_t requested_length,
    kernel_io_uring_selected_buffer_t *selected);
int kernel_io_uring_pbuf_ring_register(
    int32_t ring_id, uint16_t group_id, uint64_t address,
    uint64_t address_space,
    uint32_t entries, int kernel_allocated,
    int incremental, uint32_t minimum_left);
int kernel_io_uring_pbuf_ring_unregister(
    int32_t ring_id, uint16_t group_id);
int kernel_io_uring_pbuf_ring_snapshot(
    int32_t ring_id, uint16_t group_id,
    kernel_io_uring_pbuf_ring_t *snapshot);
int kernel_io_uring_pbuf_ring_commit(
    int32_t ring_id, uint16_t group_id, uint32_t expected_head);
int kernel_io_uring_pbuf_ring_complete(
    int32_t ring_id, uint16_t group_id, uint32_t expected_head,
    uint32_t consumed, int *buffer_more);
int kernel_io_uring_pbuf_ring_read(
    int32_t ring_id, uint16_t group_id, uint32_t head,
    struct edge_linux_io_uring_buf *buffer, uint16_t *tail);
int kernel_io_uring_file_alloc_range_set(int32_t ring_id,
                                         uint32_t offset,
                                         uint32_t length);
int kernel_io_uring_file_alloc_range_get(int32_t ring_id,
                                         uint32_t *offset,
                                         uint32_t *length);
int kernel_io_uring_clock_set(int32_t ring_id, uint32_t clock_id);
int kernel_io_uring_clock_now(int32_t ring_id,
                              uint64_t monotonic_now_us,
                              uint64_t boottime_now_us,
                              uint64_t *now_us);
int kernel_io_uring_fixed_file_pair_reserve(
    int32_t ring_id, uint32_t file_slot,
    kernel_io_uring_fixed_file_reservation_t *reservation);
int kernel_io_uring_fixed_file_pair_commit(
    kernel_io_uring_fixed_file_reservation_t *reservation,
    const kernel_fd_publication_t *publication);
int kernel_io_uring_fixed_file_pair_cancel(
    kernel_io_uring_fixed_file_reservation_t *reservation);
int kernel_io_uring_fixed_file_transfer(
    int32_t source_ring_id, uint32_t source_index,
    int32_t target_ring_id, uint32_t target_file_slot);
int kernel_io_uring_fixed_file_materialize(int32_t ring_id,
                                           uint32_t index,
                                           int32_t *descriptor);
int kernel_io_uring_fixed_file_registered(
    int32_t ring_id, uint32_t index);
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
int kernel_io_uring_link_timeout_add(int32_t ring_id,
                                     uint64_t user_data,
                                     uint64_t target_sequence,
                                     uint64_t deadline_us,
                                     int realtime_clock);
int kernel_io_uring_pending_sequence(int32_t ring_id,
                                     uint64_t user_data,
                                     uint64_t *sequence);
int kernel_io_uring_timeout_update(int32_t ring_id, uint64_t user_data,
                                   uint64_t value_us, int absolute,
                                   uint64_t monotonic_now_us,
                                   uint64_t realtime_now_us);
int kernel_io_uring_poll_add(int32_t ring_id, uint64_t user_data,
                             int32_t descriptor, uint32_t events,
                             int multishot);
int kernel_io_uring_tx_timestamp_add(
    int32_t ring_id, uint64_t user_data, int32_t descriptor,
    uint8_t opcode);
int kernel_io_uring_tx_timestamp_complete(
    uint64_t file_description_id, uint32_t timestamp_key,
    uint32_t timestamp_type, uint64_t seconds,
    uint64_t nanoseconds, int hardware);
int kernel_io_uring_epoll_wait_add(int32_t ring_id, uint64_t user_data,
                                   int32_t descriptor,
                                   uint64_t user_events,
                                   uint64_t address_space,
                                   uint32_t maximum_events,
                                   uint8_t event_size,
                                   uint8_t event_data_offset);
int kernel_io_uring_futex_wait_add(
    int32_t ring_id, uint64_t user_data, uint8_t opcode,
    const kernel_futex_request_t *request);
int kernel_io_uring_waitid_add(
    int32_t ring_id, uint64_t user_data,
    const kernel_process_wait_request_t *request, int32_t waiter_tid,
    uint64_t user_information, uint64_t address_space,
    kernel_io_uring_waitid_copy_t copy_information);
int kernel_io_uring_read_multishot_add(
    int32_t ring_id, uint64_t user_data, int32_t descriptor,
    uint16_t buffer_group, uint64_t address_space);
int kernel_io_uring_zcrx_register(
    int32_t ring_id, uint64_t address_space,
    struct edge_linux_io_uring_zcrx_ifq_reg *registration,
    struct edge_linux_io_uring_zcrx_area_reg *area,
    struct edge_linux_io_uring_region_desc *region,
    const struct edge_linux_io_uring_zcrx_notification_desc *notification);
int kernel_io_uring_zcrx_flush(int32_t ring_id, uint32_t zcrx_id);
int kernel_io_uring_zcrx_arm_notification(
    int32_t ring_id, uint32_t zcrx_id, uint32_t notification_type);
int kernel_io_uring_zcrx_unregister(int32_t ring_id, uint32_t zcrx_id);
int kernel_io_uring_zcrx_export_descriptor(
    int32_t ring_id, uint32_t zcrx_id);
int kernel_io_uring_zcrx_export_retain(int32_t export_id);
void kernel_io_uring_zcrx_export_release(int32_t export_id);
int kernel_io_uring_zcrx_import(
    int32_t ring_id, int32_t export_id,
    struct edge_linux_io_uring_zcrx_ifq_reg *registration);
int kernel_io_uring_zcrx_recv_add(
    int32_t ring_id, uint64_t user_data, int32_t descriptor,
    uint32_t zcrx_id, uint32_t maximum_length);
int kernel_io_uring_poll_update(int32_t ring_id, uint64_t old_user_data,
                                int update_events, uint32_t events,
                                int update_user_data,
                                uint64_t new_user_data,
                                int multishot);
int kernel_io_uring_pending_cancel(int32_t ring_id, uint64_t user_data);
int kernel_io_uring_pending_cancel_match(
    int32_t ring_id, const kernel_io_uring_cancel_match_t *match,
    uint64_t *canceled_user_data);
int kernel_io_uring_worker_add(
    int32_t ring_id, int32_t owner_pid,
    const struct edge_linux_io_uring_sqe *submission,
    uint32_t ready_operation, uint32_t runtime_flags,
    const struct edge_linux_iovec *vectors, uint32_t vector_count,
    uint64_t address_space);
int kernel_io_uring_worker_materialize_next(
    int32_t owner_pid, int32_t ring_filter,
    kernel_io_uring_worker_request_t *request);
int kernel_io_uring_worker_finish(
    int32_t ring_id, uint64_t sequence, int32_t result,
    uint32_t completion_flags);
/*
 * Run fixed-buffer requests that no longer require the submitting task's
 * address space. The caller supplies a strict budget because this function is
 * also used from the scheduler's general deferred-work turn.
 */
uint32_t kernel_io_uring_worker_collect(uint32_t budget);
uint32_t kernel_io_uring_collect(int32_t ring_id, uint64_t now_us);
int kernel_io_uring_mmap_info(int32_t ring_id, uint64_t offset,
                              uint64_t length, uint32_t *page_count);
int kernel_io_uring_mmap_page(int32_t ring_id, uint64_t offset,
                              uint32_t page_index,
                              kernel_io_uring_page_t *page);
int kernel_io_uring_resize(
    int32_t ring_id, struct edge_linux_io_uring_params *parameters);
int kernel_io_uring_take_submission(
    int32_t ring_id, uint32_t submission_offset,
    uint32_t submission_limit,
    struct edge_linux_io_uring_sqe *submission,
    uint8_t command[80],
    uint32_t *entries_consumed, int32_t *layout_result);
int kernel_io_uring_completion_add(int32_t ring_id, uint64_t user_data,
                                   int32_t result, uint32_t flags);
int kernel_io_uring_completion_add32(
    int32_t ring_id, uint64_t user_data, int32_t result,
    uint32_t flags, uint64_t extra1, uint64_t extra2);
int kernel_io_uring_completion_add32_async(
    int32_t ring_id, uint64_t user_data, int32_t result,
    uint32_t flags, uint64_t extra1, uint64_t extra2);
int kernel_io_uring_completion_flush(int32_t ring_id);
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
