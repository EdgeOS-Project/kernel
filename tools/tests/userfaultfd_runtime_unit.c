/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/userfaultfd.h"

static int changed_context = -1;

void kernel_userfaultfd_state_changed(int context_id) {
    changed_context = context_id;
}

int arch_mm_address_space_write_protect(
        uint64_t address_space, uint64_t address, uint64_t length,
        int enable) {
    (void)address_space;
    (void)address;
    (void)length;
    (void)enable;
    return 0;
}

static int copy_message(void *opaque, uint64_t offset,
                        const void *record, uint32_t length) {
    uint8_t *destination = (uint8_t *)opaque;
    memcpy(destination + offset, record, length);
    return 0;
}

int main(void) {
    kernel_userfaultfd_state_t state;
    kernel_uffdio_api_t api = {
        .api = KERNEL_UFFD_API,
        .features = KERNEL_UFFD_FEATURE_THREAD_ID |
                    KERNEL_UFFD_FEATURE_PAGEFAULT_FLAG_WP,
    };
    kernel_uffdio_register_t registration = {
        .range = { .start = 0x400000u, .length = 0x4000u },
        .mode = KERNEL_UFFD_REGISTER_MODE_MISSING,
    };
    kernel_userfaultfd_message_t message;
    int context_id;
    int fault_context = -1;
    uint64_t ticket = 0;

    context_id = kernel_userfaultfd_create(
        0x12345000u, 77, KERNEL_UFFD_NONBLOCK);
    assert(context_id >= 0);
    assert(kernel_userfaultfd_query(context_id, &state) == 0);
    assert(!state.api_ready && state.address_space == 0x12345000u);
    assert(kernel_userfaultfd_negotiate(context_id, &api) == 0);
    assert(api.features == KERNEL_UFFD_SUPPORTED_FEATURES &&
           api.ioctls == KERNEL_UFFD_API_IOCTLS);
    assert(kernel_userfaultfd_register(context_id, &registration) == 0);
    assert(registration.ioctls == KERNEL_UFFD_RANGE_IOCTLS);

    assert(kernel_userfaultfd_missing_fault(
        0x12345000u, 0x401234u, 1, 91,
        &fault_context, &ticket) == 1);
    assert(fault_context == context_id && ticket != 0);
    assert(changed_context == context_id);
    assert(kernel_userfaultfd_fault_pending(context_id, ticket) == 1);
    assert(kernel_userfaultfd_query(context_id, &state) == 0);
    assert(state.queued_events == 1 && state.unresolved_faults == 1);
    {
        int duplicate_context = -1;
        uint64_t duplicate_ticket = 0;
        assert(kernel_userfaultfd_missing_fault(
            0x12345000u, 0x401678u, 0, 92,
            &duplicate_context, &duplicate_ticket) == 1);
        assert(duplicate_context == context_id &&
               duplicate_ticket == ticket);
        assert(kernel_userfaultfd_query(context_id, &state) == 0);
        assert(state.queued_events == 1 && state.unresolved_faults == 1);
    }

    memset(&message, 0, sizeof(message));
    assert(kernel_userfaultfd_read(
        context_id, copy_message, &message, sizeof(message)) ==
        (int64_t)sizeof(message));
    assert(message.event == KERNEL_UFFD_EVENT_PAGEFAULT);
    assert(message.flags == KERNEL_UFFD_PAGEFAULT_FLAG_WRITE);
    assert(message.address == 0x401000u);
    assert(message.thread_id == 91);
    assert(kernel_userfaultfd_query(context_id, &state) == 0);
    assert(state.queued_events == 0 && state.unresolved_faults == 1);

    assert(kernel_userfaultfd_resolve(
        context_id, &(kernel_uffdio_range_t){
            .start = 0x401000u, .length = 0x1000u }) == 1);
    assert(kernel_userfaultfd_fault_pending(context_id, ticket) == 0);
    assert(kernel_userfaultfd_query(context_id, &state) == 0);
    assert(state.unresolved_faults == 0);

    assert(kernel_userfaultfd_unregister(
        context_id, &(kernel_uffdio_range_t){
            .start = 0x401000u, .length = 0x1000u }) == 0);
    assert(kernel_userfaultfd_missing_fault(
        0x12345000u, 0x401678u, 0, 93,
        &fault_context, &ticket) == 0);
    assert(kernel_userfaultfd_missing_fault(
        0x12345000u, 0x400678u, 0, 94,
        &fault_context, &ticket) == 1);
    assert(kernel_userfaultfd_missing_fault(
        0x12345000u, 0x402678u, 0, 95,
        &fault_context, &ticket) == 1);
    assert(kernel_userfaultfd_unregister(
        context_id, &registration.range) == 0);
    {
        kernel_uffdio_register_t writeprotect_registration = {
            .range = { .start = 0x500000u, .length = 0x4000u },
            .mode = KERNEL_UFFD_REGISTER_MODE_WP,
        };
        kernel_uffdio_range_t protected_range = {
            .start = 0x500000u, .length = 0x4000u,
        };
        uint64_t address_space = 0;

        assert(kernel_userfaultfd_register(
            context_id, &writeprotect_registration) == 0);
        assert(writeprotect_registration.ioctls ==
               KERNEL_UFFD_WP_RANGE_IOCTLS);
        assert(kernel_userfaultfd_writeprotect_validate(
            context_id, &protected_range,
            KERNEL_UFFDIO_WRITEPROTECT_MODE_WP |
            KERNEL_UFFDIO_WRITEPROTECT_MODE_DONTWAKE,
            &address_space) == -EDGE_LINUX_EINVAL);
        assert(kernel_userfaultfd_writeprotect_validate(
            context_id, &protected_range,
            KERNEL_UFFDIO_WRITEPROTECT_MODE_WP,
            &address_space) == 0);
        assert(address_space == 0x12345000u);
        assert(kernel_userfaultfd_writeprotect_commit(
            context_id, &protected_range,
            KERNEL_UFFDIO_WRITEPROTECT_MODE_WP) == 0);
        assert(kernel_userfaultfd_page_fault(
            address_space, 0x501234u, 0, 1, 96,
            &fault_context, &ticket) == 0);
        assert(kernel_userfaultfd_page_fault(
            address_space, 0x501234u, 1, 1, 97,
            &fault_context, &ticket) == 1);
        memset(&message, 0, sizeof(message));
        assert(kernel_userfaultfd_read(
            context_id, copy_message, &message, sizeof(message)) ==
            (int64_t)sizeof(message));
        assert(message.flags ==
               (KERNEL_UFFD_PAGEFAULT_FLAG_WRITE |
                KERNEL_UFFD_PAGEFAULT_FLAG_WP));
        assert(message.thread_id == 97);
        assert(kernel_userfaultfd_writeprotect_commit(
            context_id, &protected_range, 0) == 0);
        assert(kernel_userfaultfd_fault_pending(
            context_id, ticket) == 0);
        assert(kernel_userfaultfd_page_fault(
            address_space, 0x501234u, 1, 1, 98,
            &fault_context, &ticket) == 0);
        assert(kernel_userfaultfd_unregister(
            context_id, &protected_range) == 0);
    }
    kernel_userfaultfd_release(context_id);
    assert(kernel_userfaultfd_query(context_id, &state) ==
           -EDGE_LINUX_EBADF);
    puts("userfaultfd_runtime_unit: PASS");
    return 0;
}
