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

static int copy_message(void *opaque, uint64_t offset,
                        const void *record, uint32_t length) {
    uint8_t *destination = (uint8_t *)opaque;
    memcpy(destination + offset, record, length);
    return 0;
}

int main(void) {
    kernel_userfaultfd_state_t state;
    kernel_uffdio_api_t api = { .api = KERNEL_UFFD_API };
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
    assert(api.features == 0 && api.ioctls == KERNEL_UFFD_API_IOCTLS);
    assert(kernel_userfaultfd_register(context_id, &registration) == 0);
    assert(registration.ioctls == KERNEL_UFFD_RANGE_IOCTLS);

    assert(kernel_userfaultfd_missing_fault(
        0x12345000u, 0x401234u, 1, &fault_context, &ticket) == 1);
    assert(fault_context == context_id && ticket != 0);
    assert(changed_context == context_id);
    assert(kernel_userfaultfd_fault_pending(context_id, ticket) == 1);
    assert(kernel_userfaultfd_query(context_id, &state) == 0);
    assert(state.queued_events == 1 && state.unresolved_faults == 1);
    {
        int duplicate_context = -1;
        uint64_t duplicate_ticket = 0;
        assert(kernel_userfaultfd_missing_fault(
            0x12345000u, 0x401678u, 0,
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
        0x12345000u, 0x401678u, 0, &fault_context, &ticket) == 0);
    assert(kernel_userfaultfd_missing_fault(
        0x12345000u, 0x400678u, 0, &fault_context, &ticket) == 1);
    assert(kernel_userfaultfd_missing_fault(
        0x12345000u, 0x402678u, 0, &fault_context, &ticket) == 1);
    assert(kernel_userfaultfd_unregister(
        context_id, &registration.range) == 0);
    kernel_userfaultfd_release(context_id);
    assert(kernel_userfaultfd_query(context_id, &state) ==
           -EDGE_LINUX_EBADF);
    puts("userfaultfd_runtime_unit: PASS");
    return 0;
}
