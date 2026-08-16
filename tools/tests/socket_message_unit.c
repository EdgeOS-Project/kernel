/* SPDX-License-Identifier: MPL-2.0 */
/* Host-side regression tests for shared socket ancillary-control policy. */

#include "kernel/linux_errno.h"
#include "kernel/linux_time.h"
#include "kernel/socket_message.h"
#include "sys/boottime.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_USER_BASE 0x10000000ULL
#define TEST_MEMORY_SIZE 2048u
#define TEST_SENTINEL 0xa5u
#define TEST_SCM_CREDENTIALS 2

enum rights_terminal_action {
    RIGHTS_ACTION_NONE = 0,
    RIGHTS_ACTION_PUBLISHED,
    RIGHTS_ACTION_ABORTED,
    RIGHTS_ACTION_DISCARDED,
};

typedef struct copy_mock {
    uint8_t memory[TEST_MEMORY_SIZE];
    uint32_t calls;
    uint32_t fail_call;
    uint32_t fault_prefix;
} copy_mock_t;

typedef struct rights_mock {
    uint32_t source_count;
    int32_t first_descriptor;
    uint32_t prepare_calls;
    uint32_t publish_calls;
    uint32_t abort_calls;
    uint32_t discard_calls;
    uint32_t fail_prepare_index;
    int32_t fail_prepare_status;
    uint32_t fail_publish_index;
    int32_t fail_publish_status;
    uint8_t actions[KERNEL_SOCKET_SCM_RIGHTS_MAX];
} rights_mock_t;

static const kernel_socket_rights_receive_operations_t rights_operations;
static const kernel_socket_message_request_t *message_execute_request;

int64_t edge_socket_runtime_message_execute(
    const kernel_socket_message_request_t *request) {
    message_execute_request = request;
    return 37;
}

static void test_message_execute_entry(void) {
    kernel_socket_message_request_t request;

    memset(&request, 0, sizeof(request));
    message_execute_request = 0;
    assert(kernel_socket_message_execute(0) == -EDGE_LINUX_EIO);
    assert(!message_execute_request);
    assert(kernel_socket_message_execute(&request) == 37);
    assert(message_execute_request == &request);
}

static void copy_mock_initialize(copy_mock_t *mock) {
    memset(mock, 0, sizeof(*mock));
    memset(mock->memory, TEST_SENTINEL, sizeof(mock->memory));
}

static int copy_to_user(void *context, uint64_t destination,
                        const void *source, uint64_t size) {
    copy_mock_t *mock = (copy_mock_t *)context;
    uint64_t offset;
    uint64_t copied;

    assert(mock);
    assert(source || !size);
    ++mock->calls;
    if (destination < TEST_USER_BASE)
        return -1;
    offset = destination - TEST_USER_BASE;
    if (offset > sizeof(mock->memory) ||
        size > sizeof(mock->memory) - offset)
        return -1;
    if (mock->calls != mock->fail_call) {
        if (size)
            memcpy(mock->memory + offset, source, (size_t)size);
        return 0;
    }

    copied = mock->fault_prefix < size ?
        mock->fault_prefix : size;
    if (copied)
        memcpy(mock->memory + offset, source, (size_t)copied);
    return -1;
}

static int copy_from_user(void *context, void *destination,
                          uint64_t source, uint64_t size) {
    copy_mock_t *mock = (copy_mock_t *)context;
    uint64_t offset;

    assert(mock);
    assert(destination || !size);
    if (source < TEST_USER_BASE) return -1;
    offset = source - TEST_USER_BASE;
    if (offset > sizeof(mock->memory) ||
        size > sizeof(mock->memory) - offset)
        return -1;
    if (size) memcpy(destination, mock->memory + offset, (size_t)size);
    return 0;
}

static uint64_t control_length(uint32_t data_length) {
    return kernel_socket_control_align(
        sizeof(struct edge_linux_cmsghdr) + data_length);
}

static void read_header(const copy_mock_t *mock, uint64_t offset,
                        struct edge_linux_cmsghdr *header) {
    assert(offset <= sizeof(mock->memory) - sizeof(*header));
    memcpy(header, mock->memory + offset, sizeof(*header));
}

static int bytes_are_sentinel(const uint8_t *bytes, uint64_t length) {
    for (uint64_t index = 0; index < length; ++index)
        if (bytes[index] != TEST_SENTINEL)
            return 0;
    return 1;
}

static void rights_mock_initialize(rights_mock_t *mock,
                                   uint32_t source_count) {
    memset(mock, 0, sizeof(*mock));
    mock->source_count = source_count;
    mock->first_descriptor = 40;
    mock->fail_prepare_index = UINT32_MAX;
    mock->fail_publish_index = UINT32_MAX;
}

static int rights_prepare(void *context, uint32_t source_index,
                          int32_t *descriptor) {
    rights_mock_t *mock = (rights_mock_t *)context;

    assert(mock);
    assert(descriptor);
    assert(source_index < mock->source_count);
    assert(mock->actions[source_index] == RIGHTS_ACTION_NONE);
    ++mock->prepare_calls;
    if (source_index == mock->fail_prepare_index)
        return mock->fail_prepare_status;
    *descriptor = mock->first_descriptor + (int32_t)source_index;
    return 0;
}

static int rights_publish(void *context, uint32_t source_index,
                          int32_t descriptor) {
    rights_mock_t *mock = (rights_mock_t *)context;

    assert(mock);
    assert(source_index < mock->source_count);
    assert(descriptor ==
           mock->first_descriptor + (int32_t)source_index);
    assert(mock->actions[source_index] == RIGHTS_ACTION_NONE);
    ++mock->publish_calls;
    if (source_index == mock->fail_publish_index)
        return mock->fail_publish_status;
    mock->actions[source_index] = RIGHTS_ACTION_PUBLISHED;
    return 0;
}

static void rights_abort(void *context, uint32_t source_index,
                         int32_t descriptor) {
    rights_mock_t *mock = (rights_mock_t *)context;

    assert(mock);
    assert(source_index < mock->source_count);
    assert(descriptor ==
           mock->first_descriptor + (int32_t)source_index);
    assert(mock->actions[source_index] == RIGHTS_ACTION_NONE);
    mock->actions[source_index] = RIGHTS_ACTION_ABORTED;
    ++mock->abort_calls;
}

static void rights_discard(void *context, uint32_t source_index) {
    rights_mock_t *mock = (rights_mock_t *)context;

    assert(mock);
    assert(source_index < mock->source_count);
    assert(mock->actions[source_index] == RIGHTS_ACTION_NONE);
    mock->actions[source_index] = RIGHTS_ACTION_DISCARDED;
    ++mock->discard_calls;
}

static const kernel_socket_rights_receive_operations_t rights_operations = {
    .prepare = rights_prepare,
    .publish = rights_publish,
    .abort = rights_abort,
    .discard = rights_discard,
};

static int deliver_rights(
    copy_mock_t *copy, rights_mock_t *rights, uint64_t user_control,
    uint64_t capacity, uint64_t *used, int32_t *flags,
    kernel_socket_rights_receive_result_t *result) {
    return kernel_socket_control_receive_rights(
        copy, copy_to_user, user_control, capacity, used, flags,
        rights->source_count, &rights_operations, rights, result);
}

static void assert_terminal_actions(const rights_mock_t *mock,
                                    uint32_t published,
                                    uint32_t aborted,
                                    uint32_t discarded) {
    uint32_t observed_published = 0;
    uint32_t observed_aborted = 0;
    uint32_t observed_discarded = 0;

    for (uint32_t index = 0; index < mock->source_count; ++index) {
        assert(mock->actions[index] != RIGHTS_ACTION_NONE);
        observed_published +=
            mock->actions[index] == RIGHTS_ACTION_PUBLISHED;
        observed_aborted += mock->actions[index] == RIGHTS_ACTION_ABORTED;
        observed_discarded +=
            mock->actions[index] == RIGHTS_ACTION_DISCARDED;
    }
    assert(observed_published == published);
    assert(observed_aborted == aborted);
    assert(observed_discarded == discarded);
}

static void test_rights_success(void) {
    copy_mock_t copy;
    rights_mock_t rights;
    kernel_socket_rights_receive_result_t result;
    struct edge_linux_cmsghdr header;
    int32_t descriptors[3];
    uint64_t used = 0;
    int32_t flags = EDGE_LINUX_MSG_EOR;

    copy_mock_initialize(&copy);
    rights_mock_initialize(&rights, 3);
    assert(deliver_rights(
               &copy, &rights, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, &result) == 0);
    assert(result.delivered_count == 3u);
    assert(result.callback_status == 0);
    assert(!result.truncated);
    assert(!result.control_fault);
    assert(used == control_length(sizeof(descriptors)));
    assert(flags == EDGE_LINUX_MSG_EOR);
    read_header(&copy, 0, &header);
    assert(header.cmsg_len == sizeof(header) + sizeof(descriptors));
    assert(header.cmsg_level == EDGE_LINUX_SOL_SOCKET);
    assert(header.cmsg_type == KERNEL_SOCKET_SCM_RIGHTS);
    memcpy(descriptors, copy.memory + sizeof(header), sizeof(descriptors));
    assert(descriptors[0] == 40);
    assert(descriptors[1] == 41);
    assert(descriptors[2] == 42);
    assert_terminal_actions(&rights, 3, 0, 0);
}

static void test_rights_linux_maximum(void) {
    copy_mock_t copy;
    rights_mock_t rights;
    kernel_socket_rights_receive_result_t result;
    struct edge_linux_cmsghdr header;
    uint64_t used = 0;
    int32_t flags = 0;
    uint64_t expected_length = sizeof(header) +
        (uint64_t)KERNEL_SOCKET_SCM_RIGHTS_MAX * sizeof(int32_t);

    copy_mock_initialize(&copy);
    rights_mock_initialize(&rights, KERNEL_SOCKET_SCM_RIGHTS_MAX);
    assert(deliver_rights(
               &copy, &rights, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, &result) == 0);
    assert(result.delivered_count == KERNEL_SOCKET_SCM_RIGHTS_MAX);
    assert(!result.truncated);
    assert(!result.control_fault);
    assert(used == kernel_socket_control_align(expected_length));
    read_header(&copy, 0, &header);
    assert(header.cmsg_len == expected_length);
    assert_terminal_actions(
        &rights, KERNEL_SOCKET_SCM_RIGHTS_MAX, 0, 0);
}

static void test_rights_capacity_truncation(void) {
    copy_mock_t copy;
    rights_mock_t rights;
    kernel_socket_rights_receive_result_t result;
    struct edge_linux_cmsghdr header;
    int32_t descriptor;
    uint64_t used = 0;
    int32_t flags = 0;
    uint64_t capacity =
        sizeof(struct edge_linux_cmsghdr) + sizeof(int32_t);

    copy_mock_initialize(&copy);
    rights_mock_initialize(&rights, 3);
    assert(deliver_rights(
               &copy, &rights, TEST_USER_BASE, capacity,
               &used, &flags, &result) == 0);
    assert(result.delivered_count == 1u);
    assert(result.truncated);
    assert(!result.control_fault);
    assert(used == capacity);
    assert((flags & EDGE_LINUX_MSG_CTRUNC) != 0);
    read_header(&copy, 0, &header);
    assert(header.cmsg_len == capacity);
    memcpy(&descriptor, copy.memory + sizeof(header), sizeof(descriptor));
    assert(descriptor == 40);
    assert_terminal_actions(&rights, 1, 0, 2);
}

static void test_rights_header_only_capacity(void) {
    copy_mock_t copy;
    rights_mock_t rights;
    kernel_socket_rights_receive_result_t result;
    uint64_t used = 0;
    int32_t flags = 0;

    copy_mock_initialize(&copy);
    rights_mock_initialize(&rights, 3);
    assert(deliver_rights(
               &copy, &rights, TEST_USER_BASE,
               sizeof(struct edge_linux_cmsghdr),
               &used, &flags, &result) == 0);
    assert(result.delivered_count == 0u);
    assert(result.truncated);
    assert(!result.control_fault);
    assert(used == 0u);
    assert((flags & EDGE_LINUX_MSG_CTRUNC) != 0);
    assert(copy.calls == 0u);
    assert(bytes_are_sentinel(copy.memory, sizeof(copy.memory)));
    assert_terminal_actions(&rights, 0, 0, 3);
}

static void test_rights_first_word_fault(void) {
    copy_mock_t copy;
    rights_mock_t rights;
    kernel_socket_rights_receive_result_t result;
    uint64_t used = 0;
    int32_t flags = 0;

    copy_mock_initialize(&copy);
    copy.fail_call = 2u;
    copy.fault_prefix = 2u;
    rights_mock_initialize(&rights, 3);
    assert(deliver_rights(
               &copy, &rights, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, &result) == 0);
    assert(result.delivered_count == 0u);
    assert(result.truncated);
    assert(result.control_fault);
    assert(used == 0u);
    assert((flags & EDGE_LINUX_MSG_CTRUNC) != 0);
    assert_terminal_actions(&rights, 0, 3, 0);
}

static void test_rights_second_word_fault(void) {
    copy_mock_t copy;
    rights_mock_t rights;
    kernel_socket_rights_receive_result_t result;
    struct edge_linux_cmsghdr header;
    int32_t descriptor;
    uint64_t used = 0;
    int32_t flags = 0;

    copy_mock_initialize(&copy);
    copy.fail_call = 3u;
    copy.fault_prefix = 0u;
    rights_mock_initialize(&rights, 3);
    assert(deliver_rights(
               &copy, &rights, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, &result) == 0);
    assert(result.delivered_count == 1u);
    assert(result.truncated);
    assert(result.control_fault);
    assert(used == sizeof(header) + sizeof(descriptor));
    assert((flags & EDGE_LINUX_MSG_CTRUNC) != 0);
    read_header(&copy, 0, &header);
    assert(header.cmsg_len == sizeof(header) + sizeof(descriptor));
    memcpy(&descriptor, copy.memory + sizeof(header), sizeof(descriptor));
    assert(descriptor == 40);
    assert_terminal_actions(&rights, 1, 2, 0);
}

static void test_rights_whole_control_fault(void) {
    copy_mock_t copy;
    rights_mock_t rights;
    kernel_socket_rights_receive_result_t result;
    uint64_t used = 0;
    int32_t flags = EDGE_LINUX_MSG_EOR;

    copy_mock_initialize(&copy);
    copy.fail_call = 1u;
    copy.fault_prefix = 4u;
    rights_mock_initialize(&rights, 3);
    assert(deliver_rights(
               &copy, &rights, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, &result) == 0);
    assert(result.delivered_count == 0u);
    assert(result.truncated);
    assert(result.control_fault);
    assert(used == 0u);
    assert((flags & EDGE_LINUX_MSG_CTRUNC) != 0);
    assert((flags & EDGE_LINUX_MSG_EOR) != 0);
    assert(rights.prepare_calls == 0u);
    assert(rights.publish_calls == 0u);
    assert_terminal_actions(&rights, 0, 0, 3);
}

static void test_rights_prepare_failure(void) {
    copy_mock_t copy;
    rights_mock_t rights;
    kernel_socket_rights_receive_result_t result;
    struct edge_linux_cmsghdr header;
    uint64_t used = 0;
    int32_t flags = 0;

    copy_mock_initialize(&copy);
    rights_mock_initialize(&rights, 3);
    rights.fail_prepare_index = 1u;
    rights.fail_prepare_status = -EDGE_LINUX_EMFILE;
    assert(deliver_rights(
               &copy, &rights, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, &result) == 0);
    assert(result.delivered_count == 1u);
    assert(result.callback_status == -EDGE_LINUX_EMFILE);
    assert(result.truncated);
    assert(!result.control_fault);
    assert(used == sizeof(header) + sizeof(int32_t));
    read_header(&copy, 0, &header);
    assert(header.cmsg_len == used);
    assert_terminal_actions(&rights, 1, 0, 2);
}

static void test_rights_publication_failure(void) {
    copy_mock_t copy;
    rights_mock_t rights;
    kernel_socket_rights_receive_result_t result;
    struct edge_linux_cmsghdr header;
    uint64_t used = 0;
    int32_t flags = 0;

    copy_mock_initialize(&copy);
    rights_mock_initialize(&rights, 3);
    rights.fail_publish_index = 1u;
    rights.fail_publish_status = -EDGE_LINUX_EBUSY;
    assert(deliver_rights(
               &copy, &rights, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, &result) == 0);
    assert(result.delivered_count == 1u);
    assert(result.callback_status == -EDGE_LINUX_EBUSY);
    assert(result.truncated);
    assert(!result.control_fault);
    assert(used == sizeof(header) + sizeof(int32_t));
    read_header(&copy, 0, &header);
    assert(header.cmsg_len == used);
    assert_terminal_actions(&rights, 1, 2, 0);
}

static void test_rights_invalid_control_addresses(void) {
    copy_mock_t copy;
    rights_mock_t rights;
    kernel_socket_rights_receive_result_t result;
    uint64_t used = 0;
    int32_t flags = 0;

    copy_mock_initialize(&copy);
    rights_mock_initialize(&rights, 2);
    assert(deliver_rights(
               &copy, &rights, 0, sizeof(copy.memory),
               &used, &flags, &result) == 0);
    assert(result.control_fault);
    assert(result.truncated);
    assert(used == 0u);
    assert(copy.calls == 0u);
    assert_terminal_actions(&rights, 0, 0, 2);

    copy_mock_initialize(&copy);
    rights_mock_initialize(&rights, 2);
    used = 8u;
    flags = 0;
    assert(deliver_rights(
               &copy, &rights, UINT64_MAX - 4u, sizeof(copy.memory),
               &used, &flags, &result) == 0);
    assert(result.control_fault);
    assert(result.truncated);
    assert(used == 8u);
    assert(copy.calls == 0u);
    assert_terminal_actions(&rights, 0, 0, 2);

    copy_mock_initialize(&copy);
    rights_mock_initialize(&rights, 2);
    used = 9u;
    flags = 0;
    assert(deliver_rights(
               &copy, &rights, TEST_USER_BASE, 8u,
               &used, &flags, &result) == 0);
    assert(result.truncated);
    assert(!result.control_fault);
    assert(used == 9u);
    assert(copy.calls == 0u);
    assert_terminal_actions(&rights, 0, 0, 2);
}

static void test_rights_preserve_committed_prefix(void) {
    static const uint8_t metadata[] = {1, 2, 3, 4};
    copy_mock_t copy;
    rights_mock_t rights;
    kernel_socket_control_receive_result_t metadata_result;
    kernel_socket_rights_receive_result_t rights_result;
    uint8_t prefix[64];
    uint64_t used = 0;
    uint64_t prefix_length;
    int32_t flags = EDGE_LINUX_MSG_EOR;

    copy_mock_initialize(&copy);
    assert(kernel_socket_control_receive_metadata_append(
               &copy, copy_to_user, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, EDGE_LINUX_SOL_SOCKET, TEST_SCM_CREDENTIALS,
               metadata, sizeof(metadata), &metadata_result) == 0);
    assert(metadata_result == KERNEL_SOCKET_CONTROL_RECEIVE_APPENDED);
    prefix_length = used;
    assert(prefix_length <= sizeof(prefix));
    memcpy(prefix, copy.memory, (size_t)prefix_length);

    rights_mock_initialize(&rights, 2);
    copy.fail_call = copy.calls + 3u;
    assert(deliver_rights(
               &copy, &rights, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, &rights_result) == 0);
    assert(rights_result.delivered_count == 1u);
    assert(rights_result.control_fault);
    assert(used == prefix_length +
                   sizeof(struct edge_linux_cmsghdr) + sizeof(int32_t));
    assert(memcmp(copy.memory, prefix, (size_t)prefix_length) == 0);
    assert_terminal_actions(&rights, 1, 1, 0);
}

static void test_rights_limits_and_invalid_arguments(void) {
    copy_mock_t copy;
    rights_mock_t rights;
    kernel_socket_rights_receive_result_t result;
    uint64_t used = 0;
    int32_t flags = 0;

    assert(KERNEL_SOCKET_SCM_RIGHTS_MAX == 253u);
    copy_mock_initialize(&copy);
    rights_mock_initialize(&rights, 1);
    assert(kernel_socket_control_receive_rights(
               &copy, copy_to_user, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, KERNEL_SOCKET_SCM_RIGHTS_MAX + 1u,
               &rights_operations, &rights, &result) ==
           -EDGE_LINUX_EINVAL);
    assert(copy.calls == 0u);
    assert(rights.prepare_calls == 0u);

    assert(kernel_socket_control_receive_rights(
               &copy, copy_to_user, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, 1u, 0, &rights, &result) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_socket_control_receive_rights(
               &copy, copy_to_user, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, 0u, 0, 0, &result) == 0);
}

static void test_metadata_success(void) {
    static const uint32_t data[] = {0x11223344u, 0x55667788u};
    copy_mock_t copy;
    kernel_socket_control_receive_result_t result;
    struct edge_linux_cmsghdr header;
    uint64_t used = 0;
    int32_t flags = EDGE_LINUX_MSG_EOR;

    copy_mock_initialize(&copy);
    assert(kernel_socket_control_receive_metadata_append(
               &copy, copy_to_user, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, EDGE_LINUX_SOL_SOCKET, TEST_SCM_CREDENTIALS,
               data, sizeof(data), &result) == 0);
    assert(result == KERNEL_SOCKET_CONTROL_RECEIVE_APPENDED);
    assert(used == control_length(sizeof(data)));
    assert(flags == EDGE_LINUX_MSG_EOR);
    read_header(&copy, 0, &header);
    assert(header.cmsg_len == sizeof(header) + sizeof(data));
    assert(header.cmsg_level == EDGE_LINUX_SOL_SOCKET);
    assert(header.cmsg_type == TEST_SCM_CREDENTIALS);
    assert(memcmp(copy.memory + sizeof(header), data, sizeof(data)) == 0);
}

static void test_metadata_partial_capacity(void) {
    static const uint32_t data[] = {0x11223344u, 0x55667788u};
    copy_mock_t copy;
    kernel_socket_control_receive_result_t result;
    struct edge_linux_cmsghdr header;
    uint64_t used = 0;
    int32_t flags = 0;
    uint64_t capacity = sizeof(header);

    copy_mock_initialize(&copy);
    assert(kernel_socket_control_receive_metadata_append(
               &copy, copy_to_user, TEST_USER_BASE, capacity,
               &used, &flags, EDGE_LINUX_SOL_SOCKET, TEST_SCM_CREDENTIALS,
               data, sizeof(data), &result) == 0);
    assert(result == KERNEL_SOCKET_CONTROL_RECEIVE_TRUNCATED);
    assert(used == capacity);
    assert((flags & EDGE_LINUX_MSG_CTRUNC) != 0);
    read_header(&copy, 0, &header);
    assert(header.cmsg_len == capacity);
    assert(bytes_are_sentinel(
        copy.memory + sizeof(header),
        sizeof(copy.memory) - sizeof(header)));

    copy_mock_initialize(&copy);
    used = 0;
    flags = 0;
    capacity = sizeof(header) + sizeof(uint32_t);
    assert(kernel_socket_control_receive_metadata_append(
               &copy, copy_to_user, TEST_USER_BASE, capacity,
               &used, &flags, EDGE_LINUX_SOL_SOCKET, TEST_SCM_CREDENTIALS,
               data, sizeof(data), &result) == 0);
    assert(result == KERNEL_SOCKET_CONTROL_RECEIVE_TRUNCATED);
    assert(used == capacity);
    read_header(&copy, 0, &header);
    assert(header.cmsg_len == capacity);
    assert(memcmp(copy.memory + sizeof(header),
                  data, sizeof(uint32_t)) == 0);
    assert(copy.memory[capacity] == TEST_SENTINEL);
}

static void test_metadata_faults(void) {
    static const uint32_t data[] = {0x11223344u, 0x55667788u};
    copy_mock_t copy;
    kernel_socket_control_receive_result_t result;
    struct edge_linux_cmsghdr header;
    uint64_t used = 0;
    int32_t flags = EDGE_LINUX_MSG_EOR;

    copy_mock_initialize(&copy);
    copy.fail_call = 1u;
    copy.fault_prefix = 4u;
    assert(kernel_socket_control_receive_metadata_append(
               &copy, copy_to_user, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, EDGE_LINUX_SOL_SOCKET, TEST_SCM_CREDENTIALS,
               data, sizeof(data), &result) == 0);
    assert(result == KERNEL_SOCKET_CONTROL_RECEIVE_FAULTED);
    assert(used == 0u);
    assert(flags == EDGE_LINUX_MSG_EOR);

    copy_mock_initialize(&copy);
    copy.fail_call = 2u;
    copy.fault_prefix = sizeof(uint32_t);
    used = 0;
    flags = EDGE_LINUX_MSG_EOR;
    assert(kernel_socket_control_receive_metadata_append(
               &copy, copy_to_user, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, EDGE_LINUX_SOL_SOCKET, TEST_SCM_CREDENTIALS,
               data, sizeof(data), &result) == 0);
    assert(result == KERNEL_SOCKET_CONTROL_RECEIVE_FAULTED);
    assert(used == 0u);
    assert(flags == EDGE_LINUX_MSG_EOR);
    read_header(&copy, 0, &header);
    assert(header.cmsg_len == sizeof(header) + sizeof(data));
}

static void test_metadata_fault_preserves_prefix(void) {
    static const uint32_t first = 0x11223344u;
    static const uint32_t second = 0x55667788u;
    copy_mock_t copy;
    kernel_socket_control_receive_result_t result;
    uint8_t prefix[64];
    uint64_t used = 0;
    uint64_t prefix_length;
    int32_t flags = 0;

    copy_mock_initialize(&copy);
    assert(kernel_socket_control_receive_metadata_append(
               &copy, copy_to_user, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, EDGE_LINUX_SOL_SOCKET, 10,
               &first, sizeof(first), &result) == 0);
    prefix_length = used;
    assert(prefix_length <= sizeof(prefix));
    memcpy(prefix, copy.memory, (size_t)prefix_length);

    copy.fail_call = copy.calls + 2u;
    copy.fault_prefix = 0;
    assert(kernel_socket_control_receive_metadata_append(
               &copy, copy_to_user, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, EDGE_LINUX_SOL_SOCKET, 11,
               &second, sizeof(second), &result) == 0);
    assert(result == KERNEL_SOCKET_CONTROL_RECEIVE_FAULTED);
    assert(used == prefix_length);
    assert(flags == 0);
    assert(memcmp(copy.memory, prefix, (size_t)prefix_length) == 0);
}

static void test_metadata_capacity_and_address_edges(void) {
    static const uint32_t data = 0x11223344u;
    copy_mock_t copy;
    kernel_socket_control_receive_result_t result;
    uint64_t used = 0;
    int32_t flags = 0;

    copy_mock_initialize(&copy);
    assert(kernel_socket_control_receive_metadata_append(
               &copy, copy_to_user, TEST_USER_BASE,
               sizeof(struct edge_linux_cmsghdr) - 1u,
               &used, &flags, EDGE_LINUX_SOL_SOCKET, TEST_SCM_CREDENTIALS,
               &data, sizeof(data), &result) == 0);
    assert(result == KERNEL_SOCKET_CONTROL_RECEIVE_TRUNCATED);
    assert(used == 0u);
    assert((flags & EDGE_LINUX_MSG_CTRUNC) != 0);
    assert(copy.calls == 0u);

    copy_mock_initialize(&copy);
    used = 0;
    flags = EDGE_LINUX_MSG_EOR;
    assert(kernel_socket_control_receive_metadata_append(
               &copy, copy_to_user, 0, sizeof(copy.memory),
               &used, &flags, EDGE_LINUX_SOL_SOCKET, TEST_SCM_CREDENTIALS,
               &data, sizeof(data), &result) == 0);
    assert(result == KERNEL_SOCKET_CONTROL_RECEIVE_FAULTED);
    assert(used == 0u);
    assert(flags == EDGE_LINUX_MSG_EOR);
    assert(copy.calls == 0u);

    used = 8u;
    assert(kernel_socket_control_receive_metadata_append(
               &copy, copy_to_user, UINT64_MAX - 4u, sizeof(copy.memory),
               &used, &flags, EDGE_LINUX_SOL_SOCKET, TEST_SCM_CREDENTIALS,
               &data, sizeof(data), &result) == 0);
    assert(result == KERNEL_SOCKET_CONTROL_RECEIVE_FAULTED);
    assert(used == 8u);
    assert(flags == EDGE_LINUX_MSG_EOR);
}

static void test_metadata_invalid_arguments(void) {
    copy_mock_t copy;
    kernel_socket_control_receive_result_t result;
    uint64_t used = 0;
    int32_t flags = 0;

    copy_mock_initialize(&copy);
    assert(kernel_socket_control_receive_metadata_append(
               &copy, copy_to_user, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, EDGE_LINUX_SOL_SOCKET, TEST_SCM_CREDENTIALS,
               0, sizeof(uint32_t), &result) == -EDGE_LINUX_EINVAL);
    assert(kernel_socket_control_receive_metadata_append(
               &copy, 0, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, EDGE_LINUX_SOL_SOCKET, TEST_SCM_CREDENTIALS,
               0, 0, &result) == -EDGE_LINUX_EINVAL);
}

static void test_timestamp_metadata_policy(void) {
    copy_mock_t copy;
    kernel_socket_control_receive_result_t result;
    struct edge_linux_cmsghdr header;
    uint64_t used = 0;
    int32_t flags = 0;
    uint64_t capacity = sizeof(header) + sizeof(int64_t);

    copy_mock_initialize(&copy);
    assert(kernel_socket_timestamp_control_receive_append(
               KERNEL_SOCKET_TIMESTAMP_NS_OLD, 1234567u,
               &copy, copy_to_user, TEST_USER_BASE, capacity,
               &used, &flags, &result) == 0);
    assert(result == KERNEL_SOCKET_CONTROL_RECEIVE_TRUNCATED);
    assert(used == capacity);
    assert((flags & EDGE_LINUX_MSG_CTRUNC) != 0);
    read_header(&copy, 0, &header);
    assert(header.cmsg_len == capacity);
    assert(header.cmsg_type == EDGE_LINUX_SO_TIMESTAMPNS);
}

static void test_ip_receive_metadata_policy(void) {
    copy_mock_t copy;
    kernel_socket_option_state_t options;
    kernel_socket_ip_receive_metadata_t metadata;
    kernel_socket_control_receive_result_t result;
    struct edge_linux_cmsghdr header;
    struct edge_linux_in_pktinfo packet_info4;
    struct edge_linux_in6_pktinfo packet_info6;
    uint64_t used;
    uint64_t offset;
    int32_t integer_value;
    int32_t flags;

    copy_mock_initialize(&copy);
    memset(&options, 0, sizeof(options));
    memset(&metadata, 0, sizeof(metadata));
    options.ip_packet_info = 1;
    options.ip_receive_ttl = 1;
    metadata.family = EDGE_LINUX_AF_INET;
    metadata.interface_index = 7u;
    metadata.hop_limit = 31u;
    memcpy(metadata.local_address, "\x0a\x00\x00\x01", 4u);
    memcpy(metadata.destination_address, "\xe0\x00\x00\xfb", 4u);
    used = 0;
    flags = 0;
    assert(kernel_socket_ip_receive_control_append(
               &options, &metadata, &copy, copy_to_user,
               TEST_USER_BASE, sizeof(copy.memory), &used, &flags,
               &result) == 0);
    assert(result == KERNEL_SOCKET_CONTROL_RECEIVE_APPENDED);
    assert(flags == 0);
    read_header(&copy, 0, &header);
    assert(header.cmsg_level == EDGE_LINUX_SOL_IP);
    assert(header.cmsg_type == EDGE_LINUX_IP_PKTINFO);
    memcpy(&packet_info4, copy.memory + sizeof(header), sizeof(packet_info4));
    assert(packet_info4.ipi_ifindex == 7);
    assert(memcmp(&packet_info4.ipi_spec_dst,
                  metadata.local_address, 4u) == 0);
    assert(memcmp(&packet_info4.ipi_addr,
                  metadata.destination_address, 4u) == 0);
    offset = control_length(sizeof(packet_info4));
    read_header(&copy, offset, &header);
    assert(header.cmsg_level == EDGE_LINUX_SOL_IP);
    assert(header.cmsg_type == EDGE_LINUX_IP_TTL);
    memcpy(&integer_value, copy.memory + offset + sizeof(header),
           sizeof(integer_value));
    assert(integer_value == 31);
    assert(used == offset + control_length(sizeof(integer_value)));

    copy_mock_initialize(&copy);
    memset(&options, 0, sizeof(options));
    memset(&metadata, 0, sizeof(metadata));
    options.ipv6_receive_packet_info = 1;
    options.ipv6_receive_hop_limit = 1;
    options.ipv6_receive_traffic_class = 1;
    metadata.family = EDGE_LINUX_AF_INET6;
    metadata.interface_index = 9u;
    metadata.hop_limit = 63u;
    metadata.traffic_class = 0xb8u;
    for (uint32_t index = 0; index < 16u; ++index)
        metadata.destination_address[index] = (uint8_t)(index + 1u);
    used = 0;
    flags = 0;
    assert(kernel_socket_ip_receive_control_append(
               &options, &metadata, &copy, copy_to_user,
               TEST_USER_BASE, sizeof(copy.memory), &used, &flags,
               &result) == 0);
    read_header(&copy, 0, &header);
    assert(header.cmsg_level == EDGE_LINUX_SOL_IPV6);
    assert(header.cmsg_type == EDGE_LINUX_IPV6_PKTINFO);
    memcpy(&packet_info6, copy.memory + sizeof(header), sizeof(packet_info6));
    assert(packet_info6.ipi6_ifindex == 9u);
    assert(memcmp(packet_info6.ipi6_addr,
                  metadata.destination_address, 16u) == 0);
    offset = control_length(sizeof(packet_info6));
    read_header(&copy, offset, &header);
    assert(header.cmsg_type == EDGE_LINUX_IPV6_HOPLIMIT);
    memcpy(&integer_value, copy.memory + offset + sizeof(header),
           sizeof(integer_value));
    assert(integer_value == 63);
    offset += control_length(sizeof(integer_value));
    read_header(&copy, offset, &header);
    assert(header.cmsg_type == EDGE_LINUX_IPV6_TCLASS);
    memcpy(&integer_value, copy.memory + offset + sizeof(header),
           sizeof(integer_value));
    assert(integer_value == 0xb8);
}

static uint64_t write_control_item(
        copy_mock_t *copy, uint64_t offset, int32_t level, int32_t type,
        const void *data, uint32_t data_length) {
    struct edge_linux_cmsghdr header;
    uint64_t item_length = sizeof(header) + data_length;
    uint64_t aligned = kernel_socket_control_align(item_length);

    assert(aligned != UINT64_MAX);
    assert(offset <= sizeof(copy->memory) - aligned);
    memset(&header, 0, sizeof(header));
    header.cmsg_len = item_length;
    header.cmsg_level = level;
    header.cmsg_type = type;
    memcpy(copy->memory + offset, &header, sizeof(header));
    if (data_length)
        memcpy(copy->memory + offset + sizeof(header), data, data_length);
    memset(copy->memory + offset + item_length, 0,
           (size_t)(aligned - item_length));
    return offset + aligned;
}

static void test_ip_send_metadata_policy(void) {
    copy_mock_t copy;
    kernel_socket_ip_send_metadata_t metadata;
    struct edge_linux_in_pktinfo packet_info4;
    struct edge_linux_in6_pktinfo packet_info6;
    uint64_t length = 0;
    int32_t value;

    copy_mock_initialize(&copy);
    memset(&packet_info4, 0, sizeof(packet_info4));
    packet_info4.ipi_ifindex = 3;
    memcpy(&packet_info4.ipi_spec_dst, "\x0a\x00\x00\x05", 4u);
    length = write_control_item(
        &copy, length, EDGE_LINUX_SOL_IP, EDGE_LINUX_IP_PKTINFO,
        &packet_info4, sizeof(packet_info4));
    value = 41;
    length = write_control_item(
        &copy, length, EDGE_LINUX_SOL_IP, EDGE_LINUX_IP_TTL,
        &value, sizeof(value));
    value = 0xb8;
    length = write_control_item(
        &copy, length, EDGE_LINUX_SOL_IP, EDGE_LINUX_IP_TOS,
        &value, sizeof(value));
    assert(kernel_socket_ip_send_control_parse(
               EDGE_LINUX_AF_INET, &copy, copy_from_user,
               TEST_USER_BASE, length, &metadata) == 0);
    assert(metadata.family == EDGE_LINUX_AF_INET);
    assert(metadata.has_interface && metadata.interface_index == 3u);
    assert(metadata.has_source_address);
    assert(memcmp(metadata.source_address,
                  &packet_info4.ipi_spec_dst, 4u) == 0);
    assert(metadata.has_hop_limit && metadata.hop_limit == 41);
    assert(metadata.has_traffic_class && metadata.traffic_class == 0xb8);

    copy_mock_initialize(&copy);
    memset(&packet_info6, 0, sizeof(packet_info6));
    packet_info6.ipi6_addr[15] = 1u;
    packet_info6.ipi6_ifindex = 7u;
    length = write_control_item(
        &copy, 0, EDGE_LINUX_SOL_IPV6, EDGE_LINUX_IPV6_PKTINFO,
        &packet_info6, sizeof(packet_info6));
    value = 62;
    length = write_control_item(
        &copy, length, EDGE_LINUX_SOL_IPV6, EDGE_LINUX_IPV6_HOPLIMIT,
        &value, sizeof(value));
    value = 0x80;
    length = write_control_item(
        &copy, length, EDGE_LINUX_SOL_IPV6, EDGE_LINUX_IPV6_TCLASS,
        &value, sizeof(value));
    assert(kernel_socket_ip_send_control_parse(
               EDGE_LINUX_AF_INET6, &copy, copy_from_user,
               TEST_USER_BASE, length, &metadata) == 0);
    assert(metadata.family == EDGE_LINUX_AF_INET6);
    assert(metadata.has_interface && metadata.interface_index == 7u);
    assert(metadata.has_source_address);
    assert(memcmp(metadata.source_address,
                  packet_info6.ipi6_addr, 16u) == 0);
    assert(metadata.has_hop_limit && metadata.hop_limit == 62);
    assert(metadata.has_traffic_class && metadata.traffic_class == 0x80);

    copy_mock_initialize(&copy);
    value = 256;
    length = write_control_item(
        &copy, 0, EDGE_LINUX_SOL_IPV6, EDGE_LINUX_IPV6_TCLASS,
        &value, sizeof(value));
    assert(kernel_socket_ip_send_control_parse(
               EDGE_LINUX_AF_INET6, &copy, copy_from_user,
               TEST_USER_BASE, length, &metadata) == -EDGE_LINUX_EINVAL);
}

static void test_legacy_append_fault_behavior_is_unchanged(void) {
    static const int32_t right = 49;
    copy_mock_t copy;
    uint64_t used = 0;
    int32_t flags = 0;

    copy_mock_initialize(&copy);
    copy.fail_call = 1u;
    assert(kernel_socket_control_append(
               &copy, copy_to_user, TEST_USER_BASE, sizeof(copy.memory),
               &used, &flags, EDGE_LINUX_SOL_SOCKET,
               KERNEL_SOCKET_SCM_RIGHTS,
               &right, sizeof(right)) == -EDGE_LINUX_EFAULT);
    assert(used == 0u);
    assert((flags & EDGE_LINUX_MSG_CTRUNC) == 0);
}

int kernel_socket_describe_descriptor(
    int32_t descriptor, kernel_socket_descriptor_info_t *info) {
    (void)descriptor;
    (void)info;
    return -EDGE_LINUX_EBADF;
}

int kernel_socket_rights_record_info(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_record_handle_t record,
        kernel_socket_rights_record_info_t *information) {
    (void)pool;
    (void)record;
    (void)information;
    return -EDGE_LINUX_ENOSYS;
}

int kernel_socket_rights_token_cursor_initialize(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_record_handle_t record,
        kernel_socket_rights_token_cursor_t *cursor) {
    (void)pool;
    (void)record;
    (void)cursor;
    return -EDGE_LINUX_ENOSYS;
}

int kernel_socket_rights_token_cursor_next(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_token_cursor_t *cursor,
        uint32_t *source_index,
        const kernel_fd_operation_lease_t **lease) {
    (void)pool;
    (void)cursor;
    (void)source_index;
    (void)lease;
    return -EDGE_LINUX_ENOSYS;
}

int kernel_fd_transfer_target_capture(
        kernel_fd_transfer_target_t *target) {
    (void)target;
    return -EDGE_LINUX_ENOSYS;
}

int kernel_fd_transfer_target_capture_for_owner(
        const void *owner,
        kernel_fd_transfer_target_t *target) {
    (void)owner;
    return kernel_fd_transfer_target_capture(target);
}

int kernel_fd_transfer_target_prepare(
        kernel_fd_transfer_target_t *target,
        const kernel_fd_operation_lease_t *source,
        uint32_t descriptor_flags,
        int32_t *descriptor) {
    (void)target;
    (void)source;
    (void)descriptor_flags;
    (void)descriptor;
    return -EDGE_LINUX_ENOSYS;
}

int kernel_fd_transfer_target_prepared_descriptor_at(
        const kernel_fd_transfer_target_t *target,
        uint32_t index, int32_t *descriptor) {
    (void)target;
    (void)index;
    (void)descriptor;
    return -EDGE_LINUX_ENOSYS;
}

int kernel_fd_transfer_target_publish_prefix(
        kernel_fd_transfer_target_t *target, uint32_t count) {
    (void)target;
    (void)count;
    return -EDGE_LINUX_ENOSYS;
}

int kernel_fd_transfer_target_abort_many(
        kernel_fd_transfer_target_t *target,
        const int32_t *descriptors, uint32_t count) {
    (void)target;
    (void)descriptors;
    (void)count;
    return -EDGE_LINUX_ENOSYS;
}

int kernel_fd_transfer_target_abort_all(
        kernel_fd_transfer_target_t *target) {
    (void)target;
    return -EDGE_LINUX_ENOSYS;
}

int kernel_fd_transfer_target_release(
        kernel_fd_transfer_target_t *target) {
    (void)target;
    return -EDGE_LINUX_ENOSYS;
}

uint64_t boottime_monotonic_us(void) {
    return 1000000u;
}

uint64_t boottime_realtime_us(void) {
    return 2000000u;
}

void linux_timespec_from_microseconds(
    uint64_t microseconds, linux_timespec64_t *value) {
    assert(value);
    value->tv_sec = (int64_t)(microseconds / 1000000u);
    value->tv_nsec = (int64_t)(microseconds % 1000000u) * 1000;
}

void linux_timeval_from_microseconds(
    uint64_t microseconds, linux_timeval64_t *value) {
    assert(value);
    value->tv_sec = (int64_t)(microseconds / 1000000u);
    value->tv_usec = (int64_t)(microseconds % 1000000u);
}

int main(void) {
    test_message_execute_entry();
    test_rights_success();
    test_rights_linux_maximum();
    test_rights_capacity_truncation();
    test_rights_header_only_capacity();
    test_rights_first_word_fault();
    test_rights_second_word_fault();
    test_rights_whole_control_fault();
    test_rights_prepare_failure();
    test_rights_publication_failure();
    test_rights_invalid_control_addresses();
    test_rights_preserve_committed_prefix();
    test_rights_limits_and_invalid_arguments();
    test_metadata_success();
    test_metadata_partial_capacity();
    test_metadata_faults();
    test_metadata_fault_preserves_prefix();
    test_metadata_capacity_and_address_edges();
    test_metadata_invalid_arguments();
    test_timestamp_metadata_policy();
    test_ip_receive_metadata_policy();
    test_ip_send_metadata_policy();
    test_legacy_append_fault_behavior_is_unchanged();
    puts("socket_message_unit: PASS");
    return 0;
}
