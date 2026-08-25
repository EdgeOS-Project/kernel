/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux socket message policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/socket_message.h"
#include "kernel/linux_errno.h"
#include "kernel/linux_time.h"
#include "sys/boottime.h"

#include <stddef.h>
#include <string.h>

_Static_assert(
    KERNEL_SOCKET_SCM_RIGHTS_MAX ==
        KERNEL_SOCKET_RIGHTS_MAX_DESCRIPTORS,
    "SCM_RIGHTS receive limits must remain unified");

int64_t kernel_socket_message_execute(
    const kernel_socket_message_request_t *request) {
    if (!request) return -EDGE_LINUX_EIO;
    return edge_socket_runtime_message_execute(request);
}

static int kernel_socket_message_validate_iovec(
        kernel_socket_user_message_t *message) {
    uint64_t total = 0;

    if (message->header.msg_iovlen > KERNEL_SOCKET_IOV_MAX)
        return -EDGE_LINUX_EMSGSIZE;
    if (message->header.msg_iovlen && !message->header.msg_iov)
        return -EDGE_LINUX_EFAULT;
    if (message->header.msg_iovlen >
        (UINT64_MAX - message->header.msg_iov) /
            (message->abi == KERNEL_SOCKET_MESSAGE_ABI_X32 ?
                sizeof(struct edge_linux_x32_iovec) :
                sizeof(struct edge_linux_iovec)))
        return -EDGE_LINUX_EFAULT;

    for (uint32_t index = 0;
         index < (uint32_t)message->header.msg_iovlen; ++index) {
        struct edge_linux_iovec iov;
        int status = kernel_socket_message_iovec(message, index, &iov);
        if (status < 0) return status;
        if (iov.iov_len > INT64_MAX - total)
            return -EDGE_LINUX_EINVAL;
        total += iov.iov_len;
    }
    message->payload_length = total;
    return 0;
}

int kernel_socket_message_import_abi(
    void *copy_context, edge_linux_copy_from_user_fn copy_from_user,
    uint64_t user_header, kernel_socket_message_abi_t abi,
    kernel_socket_user_message_t *message) {
    if (!message || !copy_from_user) return -EDGE_LINUX_EIO;
    memset(message, 0, sizeof(*message));
    if (!user_header) return -EDGE_LINUX_EFAULT;
    if (abi == KERNEL_SOCKET_MESSAGE_ABI_X32) {
        struct edge_linux_x32_msghdr compat_header;
        if (user_header > UINT32_MAX ||
            copy_from_user(copy_context, &compat_header, user_header,
                           sizeof(compat_header)) < 0)
            return -EDGE_LINUX_EFAULT;
        message->header.msg_name = compat_header.msg_name;
        message->header.msg_namelen = compat_header.msg_namelen;
        message->header.msg_iov = compat_header.msg_iov;
        message->header.msg_iovlen = compat_header.msg_iovlen;
        message->header.msg_control = compat_header.msg_control;
        message->header.msg_controllen = compat_header.msg_controllen;
        message->header.msg_flags = compat_header.msg_flags;
    } else if (copy_from_user(
            copy_context, &message->header, user_header,
            sizeof(message->header)) < 0) {
        return -EDGE_LINUX_EFAULT;
    }
    message->user_header = user_header;
    message->copy_context = copy_context;
    message->copy_from_user = copy_from_user;
    message->abi = abi;
    return kernel_socket_message_validate_iovec(message);
}

int kernel_socket_message_import(
    void *copy_context, edge_linux_copy_from_user_fn copy_from_user,
    uint64_t user_header, kernel_socket_user_message_t *message) {
    return kernel_socket_message_import_abi(
        copy_context, copy_from_user, user_header,
        KERNEL_SOCKET_MESSAGE_ABI_NATIVE, message);
}

int kernel_socket_message_import_iovec(
    void *copy_context, edge_linux_copy_from_user_fn copy_from_user,
    uint64_t user_iovec, uint64_t vector_count,
    kernel_socket_user_message_t *message) {
    if (!message || !copy_from_user) return -EDGE_LINUX_EIO;
    memset(message, 0, sizeof(*message));
    message->copy_context = copy_context;
    message->copy_from_user = copy_from_user;
    message->abi = KERNEL_SOCKET_MESSAGE_ABI_NATIVE;
    message->header.msg_iov = user_iovec;
    message->header.msg_iovlen = vector_count;
    return kernel_socket_message_validate_iovec(message);
}

int64_t kernel_socket_message_invoke_abi(
    int32_t descriptor, uint64_t user_header, uint32_t flags, int receiving,
    void *user_registers, void *copy_context,
    edge_linux_copy_from_user_fn copy_from_user,
    edge_linux_copy_to_user_fn copy_to_user,
    kernel_socket_message_abi_t abi) {
    kernel_socket_message_request_t request;
    kernel_socket_descriptor_info_t descriptor_info;
    int status;

    if (!copy_from_user || !copy_to_user) return -EDGE_LINUX_EIO;
    status = kernel_socket_describe_descriptor(descriptor, &descriptor_info);
    if (status < 0) return status;
    (void)descriptor_info;
    memset(&request, 0, sizeof(request));
    status = kernel_socket_message_import_abi(
        copy_context, copy_from_user, user_header, abi, &request.message);
    if (status < 0) return status;
    request.descriptor = descriptor;
    request.flags = flags;
    request.user_header = user_header;
    request.receiving = receiving != 0;
    request.user_registers = user_registers;
    request.copy_context = copy_context;
    request.copy_from_user = copy_from_user;
    request.copy_to_user = copy_to_user;
    return kernel_socket_message_execute(&request);
}

int64_t kernel_socket_message_invoke(
    int32_t descriptor, uint64_t user_header, uint32_t flags, int receiving,
    void *user_registers, void *copy_context,
    edge_linux_copy_from_user_fn copy_from_user,
    edge_linux_copy_to_user_fn copy_to_user) {
    return kernel_socket_message_invoke_abi(
        descriptor, user_header, flags, receiving, user_registers,
        copy_context, copy_from_user, copy_to_user,
        KERNEL_SOCKET_MESSAGE_ABI_NATIVE);
}

int kernel_socket_message_iovec(
    const kernel_socket_user_message_t *message, uint32_t index,
    struct edge_linux_iovec *iov) {
    uint64_t address;

    if (!message || !iov || !message->copy_from_user ||
        index >= message->header.msg_iovlen)
        return -EDGE_LINUX_EINVAL;
    if (message->abi == KERNEL_SOCKET_MESSAGE_ABI_X32) {
        struct edge_linux_x32_iovec compat_iov;
        address = message->header.msg_iov +
            (uint64_t)index * sizeof(compat_iov);
        if (message->copy_from_user(
                message->copy_context, &compat_iov, address,
                sizeof(compat_iov)) < 0)
            return -EDGE_LINUX_EFAULT;
        iov->iov_base = compat_iov.iov_base;
        iov->iov_len = compat_iov.iov_len;
        return 0;
    }
    address = message->header.msg_iov + (uint64_t)index * sizeof(*iov);
    return message->copy_from_user(
        message->copy_context, iov, address, sizeof(*iov)) < 0 ?
            -EDGE_LINUX_EFAULT : 0;
}

int kernel_socket_iovec_source_from_array(
    kernel_socket_iovec_source_t *source,
    const struct edge_linux_iovec *iov, uint32_t count) {
    uint64_t total = 0;

    if (!source || (count && !iov)) return -EDGE_LINUX_EINVAL;
    memset(source, 0, sizeof(*source));
    for (uint32_t index = 0; index < count; ++index) {
        if (iov[index].iov_len > INT64_MAX - total)
            return -EDGE_LINUX_EINVAL;
        total += iov[index].iov_len;
    }
    source->kernel_iov = iov;
    source->count = count;
    source->total_length = total;
    return 0;
}

void kernel_socket_iovec_source_from_message(
    kernel_socket_iovec_source_t *source,
    const kernel_socket_user_message_t *message) {
    if (!source) return;
    memset(source, 0, sizeof(*source));
    if (!message) return;
    source->user_message = message;
    source->count = (uint32_t)message->header.msg_iovlen;
    source->total_length = message->payload_length;
}

int kernel_socket_iovec_source_read(
    const kernel_socket_iovec_source_t *source, uint32_t index,
    struct edge_linux_iovec *iov) {
    if (!source || !iov || index >= source->count)
        return -EDGE_LINUX_EINVAL;
    if (source->kernel_iov) {
        *iov = source->kernel_iov[index];
        return 0;
    }
    if (!source->user_message) return -EDGE_LINUX_EINVAL;
    return kernel_socket_message_iovec(source->user_message, index, iov);
}

int kernel_socket_message_write_output(
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    const kernel_socket_user_message_t *message, uint32_t name_length,
    uint64_t control_length, int32_t flags) {
    uint64_t address;

    if (!message || !copy_to_user || !message->user_header)
        return -EDGE_LINUX_EIO;
    address = message->user_header +
        (message->abi == KERNEL_SOCKET_MESSAGE_ABI_X32 ?
            offsetof(struct edge_linux_x32_msghdr, msg_namelen) :
            offsetof(struct edge_linux_msghdr, msg_namelen));
    if (copy_to_user(copy_context, address, &name_length,
                     sizeof(name_length)) < 0)
        return -EDGE_LINUX_EFAULT;
    address = message->user_header +
        (message->abi == KERNEL_SOCKET_MESSAGE_ABI_X32 ?
            offsetof(struct edge_linux_x32_msghdr, msg_controllen) :
            offsetof(struct edge_linux_msghdr, msg_controllen));
    if (message->abi == KERNEL_SOCKET_MESSAGE_ABI_X32) {
        uint32_t compat_control_length = control_length > UINT32_MAX ?
            UINT32_MAX : (uint32_t)control_length;
        if (copy_to_user(copy_context, address, &compat_control_length,
                         sizeof(compat_control_length)) < 0)
            return -EDGE_LINUX_EFAULT;
    } else if (copy_to_user(copy_context, address, &control_length,
                            sizeof(control_length)) < 0) {
        return -EDGE_LINUX_EFAULT;
    }
    address = message->user_header +
        (message->abi == KERNEL_SOCKET_MESSAGE_ABI_X32 ?
            offsetof(struct edge_linux_x32_msghdr, msg_flags) :
            offsetof(struct edge_linux_msghdr, msg_flags));
    return copy_to_user(copy_context, address, &flags, sizeof(flags)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

int32_t kernel_socket_message_receive_output_flags(uint32_t receive_flags) {
    return (int32_t)(receive_flags & EDGE_LINUX_MSG_CMSG_CLOEXEC);
}

uint64_t kernel_socket_control_align(uint64_t length) {
    return length > UINT64_MAX - 7u ? UINT64_MAX : (length + 7u) & ~7ULL;
}

uint64_t kernel_socket_control_align_abi(
    uint64_t length, kernel_socket_message_abi_t abi) {
    if (abi == KERNEL_SOCKET_MESSAGE_ABI_X32)
        return length > UINT64_MAX - 3u ?
            UINT64_MAX : (length + 3u) & ~3ULL;
    return kernel_socket_control_align(length);
}

static uint64_t socket_control_header_size(
    kernel_socket_message_abi_t abi) {
    return abi == KERNEL_SOCKET_MESSAGE_ABI_X32 ?
        sizeof(struct edge_linux_x32_cmsghdr) :
        sizeof(struct edge_linux_cmsghdr);
}

void kernel_socket_control_cursor_initialize(
    kernel_socket_control_cursor_t *cursor, void *copy_context,
    edge_linux_copy_from_user_fn copy_from_user, uint64_t user_control,
    uint64_t control_length) {
    kernel_socket_control_cursor_initialize_abi(
        cursor, copy_context, copy_from_user, user_control, control_length,
        KERNEL_SOCKET_MESSAGE_ABI_NATIVE);
}

void kernel_socket_control_cursor_initialize_abi(
    kernel_socket_control_cursor_t *cursor, void *copy_context,
    edge_linux_copy_from_user_fn copy_from_user, uint64_t user_control,
    uint64_t control_length, kernel_socket_message_abi_t abi) {
    if (!cursor) return;
    memset(cursor, 0, sizeof(*cursor));
    cursor->copy_context = copy_context;
    cursor->copy_from_user = copy_from_user;
    cursor->user_control = user_control;
    cursor->control_length = control_length;
    cursor->abi = abi;
}

int kernel_socket_control_next(kernel_socket_control_cursor_t *cursor,
                               kernel_socket_control_item_t *item) {
    uint64_t remaining;
    uint64_t header_size;
    uint64_t aligned;
    uint64_t next;

    if (!cursor || !item || !cursor->copy_from_user)
        return -EDGE_LINUX_EIO;
    if (cursor->offset > cursor->control_length)
        return -EDGE_LINUX_EINVAL;
    remaining = cursor->control_length - cursor->offset;
    header_size = socket_control_header_size(cursor->abi);
    if (remaining < header_size) return 0;
    if (cursor->user_control > UINT64_MAX - cursor->offset)
        return -EDGE_LINUX_EFAULT;
    if (cursor->abi == KERNEL_SOCKET_MESSAGE_ABI_X32) {
        struct edge_linux_x32_cmsghdr compat_header;
        if (cursor->copy_from_user(
                cursor->copy_context, &compat_header,
                cursor->user_control + cursor->offset,
                sizeof(compat_header)) < 0)
            return -EDGE_LINUX_EFAULT;
        item->header.cmsg_len = compat_header.cmsg_len;
        item->header.cmsg_level = compat_header.cmsg_level;
        item->header.cmsg_type = compat_header.cmsg_type;
    } else if (cursor->copy_from_user(
            cursor->copy_context, &item->header,
            cursor->user_control + cursor->offset,
            sizeof(item->header)) < 0) {
        return -EDGE_LINUX_EFAULT;
    }
    if (item->header.cmsg_len < header_size ||
        item->header.cmsg_len > remaining)
        return -EDGE_LINUX_EINVAL;
    if (cursor->user_control + cursor->offset >
        UINT64_MAX - header_size)
        return -EDGE_LINUX_EFAULT;
    item->user_data = cursor->user_control + cursor->offset +
                      header_size;
    item->data_length = item->header.cmsg_len - header_size;
    aligned = kernel_socket_control_align_abi(
        item->header.cmsg_len, cursor->abi);
    if (aligned == UINT64_MAX || aligned > remaining)
        cursor->offset = cursor->control_length;
    else {
        next = cursor->offset + aligned;
        if (next < cursor->offset) return -EDGE_LINUX_EINVAL;
        cursor->offset = next;
    }
    return 1;
}

int kernel_socket_control_append(
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags, int32_t level, int32_t type,
    const void *data, uint32_t data_length) {
    struct edge_linux_cmsghdr header;
    uint64_t required;
    uint64_t aligned;
    uint64_t destination;

    if (!copy_to_user || !used || !message_flags ||
        (data_length && !data))
        return -EDGE_LINUX_EINVAL;
    required = sizeof(header) + data_length;
    aligned = kernel_socket_control_align(required);
    if (!user_control || *used > control_capacity ||
        required > control_capacity - *used) {
        *message_flags |= EDGE_LINUX_MSG_CTRUNC;
        return -EDGE_LINUX_ENOSPC;
    }
    if (user_control > UINT64_MAX - *used)
        return -EDGE_LINUX_EFAULT;
    destination = user_control + *used;
    if (destination > UINT64_MAX - required)
        return -EDGE_LINUX_EFAULT;
    memset(&header, 0, sizeof(header));
    header.cmsg_len = required;
    header.cmsg_level = level;
    header.cmsg_type = type;
    if (copy_to_user(copy_context, destination, &header, sizeof(header)) < 0 ||
        (data_length && copy_to_user(
            copy_context, destination + sizeof(header), data,
            data_length) < 0))
        return -EDGE_LINUX_EFAULT;
    if (aligned == UINT64_MAX || aligned > control_capacity - *used)
        *used = control_capacity;
    else
        *used += aligned;
    return 0;
}

int kernel_socket_control_receive_append(
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags, int32_t level, int32_t type,
    const void *data, uint32_t data_length,
    kernel_socket_control_receive_result_t *result) {
    uint64_t committed;
    int status;

    if (result)
        *result = KERNEL_SOCKET_CONTROL_RECEIVE_TRUNCATED;
    if (!copy_to_user || !used || !message_flags || !result ||
        (data_length && !data))
        return -EDGE_LINUX_EINVAL;

    committed = *used;
    status = kernel_socket_control_append(
        copy_context, copy_to_user, user_control, control_capacity, used,
        message_flags, level, type, data, data_length);
    if (status == 0) {
        *result = KERNEL_SOCKET_CONTROL_RECEIVE_APPENDED;
        return 0;
    }

    *used = committed;
    *message_flags |= EDGE_LINUX_MSG_CTRUNC;
    return 0;
}

static void socket_rights_discard_range(
    const kernel_socket_rights_receive_operations_t *operations,
    void *operations_context, uint32_t first, uint32_t count) {
    for (uint32_t index = first; index < count; ++index)
        operations->discard(operations_context, index);
}

static void socket_rights_abort_range(
    const kernel_socket_rights_receive_operations_t *operations,
    void *operations_context, const int32_t *descriptors,
    uint32_t first, uint32_t count) {
    for (uint32_t index = first; index < count; ++index)
        operations->abort(
            operations_context, index, descriptors[index]);
}

static int socket_control_copy_header(
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t destination, int32_t level, int32_t type,
    uint64_t data_length, kernel_socket_message_abi_t abi) {
    struct edge_linux_cmsghdr header;
    uint64_t header_size = socket_control_header_size(abi);

    if (data_length > UINT64_MAX - header_size)
        return -EDGE_LINUX_EFAULT;
    if (abi == KERNEL_SOCKET_MESSAGE_ABI_X32) {
        struct edge_linux_x32_cmsghdr compat_header;
        if (data_length > UINT32_MAX - sizeof(compat_header))
            return -EDGE_LINUX_EFAULT;
        memset(&compat_header, 0, sizeof(compat_header));
        compat_header.cmsg_len =
            (uint32_t)(sizeof(compat_header) + data_length);
        compat_header.cmsg_level = level;
        compat_header.cmsg_type = type;
        return copy_to_user(
            copy_context, destination, &compat_header,
            sizeof(compat_header)) < 0 ? -EDGE_LINUX_EFAULT : 0;
    }
    memset(&header, 0, sizeof(header));
    header.cmsg_len = sizeof(header) + data_length;
    header.cmsg_level = level;
    header.cmsg_type = type;
    return copy_to_user(
        copy_context, destination, &header, sizeof(header)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

int kernel_socket_control_receive_rights(
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags, uint32_t source_count,
    const kernel_socket_rights_receive_operations_t *operations,
    void *operations_context,
    kernel_socket_rights_receive_result_t *result) {
    int32_t descriptors[KERNEL_SOCKET_SCM_RIGHTS_MAX];
    uint64_t committed;
    uint64_t remaining;
    uint64_t destination;
    uint64_t initial_length;
    uint64_t final_length;
    uint64_t aligned;
    uint64_t capacity_count;
    uint32_t candidate_count;
    uint32_t header_count;
    uint32_t prepared_count = 0;
    uint32_t copied_count = 0;
    uint32_t published_count = 0;
    uint32_t discard_start;

    if (result) memset(result, 0, sizeof(*result));
    if (!used || !message_flags || !result ||
        source_count > KERNEL_SOCKET_SCM_RIGHTS_MAX)
        return -EDGE_LINUX_EINVAL;
    if (!source_count) return 0;
    if (!copy_to_user || !operations || !operations->prepare ||
        !operations->publish || !operations->abort ||
        !operations->discard)
        return -EDGE_LINUX_EINVAL;

    committed = *used;
    if (committed > control_capacity) {
        result->truncated = 1;
        *message_flags |= EDGE_LINUX_MSG_CTRUNC;
        socket_rights_discard_range(
            operations, operations_context, 0, source_count);
        return 0;
    }
    remaining = control_capacity - committed;
    if (remaining < sizeof(struct edge_linux_cmsghdr) + sizeof(int32_t)) {
        result->truncated = 1;
        *message_flags |= EDGE_LINUX_MSG_CTRUNC;
        socket_rights_discard_range(
            operations, operations_context, 0, source_count);
        return 0;
    }
    if (!user_control || user_control > UINT64_MAX - committed) {
        result->truncated = 1;
        result->control_fault = 1;
        *message_flags |= EDGE_LINUX_MSG_CTRUNC;
        socket_rights_discard_range(
            operations, operations_context, 0, source_count);
        return 0;
    }
    destination = user_control + committed;
    capacity_count =
        (remaining - sizeof(struct edge_linux_cmsghdr)) / sizeof(int32_t);
    candidate_count = capacity_count > source_count ?
        source_count : (uint32_t)capacity_count;
    header_count = candidate_count;
    initial_length = sizeof(struct edge_linux_cmsghdr) +
        (uint64_t)candidate_count * sizeof(int32_t);
    if (destination > UINT64_MAX - initial_length ||
        socket_control_copy_header(
            copy_context, copy_to_user, destination,
            EDGE_LINUX_SOL_SOCKET, KERNEL_SOCKET_SCM_RIGHTS,
            (uint64_t)candidate_count * sizeof(int32_t),
            KERNEL_SOCKET_MESSAGE_ABI_NATIVE) < 0) {
        result->truncated = 1;
        result->control_fault = 1;
        *message_flags |= EDGE_LINUX_MSG_CTRUNC;
        socket_rights_discard_range(
            operations, operations_context, 0, source_count);
        return 0;
    }

    discard_start = candidate_count;
    while (prepared_count < candidate_count) {
        int32_t descriptor = -1;
        int status = operations->prepare(
            operations_context, prepared_count, &descriptor);

        if (status != 0) {
            result->callback_status =
                status < 0 ? status : -EDGE_LINUX_EIO;
            discard_start = prepared_count;
            break;
        }
        if (descriptor < 0) {
            result->callback_status = -EDGE_LINUX_EIO;
            operations->abort(
                operations_context, prepared_count, descriptor);
            discard_start = prepared_count + 1u;
            break;
        }
        descriptors[prepared_count++] = descriptor;
    }

    while (copied_count < prepared_count) {
        uint64_t descriptor_destination = destination +
            sizeof(struct edge_linux_cmsghdr) +
            (uint64_t)copied_count * sizeof(int32_t);
        if (copy_to_user(
                copy_context, descriptor_destination,
                &descriptors[copied_count], sizeof(int32_t)) < 0) {
            result->control_fault = 1;
            break;
        }
        ++copied_count;
    }

    /*
     * Shorten the header before publishing a copy-limited prefix.  If the
     * header itself can no longer be reached, no descriptor is exposed.
     */
    if (copied_count && copied_count != candidate_count &&
        socket_control_copy_header(
            copy_context, copy_to_user, destination,
            EDGE_LINUX_SOL_SOCKET, KERNEL_SOCKET_SCM_RIGHTS,
            (uint64_t)copied_count * sizeof(int32_t),
            KERNEL_SOCKET_MESSAGE_ABI_NATIVE) < 0) {
        result->control_fault = 1;
        copied_count = 0;
    } else if (copied_count) {
        header_count = copied_count;
    }

    while (published_count < copied_count) {
        int status = operations->publish(
            operations_context, published_count,
            descriptors[published_count]);
        if (status != 0) {
            result->callback_status =
                status < 0 ? status : -EDGE_LINUX_EIO;
            break;
        }
        ++published_count;
    }

    socket_rights_abort_range(
        operations, operations_context, descriptors,
        published_count, prepared_count);
    socket_rights_discard_range(
        operations, operations_context, discard_start, source_count);

    result->delivered_count = published_count;
    result->truncated = published_count != source_count;
    if (result->truncated)
        *message_flags |= EDGE_LINUX_MSG_CTRUNC;
    if (!published_count) return 0;

    final_length = sizeof(struct edge_linux_cmsghdr) +
        (uint64_t)published_count * sizeof(int32_t);
    if (published_count != header_count &&
        socket_control_copy_header(
            copy_context, copy_to_user, destination,
            EDGE_LINUX_SOL_SOCKET, KERNEL_SOCKET_SCM_RIGHTS,
            (uint64_t)published_count * sizeof(int32_t),
            KERNEL_SOCKET_MESSAGE_ABI_NATIVE) < 0)
        result->control_fault = 1;

    if (result->truncated) {
        *used = committed + final_length;
        return 0;
    }
    aligned = kernel_socket_control_align(final_length);
    *used = aligned != UINT64_MAX && aligned <= remaining ?
        committed + aligned : committed + final_length;
    return 0;
}

/*
 * Both architecture backends make release infallible for a valid captured
 * table once the target owns no prepared descriptors: they clear the pinned
 * table pointer, drop that reference, and return success.  fd_runtime can
 * reject release only for a caller state violation or a backend contract
 * violation.  Returning in either case would abandon an address-stable token
 * and leak the pinned table, so this receive transaction fails closed.
 */
static void socket_rights_target_release_required(
        kernel_fd_transfer_target_t *target) {
    if (kernel_fd_transfer_target_release(target) < 0)
        __builtin_trap();
}

static void socket_rights_target_abort_and_release_required(
        kernel_fd_transfer_target_t *target) {
    if (kernel_fd_transfer_target_abort_all(target) < 0)
        __builtin_trap();
    socket_rights_target_release_required(target);
}

static int socket_rights_target_abort_suffix(
        kernel_fd_transfer_target_t *target,
        uint32_t retained_count, uint32_t prepared_count) {
    while (prepared_count > retained_count) {
        int32_t descriptor;
        int status;

        --prepared_count;
        status = kernel_fd_transfer_target_prepared_descriptor_at(
            target, prepared_count, &descriptor);
        if (status < 0) return status;
        status = kernel_fd_transfer_target_abort_many(
            target, &descriptor, 1u);
        if (status < 0) return status;
    }
    return 0;
}

static int socket_rights_target_cleanup_failure(
        kernel_fd_transfer_target_t *target, int original_status) {
    socket_rights_target_abort_and_release_required(target);
    return original_status;
}

int kernel_socket_control_receive_rights_record_abi(
    kernel_socket_rights_pool_t *pool,
    kernel_socket_rights_record_handle_t record,
    kernel_fd_transfer_target_t *target_workspace,
    const void *fd_owner, void *copy_context,
    edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags, uint32_t receive_flags,
    kernel_socket_rights_receive_result_t *result,
    kernel_socket_message_abi_t abi) {
    kernel_socket_rights_record_info_t information;
    kernel_socket_rights_token_cursor_t cursor;
    uint64_t committed;
    uint64_t remaining;
    uint64_t destination;
    uint64_t final_length;
    uint64_t aligned_length;
    uint64_t capacity_count;
    uint64_t header_size = socket_control_header_size(abi);
    uint32_t candidate_count;
    uint32_t prepared_count = 0;
    uint32_t copied_count = 0;
    uint32_t descriptor_flags;
    int prepare_limited = 0;
    int copy_limited = 0;
    int status;

    if (result) memset(result, 0, sizeof(*result));
    if (!pool || !record || !target_workspace || !copy_to_user ||
        !used || !message_flags || !result)
        return -EDGE_LINUX_EINVAL;

    status = kernel_socket_rights_record_info(
        pool, record, &information);
    if (status < 0) return status;
    if (information.state !=
            KERNEL_SOCKET_RIGHTS_RECORD_DETACHED &&
        information.state !=
            KERNEL_SOCKET_RIGHTS_RECORD_QUEUED)
        return -EDGE_LINUX_EBUSY;
    if (information.descriptor_count >
        KERNEL_SOCKET_SCM_RIGHTS_MAX)
        return -EDGE_LINUX_EINVAL;
    if (!information.descriptor_count) return 0;

    committed = *used;
    if (committed > control_capacity) {
        result->truncated = 1;
        *message_flags |= EDGE_LINUX_MSG_CTRUNC;
        return 0;
    }
    remaining = control_capacity - committed;
    if (remaining < header_size + sizeof(int32_t)) {
        result->truncated = 1;
        *message_flags |= EDGE_LINUX_MSG_CTRUNC;
        return 0;
    }
    if (!user_control || user_control > UINT64_MAX - committed) {
        result->truncated = 1;
        result->control_fault = 1;
        *message_flags |= EDGE_LINUX_MSG_CTRUNC;
        return 0;
    }
    destination = user_control + committed;
    capacity_count =
        (remaining - header_size) /
        sizeof(int32_t);
    candidate_count =
        capacity_count > information.descriptor_count ?
        information.descriptor_count : (uint32_t)capacity_count;
    final_length = header_size +
        (uint64_t)candidate_count * sizeof(int32_t);
    if (destination > UINT64_MAX - final_length) {
        result->truncated = 1;
        result->control_fault = 1;
        *message_flags |= EDGE_LINUX_MSG_CTRUNC;
        return 0;
    }

    status = kernel_socket_rights_token_cursor_initialize(
        pool, record, &cursor);
    if (status < 0) return status;
    status = kernel_fd_transfer_target_capture_for_owner(
        fd_owner, target_workspace);
    if (status < 0) return status;
    descriptor_flags =
        (receive_flags & EDGE_LINUX_MSG_CMSG_CLOEXEC) ?
        KERNEL_FD_CLOEXEC : 0u;

    while (prepared_count < candidate_count) {
        const kernel_fd_operation_lease_t *lease;
        uint32_t source_index;
        int32_t descriptor;

        status = kernel_socket_rights_token_cursor_next(
            pool, &cursor, &source_index, &lease);
        if (status != 1 || source_index != prepared_count || !lease) {
            status = status < 0 ? status : -EDGE_LINUX_EIO;
            return socket_rights_target_cleanup_failure(
                target_workspace, status);
        }
        status = kernel_fd_transfer_target_prepare(
            target_workspace, lease, descriptor_flags, &descriptor);
        if (status != 0) {
            result->callback_status =
                status < 0 ? status : -EDGE_LINUX_EIO;
            prepare_limited = 1;
            break;
        }
        ++prepared_count;
    }

    if (!prepared_count) {
        socket_rights_target_abort_and_release_required(
            target_workspace);
        result->truncated = 1;
        *message_flags |= EDGE_LINUX_MSG_CTRUNC;
        return 0;
    }

    status = socket_control_copy_header(
        copy_context, copy_to_user, destination,
        EDGE_LINUX_SOL_SOCKET, KERNEL_SOCKET_SCM_RIGHTS,
        (uint64_t)prepared_count * sizeof(int32_t), abi);
    if (status < 0) {
        status = socket_rights_target_cleanup_failure(
            target_workspace, status);
        if (status != -EDGE_LINUX_EFAULT) return status;
        result->truncated = 1;
        result->control_fault = 1;
        *message_flags |= EDGE_LINUX_MSG_CTRUNC;
        return 0;
    }

    while (copied_count < prepared_count) {
        uint64_t descriptor_destination =
            destination + header_size +
            (uint64_t)copied_count * sizeof(int32_t);
        int32_t descriptor;

        status = kernel_fd_transfer_target_prepared_descriptor_at(
            target_workspace, copied_count, &descriptor);
        if (status < 0)
            return socket_rights_target_cleanup_failure(
                target_workspace, status);
        if (copy_to_user(
                copy_context, descriptor_destination,
                &descriptor, sizeof(descriptor)) < 0) {
            result->control_fault = 1;
            copy_limited = 1;
            break;
        }
        ++copied_count;
    }

    if (copied_count && copied_count != prepared_count) {
        status = socket_control_copy_header(
            copy_context, copy_to_user, destination,
            EDGE_LINUX_SOL_SOCKET, KERNEL_SOCKET_SCM_RIGHTS,
            (uint64_t)copied_count * sizeof(int32_t), abi);
        if (status < 0) {
            result->control_fault = 1;
            copied_count = 0;
        }
    }

    status = socket_rights_target_abort_suffix(
        target_workspace, copied_count, prepared_count);
    if (status < 0)
        return socket_rights_target_cleanup_failure(
            target_workspace, status);

    if (!copied_count) {
        socket_rights_target_abort_and_release_required(
            target_workspace);
        result->truncated = 1;
        *message_flags |= EDGE_LINUX_MSG_CTRUNC;
        return 0;
    }

    status = kernel_fd_transfer_target_publish_prefix(
        target_workspace, copied_count);
    if (status != 0) {
        result->callback_status =
            status < 0 ? status : -EDGE_LINUX_EIO;
        socket_rights_target_abort_and_release_required(
            target_workspace);
        result->truncated = 1;
        *message_flags |= EDGE_LINUX_MSG_CTRUNC;
        return 0;
    }

    socket_rights_target_release_required(target_workspace);

    result->delivered_count = copied_count;
    result->truncated =
        copied_count != information.descriptor_count;
    if (result->truncated)
        *message_flags |= EDGE_LINUX_MSG_CTRUNC;

    final_length = header_size +
        (uint64_t)copied_count * sizeof(int32_t);
    aligned_length = kernel_socket_control_align_abi(final_length, abi);
    if (result->truncated &&
        (!prepare_limited || copy_limited)) {
        *used = committed + final_length;
    } else if (aligned_length != UINT64_MAX &&
               aligned_length <= remaining) {
        *used = committed + aligned_length;
    } else {
        *used = committed + final_length;
    }
    return 0;
}

int kernel_socket_control_receive_rights_record(
    kernel_socket_rights_pool_t *pool,
    kernel_socket_rights_record_handle_t record,
    kernel_fd_transfer_target_t *target_workspace,
    const void *fd_owner, void *copy_context,
    edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags, uint32_t receive_flags,
    kernel_socket_rights_receive_result_t *result) {
    return kernel_socket_control_receive_rights_record_abi(
        pool, record, target_workspace, fd_owner, copy_context,
        copy_to_user, user_control, control_capacity, used, message_flags,
        receive_flags, result, KERNEL_SOCKET_MESSAGE_ABI_NATIVE);
}

int kernel_socket_control_receive_metadata_append_abi(
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags, int32_t level, int32_t type,
    const void *data, uint32_t data_length,
    kernel_socket_control_receive_result_t *result,
    kernel_socket_message_abi_t abi) {
    uint64_t committed;
    uint64_t remaining;
    uint64_t destination;
    uint64_t required;
    uint64_t copied_length;
    uint64_t copied_data;
    uint64_t aligned;
    uint64_t header_size = socket_control_header_size(abi);

    if (result) *result = KERNEL_SOCKET_CONTROL_RECEIVE_FAULTED;
    if (!copy_to_user || !used || !message_flags || !result ||
        (data_length && !data))
        return -EDGE_LINUX_EINVAL;

    committed = *used;
    if (committed > control_capacity) {
        *message_flags |= EDGE_LINUX_MSG_CTRUNC;
        *result = KERNEL_SOCKET_CONTROL_RECEIVE_TRUNCATED;
        return 0;
    }
    remaining = control_capacity - committed;
    if (remaining < header_size) {
        *message_flags |= EDGE_LINUX_MSG_CTRUNC;
        *result = KERNEL_SOCKET_CONTROL_RECEIVE_TRUNCATED;
        return 0;
    }
    if (!user_control || user_control > UINT64_MAX - committed) return 0;
    destination = user_control + committed;
    required = header_size + (uint64_t)data_length;
    copied_length = required < remaining ? required : remaining;
    if (destination > UINT64_MAX - copied_length) return 0;

    if (socket_control_copy_header(
            copy_context, copy_to_user, destination, level, type,
            copied_length - header_size, abi) < 0)
        return 0;
    copied_data = copied_length - header_size;
    if (copied_data && copy_to_user(
            copy_context, destination + header_size,
            data, copied_data) < 0)
        return 0;

    if (copied_length < required) {
        *used = committed + copied_length;
        *message_flags |= EDGE_LINUX_MSG_CTRUNC;
        *result = KERNEL_SOCKET_CONTROL_RECEIVE_TRUNCATED;
        return 0;
    }
    aligned = kernel_socket_control_align_abi(required, abi);
    *used = aligned != UINT64_MAX && aligned <= remaining ?
        committed + aligned : committed + required;
    *result = KERNEL_SOCKET_CONTROL_RECEIVE_APPENDED;
    return 0;
}

int kernel_socket_control_receive_metadata_append(
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags, int32_t level, int32_t type,
    const void *data, uint32_t data_length,
    kernel_socket_control_receive_result_t *result) {
    return kernel_socket_control_receive_metadata_append_abi(
        copy_context, copy_to_user, user_control, control_capacity, used,
        message_flags, level, type, data, data_length, result,
        KERNEL_SOCKET_MESSAGE_ABI_NATIVE);
}

static int socket_ip_control_append_one(
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags, int32_t level, int32_t type,
    const void *data, uint32_t data_length,
    kernel_socket_control_receive_result_t *result,
    kernel_socket_message_abi_t abi) {
    int status;

    status = kernel_socket_control_receive_metadata_append_abi(
        copy_context, copy_to_user, user_control, control_capacity, used,
        message_flags, level, type, data, data_length, result, abi);
    if (status < 0 || *result != KERNEL_SOCKET_CONTROL_RECEIVE_APPENDED)
        return status;
    return 0;
}

int kernel_socket_ip_receive_control_append_abi(
    const kernel_socket_option_state_t *options,
    const kernel_socket_ip_receive_metadata_t *metadata,
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags,
    kernel_socket_control_receive_result_t *result,
    kernel_socket_message_abi_t abi) {
    int32_t integer_value;
    int status;

    if (result) *result = KERNEL_SOCKET_CONTROL_RECEIVE_APPENDED;
    if (!options || !metadata || !copy_to_user || !used ||
        !message_flags || !result)
        return -EDGE_LINUX_EINVAL;

    if (metadata->family == EDGE_LINUX_AF_INET) {
        if (options->ip_packet_info) {
            struct edge_linux_in_pktinfo packet_info;

            memset(&packet_info, 0, sizeof(packet_info));
            packet_info.ipi_ifindex = (int32_t)metadata->interface_index;
            memcpy(&packet_info.ipi_spec_dst,
                   metadata->local_address,
                   sizeof(packet_info.ipi_spec_dst));
            memcpy(&packet_info.ipi_addr,
                   metadata->destination_address,
                   sizeof(packet_info.ipi_addr));
            status = socket_ip_control_append_one(
                copy_context, copy_to_user, user_control, control_capacity,
                used, message_flags, EDGE_LINUX_SOL_IP,
                EDGE_LINUX_IP_PKTINFO, &packet_info, sizeof(packet_info),
                result, abi);
            if (status < 0 ||
                *result != KERNEL_SOCKET_CONTROL_RECEIVE_APPENDED)
                return status;
        }
        if (options->ip_receive_ttl) {
            integer_value = metadata->hop_limit;
            return socket_ip_control_append_one(
                copy_context, copy_to_user, user_control, control_capacity,
                used, message_flags, EDGE_LINUX_SOL_IP,
                EDGE_LINUX_IP_TTL, &integer_value, sizeof(integer_value),
                result, abi);
        }
        return 0;
    }

    if (metadata->family == EDGE_LINUX_AF_INET6) {
        if (options->ipv6_receive_packet_info) {
            struct edge_linux_in6_pktinfo packet_info;

            memset(&packet_info, 0, sizeof(packet_info));
            memcpy(packet_info.ipi6_addr, metadata->destination_address,
                   sizeof(packet_info.ipi6_addr));
            packet_info.ipi6_ifindex = metadata->interface_index;
            status = socket_ip_control_append_one(
                copy_context, copy_to_user, user_control, control_capacity,
                used, message_flags, EDGE_LINUX_SOL_IPV6,
                EDGE_LINUX_IPV6_PKTINFO, &packet_info, sizeof(packet_info),
                result, abi);
            if (status < 0 ||
                *result != KERNEL_SOCKET_CONTROL_RECEIVE_APPENDED)
                return status;
        }
        if (options->ipv6_receive_hop_limit) {
            integer_value = metadata->hop_limit;
            status = socket_ip_control_append_one(
                copy_context, copy_to_user, user_control, control_capacity,
                used, message_flags, EDGE_LINUX_SOL_IPV6,
                EDGE_LINUX_IPV6_HOPLIMIT, &integer_value,
                sizeof(integer_value), result, abi);
            if (status < 0 ||
                *result != KERNEL_SOCKET_CONTROL_RECEIVE_APPENDED)
                return status;
        }
        if (options->ipv6_receive_traffic_class) {
            integer_value = metadata->traffic_class;
            return socket_ip_control_append_one(
                copy_context, copy_to_user, user_control, control_capacity,
                used, message_flags, EDGE_LINUX_SOL_IPV6,
                EDGE_LINUX_IPV6_TCLASS, &integer_value,
                sizeof(integer_value), result, abi);
        }
        return 0;
    }

    return metadata->family ? -EDGE_LINUX_EAFNOSUPPORT : 0;
}

int kernel_socket_ip_receive_control_append(
    const kernel_socket_option_state_t *options,
    const kernel_socket_ip_receive_metadata_t *metadata,
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags,
    kernel_socket_control_receive_result_t *result) {
    return kernel_socket_ip_receive_control_append_abi(
        options, metadata, copy_context, copy_to_user, user_control,
        control_capacity, used, message_flags, result,
        KERNEL_SOCKET_MESSAGE_ABI_NATIVE);
}

static int socket_ip_send_control_copy(
        const kernel_socket_control_cursor_t *cursor,
        const kernel_socket_control_item_t *item,
        void *destination, uint32_t required) {
    if (!cursor || !item || !destination || item->data_length < required)
        return -EDGE_LINUX_EINVAL;
    return cursor->copy_from_user(
        cursor->copy_context, destination, item->user_data, required) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

int kernel_socket_ip_send_control_parse_abi(
    uint8_t family, void *copy_context,
    edge_linux_copy_from_user_fn copy_from_user,
    uint64_t user_control, uint64_t control_length,
    kernel_socket_ip_send_metadata_t *metadata,
    kernel_socket_message_abi_t abi) {
    kernel_socket_control_cursor_t cursor;

    if (!copy_from_user || !metadata ||
        (family != EDGE_LINUX_AF_INET &&
         family != EDGE_LINUX_AF_INET6))
        return -EDGE_LINUX_EINVAL;
    memset(metadata, 0, sizeof(*metadata));
    metadata->family = family;
    if (!control_length) return 0;
    kernel_socket_control_cursor_initialize_abi(
        &cursor, copy_context, copy_from_user,
        user_control, control_length, abi);
    for (;;) {
        kernel_socket_control_item_t item;
        int32_t integer_value;
        int status;
        int next = kernel_socket_control_next(&cursor, &item);

        if (next < 0) return next;
        if (!next) return 0;
        if (item.header.cmsg_level == (int32_t)EDGE_LINUX_SOL_SOCKET)
            continue;
        if (family == EDGE_LINUX_AF_INET &&
            item.header.cmsg_level == (int32_t)EDGE_LINUX_SOL_IP) {
            if (item.header.cmsg_type ==
                    (int32_t)EDGE_LINUX_IP_PKTINFO) {
                struct edge_linux_in_pktinfo packet_info;

                status = socket_ip_send_control_copy(
                    &cursor, &item, &packet_info, sizeof(packet_info));
                if (status < 0) return status;
                if (packet_info.ipi_ifindex < 0)
                    return -EDGE_LINUX_ENODEV;
                metadata->interface_index =
                    (uint32_t)packet_info.ipi_ifindex;
                metadata->has_interface =
                    metadata->interface_index != 0u;
                memcpy(metadata->source_address,
                       &packet_info.ipi_spec_dst, 4u);
                metadata->has_source_address =
                    packet_info.ipi_spec_dst != 0u;
                continue;
            }
            if (item.header.cmsg_type != (int32_t)EDGE_LINUX_IP_TTL &&
                item.header.cmsg_type != (int32_t)EDGE_LINUX_IP_TOS)
                return -EDGE_LINUX_EINVAL;
            status = socket_ip_send_control_copy(
                &cursor, &item, &integer_value, sizeof(integer_value));
            if (status < 0) return status;
            if (item.header.cmsg_type == (int32_t)EDGE_LINUX_IP_TTL) {
                if (integer_value < 1 || integer_value > 255)
                    return -EDGE_LINUX_EINVAL;
                metadata->hop_limit = integer_value;
                metadata->has_hop_limit = 1u;
            } else {
                if (integer_value < 0 || integer_value > 255)
                    return -EDGE_LINUX_EINVAL;
                metadata->traffic_class = integer_value;
                metadata->has_traffic_class = 1u;
            }
            continue;
        }
        if (family == EDGE_LINUX_AF_INET6 &&
            item.header.cmsg_level == (int32_t)EDGE_LINUX_SOL_IPV6) {
            if (item.header.cmsg_type ==
                    (int32_t)EDGE_LINUX_IPV6_PKTINFO) {
                struct edge_linux_in6_pktinfo packet_info;
                uint8_t any = 0u;

                status = socket_ip_send_control_copy(
                    &cursor, &item, &packet_info, sizeof(packet_info));
                if (status < 0) return status;
                metadata->interface_index = packet_info.ipi6_ifindex;
                metadata->has_interface =
                    metadata->interface_index != 0u;
                memcpy(metadata->source_address,
                       packet_info.ipi6_addr, 16u);
                for (uint32_t index = 0; index < 16u; ++index)
                    any |= packet_info.ipi6_addr[index];
                metadata->has_source_address = any != 0u;
                continue;
            }
            if (item.header.cmsg_type !=
                    (int32_t)EDGE_LINUX_IPV6_HOPLIMIT &&
                item.header.cmsg_type !=
                    (int32_t)EDGE_LINUX_IPV6_TCLASS)
                return -EDGE_LINUX_EINVAL;
            status = socket_ip_send_control_copy(
                &cursor, &item, &integer_value, sizeof(integer_value));
            if (status < 0) return status;
            if (integer_value < -1 || integer_value > 255)
                return -EDGE_LINUX_EINVAL;
            if (item.header.cmsg_type ==
                    (int32_t)EDGE_LINUX_IPV6_HOPLIMIT) {
                metadata->hop_limit = integer_value;
                metadata->has_hop_limit = integer_value >= 0;
            } else {
                metadata->traffic_class = integer_value;
                metadata->has_traffic_class = integer_value >= 0;
            }
            continue;
        }
        return -EDGE_LINUX_EINVAL;
    }
}

int kernel_socket_ip_send_control_parse(
    uint8_t family, void *copy_context,
    edge_linux_copy_from_user_fn copy_from_user,
    uint64_t user_control, uint64_t control_length,
    kernel_socket_ip_send_metadata_t *metadata) {
    return kernel_socket_ip_send_control_parse_abi(
        family, copy_context, copy_from_user, user_control, control_length,
        metadata, KERNEL_SOCKET_MESSAGE_ABI_NATIVE);
}

int kernel_socket_timestamp_control_append(
    kernel_socket_timestamp_mode_t mode, uint64_t timestamp_microseconds,
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags) {
    linux_timespec64_t timespec;
    linux_timeval64_t timeval;
    int32_t type;

    if (mode == KERNEL_SOCKET_TIMESTAMP_DISABLED) return 0;
    if (!timestamp_microseconds)
        timestamp_microseconds = boottime_realtime_us();
    switch (mode) {
        case KERNEL_SOCKET_TIMESTAMP_US_OLD:
        case KERNEL_SOCKET_TIMESTAMP_US_NEW:
            linux_timeval_from_microseconds(timestamp_microseconds, &timeval);
            type = mode == KERNEL_SOCKET_TIMESTAMP_US_OLD ?
                EDGE_LINUX_SO_TIMESTAMP : EDGE_LINUX_SO_TIMESTAMP_NEW;
            return kernel_socket_control_append(
                copy_context, copy_to_user, user_control, control_capacity,
                used, message_flags, EDGE_LINUX_SOL_SOCKET, type,
                &timeval, sizeof(timeval));
        case KERNEL_SOCKET_TIMESTAMP_NS_OLD:
        case KERNEL_SOCKET_TIMESTAMP_NS_NEW:
            linux_timespec_from_microseconds(timestamp_microseconds, &timespec);
            type = mode == KERNEL_SOCKET_TIMESTAMP_NS_OLD ?
                EDGE_LINUX_SO_TIMESTAMPNS : EDGE_LINUX_SO_TIMESTAMPNS_NEW;
            return kernel_socket_control_append(
                copy_context, copy_to_user, user_control, control_capacity,
                used, message_flags, EDGE_LINUX_SOL_SOCKET, type,
                &timespec, sizeof(timespec));
        default:
            return -EDGE_LINUX_EINVAL;
    }
}

int kernel_socket_timestamp_control_receive_append_abi(
    kernel_socket_timestamp_mode_t mode, uint64_t timestamp_microseconds,
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags,
    kernel_socket_control_receive_result_t *result,
    kernel_socket_message_abi_t abi) {
    linux_timespec64_t timespec;
    linux_timeval64_t timeval;
    int32_t type;

    if (mode == KERNEL_SOCKET_TIMESTAMP_DISABLED) {
        if (!result) return -EDGE_LINUX_EINVAL;
        *result = KERNEL_SOCKET_CONTROL_RECEIVE_APPENDED;
        return 0;
    }
    if (!timestamp_microseconds)
        timestamp_microseconds = boottime_realtime_us();
    switch (mode) {
        case KERNEL_SOCKET_TIMESTAMP_US_OLD:
        case KERNEL_SOCKET_TIMESTAMP_US_NEW:
            linux_timeval_from_microseconds(timestamp_microseconds, &timeval);
            type = mode == KERNEL_SOCKET_TIMESTAMP_US_OLD ?
                EDGE_LINUX_SO_TIMESTAMP : EDGE_LINUX_SO_TIMESTAMP_NEW;
            return kernel_socket_control_receive_metadata_append_abi(
                copy_context, copy_to_user, user_control, control_capacity,
                used, message_flags, EDGE_LINUX_SOL_SOCKET, type,
                &timeval, sizeof(timeval), result, abi);
        case KERNEL_SOCKET_TIMESTAMP_NS_OLD:
        case KERNEL_SOCKET_TIMESTAMP_NS_NEW:
            linux_timespec_from_microseconds(timestamp_microseconds, &timespec);
            type = mode == KERNEL_SOCKET_TIMESTAMP_NS_OLD ?
                EDGE_LINUX_SO_TIMESTAMPNS : EDGE_LINUX_SO_TIMESTAMPNS_NEW;
            return kernel_socket_control_receive_metadata_append_abi(
                copy_context, copy_to_user, user_control, control_capacity,
                used, message_flags, EDGE_LINUX_SOL_SOCKET, type,
                &timespec, sizeof(timespec), result, abi);
        default:
            return -EDGE_LINUX_EINVAL;
    }
}

int kernel_socket_timestamp_control_receive_append(
    kernel_socket_timestamp_mode_t mode, uint64_t timestamp_microseconds,
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags,
    kernel_socket_control_receive_result_t *result) {
    return kernel_socket_timestamp_control_receive_append_abi(
        mode, timestamp_microseconds, copy_context, copy_to_user,
        user_control, control_capacity, used, message_flags, result,
        KERNEL_SOCKET_MESSAGE_ABI_NATIVE);
}

int kernel_socket_mmsg_import_abi(
    uint64_t user_messages, uint64_t requested_count,
    uint32_t *effective_count, kernel_socket_message_abi_t abi) {
    uint64_t count;
    uint64_t entry_size = abi == KERNEL_SOCKET_MESSAGE_ABI_X32 ?
        sizeof(struct edge_linux_x32_mmsghdr) :
        sizeof(struct edge_linux_mmsghdr);

    if (!effective_count) return -EDGE_LINUX_EIO;
    *effective_count = 0;
    if (!requested_count) return 0;
    if (!user_messages) return -EDGE_LINUX_EFAULT;
    count = requested_count > KERNEL_SOCKET_IOV_MAX ?
        KERNEL_SOCKET_IOV_MAX : requested_count;
    if (count > (UINT64_MAX - user_messages) / entry_size)
        return -EDGE_LINUX_EFAULT;
    *effective_count = (uint32_t)count;
    return 0;
}

int kernel_socket_mmsg_import(uint64_t user_messages, uint64_t requested_count,
                              uint32_t *effective_count) {
    return kernel_socket_mmsg_import_abi(
        user_messages, requested_count, effective_count,
        KERNEL_SOCKET_MESSAGE_ABI_NATIVE);
}

int kernel_socket_mmsg_timeout_import(
    void *copy_context, edge_linux_copy_from_user_fn copy_from_user,
    uint64_t user_timeout, uint64_t *deadline_microseconds) {
    linux_timespec64_t timeout;
    uint64_t duration;
    uint64_t now;

    if (!deadline_microseconds || !copy_from_user)
        return -EDGE_LINUX_EIO;
    *deadline_microseconds = UINT64_MAX;
    if (!user_timeout) return 0;
    if (copy_from_user(copy_context, &timeout, user_timeout,
                       sizeof(timeout)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (timeout.tv_sec < 0 || timeout.tv_nsec < 0 ||
        timeout.tv_nsec >= 1000000000LL ||
        (uint64_t)timeout.tv_sec >
            (UINT64_MAX - (uint64_t)timeout.tv_nsec / 1000u) /
                1000000ULL)
        return -EDGE_LINUX_EINVAL;
    duration = (uint64_t)timeout.tv_sec * 1000000ULL +
               (uint64_t)timeout.tv_nsec / 1000ULL;
    now = boottime_monotonic_us();
    if (duration > UINT64_MAX - now) return -EDGE_LINUX_EINVAL;
    *deadline_microseconds = now + duration;
    return 0;
}

int kernel_socket_mmsg_timeout_write(
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_timeout, uint64_t deadline_microseconds) {
    linux_timespec64_t remaining;
    uint64_t now;
    uint64_t microseconds;

    if (!copy_to_user) return -EDGE_LINUX_EIO;
    if (!user_timeout) return 0;
    now = boottime_monotonic_us();
    microseconds = deadline_microseconds > now ?
        deadline_microseconds - now : 0u;
    linux_timespec_from_microseconds(microseconds, &remaining);
    return copy_to_user(copy_context, user_timeout, &remaining,
                        sizeof(remaining)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

int64_t kernel_socket_mmsg_run(
    const kernel_socket_mmsg_request_t *request, uint32_t first_message,
    int force_nonblocking, kernel_socket_message_call_fn call_message,
    void *call_context, uint32_t *completed_messages) {
    uint32_t completed = first_message;
    int64_t result = -EDGE_LINUX_EAGAIN;

    if (completed_messages) *completed_messages = first_message;
    if (!request || !request->copy_to_user || !call_message ||
        first_message > request->vector_length)
        return -EDGE_LINUX_EIO;

    while (completed < request->vector_length) {
        uint64_t entry_size =
            request->abi == KERNEL_SOCKET_MESSAGE_ABI_X32 ?
                sizeof(struct edge_linux_x32_mmsghdr) :
                sizeof(struct edge_linux_mmsghdr);
        uint64_t length_offset =
            request->abi == KERNEL_SOCKET_MESSAGE_ABI_X32 ?
                offsetof(struct edge_linux_x32_mmsghdr, msg_len) :
                offsetof(struct edge_linux_mmsghdr, msg_len);
        uint64_t entry = request->user_messages +
            (uint64_t)completed * entry_size;
        uint32_t call_flags = request->flags;
        uint32_t message_length;

        if (force_nonblocking || (request->receiving && completed > 0u))
            call_flags |= EDGE_LINUX_MSG_DONTWAIT;
        result = call_message(
            call_context, request->descriptor, entry, call_flags,
            request->user_registers);
        if (result < 0) {
            result = completed ? completed : result;
            break;
        }
        message_length = (uint32_t)result;
        if (request->copy_to_user(
                request->copy_context,
                entry + length_offset,
                &message_length, sizeof(message_length)) < 0) {
            result = completed ? (int64_t)completed :
                                 -EDGE_LINUX_EFAULT;
            break;
        }
        ++completed;
        result = completed;
        if (request->receiving && message_length == 0u) break;
    }
    if (completed_messages) *completed_messages = completed;
    return result;
}
