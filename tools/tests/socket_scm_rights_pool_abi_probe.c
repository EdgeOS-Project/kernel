/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Linux SCM_RIGHTS transfer-limit, lifetime, and receive-policy ABI probe.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_close_range
#if defined(__x86_64__) || defined(__aarch64__)
#define SYS_close_range 436
#else
#error "socket_scm_rights_pool_abi_probe requires close_range"
#endif
#endif

enum {
    LINUX_SCM_MAX_FD = 253,
    MAX_RECEIVED_RIGHTS = 254,
    CASE_TIMEOUT_SECONDS = 10,
};

struct received_message {
    ssize_t result;
    int saved_errno;
    int message_flags;
    size_t control_length;
    unsigned int header_count;
    size_t first_header_length;
    unsigned char payload;
    int descriptors[MAX_RECEIVED_RIGHTS];
    unsigned int descriptor_count;
};

typedef void (*test_function_t)(void);

static const char *active_case;

static _Noreturn void fail(const char *format, ...)
{
    va_list arguments;

    dprintf(STDERR_FILENO,
            "SOCKET_SCM_RIGHTS_POOL_ABI_PROBE_FAIL case=%s ",
            active_case != NULL ? active_case : "unknown");
    va_start(arguments, format);
    vdprintf(STDERR_FILENO, format, arguments);
    va_end(arguments);
    dprintf(STDERR_FILENO, "\n");
    _exit(EXIT_FAILURE);
}

static void require(bool condition, const char *format, ...)
{
    va_list arguments;

    if (condition) {
        return;
    }

    dprintf(STDERR_FILENO,
            "SOCKET_SCM_RIGHTS_POOL_ABI_PROBE_FAIL case=%s ",
            active_case != NULL ? active_case : "unknown");
    va_start(arguments, format);
    vdprintf(STDERR_FILENO, format, arguments);
    va_end(arguments);
    dprintf(STDERR_FILENO, "\n");
    _exit(EXIT_FAILURE);
}

static void close_checked(int descriptor)
{
    if (close(descriptor) != 0) {
        fail("close descriptor=%d errno=%d", descriptor, errno);
    }
}

static void ensure_standard_descriptors(void)
{
    int target;

    for (target = STDIN_FILENO; target <= STDERR_FILENO; target++) {
        int descriptor;

        errno = 0;
        if (fcntl(target, F_GETFD) >= 0) {
            continue;
        }
        require(errno == EBADF,
                "fcntl standard descriptor=%d errno=%d",
                target,
                errno);
        descriptor = open("/dev/null", O_RDWR | O_CLOEXEC);
        require(descriptor >= 0,
                "open /dev/null for standard descriptor=%d errno=%d",
                target,
                errno);
        if (descriptor != target) {
            require(dup2(descriptor, target) == target,
                    "dup2 standard descriptor=%d errno=%d",
                    target,
                    errno);
            close_checked(descriptor);
        }
    }
}

static void prepare_clean_descriptor_table(void)
{
    unsigned int descriptor;

    ensure_standard_descriptors();
    errno = 0;
    if (syscall(SYS_close_range, 3U, UINT_MAX, 0U) == 0) {
        return;
    }
    require(errno == ENOSYS,
            "close_range result=-1 errno=%d",
            errno);
    for (descriptor = 3; descriptor < 65536U; descriptor++) {
        (void)close((int)descriptor);
    }
}

static void create_socket_pair(int type, int sockets[2])
{
    require(socketpair(AF_UNIX,
                       type | SOCK_NONBLOCK | SOCK_CLOEXEC,
                       0,
                       sockets) == 0,
            "socketpair type=%d errno=%d",
            type,
            errno);
}

static void require_descriptor_open(int descriptor)
{
    require(fcntl(descriptor, F_GETFD) >= 0,
            "descriptor=%d is not open errno=%d",
            descriptor,
            errno);
}

static void require_descriptor_closed(int descriptor)
{
    int result;
    int saved_errno;

    errno = 0;
    result = fcntl(descriptor, F_GETFD);
    saved_errno = errno;
    require(result == -1 && saved_errno == EBADF,
            "descriptor=%d result=%d errno=%d expected=-1/EBADF",
            descriptor,
            result,
            saved_errno);
}

static ssize_t send_rights_chunks(int sender,
                                  const int *descriptors,
                                  const unsigned int *chunk_counts,
                                  unsigned int chunk_count,
                                  bool include_payload,
                                  unsigned char payload,
                                  int *saved_errno)
{
    struct iovec vector;
    struct msghdr message;
    unsigned char *control;
    unsigned char *cursor;
    size_t control_size = 0;
    unsigned int descriptor_index = 0;
    unsigned int chunk_index;
    ssize_t result;

    for (chunk_index = 0; chunk_index < chunk_count; chunk_index++) {
        size_t data_size = (size_t)chunk_counts[chunk_index] * sizeof(int);

        require(data_size <= SIZE_MAX - control_size,
                "control data size overflow");
        require(CMSG_SPACE(data_size) <= SIZE_MAX - control_size,
                "control buffer size overflow");
        control_size += CMSG_SPACE(data_size);
    }
    control = calloc(1, control_size);
    require(control != NULL,
            "calloc control size=%zu errno=%d",
            control_size,
            errno);

    memset(&message, 0, sizeof(message));
    vector.iov_base = &payload;
    vector.iov_len = include_payload ? sizeof(payload) : 0;
    if (include_payload) {
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
    }
    message.msg_control = control;
    message.msg_controllen = control_size;

    cursor = control;
    for (chunk_index = 0; chunk_index < chunk_count; chunk_index++) {
        struct cmsghdr *header = (struct cmsghdr *)(void *)cursor;
        size_t data_size =
            (size_t)chunk_counts[chunk_index] * sizeof(int);

        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(data_size);
        memcpy(CMSG_DATA(header),
               descriptors + descriptor_index,
               data_size);
        descriptor_index += chunk_counts[chunk_index];
        cursor += CMSG_SPACE(data_size);
    }

    errno = 0;
    result = sendmsg(sender, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
    *saved_errno = errno;
    free(control);
    return result;
}

static struct received_message receive_rights(int receiver,
                                              size_t control_capacity,
                                              int receive_flags)
{
    struct received_message received;
    struct iovec vector;
    struct msghdr message;
    struct cmsghdr *header;
    unsigned char *control = NULL;

    memset(&received, 0, sizeof(received));
    memset(&message, 0, sizeof(message));
    received.payload = 0;
    vector.iov_base = &received.payload;
    vector.iov_len = sizeof(received.payload);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    if (control_capacity != 0) {
        control = malloc(control_capacity);
        require(control != NULL,
                "malloc receive control size=%zu errno=%d",
                control_capacity,
                errno);
        memset(control, 0xa5, control_capacity);
        message.msg_control = control;
        message.msg_controllen = control_capacity;
    }

    errno = 0;
    received.result =
        recvmsg(receiver, &message, receive_flags | MSG_DONTWAIT);
    received.saved_errno = errno;
    received.message_flags = message.msg_flags;
    received.control_length = message.msg_controllen;
    if (received.result < 0) {
        free(control);
        return received;
    }

    for (header = CMSG_FIRSTHDR(&message);
         header != NULL;
         header = CMSG_NXTHDR(&message, header)) {
        size_t data_size;
        unsigned int descriptor_count;

        require(header->cmsg_len >= CMSG_LEN(0),
                "received cmsg_len=%zu is smaller than header",
                (size_t)header->cmsg_len);
        require(header->cmsg_level == SOL_SOCKET &&
                    header->cmsg_type == SCM_RIGHTS,
                "received unexpected cmsg level=%d type=%d",
                header->cmsg_level,
                header->cmsg_type);
        data_size = header->cmsg_len - CMSG_LEN(0);
        require(data_size % sizeof(int) == 0,
                "received SCM_RIGHTS data size=%zu is misaligned",
                data_size);
        descriptor_count = (unsigned int)(data_size / sizeof(int));
        require(descriptor_count <=
                    MAX_RECEIVED_RIGHTS - received.descriptor_count,
                "received too many descriptors count=%u",
                received.descriptor_count + descriptor_count);
        if (received.header_count == 0) {
            received.first_header_length = header->cmsg_len;
        }
        memcpy(received.descriptors + received.descriptor_count,
               CMSG_DATA(header),
               data_size);
        received.descriptor_count += descriptor_count;
        received.header_count++;
    }

    free(control);
    return received;
}

static void close_received_descriptors(struct received_message *received)
{
    unsigned int index;

    for (index = 0; index < received->descriptor_count; index++) {
        close_checked(received->descriptors[index]);
        received->descriptors[index] = -1;
    }
    received->descriptor_count = 0;
}

static void require_queue_empty(int receiver, const char *stage)
{
    unsigned char byte = 0;
    ssize_t result;
    int saved_errno;

    errno = 0;
    result = recv(receiver, &byte, sizeof(byte), MSG_DONTWAIT);
    saved_errno = errno;
    require(result == -1 &&
                (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK),
            "%s queue result=%zd errno=%d expected=-1/EAGAIN",
            stage,
            result,
            saved_errno);
}

static void fill_repeated_descriptor(int *descriptors,
                                     unsigned int count,
                                     int descriptor)
{
    unsigned int index;

    for (index = 0; index < count; index++) {
        descriptors[index] = descriptor;
    }
}

static int create_tagged_memfd(unsigned int tag)
{
    unsigned char value = (unsigned char)tag;
    int descriptor;

    descriptor = memfd_create("edgeos-scm-rights-probe", MFD_CLOEXEC);
    require(descriptor >= 0,
            "memfd_create tag=%u errno=%d",
            tag,
            errno);
    require(write(descriptor, &value, sizeof(value)) ==
                (ssize_t)sizeof(value),
            "write memfd tag=%u errno=%d",
            tag,
            errno);
    require(lseek(descriptor, 0, SEEK_SET) == 0,
            "lseek memfd tag=%u errno=%d",
            tag,
            errno);
    return descriptor;
}

static void require_tagged_descriptor(int descriptor, unsigned int tag)
{
    unsigned char value = 0;

    require(read(descriptor, &value, sizeof(value)) ==
                (ssize_t)sizeof(value),
            "read received tagged descriptor=%d tag=%u errno=%d",
            descriptor,
            tag,
            errno);
    require(value == (unsigned char)tag,
            "received tagged descriptor=%d value=%u expected=%u",
            descriptor,
            (unsigned int)value,
            tag);
}

static void test_maximum_transfer(void)
{
    int sockets[2];
    int source;
    int descriptors[LINUX_SCM_MAX_FD];
    unsigned int chunks[] = {LINUX_SCM_MAX_FD};
    struct received_message received;
    ssize_t result;
    int saved_errno;
    unsigned int index;

    create_socket_pair(SOCK_DGRAM, sockets);
    source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    require(source >= 0, "open maximum-transfer source errno=%d", errno);
    fill_repeated_descriptor(descriptors, LINUX_SCM_MAX_FD, source);

    result = send_rights_chunks(sockets[0],
                                descriptors,
                                chunks,
                                1,
                                true,
                                'M',
                                &saved_errno);
    require(result == 1 && saved_errno == 0,
            "send 253 rights result=%zd errno=%d",
            result,
            saved_errno);
    close_checked(source);

    received = receive_rights(
        sockets[1],
        CMSG_SPACE((size_t)LINUX_SCM_MAX_FD * sizeof(int)),
        0);
    require(received.result == 1 && received.saved_errno == 0,
            "receive 253 rights result=%zd errno=%d",
            received.result,
            received.saved_errno);
    require(received.payload == 'M',
            "receive 253 rights payload=%u",
            (unsigned int)received.payload);
    require((received.message_flags & MSG_CTRUNC) == 0,
            "receive 253 rights flags=0x%x",
            received.message_flags);
    require(received.descriptor_count == LINUX_SCM_MAX_FD,
            "receive 253 rights count=%u",
            received.descriptor_count);
    require(received.header_count == 1,
            "receive 253 rights headers=%u",
            received.header_count);
    require(received.first_header_length ==
                CMSG_LEN((size_t)LINUX_SCM_MAX_FD * sizeof(int)),
            "receive 253 rights cmsg_len=%zu expected=%zu",
            received.first_header_length,
            (size_t)CMSG_LEN(
                (size_t)LINUX_SCM_MAX_FD * sizeof(int)));
    require(received.control_length ==
                CMSG_SPACE((size_t)LINUX_SCM_MAX_FD * sizeof(int)),
            "receive 253 rights controllen=%zu expected=%zu",
            received.control_length,
            (size_t)CMSG_SPACE(
                (size_t)LINUX_SCM_MAX_FD * sizeof(int)));
    for (index = 0; index < received.descriptor_count; index++) {
        require_descriptor_open(received.descriptors[index]);
    }
    dprintf(STDOUT_FILENO,
            "OBS case=%s sent=253 received=%u headers=%u "
            "flags=0x%x controllen=%zu cmsg_len=%zu\n",
            active_case,
            received.descriptor_count,
            received.header_count,
            received.message_flags,
            received.control_length,
            received.first_header_length);

    close_received_descriptors(&received);
    require_queue_empty(sockets[1], "maximum transfer");
    close_checked(sockets[0]);
    close_checked(sockets[1]);
}

static void test_transfer_limit_and_multiple_headers(void)
{
    int sockets[2];
    int source;
    int descriptors[MAX_RECEIVED_RIGHTS];
    unsigned int one_too_many[] = {LINUX_SCM_MAX_FD + 1};
    unsigned int split_maximum[] = {126, 127};
    unsigned int split_too_many[] = {126, 128};
    struct received_message received;
    ssize_t single_result;
    ssize_t split_success_result;
    ssize_t split_failure_result;
    int single_errno;
    int split_success_errno;
    int split_failure_errno;

    create_socket_pair(SOCK_DGRAM, sockets);
    source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    require(source >= 0, "open transfer-limit source errno=%d", errno);
    fill_repeated_descriptor(descriptors,
                             MAX_RECEIVED_RIGHTS,
                             source);

    single_result = send_rights_chunks(sockets[0],
                                       descriptors,
                                       one_too_many,
                                       1,
                                       true,
                                       '1',
                                       &single_errno);
    require(single_result == -1 && single_errno == EINVAL,
            "single 254 send result=%zd errno=%d expected=-1/EINVAL",
            single_result,
            single_errno);
    require_queue_empty(sockets[1], "single 254 rejection");

    split_success_result = send_rights_chunks(sockets[0],
                                              descriptors,
                                              split_maximum,
                                              2,
                                              true,
                                              '2',
                                              &split_success_errno);
    require(split_success_result == 1 && split_success_errno == 0,
            "split 126+127 send result=%zd errno=%d",
            split_success_result,
            split_success_errno);
    received = receive_rights(
        sockets[1],
        CMSG_SPACE((size_t)LINUX_SCM_MAX_FD * sizeof(int)),
        0);
    require(received.result == 1 &&
                received.payload == '2' &&
                received.descriptor_count == LINUX_SCM_MAX_FD &&
                (received.message_flags & MSG_CTRUNC) == 0,
            "split 126+127 receive result=%zd errno=%d payload=%u "
            "count=%u flags=0x%x",
            received.result,
            received.saved_errno,
            (unsigned int)received.payload,
            received.descriptor_count,
            received.message_flags);
    require(received.header_count == 1,
            "split 126+127 receive headers=%u expected=1",
            received.header_count);
    close_received_descriptors(&received);

    split_failure_result = send_rights_chunks(sockets[0],
                                              descriptors,
                                              split_too_many,
                                              2,
                                              true,
                                              '3',
                                              &split_failure_errno);
    require(split_failure_result == -1 && split_failure_errno == EINVAL,
            "split 126+128 send result=%zd errno=%d expected=-1/EINVAL",
            split_failure_result,
            split_failure_errno);
    require_queue_empty(sockets[1], "split 126+128 rejection");

    dprintf(STDOUT_FILENO,
            "OBS case=%s single254_result=%zd single254_errno=%d "
            "split253_result=%zd split253_errno=%d "
            "split253_receive_headers=1 split254_result=%zd "
            "split254_errno=%d\n",
            active_case,
            single_result,
            single_errno,
            split_success_result,
            split_success_errno,
            split_failure_result,
            split_failure_errno);

    close_checked(source);
    close_checked(sockets[0]);
    close_checked(sockets[1]);
}

static void test_zero_payload(void)
{
    int datagram_sockets[2];
    int stream_sockets[2];
    int datagram_source;
    int stream_source;
    int descriptors[1];
    unsigned int chunks[] = {1};
    struct received_message received;
    ssize_t result;
    int saved_errno;
    int stream_empty_errno;
    unsigned char payload = 'S';

    create_socket_pair(SOCK_DGRAM, datagram_sockets);
    datagram_source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    require(datagram_source >= 0,
            "open zero-payload datagram source errno=%d",
            errno);
    descriptors[0] = datagram_source;
    result = send_rights_chunks(datagram_sockets[0],
                                descriptors,
                                chunks,
                                1,
                                false,
                                0,
                                &saved_errno);
    require(result == 0 && saved_errno == 0,
            "zero-payload datagram send result=%zd errno=%d",
            result,
            saved_errno);
    close_checked(datagram_source);
    received = receive_rights(
        datagram_sockets[1],
        CMSG_SPACE(sizeof(int)),
        0);
    require(received.result == 0 &&
                received.saved_errno == 0 &&
                received.descriptor_count == 1 &&
                (received.message_flags & MSG_CTRUNC) == 0,
            "zero-payload datagram receive result=%zd errno=%d "
            "count=%u flags=0x%x",
            received.result,
            received.saved_errno,
            received.descriptor_count,
            received.message_flags);
    close_received_descriptors(&received);
    close_checked(datagram_sockets[0]);
    close_checked(datagram_sockets[1]);

    create_socket_pair(SOCK_STREAM, stream_sockets);
    stream_source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    require(stream_source >= 0,
            "open zero-payload stream source errno=%d",
            errno);
    descriptors[0] = stream_source;
    result = send_rights_chunks(stream_sockets[0],
                                descriptors,
                                chunks,
                                1,
                                false,
                                0,
                                &saved_errno);
    require(result == 0 && saved_errno == 0,
            "zero-payload stream send result=%zd errno=%d",
            result,
            saved_errno);
    close_checked(stream_source);
    received = receive_rights(
        stream_sockets[1],
        CMSG_SPACE(sizeof(int)),
        0);
    require(received.result == -1 &&
                (received.saved_errno == EAGAIN ||
                 received.saved_errno == EWOULDBLOCK) &&
                received.descriptor_count == 0,
            "zero-payload stream immediate receive result=%zd errno=%d "
            "count=%u",
            received.result,
            received.saved_errno,
            received.descriptor_count);
    stream_empty_errno = received.saved_errno;
    require(send(stream_sockets[0],
                 &payload,
                 sizeof(payload),
                 MSG_DONTWAIT | MSG_NOSIGNAL) ==
                (ssize_t)sizeof(payload),
            "send stream payload after zero-payload control errno=%d",
            errno);
    received = receive_rights(
        stream_sockets[1],
        CMSG_SPACE(sizeof(int)),
        0);
    require(received.result == 1 &&
                received.saved_errno == 0 &&
                received.payload == payload &&
                received.descriptor_count == 0,
            "stream receive after zero-payload control result=%zd "
            "errno=%d payload=%u count=%u",
            received.result,
            received.saved_errno,
            (unsigned int)received.payload,
            received.descriptor_count);
    require_queue_empty(stream_sockets[1],
                        "zero-payload stream follow-up");
    close_checked(stream_sockets[0]);
    close_checked(stream_sockets[1]);

    dprintf(STDOUT_FILENO,
            "OBS case=%s datagram_send=0 datagram_receive=0 "
            "datagram_rights=1 stream_send=0 "
            "stream_immediate_errno=%d stream_followup_rights=0\n",
            active_case,
            stream_empty_errno);
}

static void check_plain_read_discards(int socket_type, const char *name)
{
    int sockets[2];
    int pipe_descriptors[2];
    int descriptors[1];
    unsigned int chunks[] = {1};
    unsigned char queued_payload = 'D';
    unsigned char observed_payload = 0;
    unsigned char pipe_payload = 0;
    ssize_t result;
    int saved_errno;

    create_socket_pair(socket_type, sockets);
    require(pipe2(pipe_descriptors, O_NONBLOCK | O_CLOEXEC) == 0,
            "%s pipe2 errno=%d",
            name,
            errno);
    descriptors[0] = pipe_descriptors[1];
    result = send_rights_chunks(sockets[0],
                                descriptors,
                                chunks,
                                1,
                                true,
                                queued_payload,
                                &saved_errno);
    require(result == 1 && saved_errno == 0,
            "%s send right result=%zd errno=%d",
            name,
            result,
            saved_errno);
    close_checked(pipe_descriptors[1]);

    errno = 0;
    result = read(pipe_descriptors[0],
                  &pipe_payload,
                  sizeof(pipe_payload));
    saved_errno = errno;
    require(result == -1 &&
                (saved_errno == EAGAIN ||
                 saved_errno == EWOULDBLOCK),
            "%s pipe before plain read result=%zd errno=%d",
            name,
            result,
            saved_errno);

    errno = 0;
    result = read(sockets[1],
                  &observed_payload,
                  sizeof(observed_payload));
    saved_errno = errno;
    require(result == 1 &&
                saved_errno == 0 &&
                observed_payload == queued_payload,
            "%s plain read result=%zd errno=%d payload=%u",
            name,
            result,
            saved_errno,
            (unsigned int)observed_payload);
    require_descriptor_closed(pipe_descriptors[1]);

    errno = 0;
    result = read(pipe_descriptors[0],
                  &pipe_payload,
                  sizeof(pipe_payload));
    saved_errno = errno;
    require(result == 0 && saved_errno == 0,
            "%s pipe after plain read result=%zd errno=%d expected=EOF",
            name,
            result,
            saved_errno);
    require_queue_empty(sockets[1], name);

    dprintf(STDOUT_FILENO,
            "OBS case=%s socket=%s plain_read=%zd "
            "queued_writer_before=alive queued_writer_after=eof "
            "installed_rights=0\n",
            active_case,
            name,
            (ssize_t)1);

    close_checked(pipe_descriptors[0]);
    close_checked(sockets[0]);
    close_checked(sockets[1]);
}

static void test_plain_read_discard(void)
{
    check_plain_read_discards(SOCK_STREAM, "stream");
    check_plain_read_discards(SOCK_DGRAM, "datagram");
}

static void check_peek_nonconsumption(int socket_type, const char *name)
{
    int sockets[2];
    int pipe_descriptors[2];
    int descriptors[1];
    unsigned int chunks[] = {1};
    struct received_message first;
    struct received_message second;
    struct received_message consumed;
    int status_flags;
    ssize_t result;
    int saved_errno;
    unsigned char pipe_payload = 'P';
    unsigned char observed = 0;

    create_socket_pair(socket_type, sockets);
    require(pipe2(pipe_descriptors, O_CLOEXEC) == 0,
            "%s peek pipe2 errno=%d",
            name,
            errno);
    descriptors[0] = pipe_descriptors[0];
    result = send_rights_chunks(sockets[0],
                                descriptors,
                                chunks,
                                1,
                                true,
                                'K',
                                &saved_errno);
    require(result == 1 && saved_errno == 0,
            "%s peek send result=%zd errno=%d",
            name,
            result,
            saved_errno);
    close_checked(pipe_descriptors[0]);

    first = receive_rights(
        sockets[1],
        CMSG_SPACE(sizeof(int)),
        MSG_PEEK);
    require(first.result == 1 &&
                first.saved_errno == 0 &&
                first.payload == 'K' &&
                first.descriptor_count == 1,
            "%s first peek result=%zd errno=%d payload=%u count=%u",
            name,
            first.result,
            first.saved_errno,
            (unsigned int)first.payload,
            first.descriptor_count);
    status_flags = fcntl(first.descriptors[0], F_GETFL);
    require(status_flags >= 0 &&
                fcntl(first.descriptors[0],
                      F_SETFL,
                      status_flags | O_NONBLOCK) == 0,
            "%s set shared O_NONBLOCK errno=%d",
            name,
            errno);

    second = receive_rights(
        sockets[1],
        CMSG_SPACE(sizeof(int)),
        MSG_PEEK);
    require(second.result == 1 &&
                second.saved_errno == 0 &&
                second.payload == 'K' &&
                second.descriptor_count == 1,
            "%s second peek result=%zd errno=%d payload=%u count=%u",
            name,
            second.result,
            second.saved_errno,
            (unsigned int)second.payload,
            second.descriptor_count);
    status_flags = fcntl(second.descriptors[0], F_GETFL);
    require(status_flags >= 0 && (status_flags & O_NONBLOCK) != 0,
            "%s second peek did not preserve shared status flags=0x%x",
            name,
            status_flags);

    consumed = receive_rights(
        sockets[1],
        CMSG_SPACE(sizeof(int)),
        0);
    require(consumed.result == 1 &&
                consumed.saved_errno == 0 &&
                consumed.payload == 'K' &&
                consumed.descriptor_count == 1,
            "%s consuming receive result=%zd errno=%d payload=%u "
            "count=%u",
            name,
            consumed.result,
            consumed.saved_errno,
            (unsigned int)consumed.payload,
            consumed.descriptor_count);
    status_flags = fcntl(consumed.descriptors[0], F_GETFL);
    require(status_flags >= 0 && (status_flags & O_NONBLOCK) != 0,
            "%s consumed right did not preserve shared status flags=0x%x",
            name,
            status_flags);
    require_queue_empty(sockets[1], name);

    require(write(pipe_descriptors[1],
                  &pipe_payload,
                  sizeof(pipe_payload)) ==
                (ssize_t)sizeof(pipe_payload),
            "%s write through retained pipe errno=%d",
            name,
            errno);
    require(read(consumed.descriptors[0],
                 &observed,
                 sizeof(observed)) ==
                (ssize_t)sizeof(observed) &&
                observed == pipe_payload,
            "%s read through consumed right result byte=%u errno=%d",
            name,
            (unsigned int)observed,
            errno);

    dprintf(STDOUT_FILENO,
            "OBS case=%s socket=%s first_peek_rights=1 "
            "second_peek_rights=1 consume_rights=1 "
            "message_consumed_only_by_nonpeek=1\n",
            active_case,
            name);

    close_received_descriptors(&first);
    close_received_descriptors(&second);
    close_received_descriptors(&consumed);
    close_checked(pipe_descriptors[1]);
    close_checked(sockets[0]);
    close_checked(sockets[1]);
}

static void test_peek_nonconsumption(void)
{
    check_peek_nonconsumption(SOCK_STREAM, "stream");
    check_peek_nonconsumption(SOCK_DGRAM, "datagram");
}

static void test_control_truncation_prefix(void)
{
    enum { SOURCE_COUNT = 8, RECEIVE_COUNT = 3 };
    int sockets[2];
    int sources[SOURCE_COUNT];
    unsigned int chunks[] = {SOURCE_COUNT};
    struct received_message received;
    ssize_t result;
    int saved_errno;
    unsigned int index;
    size_t capacity = CMSG_LEN(RECEIVE_COUNT * sizeof(int));

    create_socket_pair(SOCK_DGRAM, sockets);
    for (index = 0; index < SOURCE_COUNT; index++) {
        sources[index] = create_tagged_memfd(index);
    }
    result = send_rights_chunks(sockets[0],
                                sources,
                                chunks,
                                1,
                                true,
                                'T',
                                &saved_errno);
    require(result == 1 && saved_errno == 0,
            "control truncation send result=%zd errno=%d",
            result,
            saved_errno);
    for (index = 0; index < SOURCE_COUNT; index++) {
        close_checked(sources[index]);
    }

    received = receive_rights(sockets[1], capacity, 0);
    require(received.result == 1 &&
                received.saved_errno == 0 &&
                received.payload == 'T',
            "control truncation receive result=%zd errno=%d payload=%u",
            received.result,
            received.saved_errno,
            (unsigned int)received.payload);
    require((received.message_flags & MSG_CTRUNC) != 0,
            "control truncation flags=0x%x missing MSG_CTRUNC",
            received.message_flags);
    require(received.descriptor_count == RECEIVE_COUNT,
            "control truncation received=%u expected=%u",
            received.descriptor_count,
            RECEIVE_COUNT);
    require(received.control_length == capacity &&
                received.first_header_length == capacity,
            "control truncation controllen=%zu cmsg_len=%zu expected=%zu",
            received.control_length,
            received.first_header_length,
            capacity);
    for (index = 0; index < RECEIVE_COUNT; index++) {
        require_tagged_descriptor(received.descriptors[index], index);
    }

    dprintf(STDOUT_FILENO,
            "OBS case=%s sent=%u capacity=%zu received=%u "
            "prefix_tags=0,1,2 flags=0x%x controllen=%zu\n",
            active_case,
            SOURCE_COUNT,
            capacity,
            received.descriptor_count,
            received.message_flags,
            received.control_length);

    close_received_descriptors(&received);
    require_queue_empty(sockets[1], "control truncation");
    close_checked(sockets[0]);
    close_checked(sockets[1]);
}

static void set_soft_descriptor_limit(rlim_t limit)
{
    struct rlimit resource_limit;

    require(getrlimit(RLIMIT_NOFILE, &resource_limit) == 0,
            "getrlimit RLIMIT_NOFILE errno=%d",
            errno);
    require(resource_limit.rlim_max >= limit,
            "RLIMIT_NOFILE hard=%llu requested=%llu",
            (unsigned long long)resource_limit.rlim_max,
            (unsigned long long)limit);
    resource_limit.rlim_cur = limit;
    require(setrlimit(RLIMIT_NOFILE, &resource_limit) == 0,
            "setrlimit RLIMIT_NOFILE=%llu errno=%d",
            (unsigned long long)limit,
            errno);
}

static void check_emfile_receive_prefix(unsigned int expected_count,
                                        rlim_t receive_limit)
{
    enum { SOURCE_COUNT = 10 };
    int sockets[2];
    int sources[SOURCE_COUNT];
    unsigned int chunks[] = {SOURCE_COUNT};
    struct received_message received;
    ssize_t result;
    int saved_errno;
    unsigned int index;

    create_socket_pair(SOCK_DGRAM, sockets);
    for (index = 0; index < SOURCE_COUNT; index++) {
        sources[index] = create_tagged_memfd(index);
    }
    result = send_rights_chunks(sockets[0],
                                sources,
                                chunks,
                                1,
                                true,
                                'E',
                                &saved_errno);
    require(result == 1 && saved_errno == 0,
            "EMFILE send result=%zd errno=%d",
            result,
            saved_errno);
    for (index = 0; index < SOURCE_COUNT; index++) {
        close_checked(sources[index]);
    }
    close_checked(sockets[0]);
    set_soft_descriptor_limit(receive_limit);

    received = receive_rights(
        sockets[1],
        CMSG_SPACE(SOURCE_COUNT * sizeof(int)),
        0);
    require(received.result == 1 &&
                received.saved_errno == 0 &&
                received.payload == 'E',
            "EMFILE receive result=%zd errno=%d payload=%u",
            received.result,
            received.saved_errno,
            (unsigned int)received.payload);
    require((received.message_flags & MSG_CTRUNC) != 0,
            "EMFILE receive flags=0x%x missing MSG_CTRUNC",
            received.message_flags);
    require(received.descriptor_count == expected_count,
            "EMFILE receive count=%u expected=%u",
            received.descriptor_count,
            expected_count);
    if (expected_count == 0) {
        require(received.control_length == 0 &&
                    received.header_count == 0,
                "EMFILE zero-prefix controllen=%zu headers=%u",
                received.control_length,
                received.header_count);
    } else {
        size_t expected_header_length =
            CMSG_LEN((size_t)expected_count * sizeof(int));
        size_t expected_control_length =
            CMSG_SPACE((size_t)expected_count * sizeof(int));

        require(received.control_length == expected_control_length &&
                    received.first_header_length ==
                        expected_header_length,
                "EMFILE prefix controllen=%zu cmsg_len=%zu "
                "expected_controllen=%zu expected_cmsg_len=%zu",
                received.control_length,
                received.first_header_length,
                expected_control_length,
                expected_header_length);
        for (index = 0; index < expected_count; index++) {
            require_tagged_descriptor(received.descriptors[index],
                                      index);
        }
    }

    dprintf(STDOUT_FILENO,
            "OBS case=%s sent=%u rlimit=%llu recv_result=%zd "
            "recv_errno=%d installed_prefix=%u flags=0x%x "
            "controllen=%zu\n",
            active_case,
            SOURCE_COUNT,
            (unsigned long long)receive_limit,
            received.result,
            received.saved_errno,
            received.descriptor_count,
            received.message_flags,
            received.control_length);

    close_received_descriptors(&received);
    require_queue_empty(sockets[1], "EMFILE receive");
    close_checked(sockets[1]);
}

static void test_emfile_partial_prefix(void)
{
    /*
     * Descriptors 0, 1, 2, and receiver 4 remain open.  With a limit of
     * seven, only descriptor numbers 3, 5, and 6 can be installed.
     */
    check_emfile_receive_prefix(3, 7);
}

static void test_emfile_zero_prefix(void)
{
    /*
     * Descriptors 0, 1, and 2 occupy every number below this limit.
     * The receiver remains usable at descriptor 4 after the limit is lowered.
     */
    check_emfile_receive_prefix(0, 3);
}

static void test_source_close_and_numeric_reuse(void)
{
    int sockets[2];
    int pipe_descriptors[2];
    int descriptors[1];
    unsigned int chunks[] = {1};
    struct received_message received;
    int original_number;
    int replacement;
    ssize_t result;
    int saved_errno;
    unsigned char pipe_payload = 'O';
    unsigned char observed = 0xff;

    create_socket_pair(SOCK_DGRAM, sockets);
    require(pipe2(pipe_descriptors, O_CLOEXEC) == 0,
            "source-reuse pipe2 errno=%d",
            errno);
    original_number = pipe_descriptors[0];
    descriptors[0] = original_number;
    result = send_rights_chunks(sockets[0],
                                descriptors,
                                chunks,
                                1,
                                true,
                                'R',
                                &saved_errno);
    require(result == 1 && saved_errno == 0,
            "source-reuse send result=%zd errno=%d",
            result,
            saved_errno);
    close_checked(original_number);

    replacement = open("/dev/null", O_RDONLY | O_CLOEXEC);
    require(replacement == original_number,
            "source numeric reuse replacement=%d expected=%d errno=%d",
            replacement,
            original_number,
            errno);
    require(write(pipe_descriptors[1],
                  &pipe_payload,
                  sizeof(pipe_payload)) ==
                (ssize_t)sizeof(pipe_payload),
            "write original pipe after source reuse errno=%d",
            errno);

    received = receive_rights(
        sockets[1],
        CMSG_SPACE(sizeof(int)),
        0);
    require(received.result == 1 &&
                received.saved_errno == 0 &&
                received.payload == 'R' &&
                received.descriptor_count == 1,
            "source-reuse receive result=%zd errno=%d payload=%u "
            "count=%u",
            received.result,
            received.saved_errno,
            (unsigned int)received.payload,
            received.descriptor_count);
    require(read(received.descriptors[0],
                 &observed,
                 sizeof(observed)) ==
                (ssize_t)sizeof(observed) &&
                observed == pipe_payload,
            "received right did not retain original pipe byte=%u errno=%d",
            (unsigned int)observed,
            errno);
    observed = 0xff;
    require(read(replacement, &observed, sizeof(observed)) == 0,
            "replacement descriptor is not /dev/null byte=%u errno=%d",
            (unsigned int)observed,
            errno);

    dprintf(STDOUT_FILENO,
            "OBS case=%s source_fd=%d replacement_fd=%d "
            "received_fd=%d received_object=original_pipe "
            "replacement_object=/dev/null\n",
            active_case,
            original_number,
            replacement,
            received.descriptors[0]);

    close_received_descriptors(&received);
    close_checked(replacement);
    close_checked(pipe_descriptors[1]);
    close_checked(sockets[0]);
    close_checked(sockets[1]);
}

struct test_case {
    const char *name;
    test_function_t function;
};

static int run_isolated(const struct test_case *test)
{
    pid_t child;
    int wait_status;

    child = fork();
    if (child < 0) {
        dprintf(STDERR_FILENO,
                "fork case=%s errno=%d\n",
                test->name,
                errno);
        return 1;
    }
    if (child == 0) {
        active_case = test->name;
        (void)signal(SIGPIPE, SIG_IGN);
        (void)alarm(CASE_TIMEOUT_SECONDS);
        prepare_clean_descriptor_table();
        test->function();
        dprintf(STDOUT_FILENO, "CASE name=%s state=pass\n", test->name);
        _exit(EXIT_SUCCESS);
    }

    for (;;) {
        pid_t waited = waitpid(child, &wait_status, 0);

        if (waited == child) {
            break;
        }
        if (waited < 0 && errno == EINTR) {
            continue;
        }
        dprintf(STDERR_FILENO,
                "waitpid case=%s result=%ld errno=%d\n",
                test->name,
                (long)waited,
                errno);
        return 1;
    }
    if (!WIFEXITED(wait_status) ||
        WEXITSTATUS(wait_status) != EXIT_SUCCESS) {
        dprintf(STDERR_FILENO,
                "CASE name=%s state=fail wait_status=%d\n",
                test->name,
                wait_status);
        return 1;
    }
    return 0;
}

int main(void)
{
    static const struct test_case tests[] = {
        {"maximum_253", test_maximum_transfer},
        {"limit_and_multiple_cmsg",
         test_transfer_limit_and_multiple_headers},
        {"zero_payload", test_zero_payload},
        {"plain_read_discard", test_plain_read_discard},
        {"peek_nonconsumption", test_peek_nonconsumption},
        {"control_truncation_prefix",
         test_control_truncation_prefix},
        {"emfile_partial_prefix", test_emfile_partial_prefix},
        {"emfile_zero_prefix", test_emfile_zero_prefix},
        {"source_close_numeric_reuse",
         test_source_close_and_numeric_reuse},
    };
    unsigned int failures = 0;
    size_t index;

    for (index = 0; index < sizeof(tests) / sizeof(tests[0]); index++) {
        failures += (unsigned int)run_isolated(&tests[index]);
    }
    dprintf(STDOUT_FILENO,
            "SOCKET_SCM_RIGHTS_POOL_ABI_PROBE_%s cases=%zu failures=%u\n",
            failures == 0 ? "PASS" : "FAIL",
            sizeof(tests) / sizeof(tests[0]),
            failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
