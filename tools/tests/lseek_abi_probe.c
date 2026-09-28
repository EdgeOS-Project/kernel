/*
 * Original EdgeOS code licensed under MPL-2.0.
 *
 * Linux lseek ABI probe for native and guest parity.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__aarch64__)
#ifndef SYS_lseek
#define SYS_lseek 62
#endif
#else
#ifndef SYS_lseek
#define SYS_lseek 8
#endif
#endif

static const char g_path[] = "/root/edgeos-lseek-abi-probe";
static int g_failures;

static void expect_seek(const char *name, int descriptor, int64_t offset,
                        int whence, int64_t expected, int expected_errno) {
    long result;
    int saved_errno;

    errno = 0;
    result = syscall(SYS_lseek, descriptor, offset, whence);
    saved_errno = errno;
    dprintf(STDOUT_FILENO, "%s_rc:%ld errno:%d\n", name, result,
            saved_errno);
    if (result != expected || saved_errno != expected_errno)
        ++g_failures;
}

static void test_regular_file(int descriptor) {
    int duplicate;

    if (write(descriptor, "abcdefghij", 10) != 10) {
        dprintf(STDOUT_FILENO, "regular_setup_errno:%d\n", errno);
        ++g_failures;
        return;
    }
    expect_seek("regular_set", descriptor, 4, SEEK_SET, 4, 0);
    expect_seek("regular_cur", descriptor, 2, SEEK_CUR, 6, 0);
    expect_seek("regular_end", descriptor, -1, SEEK_END, 9, 0);
    expect_seek("regular_negative", descriptor, -1, SEEK_SET, -1, EINVAL);
    expect_seek("regular_invalid_whence", descriptor, 0, 99, -1, EINVAL);

    duplicate = dup(descriptor);
    if (duplicate < 0) {
        dprintf(STDOUT_FILENO, "regular_dup_errno:%d\n", errno);
        ++g_failures;
    } else {
        expect_seek("regular_dup_source", descriptor, 3, SEEK_SET, 3, 0);
        expect_seek("regular_dup_observe", duplicate, 0, SEEK_CUR, 3, 0);
        expect_seek("regular_dup_move", duplicate, 5, SEEK_SET, 5, 0);
        expect_seek("regular_source_observe", descriptor, 0, SEEK_CUR, 5, 0);
        expect_seek("regular_shared_read_reset", descriptor, 0, SEEK_SET,
                    0, 0);
        {
            char byte = 0;
            ssize_t count = read(duplicate, &byte, 1);
            dprintf(STDOUT_FILENO,
                    "regular_shared_read_count:%ld byte:%d\n",
                    (long)count, (int)(unsigned char)byte);
            if (count != 1 || byte != 'a') ++g_failures;
        }
        expect_seek("regular_shared_read_offset", descriptor, 0,
                    SEEK_CUR, 1, 0);
        close(duplicate);
    }

    expect_seek("regular_data_start", descriptor, 0, SEEK_DATA, 0, 0);
    expect_seek("regular_data_last", descriptor, 9, SEEK_DATA, 9, 0);
    expect_seek("regular_data_eof", descriptor, 10, SEEK_DATA, -1, ENXIO);
    expect_seek("regular_hole_start", descriptor, 0, SEEK_HOLE, 10, 0);
    expect_seek("regular_hole_eof", descriptor, 10, SEEK_HOLE, -1, ENXIO);
    expect_seek("regular_data_past", descriptor, 11, SEEK_DATA, -1, ENXIO);
    expect_seek("regular_hole_past", descriptor, 11, SEEK_HOLE, -1, ENXIO);

    expect_seek("regular_large", descriptor, INT64_C(1) << 40,
                SEEK_SET, INT64_C(1) << 40, 0);
    expect_seek("regular_max", descriptor, INT64_MAX, SEEK_SET,
                INT64_MAX, 0);
    expect_seek("regular_overflow", descriptor, INT64_MAX, SEEK_CUR,
                -1, EINVAL);
    expect_seek("regular_after_overflow", descriptor, 0, SEEK_CUR,
                INT64_MAX, 0);
}

static void test_shared_descriptions(int descriptor) {
    int status;
    pid_t child;

    expect_seek("fork_offset_setup", descriptor, 2, SEEK_SET, 2, 0);
    child = fork();
    if (child < 0) {
        dprintf(STDOUT_FILENO, "fork_setup_errno:%d\n", errno);
        ++g_failures;
    } else if (child == 0) {
        long result = syscall(SYS_lseek, descriptor, 7, SEEK_SET);
        _exit(result == 7 ? 0 : 1);
    } else {
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)
            ++g_failures;
        expect_seek("fork_offset_observe", descriptor, 0, SEEK_CUR, 7, 0);
    }

    {
        int sockets[2];
        int received = -1;
        char byte = 'x';
        char control[CMSG_SPACE(sizeof(int))];
        struct iovec vector = { .iov_base = &byte, .iov_len = 1 };
        struct msghdr message;
        struct cmsghdr *header;

        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
            dprintf(STDOUT_FILENO, "rights_socketpair_errno:%d\n", errno);
            ++g_failures;
            return;
        }
        memset(&message, 0, sizeof(message));
        memset(control, 0, sizeof(control));
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        message.msg_control = control;
        message.msg_controllen = sizeof(control);
        header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
        expect_seek("rights_offset_setup", descriptor, 3, SEEK_SET, 3, 0);
        if (sendmsg(sockets[0], &message, 0) != 1) {
            dprintf(STDOUT_FILENO, "rights_send_errno:%d\n", errno);
            ++g_failures;
        } else {
            memset(&message, 0, sizeof(message));
            memset(control, 0, sizeof(control));
            byte = 0;
            message.msg_iov = &vector;
            message.msg_iovlen = 1;
            message.msg_control = control;
            message.msg_controllen = sizeof(control);
            if (recvmsg(sockets[1], &message, 0) != 1) {
                dprintf(STDOUT_FILENO, "rights_recv_errno:%d\n", errno);
                ++g_failures;
            } else {
                header = CMSG_FIRSTHDR(&message);
                if (!header || header->cmsg_level != SOL_SOCKET ||
                    header->cmsg_type != SCM_RIGHTS ||
                    header->cmsg_len < CMSG_LEN(sizeof(int))) {
                    dprintf(STDOUT_FILENO, "rights_control_invalid:1\n");
                    ++g_failures;
                } else {
                    memcpy(&received, CMSG_DATA(header), sizeof(received));
                    expect_seek("rights_offset_observe", received, 0,
                                SEEK_CUR, 3, 0);
                    expect_seek("rights_offset_move", received, 8,
                                SEEK_SET, 8, 0);
                    expect_seek("rights_source_observe", descriptor, 0,
                                SEEK_CUR, 8, 0);
                }
            }
        }
        if (received >= 0) close(received);
        close(sockets[0]);
        close(sockets[1]);
    }
}

static void test_directory(void) {
    int descriptor = open("/root", O_RDONLY | O_DIRECTORY);

    if (descriptor < 0) {
        dprintf(STDOUT_FILENO, "directory_setup_errno:%d\n", errno);
        ++g_failures;
        return;
    }
    expect_seek("directory_set", descriptor, 0, SEEK_SET, 0, 0);
    expect_seek("directory_cur", descriptor, 0, SEEK_CUR, 0, 0);
    expect_seek("directory_end", descriptor, 0, SEEK_END, -1, EINVAL);
    expect_seek("directory_data", descriptor, 0, SEEK_DATA, -1, EINVAL);
    expect_seek("directory_hole", descriptor, 0, SEEK_HOLE, -1, EINVAL);
    close(descriptor);
}

static void test_special_descriptors(void) {
    int pipe_descriptors[2];
    int socket_descriptors[2];
    int event_descriptor;
    int path_descriptor;
    int null_descriptor;

    if (pipe(pipe_descriptors) < 0) {
        dprintf(STDOUT_FILENO, "pipe_setup_errno:%d\n", errno);
        ++g_failures;
        return;
    }
    socket_descriptors[0] = socket_descriptors[1] = -1;
    (void)socketpair(AF_UNIX, SOCK_STREAM, 0, socket_descriptors);
    event_descriptor = eventfd(0, EFD_CLOEXEC);
    path_descriptor = open(g_path, O_PATH | O_CLOEXEC);
    null_descriptor = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (socket_descriptors[0] < 0 || event_descriptor < 0 ||
        path_descriptor < 0 || null_descriptor < 0) {
        dprintf(STDOUT_FILENO, "special_setup_errno:%d\n", errno);
        ++g_failures;
        return;
    }

    expect_seek("bad_descriptor", -1, 0, SEEK_SET, -1, EBADF);
    expect_seek("pipe", pipe_descriptors[0], 0, SEEK_SET, -1, ESPIPE);
    expect_seek("socket", socket_descriptors[0], 0, SEEK_SET, -1, ESPIPE);
    expect_seek("opath", path_descriptor, 0, SEEK_SET, -1, EBADF);
    expect_seek("eventfd_set", event_descriptor, 7, SEEK_SET, 0, 0);
    expect_seek("eventfd_cur", event_descriptor, 4, SEEK_CUR, 0, 0);
    expect_seek("null_set", null_descriptor, 7, SEEK_SET, 0, 0);
    expect_seek("null_cur", null_descriptor, 4, SEEK_CUR, 0, 0);
    expect_seek("null_end", null_descriptor, 4, SEEK_END, 0, 0);

    close(null_descriptor);
    close(path_descriptor);
    close(event_descriptor);
    close(socket_descriptors[0]);
    close(socket_descriptors[1]);
    close(pipe_descriptors[0]);
    close(pipe_descriptors[1]);
}

int main(void) {
    int descriptor;

    unlink(g_path);
    descriptor = open(g_path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (descriptor < 0) {
        dprintf(STDOUT_FILENO, "lseek_file_setup_errno:%d\n", errno);
        return 1;
    }

    test_regular_file(descriptor);
    test_shared_descriptions(descriptor);
    test_directory();
    test_special_descriptors();

    close(descriptor);
    unlink(g_path);
    dprintf(STDOUT_FILENO, "LSEEK_ABI_PROBE_%s failures:%d\n",
            g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
