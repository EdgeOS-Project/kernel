/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Unix datagram socket-activation ABI regression test. */

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

enum { CLIENTS = 4 };

static int fail(const char *operation) {
    fprintf(stderr, "unix_dgram_activation_abi_probe: %s: %s\n",
            operation, strerror(errno));
    return 1;
}

static int connect_and_send(const struct sockaddr_un *address,
                            socklen_t address_length, uint32_t value) {
    int descriptor = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) return fail("client socket");
    if (connect(descriptor, (const struct sockaddr *)address,
                address_length) < 0)
        return fail("client connect");
    if (send(descriptor, &value, sizeof(value), 0) != (ssize_t)sizeof(value))
        return fail("client send");
    if (close(descriptor) < 0) return fail("client close");
    return 0;
}

int main(void) {
    struct sockaddr_un address;
    struct sockaddr_un alias_address;
    socklen_t address_length;
    int receiver;
    int ready[2];
    pid_t child;
    int status;

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path),
             "/tmp/edgeos-dgram-activation-%ld", (long)getpid());
    address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                 strlen(address.sun_path) + 1);
    unlink(address.sun_path);
    memset(&alias_address, 0, sizeof(alias_address));
    alias_address.sun_family = AF_UNIX;
    snprintf(alias_address.sun_path, sizeof(alias_address.sun_path),
             "/tmp/edgeos-dgram-alias-%ld", (long)getpid());
    unlink(alias_address.sun_path);
    receiver = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (receiver < 0) return fail("receiver socket");
    if (bind(receiver, (const struct sockaddr *)&address, address_length) < 0)
        return fail("receiver bind");
    if (symlink(address.sun_path, alias_address.sun_path) < 0)
        return fail("receiver symlink");
    if (pipe(ready) < 0) return fail("ready pipe");

    child = fork();
    if (child < 0) return fail("fork");
    if (child == 0) {
        uint8_t token = 1;
        close(ready[0]);
        if (write(ready[1], &token, sizeof(token)) != (ssize_t)sizeof(token))
            _exit(20);
        close(ready[1]);
        for (uint32_t expected = 0; expected < CLIENTS; ++expected) {
            struct pollfd pollfd = { .fd = receiver, .events = POLLIN };
            uint32_t value = UINT32_MAX;
            if (poll(&pollfd, 1, 5000) != 1) _exit(21);
            if (recv(receiver, &value, sizeof(value), 0) !=
                (ssize_t)sizeof(value) || value != expected)
                _exit(22);
        }
        close(receiver);
        _exit(0);
    }

    close(ready[1]);
    close(receiver);
    {
        uint8_t token;
        if (read(ready[0], &token, sizeof(token)) != (ssize_t)sizeof(token))
            return fail("child ready");
    }
    close(ready[0]);
    for (uint32_t value = 0; value < CLIENTS; ++value) {
        const struct sockaddr_un *destination =
            value & 1u ? &alias_address : &address;
        socklen_t destination_length = (socklen_t)(
            offsetof(struct sockaddr_un, sun_path) +
            strlen(destination->sun_path) + 1);
        if (connect_and_send(destination, destination_length, value) != 0)
            return 1;
    }
    if (waitpid(child, &status, 0) != child) return fail("waitpid");
    unlink(address.sun_path);
    unlink(alias_address.sun_path);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "unix_dgram_activation_abi_probe: child status=%d\n",
                status);
        return 1;
    }
    puts("unix_dgram_activation_abi_probe: PASS");
    return 0;
}
