/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent descriptor factory unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/fd_runtime.h"
#include "kernel/linux_abi.h"
#include "kernel/linux_errno.h"
#include "kernel/memfd_runtime.h"
#include "kernel/namespace_runtime.h"
#include "kernel/socket_runtime.h"

static int g_failures;
static int g_pipe_calls;
static int g_memfd_calls;
static int g_memfd_secret_calls;
static int g_namespace_calls;
static int g_socket_create_calls;
static int g_pair_prepare_calls;
static int g_pair_construct_calls;
static int g_accept_calls;
static int g_pair_prepare_saw_initialized;
static int g_accept_saw_initialized;

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

int arch_fd_pipe_prepare(
    uint32_t flags, int32_t descriptors[2],
    kernel_fd_publication_t *publication) {
    (void)flags;
    (void)publication;
    ++g_pipe_calls;
    descriptors[0] = 3;
    descriptors[1] = 4;
    return 17;
}

int64_t arch_memfd_create_descriptor(const char *name, uint32_t flags) {
    ++g_memfd_calls;
    return name[0] == 'm' && flags == 7u ? 18 : -1;
}

int64_t arch_memfd_secret_descriptor(uint32_t descriptor_flags) {
    ++g_memfd_secret_calls;
    return descriptor_flags == KERNEL_MEMFD_CLOEXEC ? 23 : -1;
}

int arch_namespace_descriptor_get(
    int32_t descriptor, kernel_namespace_descriptor_t *information) {
    ++g_namespace_calls;
    information->id = (uint32_t)descriptor;
    return 19;
}

int64_t arch_socket_create_descriptor(
    uint32_t domain, uint32_t type, uint32_t protocol, uint32_t flags) {
    ++g_socket_create_calls;
    return (int64_t)(domain + type + protocol + flags);
}

int arch_socket_create_unix_pair_prepare(
    int32_t descriptors[2], kernel_fd_publication_t *publication) {
    ++g_pair_prepare_calls;
    g_pair_prepare_saw_initialized =
        descriptors[0] == -1 && descriptors[1] == -1;
    descriptors[0] = 5;
    descriptors[1] = 6;
    publication->active = 1;
    return 20;
}

int arch_socket_create_unix_pair_construct(
    uint32_t type, uint32_t flags, const int32_t descriptors[2],
    const kernel_fd_publication_t *publication) {
    ++g_pair_construct_calls;
    return type == 1u && flags == 2u &&
           descriptors[0] == 5 && descriptors[1] == 6 &&
           publication->active ? 21 : -1;
}

int arch_socket_accept_prepare(
    int32_t descriptor, uint32_t flags, kernel_socket_address_t *address,
    uint64_t deferred_user_address, uint64_t deferred_user_length,
    void *user_registers, int32_t *accepted_descriptor,
    kernel_fd_publication_t *publication) {
    (void)flags;
    (void)address;
    (void)deferred_user_address;
    (void)deferred_user_length;
    (void)user_registers;
    (void)publication;
    ++g_accept_calls;
    g_accept_saw_initialized = *accepted_descriptor == -1;
    *accepted_descriptor = descriptor + 1;
    return 22;
}

static void test_descriptor_factories(void) {
    int32_t descriptors[2] = {9, 10};
    kernel_fd_publication_t publication;
    kernel_namespace_descriptor_t namespace_information;

    memset(&publication, 0, sizeof(publication));
    expect_true("pipe null descriptors",
                kernel_fd_pipe_prepare(0, 0, &publication) ==
                    -EDGE_LINUX_EINVAL &&
                g_pipe_calls == 0);
    expect_true("pipe invalid flags",
                kernel_fd_pipe_prepare(1u, descriptors, &publication) ==
                    -EDGE_LINUX_EINVAL &&
                descriptors[0] == -1 && descriptors[1] == -1 &&
                g_pipe_calls == 0);
    publication.active = 1;
    expect_true("pipe active publication",
                kernel_fd_pipe_prepare(0, descriptors, &publication) ==
                    -EDGE_LINUX_EBUSY &&
                g_pipe_calls == 0);
    publication.active = 0;
    expect_true("pipe dispatch",
                kernel_fd_pipe_prepare(
                    EDGE_LINUX_SOCK_NONBLOCK |
                    EDGE_LINUX_SOCK_CLOEXEC,
                    descriptors, &publication) == 17 &&
                descriptors[0] == 3 && descriptors[1] == 4 &&
                g_pipe_calls == 1);
    expect_true("notification pipe dispatch",
                kernel_fd_pipe_prepare(
                    0x00000080u, descriptors, &publication) == 17 &&
                g_pipe_calls == 2);

    expect_true("memfd null name",
                kernel_memfd_create_descriptor(0, 7) ==
                    -EDGE_LINUX_EINVAL &&
                g_memfd_calls == 0);
    expect_true("memfd dispatch",
                kernel_memfd_create_descriptor("memory", 7) == 18 &&
                g_memfd_calls == 1);
    expect_true("secret memfd invalid descriptor flags",
                kernel_memfd_secret_descriptor(2u) ==
                    -EDGE_LINUX_EINVAL &&
                g_memfd_secret_calls == 0);
    expect_true("secret memfd dispatch",
                kernel_memfd_secret_descriptor(KERNEL_MEMFD_CLOEXEC) ==
                    23 &&
                g_memfd_secret_calls == 1);

    expect_true("namespace null output",
                kernel_namespace_descriptor_get(9, 0) ==
                    -EDGE_LINUX_EINVAL &&
                g_namespace_calls == 0);
    expect_true("namespace dispatch",
                kernel_namespace_descriptor_get(
                    9, &namespace_information) == 19 &&
                namespace_information.id == 9u &&
                g_namespace_calls == 1);
}

static void test_socket_factories(void) {
    int32_t descriptors[2] = {9, 10};
    int32_t accepted = 99;
    kernel_fd_publication_t publication;
    kernel_socket_address_t address;

    memset(&publication, 0, sizeof(publication));
    memset(&address, 0, sizeof(address));

    expect_true("socket create dispatch",
                kernel_socket_create_descriptor(1, 2, 3, 4) == 10 &&
                g_socket_create_calls == 1);

    expect_true("pair prepare null publication",
                kernel_socket_create_unix_pair_prepare(
                    descriptors, 0) == -EDGE_LINUX_EINVAL &&
                g_pair_prepare_calls == 0);
    publication.active = 1;
    expect_true("pair prepare active publication",
                kernel_socket_create_unix_pair_prepare(
                    descriptors, &publication) == -EDGE_LINUX_EBUSY &&
                descriptors[0] == -1 && descriptors[1] == -1 &&
                g_pair_prepare_calls == 0);
    publication.active = 0;
    expect_true("pair prepare dispatch",
                kernel_socket_create_unix_pair_prepare(
                    descriptors, &publication) == 20 &&
                g_pair_prepare_calls == 1 &&
                g_pair_prepare_saw_initialized &&
                descriptors[0] == 5 && descriptors[1] == 6);
    expect_true("pair construct null descriptors",
                kernel_socket_create_unix_pair_construct(
                    1, 2, 0, &publication) == -EDGE_LINUX_EINVAL &&
                g_pair_construct_calls == 0);
    expect_true("pair construct dispatch",
                kernel_socket_create_unix_pair_construct(
                    1, 2, descriptors, &publication) == 21 &&
                g_pair_construct_calls == 1);

    publication.active = 0;
    expect_true("accept null address",
                kernel_socket_accept_prepare(
                    7, 0, 0, 0, 0, 0, &accepted,
                    &publication) == -EDGE_LINUX_EIO &&
                accepted == -1 && g_accept_calls == 0);
    expect_true("accept invalid flags",
                kernel_socket_accept_prepare(
                    7, 1u, &address, 0, 0, 0, &accepted,
                    &publication) == -EDGE_LINUX_EINVAL &&
                accepted == -1 && g_accept_calls == 0);
    publication.active = 1;
    expect_true("accept active publication",
                kernel_socket_accept_prepare(
                    7, 0, &address, 0, 0, 0, &accepted,
                    &publication) == -EDGE_LINUX_EBUSY &&
                g_accept_calls == 0);
    publication.active = 0;
    expect_true("accept dispatch",
                kernel_socket_accept_prepare(
                    7, EDGE_LINUX_SOCK_CLOEXEC, &address,
                    11, 12, (void *)(uintptr_t)13, &accepted,
                    &publication) == 22 &&
                accepted == 8 && g_accept_calls == 1 &&
                g_accept_saw_initialized);
}

int main(void) {
    test_descriptor_factories();
    test_socket_factories();
    if (g_failures) return 1;
    puts("descriptor_factory_runtime_unit: PASS");
    return 0;
}
