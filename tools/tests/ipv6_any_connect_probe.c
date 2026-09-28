/* SPDX-License-Identifier: MPL-2.0 */
/* Verify Linux IPv6 unspecified-destination semantics for connect(2). */

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

struct accept_context {
    int listener;
    int accepted;
};

static uint64_t monotonic_us(void) {
    struct timeval now;
    gettimeofday(&now, NULL);
    return (uint64_t)now.tv_sec * 1000000u + (uint64_t)now.tv_usec;
}

static void *accept_one(void *opaque) {
    struct accept_context *context = opaque;
    context->accepted = accept(context->listener, NULL, NULL);
    return NULL;
}

int main(void) {
    struct sockaddr_in6 address;
    struct accept_context context;
    pthread_t thread;
    socklen_t address_length;
    uint64_t started;
    uint64_t elapsed;
    int listener;
    int client;
    int unused;
    int result;

    listener = socket(AF_INET6, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("socket listener");
        return 1;
    }
    memset(&address, 0, sizeof(address));
    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_loopback;
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        listen(listener, 1) < 0) {
        perror("bind/listen");
        return 1;
    }
    address_length = sizeof(address);
    if (getsockname(listener, (struct sockaddr *)&address, &address_length) < 0) {
        perror("getsockname");
        return 1;
    }
    context.listener = listener;
    context.accepted = -1;
    if (pthread_create(&thread, NULL, accept_one, &context) != 0) {
        perror("pthread_create");
        return 1;
    }
    client = socket(AF_INET6, SOCK_STREAM, 0);
    address.sin6_addr = in6addr_any;
    if (client < 0 || connect(client, (struct sockaddr *)&address,
                              sizeof(address)) < 0) {
        perror("connect IPv6 unspecified to loopback listener");
        return 1;
    }
    pthread_join(thread, NULL);
    if (context.accepted < 0) {
        perror("accept");
        return 1;
    }
    close(context.accepted);
    close(client);
    close(listener);

    unused = socket(AF_INET6, SOCK_STREAM, 0);
    memset(&address, 0, sizeof(address));
    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_any;
    address.sin6_port = htons(9);
    started = monotonic_us();
    result = connect(unused, (struct sockaddr *)&address, sizeof(address));
    elapsed = monotonic_us() - started;
    if (result == 0 || errno != ECONNREFUSED) {
        fprintf(stderr,
                "unused IPv6 unspecified connect result=%d errno=%d (%s)\n",
                result, errno, strerror(errno));
        return 1;
    }
    if (elapsed > 1000000u) {
        fprintf(stderr, "unused IPv6 unspecified connect took %llu us\n",
                (unsigned long long)elapsed);
        return 1;
    }
    close(unused);
    printf("ipv6_any_connect: PASS elapsed_us=%llu\n",
           (unsigned long long)elapsed);
    return 0;
}
