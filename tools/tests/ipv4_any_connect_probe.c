/* SPDX-License-Identifier: MPL-2.0 */
/* Verify Linux INADDR_ANY destination semantics for IPv4 connect(2). */

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
    struct sockaddr_in address;
    struct accept_context context;
    pthread_t thread;
    socklen_t address_length;
    uint64_t started;
    uint64_t elapsed;
    int listener;
    int client;
    int unused;
    int result;

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("socket listener");
        return 1;
    }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
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
    client = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (client < 0 || connect(client, (struct sockaddr *)&address,
                              sizeof(address)) < 0) {
        perror("connect INADDR_ANY to loopback listener");
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

    unused = socket(AF_INET, SOCK_STREAM, 0);
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(9);
    started = monotonic_us();
    result = connect(unused, (struct sockaddr *)&address, sizeof(address));
    elapsed = monotonic_us() - started;
    if (result == 0 || errno != ECONNREFUSED) {
        fprintf(stderr, "unused INADDR_ANY connect result=%d errno=%d (%s)\n",
                result, errno, strerror(errno));
        return 1;
    }
    if (elapsed > 1000000u) {
        fprintf(stderr, "unused INADDR_ANY connect took %llu us\n",
                (unsigned long long)elapsed);
        return 1;
    }
    close(unused);
    printf("ipv4_any_connect: PASS elapsed_us=%llu\n",
           (unsigned long long)elapsed);
    return 0;
}
