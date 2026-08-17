/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux TUN/TAP runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_LINUX_TUN_H
#define EDGEOS_KERNEL_LINUX_TUN_H

#include <stdint.h>

#define EDGE_LINUX_TUN_PATH "/dev/net/tun"

#define EDGE_LINUX_IFF_TUN 0x0001u
#define EDGE_LINUX_IFF_TAP 0x0002u
#define EDGE_LINUX_IFF_NAPI 0x0010u
#define EDGE_LINUX_IFF_NAPI_FRAGS 0x0020u
#define EDGE_LINUX_IFF_NO_CARRIER 0x0040u
#define EDGE_LINUX_IFF_NO_PI 0x1000u
#define EDGE_LINUX_IFF_ONE_QUEUE 0x2000u
#define EDGE_LINUX_IFF_VNET_HDR 0x4000u
#define EDGE_LINUX_IFF_TUN_EXCL 0x8000u
#define EDGE_LINUX_IFF_MULTI_QUEUE 0x0100u
#define EDGE_LINUX_IFF_ATTACH_QUEUE 0x0200u
#define EDGE_LINUX_IFF_DETACH_QUEUE 0x0400u
#define EDGE_LINUX_IFF_PERSIST 0x0800u

#define EDGE_LINUX_TUNSETNOCSUM 0x400454c8u
#define EDGE_LINUX_TUNSETDEBUG 0x400454c9u
#define EDGE_LINUX_TUNSETIFF 0x400454cau
#define EDGE_LINUX_TUNSETPERSIST 0x400454cbu
#define EDGE_LINUX_TUNSETOWNER 0x400454ccu
#define EDGE_LINUX_TUNSETGROUP 0x400454ceu
#define EDGE_LINUX_TUNGETFEATURES 0x800454cfu
#define EDGE_LINUX_TUNSETOFFLOAD 0x400454d0u
#define EDGE_LINUX_TUNSETLINK 0x400454cdu
#define EDGE_LINUX_TUNGETIFF 0x800454d2u
#define EDGE_LINUX_TUNGETSNDBUF 0x800454d3u
#define EDGE_LINUX_TUNSETSNDBUF 0x400454d4u
#define EDGE_LINUX_TUNGETVNETHDRSZ 0x800454d7u
#define EDGE_LINUX_TUNSETVNETHDRSZ 0x400454d8u
#define EDGE_LINUX_TUNSETQUEUE 0x400454d9u
#define EDGE_LINUX_TUNSETIFINDEX 0x400454dau
#define EDGE_LINUX_TUNSETCARRIER 0x400454e2u

typedef int (*edge_linux_tun_copy_from_user_fn)(
    void *context, void *destination, uint64_t source, uint32_t length);
typedef int (*edge_linux_tun_copy_to_user_fn)(
    void *context, uint64_t destination, const void *source,
    uint32_t length);
typedef void (*edge_linux_tun_wake_fn)(uint64_t description_identity);

void edge_linux_tun_reset(void);
void edge_linux_tun_set_wake_callback(edge_linux_tun_wake_fn callback);
int edge_linux_tun_open(uint64_t description_identity);
void edge_linux_tun_close(uint64_t description_identity);
int edge_linux_tun_ioctl(
    uint64_t description_identity, uint32_t network_namespace,
    uint32_t command, uint64_t argument,
    edge_linux_tun_copy_from_user_fn copy_from_user,
    edge_linux_tun_copy_to_user_fn copy_to_user, void *copy_context);
int64_t edge_linux_tun_read(
    uint64_t description_identity, uint64_t destination,
    uint32_t capacity, edge_linux_tun_copy_to_user_fn copy_to_user,
    void *copy_context);
int64_t edge_linux_tun_write(
    uint64_t description_identity, uint64_t source, uint32_t length,
    edge_linux_tun_copy_from_user_fn copy_from_user,
    void *copy_context);
int edge_linux_tun_read_ready(uint64_t description_identity);
int edge_linux_tun_write_ready(uint64_t description_identity);
uint64_t edge_linux_tun_read_sequence(uint64_t description_identity);
uint64_t edge_linux_tun_write_sequence(uint64_t description_identity);

#endif
