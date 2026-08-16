/* SPDX-License-Identifier: MPL-2.0 */
/* Shared network-device registry for architecture-neutral drivers. */

#ifndef EDGEOS_NET_NETDEV_H
#define EDGEOS_NET_NETDEV_H

#include <stddef.h>
#include <stdint.h>

#define EDGE_NETDEV_NAME_MAX 16
#define EDGE_NETDEV_MAX 8
#define EDGE_NETDEV_MAC_LENGTH 6
#define EDGE_NETDEV_FRAME_MAX 65550u

typedef uint64_t edge_netdev_handle_t;
typedef void (*edge_netdev_receive_fn)(const uint8_t *frame, uint32_t length,
    void *context);
typedef void (*edge_netdev_link_fn)(int link_up, void *context);

typedef struct edge_netdev_ops {
    /*
     * A transmit callback returns a non-negative result on success and a
     * negative result on failure. Native drivers may return a byte count.
     */
    int (*transmit)(void *context, const void *frame, uint32_t length);
    void (*poll)(void *context);
    int (*set_up)(void *context, int up);
} edge_netdev_ops_t;

typedef struct edge_netdev_config {
    const char *name;
    uint8_t mac[EDGE_NETDEV_MAC_LENGTH];
    uint32_t mtu;
    int link_up;
    edge_netdev_ops_t ops;
    void *context;
} edge_netdev_config_t;

int edge_netdev_register(const edge_netdev_config_t *config,
    edge_netdev_handle_t *handle);
int edge_netdev_unregister(edge_netdev_handle_t handle);
int edge_netdev_set_active(edge_netdev_handle_t handle);
edge_netdev_handle_t edge_netdev_get_active(void);
int edge_netdev_set_receive_callback(edge_netdev_handle_t handle,
    edge_netdev_receive_fn callback, void *context);
int edge_netdev_set_link_callback(edge_netdev_handle_t handle,
    edge_netdev_link_fn callback, void *context);
int edge_netdev_receive(edge_netdev_handle_t handle, const void *frame,
    uint32_t length);
int edge_netdev_transmit(edge_netdev_handle_t handle, const void *frame,
    uint32_t length);
void edge_netdev_poll(edge_netdev_handle_t handle);
int edge_netdev_set_up(edge_netdev_handle_t handle, int up);
int edge_netdev_set_link(edge_netdev_handle_t handle, int link_up);
int edge_netdev_get_info(edge_netdev_handle_t handle, char *name,
    size_t name_size, uint8_t mac[EDGE_NETDEV_MAC_LENGTH], uint32_t *mtu,
    int *link_up, int *up);
int edge_netdev_snapshot(edge_netdev_handle_t *handles, size_t capacity,
    size_t *count);
int edge_netdev_count(void);

#endif
