/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux TUN/TAP runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/linux_tun.h"

#include "kernel/linux_errno.h"
#include "kernel/linux_netlink.h"
#include "net/network_core.h"
#include "string.h"

#define EDGE_LINUX_TUN_MAX 16u
#define EDGE_LINUX_TUN_QUEUE_DEPTH 8u
#define EDGE_LINUX_TUN_PACKET_MAX 2048u
#define EDGE_LINUX_TUN_VNET_HEADER_DEFAULT 10u
#define EDGE_LINUX_TUN_SUPPORTED_FLAGS \
    (EDGE_LINUX_IFF_TUN | EDGE_LINUX_IFF_TAP | EDGE_LINUX_IFF_NO_PI | \
     EDGE_LINUX_IFF_ONE_QUEUE | EDGE_LINUX_IFF_VNET_HDR | \
     EDGE_LINUX_IFF_TUN_EXCL | EDGE_LINUX_IFF_MULTI_QUEUE | \
     EDGE_LINUX_IFF_NO_CARRIER)

typedef struct edge_linux_tun_ifreq {
    char name[16];
    union {
        uint16_t flags;
        uint8_t padding[24];
    } value;
} edge_linux_tun_ifreq_t;

typedef struct edge_linux_tun_packet {
    uint32_t length;
    uint16_t protocol;
    uint8_t data[EDGE_LINUX_TUN_PACKET_MAX];
} edge_linux_tun_packet_t;

typedef struct edge_linux_tun_state {
    uint8_t used;
    uint8_t attached;
    uint8_t persistent;
    uint8_t write_active;
    uint8_t queue_attached;
    uint64_t description_identity;
    uint64_t read_sequence;
    uint64_t write_sequence;
    uint32_t network_namespace;
    int32_t ifindex;
    int32_t requested_ifindex;
    uint32_t flags;
    uint32_t owner;
    uint32_t group;
    uint32_t send_buffer;
    uint32_t offload;
    uint32_t vnet_header_size;
    uint8_t queue_head;
    uint8_t queue_count;
    char name[16];
    edge_linux_tun_packet_t queue[EDGE_LINUX_TUN_QUEUE_DEPTH];
    uint8_t ingress[EDGE_LINUX_TUN_PACKET_MAX];
} edge_linux_tun_state_t;

static volatile uint32_t g_edge_linux_tun_lock;
static edge_linux_tun_state_t g_edge_linux_tun_states[EDGE_LINUX_TUN_MAX];
static edge_linux_tun_wake_fn g_edge_linux_tun_wake;

static void edge_linux_tun_lock(void) {
    while (__atomic_exchange_n(
            &g_edge_linux_tun_lock, 1u, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(
                &g_edge_linux_tun_lock, __ATOMIC_RELAXED)) {
        }
    }
}

static void edge_linux_tun_unlock(void) {
    __atomic_store_n(&g_edge_linux_tun_lock, 0u, __ATOMIC_RELEASE);
}

static edge_linux_tun_state_t *edge_linux_tun_find_locked(
    uint64_t description_identity) {
    uint32_t index;

    if (!description_identity) return 0;
    for (index = 0; index < EDGE_LINUX_TUN_MAX; ++index) {
        edge_linux_tun_state_t *state = &g_edge_linux_tun_states[index];

        if (state->used &&
            state->description_identity == description_identity)
            return state;
    }
    return 0;
}

static edge_linux_tun_state_t *edge_linux_tun_free_locked(void) {
    uint32_t index;

    for (index = 0; index < EDGE_LINUX_TUN_MAX; ++index)
        if (!g_edge_linux_tun_states[index].used)
            return &g_edge_linux_tun_states[index];
    return 0;
}

static edge_linux_tun_state_t *edge_linux_tun_persistent_locked(
    uint32_t network_namespace, const char *name, uint32_t type) {
    uint32_t index;

    for (index = 0; index < EDGE_LINUX_TUN_MAX; ++index) {
        edge_linux_tun_state_t *state = &g_edge_linux_tun_states[index];

        if (state->used && state->attached && state->persistent &&
            !state->description_identity &&
            state->network_namespace == network_namespace &&
            (state->flags & (EDGE_LINUX_IFF_TUN | EDGE_LINUX_IFF_TAP)) ==
                type &&
            strcmp(state->name, name) == 0)
            return state;
    }
    return 0;
}

static edge_linux_tun_state_t *edge_linux_tun_interface_locked(
    uint32_t network_namespace, const char *name, uint32_t type) {
    uint32_t index;

    for (index = 0; index < EDGE_LINUX_TUN_MAX; ++index) {
        edge_linux_tun_state_t *state = &g_edge_linux_tun_states[index];

        if (state->used && state->attached && state->ifindex > 0 &&
            state->network_namespace == network_namespace &&
            (state->flags & (EDGE_LINUX_IFF_TUN | EDGE_LINUX_IFF_TAP)) ==
                type &&
            strcmp(state->name, name) == 0)
            return state;
    }
    return 0;
}

static uint16_t edge_linux_tun_protocol(
    const uint8_t *packet, uint32_t length, int tap) {
    if (tap) {
        if (length < 14u) return 0u;
        return (uint16_t)(((uint16_t)packet[12] << 8u) | packet[13]);
    }
    if (!length) return 0u;
    if ((packet[0] >> 4u) == 4u) return 0x0800u;
    if ((packet[0] >> 4u) == 6u) return 0x86ddu;
    return 0u;
}

static void edge_linux_tun_transmit(
    int32_t ifindex, uint32_t network_namespace,
    edge_net_packet_t *packet, void *context) {
    edge_linux_tun_state_t *state = 0;
    edge_linux_tun_packet_t *queued;
    uint64_t identity = 0u;
    uint32_t offset = 0u;
    uint32_t length;
    uint16_t protocol;
    int tap;

    uint32_t index;

    (void)context;
    if (!packet) return;
    edge_linux_tun_lock();
    for (index = 0; index < EDGE_LINUX_TUN_MAX; ++index) {
        edge_linux_tun_state_t *candidate =
            &g_edge_linux_tun_states[index];

        if (!candidate->used || !candidate->attached ||
            !candidate->queue_attached ||
            candidate->ifindex != ifindex ||
            candidate->network_namespace != network_namespace ||
            candidate->queue_count >= EDGE_LINUX_TUN_QUEUE_DEPTH)
            continue;
        if (!state || candidate->queue_count < state->queue_count)
            state = candidate;
    }
    if (!state) {
        edge_linux_tun_unlock();
        return;
    }
    tap = (state->flags & EDGE_LINUX_IFF_TAP) != 0u;
    length = packet->total_length;
    if (!tap && length >= 14u) {
        uint8_t ethernet[14];
        uint16_t ethernet_protocol;

        if (edge_net_packet_read(
                packet, 0u, ethernet, sizeof(ethernet)) == EDGE_NET_OK) {
            ethernet_protocol = (uint16_t)(
                ((uint16_t)ethernet[12] << 8u) | ethernet[13]);
            if (ethernet_protocol == 0x0800u ||
                ethernet_protocol == 0x86ddu) {
                offset = 14u;
                length -= 14u;
            }
        }
    }
    if (!length || length > EDGE_LINUX_TUN_PACKET_MAX) {
        edge_linux_tun_unlock();
        return;
    }
    queued = &state->queue[(state->queue_head + state->queue_count) %
                           EDGE_LINUX_TUN_QUEUE_DEPTH];
    if (edge_net_packet_read(
            packet, offset, queued->data, length) != EDGE_NET_OK) {
        edge_linux_tun_unlock();
        return;
    }
    protocol = packet->metadata.protocol;
    if (protocol != 0x0800u && protocol != 0x86ddu)
        protocol = edge_linux_tun_protocol(queued->data, length, tap);
    queued->length = length;
    queued->protocol = protocol;
    ++state->queue_count;
    if (++state->read_sequence == 0u) state->read_sequence = 1u;
    identity = state->description_identity;
    edge_linux_tun_unlock();
    if (identity && g_edge_linux_tun_wake)
        g_edge_linux_tun_wake(identity);
}

static int edge_linux_tun_name_candidate(
    const char *requested, uint32_t number, char output[16]) {
    uint32_t source = 0u;
    uint32_t destination = 0u;
    int replaced = 0;

    if (!requested || !output) return -EDGE_LINUX_EINVAL;
    while (requested[source]) {
        if (destination >= 15u) return -EDGE_LINUX_EINVAL;
        if (!replaced && requested[source] == '%' &&
            requested[source + 1u] == 'd') {
            char reverse[10];
            uint32_t digits = 0u;

            do {
                reverse[digits++] = (char)('0' + number % 10u);
                number /= 10u;
            } while (number && digits < sizeof(reverse));
            if (destination + digits > 15u)
                return -EDGE_LINUX_EINVAL;
            while (digits) output[destination++] = reverse[--digits];
            source += 2u;
            replaced = 1;
            continue;
        }
        output[destination++] = requested[source++];
    }
    output[destination] = 0;
    return replaced;
}

static int edge_linux_tun_attach(
    edge_linux_tun_state_t *state, uint32_t network_namespace,
    edge_linux_tun_ifreq_t *request) {
    char requested[16];
    char candidate[16];
    uint32_t type;
    uint32_t flags;
    uint32_t number;
    int generated;
    int32_t created_ifindex = 0;
    int result = -EDGE_LINUX_EEXIST;

    if (!state || !request) return -EDGE_LINUX_EINVAL;
    flags = request->value.flags;
    type = flags & (EDGE_LINUX_IFF_TUN | EDGE_LINUX_IFF_TAP);
    if (type != EDGE_LINUX_IFF_TUN && type != EDGE_LINUX_IFF_TAP)
        return -EDGE_LINUX_EINVAL;
    if (flags & ~EDGE_LINUX_TUN_SUPPORTED_FLAGS)
        return -EDGE_LINUX_EINVAL;
    memcpy(requested, request->name, sizeof(requested));
    requested[sizeof(requested) - 1u] = 0;
    if (!requested[0])
        memcpy(requested,
               type == EDGE_LINUX_IFF_TUN ? "tun%d" : "tap%d", 6u);

    for (number = 0u; number < 256u; ++number) {
        edge_linux_tun_state_t *persistent;

        memset(candidate, 0, sizeof(candidate));
        generated = edge_linux_tun_name_candidate(
            requested, number, candidate);
        if (generated < 0) return generated;
        edge_linux_tun_lock();
        persistent = edge_linux_tun_persistent_locked(
            network_namespace, candidate, type);
        if (persistent) {
            uint64_t identity = state->description_identity;

            memset(state, 0, sizeof(*state));
            persistent->description_identity = identity;
            persistent->flags = flags;
            persistent->queue_attached = 1u;
            memcpy(request->name, persistent->name,
                   sizeof(request->name));
            request->value.flags = (uint16_t)persistent->flags;
            edge_linux_tun_unlock();
            return 0;
        }
        if (!generated) {
            edge_linux_tun_state_t *existing =
                edge_linux_tun_interface_locked(
                    network_namespace, candidate, type);

            if (existing) {
                if ((flags & EDGE_LINUX_IFF_TUN_EXCL) ||
                    !(flags & EDGE_LINUX_IFF_MULTI_QUEUE) ||
                    !(existing->flags & EDGE_LINUX_IFF_MULTI_QUEUE)) {
                    edge_linux_tun_unlock();
                    return -EDGE_LINUX_EBUSY;
                }
                state->attached = 1u;
                state->queue_attached = 1u;
                state->network_namespace = network_namespace;
                state->ifindex = existing->ifindex;
                state->flags = flags;
                memcpy(state->name, existing->name, sizeof(state->name));
                memcpy(request->name, state->name, sizeof(request->name));
                request->value.flags = (uint16_t)state->flags;
                edge_linux_tun_unlock();
                return 0;
            }
        }
        state->attached = 1u;
        state->queue_attached = 1u;
        state->network_namespace = network_namespace;
        state->flags = flags;
        memcpy(state->name, candidate, sizeof(state->name));
        edge_linux_tun_unlock();

        result = edge_linux_network_tuntap_create(
            network_namespace, candidate,
            type == EDGE_LINUX_IFF_TUN ?
                EDGE_NET_DEVICE_TUN : EDGE_NET_DEVICE_TAP,
            0, edge_linux_tun_transmit, 0,
            state->requested_ifindex, &created_ifindex);
        if (result == 0) break;
        edge_linux_tun_lock();
        state->attached = 0u;
        state->queue_attached = 0u;
        state->network_namespace = 0u;
        state->flags = 0u;
        state->name[0] = 0;
        edge_linux_tun_unlock();
        if (result != -EDGE_LINUX_EEXIST || !generated) return result;
    }
    if (result < 0) return result;
    edge_linux_tun_lock();
    state->ifindex = created_ifindex;
    memcpy(request->name, state->name, sizeof(request->name));
    request->value.flags = (uint16_t)state->flags;
    edge_linux_tun_unlock();
    if (flags & EDGE_LINUX_IFF_NO_CARRIER)
        (void)edge_net_device_set_carrier(created_ifindex, 0);
    return 0;
}

void edge_linux_tun_reset(void) {
    uint32_t index;

    for (index = 0; index < EDGE_LINUX_TUN_MAX; ++index) {
        edge_linux_tun_state_t snapshot;

        edge_linux_tun_lock();
        snapshot = g_edge_linux_tun_states[index];
        memset(&g_edge_linux_tun_states[index], 0,
               sizeof(g_edge_linux_tun_states[index]));
        edge_linux_tun_unlock();
        if (snapshot.used && snapshot.attached)
            (void)edge_linux_network_tuntap_destroy(
                snapshot.network_namespace, snapshot.ifindex);
    }
}

void edge_linux_tun_set_wake_callback(edge_linux_tun_wake_fn callback) {
    g_edge_linux_tun_wake = callback;
}

int edge_linux_tun_open(uint64_t description_identity) {
    edge_linux_tun_state_t *state;

    if (!description_identity) return -EDGE_LINUX_EINVAL;
    edge_linux_tun_lock();
    if (edge_linux_tun_find_locked(description_identity)) {
        edge_linux_tun_unlock();
        return -EDGE_LINUX_EEXIST;
    }
    state = edge_linux_tun_free_locked();
    if (!state) {
        edge_linux_tun_unlock();
        return -EDGE_LINUX_ENOSPC;
    }
    memset(state, 0, sizeof(*state));
    state->used = 1u;
    state->description_identity = description_identity;
    state->read_sequence = 1u;
    state->write_sequence = 1u;
    state->send_buffer = EDGE_LINUX_TUN_PACKET_MAX;
    state->vnet_header_size = EDGE_LINUX_TUN_VNET_HEADER_DEFAULT;
    edge_linux_tun_unlock();
    return 0;
}

void edge_linux_tun_close(uint64_t description_identity) {
    edge_linux_tun_state_t *state;
    uint32_t network_namespace = 0u;
    int32_t ifindex = 0;
    int retain_interface = 0;
    uint32_t index;

    edge_linux_tun_lock();
    state = edge_linux_tun_find_locked(description_identity);
    if (!state) {
        edge_linux_tun_unlock();
        return;
    }
    if (state->persistent && state->attached) {
        state->description_identity = 0u;
        state->queue_attached = 0u;
        state->queue_head = 0u;
        state->queue_count = 0u;
        edge_linux_tun_unlock();
        return;
    }
    if (state->attached) {
        network_namespace = state->network_namespace;
        ifindex = state->ifindex;
    }
    memset(state, 0, sizeof(*state));
    for (index = 0; index < EDGE_LINUX_TUN_MAX; ++index) {
        edge_linux_tun_state_t *candidate =
            &g_edge_linux_tun_states[index];

        if (candidate->used && candidate->attached &&
            candidate->ifindex == ifindex &&
            candidate->network_namespace == network_namespace) {
            retain_interface = 1;
            break;
        }
    }
    edge_linux_tun_unlock();
    if (ifindex > 0 && !retain_interface)
        (void)edge_linux_network_tuntap_destroy(
            network_namespace, ifindex);
}

int edge_linux_tun_ioctl(
    uint64_t description_identity, uint32_t network_namespace,
    uint32_t command, uint64_t argument,
    edge_linux_tun_copy_from_user_fn copy_from_user,
    edge_linux_tun_copy_to_user_fn copy_to_user, void *copy_context) {
    edge_linux_tun_state_t *state;
    edge_linux_tun_ifreq_t interface_request;
    uint32_t value;
    int result = 0;

    if (!description_identity) return -EDGE_LINUX_EBADF;
    if (command == EDGE_LINUX_TUNSETIFF) {
        if (!argument || !copy_from_user || !copy_to_user ||
            copy_from_user(copy_context, &interface_request, argument,
                           sizeof(interface_request)) < 0)
            return -EDGE_LINUX_EFAULT;
        interface_request.name[15] = 0;
        edge_linux_tun_lock();
        state = edge_linux_tun_find_locked(description_identity);
        if (!state) {
            edge_linux_tun_unlock();
            return -EDGE_LINUX_EBADF;
        }
        if (state->attached) {
            uint32_t type = interface_request.value.flags &
                (EDGE_LINUX_IFF_TUN | EDGE_LINUX_IFF_TAP);

            result = (type == (state->flags &
                      (EDGE_LINUX_IFF_TUN | EDGE_LINUX_IFF_TAP)) &&
                      (!interface_request.name[0] ||
                       strcmp(interface_request.name, state->name) == 0)) ?
                0 : -EDGE_LINUX_EINVAL;
            memcpy(interface_request.name, state->name,
                   sizeof(interface_request.name));
            interface_request.value.flags = (uint16_t)state->flags;
            edge_linux_tun_unlock();
        } else {
            edge_linux_tun_unlock();
            result = edge_linux_tun_attach(
                state, network_namespace, &interface_request);
        }
        if (result < 0) return result;
        return copy_to_user(copy_context, argument, &interface_request,
                            sizeof(interface_request)) < 0 ?
            -EDGE_LINUX_EFAULT : 0;
    }
    if (command == EDGE_LINUX_TUNSETQUEUE) {
        uint32_t queue_flags;

        if (!argument || !copy_from_user ||
            copy_from_user(copy_context, &interface_request, argument,
                           sizeof(interface_request)) < 0)
            return -EDGE_LINUX_EFAULT;
        queue_flags = interface_request.value.flags;
        edge_linux_tun_lock();
        state = edge_linux_tun_find_locked(description_identity);
        if (!state || !state->attached) {
            edge_linux_tun_unlock();
            return -EDGE_LINUX_EBADF;
        }
        if (!(state->flags & EDGE_LINUX_IFF_MULTI_QUEUE)) {
            edge_linux_tun_unlock();
            return -EDGE_LINUX_EINVAL;
        }
        if (queue_flags == EDGE_LINUX_IFF_DETACH_QUEUE) {
            if (!state->queue_attached) {
                edge_linux_tun_unlock();
                return -EDGE_LINUX_EINVAL;
            }
            state->queue_attached = 0u;
            state->queue_head = 0u;
            state->queue_count = 0u;
        } else if (queue_flags == EDGE_LINUX_IFF_ATTACH_QUEUE) {
            if (state->queue_attached) {
                edge_linux_tun_unlock();
                return -EDGE_LINUX_EINVAL;
            }
            state->queue_attached = 1u;
        } else {
            edge_linux_tun_unlock();
            return -EDGE_LINUX_EINVAL;
        }
        if (++state->read_sequence == 0u) state->read_sequence = 1u;
        if (++state->write_sequence == 0u) state->write_sequence = 1u;
        edge_linux_tun_unlock();
        return 0;
    }

    edge_linux_tun_lock();
    state = edge_linux_tun_find_locked(description_identity);
    if (!state) {
        edge_linux_tun_unlock();
        return -EDGE_LINUX_EBADF;
    }
    if (command == EDGE_LINUX_TUNGETFEATURES) {
        value = EDGE_LINUX_TUN_SUPPORTED_FLAGS;
    } else if (command == EDGE_LINUX_TUNGETIFF) {
        if (!state->attached) {
            edge_linux_tun_unlock();
            return -EDGE_LINUX_EBADF;
        }
        memset(&interface_request, 0, sizeof(interface_request));
        memcpy(interface_request.name, state->name,
               sizeof(interface_request.name));
        interface_request.value.flags = (uint16_t)state->flags;
        if (!state->queue_attached)
            interface_request.value.flags |=
                EDGE_LINUX_IFF_DETACH_QUEUE;
        edge_linux_tun_unlock();
        if (!argument || !copy_to_user ||
            copy_to_user(copy_context, argument, &interface_request,
                         sizeof(interface_request)) < 0)
            return -EDGE_LINUX_EFAULT;
        return 0;
    } else if (command == EDGE_LINUX_TUNGETSNDBUF) {
        value = state->send_buffer;
    } else if (command == EDGE_LINUX_TUNGETVNETHDRSZ) {
        value = state->vnet_header_size;
    } else {
        edge_linux_tun_unlock();
        if (!argument || !copy_from_user ||
            copy_from_user(copy_context, &value, argument,
                           sizeof(value)) < 0)
            return -EDGE_LINUX_EFAULT;
        edge_linux_tun_lock();
        state = edge_linux_tun_find_locked(description_identity);
        if (!state) {
            edge_linux_tun_unlock();
            return -EDGE_LINUX_EBADF;
        }
        switch (command) {
            case EDGE_LINUX_TUNSETPERSIST:
                if (!state->attached) result = -EDGE_LINUX_EBADF;
                else {
                    uint32_t index;

                    for (index = 0; index < EDGE_LINUX_TUN_MAX; ++index) {
                        edge_linux_tun_state_t *candidate =
                            &g_edge_linux_tun_states[index];

                        if (candidate->used && candidate->attached &&
                            candidate->ifindex == state->ifindex &&
                            candidate->network_namespace ==
                                state->network_namespace)
                            candidate->persistent = 0u;
                    }
                    if (value) state->persistent = 1u;
                }
                break;
            case EDGE_LINUX_TUNSETOWNER:
                state->owner = value;
                break;
            case EDGE_LINUX_TUNSETGROUP:
                state->group = value;
                break;
            case EDGE_LINUX_TUNSETSNDBUF:
                if (value < 2048u) result = -EDGE_LINUX_EINVAL;
                else state->send_buffer = value;
                break;
            case EDGE_LINUX_TUNSETVNETHDRSZ:
                if (value < 10u || value > 64u)
                    result = -EDGE_LINUX_EINVAL;
                else
                    state->vnet_header_size = value;
                break;
            case EDGE_LINUX_TUNSETOFFLOAD:
                state->offload = value;
                break;
            case EDGE_LINUX_TUNSETIFINDEX:
                if (state->attached)
                    result = -EDGE_LINUX_EPERM;
                else if (value > 0x7ffffffeu)
                    result = -EDGE_LINUX_EINVAL;
                else
                    state->requested_ifindex = (int32_t)value;
                break;
            case EDGE_LINUX_TUNSETCARRIER:
                if (!state->attached)
                    result = -EDGE_LINUX_EBADF;
                else
                    result = edge_net_device_set_carrier(
                        state->ifindex, value != 0u) == EDGE_NET_OK ?
                        0 : -EDGE_LINUX_ENODEV;
                break;
            case EDGE_LINUX_TUNSETNOCSUM:
            case EDGE_LINUX_TUNSETDEBUG:
            case EDGE_LINUX_TUNSETLINK:
                break;
            default:
                result = -EDGE_LINUX_ENOTTY;
                break;
        }
        edge_linux_tun_unlock();
        return result;
    }
    edge_linux_tun_unlock();
    if (!argument || !copy_to_user ||
        copy_to_user(copy_context, argument, &value, sizeof(value)) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

int64_t edge_linux_tun_read(
    uint64_t description_identity, uint64_t destination,
    uint32_t capacity, edge_linux_tun_copy_to_user_fn copy_to_user,
    void *copy_context) {
    edge_linux_tun_state_t *state;
    edge_linux_tun_packet_t *packet;
    uint8_t header[68];
    uint32_t header_length = 0u;
    uint32_t payload_length;

    if (!destination || !capacity || !copy_to_user)
        return -EDGE_LINUX_EINVAL;
    edge_linux_tun_lock();
    state = edge_linux_tun_find_locked(description_identity);
    if (!state || !state->attached || !state->queue_attached) {
        edge_linux_tun_unlock();
        return -EDGE_LINUX_EBADF;
    }
    if (!state->queue_count) {
        edge_linux_tun_unlock();
        return -EDGE_LINUX_EAGAIN;
    }
    packet = &state->queue[state->queue_head];
    memset(header, 0, sizeof(header));
    if (!(state->flags & EDGE_LINUX_IFF_NO_PI)) {
        header[2] = (uint8_t)(packet->protocol >> 8u);
        header[3] = (uint8_t)packet->protocol;
        header_length = 4u;
    }
    if (state->flags & EDGE_LINUX_IFF_VNET_HDR) {
        if (header_length + state->vnet_header_size > sizeof(header)) {
            edge_linux_tun_unlock();
            return -EDGE_LINUX_EINVAL;
        }
        header_length += state->vnet_header_size;
    }
    if (capacity < header_length) {
        edge_linux_tun_unlock();
        return -EDGE_LINUX_EINVAL;
    }
    payload_length = packet->length;
    if (payload_length > capacity - header_length)
        payload_length = capacity - header_length;
    if ((header_length &&
         copy_to_user(copy_context, destination, header,
                      header_length) < 0) ||
        (payload_length &&
         copy_to_user(copy_context, destination + header_length,
                      packet->data, payload_length) < 0)) {
        edge_linux_tun_unlock();
        return -EDGE_LINUX_EFAULT;
    }
    state->queue_head = (uint8_t)(
        (state->queue_head + 1u) % EDGE_LINUX_TUN_QUEUE_DEPTH);
    --state->queue_count;
    if (++state->write_sequence == 0u) state->write_sequence = 1u;
    edge_linux_tun_unlock();
    return (int64_t)(header_length + payload_length);
}

int64_t edge_linux_tun_write(
    uint64_t description_identity, uint64_t source, uint32_t length,
    edge_linux_tun_copy_from_user_fn copy_from_user,
    void *copy_context) {
    edge_linux_tun_state_t *state;
    edge_net_packet_segment_t segment;
    edge_net_packet_metadata_t metadata;
    edge_net_packet_t packet;
    uint8_t header[68];
    uint32_t header_length = 0u;
    uint32_t payload_length;
    uint16_t protocol = 0u;
    int tap;
    int result;

    if (!source || !length || !copy_from_user)
        return -EDGE_LINUX_EINVAL;
    edge_linux_tun_lock();
    state = edge_linux_tun_find_locked(description_identity);
    if (!state || !state->attached || !state->queue_attached) {
        edge_linux_tun_unlock();
        return -EDGE_LINUX_EBADF;
    }
    if (state->write_active) {
        edge_linux_tun_unlock();
        return -EDGE_LINUX_EAGAIN;
    }
    if (!(state->flags & EDGE_LINUX_IFF_NO_PI)) header_length = 4u;
    if (state->flags & EDGE_LINUX_IFF_VNET_HDR)
        header_length += state->vnet_header_size;
    if (header_length > sizeof(header) || length <= header_length ||
        length - header_length > EDGE_LINUX_TUN_PACKET_MAX) {
        edge_linux_tun_unlock();
        return -EDGE_LINUX_EMSGSIZE;
    }
    state->write_active = 1u;
    tap = (state->flags & EDGE_LINUX_IFF_TAP) != 0u;
    payload_length = length - header_length;
    edge_linux_tun_unlock();

    if ((header_length &&
         copy_from_user(copy_context, header, source,
                        header_length) < 0) ||
        copy_from_user(copy_context, state->ingress,
                       source + header_length, payload_length) < 0) {
        result = -EDGE_LINUX_EFAULT;
        goto write_complete;
    }
    if (!(state->flags & EDGE_LINUX_IFF_NO_PI))
        protocol = (uint16_t)(((uint16_t)header[2] << 8u) | header[3]);
    if (!protocol)
        protocol = edge_linux_tun_protocol(
            state->ingress, payload_length, tap);
    if (!protocol) {
        result = -EDGE_LINUX_EINVAL;
        goto write_complete;
    }
    segment.data = state->ingress;
    segment.length = payload_length;
    memset(&metadata, 0, sizeof(metadata));
    metadata.network_namespace = state->network_namespace;
    metadata.input_ifindex = state->ifindex;
    metadata.protocol = protocol;
    metadata.network_header = tap ? 14u : 0u;
    if (edge_net_packet_initialize(
            &packet, &segment, 1u, &metadata, 0, 0) != EDGE_NET_OK) {
        result = -EDGE_LINUX_EINVAL;
        goto write_complete;
    }
    result = edge_net_device_receive(state->ifindex, &packet);
    if (result == EDGE_NET_MESSAGE_TOO_LARGE)
        result = -EDGE_LINUX_EMSGSIZE;
    else if (result == EDGE_NET_LINK_DOWN)
        result = -EDGE_LINUX_ENETDOWN;
    else if (result < 0)
        result = -EDGE_LINUX_EIO;
    else
        result = (int)length;

write_complete:
    edge_linux_tun_lock();
    state->write_active = 0u;
    if (++state->write_sequence == 0u) state->write_sequence = 1u;
    edge_linux_tun_unlock();
    return result;
}

int edge_linux_tun_read_ready(uint64_t description_identity) {
    edge_linux_tun_state_t *state;
    int ready;

    edge_linux_tun_lock();
    state = edge_linux_tun_find_locked(description_identity);
    ready = state && state->attached && state->queue_attached &&
            state->queue_count != 0u;
    edge_linux_tun_unlock();
    return ready;
}

int edge_linux_tun_write_ready(uint64_t description_identity) {
    edge_linux_tun_state_t *state;
    int ready;

    edge_linux_tun_lock();
    state = edge_linux_tun_find_locked(description_identity);
    ready = state && state->attached && state->queue_attached &&
            !state->write_active;
    edge_linux_tun_unlock();
    return ready;
}

uint64_t edge_linux_tun_read_sequence(uint64_t description_identity) {
    edge_linux_tun_state_t *state;
    uint64_t sequence;

    edge_linux_tun_lock();
    state = edge_linux_tun_find_locked(description_identity);
    sequence = state ? state->read_sequence : 0u;
    edge_linux_tun_unlock();
    return sequence;
}

uint64_t edge_linux_tun_write_sequence(uint64_t description_identity) {
    edge_linux_tun_state_t *state;
    uint64_t sequence;

    edge_linux_tun_lock();
    state = edge_linux_tun_find_locked(description_identity);
    sequence = state ? state->write_sequence : 0u;
    edge_linux_tun_unlock();
    return sequence;
}
