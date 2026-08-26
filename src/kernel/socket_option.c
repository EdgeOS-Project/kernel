/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent socket option state.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/socket_runtime.h"
#include "kernel/bpf_runtime.h"
#include "kernel/fs_context.h"
#include "kernel/io_uring_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/linux_netlink.h"
#include "kernel/linux_packet.h"
#include "kernel/process_runtime.h"
#include "sys/boottime.h"
#include "vfs/vfs.h"

#include <string.h>

#include "lwip/igmp.h"
#include "lwip/err.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip6_addr.h"
#include "lwip/mld6.h"
#include "lwip/netif.h"

int kernel_socket_lwip_errno(int transport_error, int active_open) {
    switch (transport_error) {
    case ERR_OK:
        return 0;
    case ERR_MEM:
        return EDGE_LINUX_ENOMEM;
    case ERR_BUF:
        return EDGE_LINUX_ENOBUFS;
    case ERR_TIMEOUT:
        return EDGE_LINUX_ETIMEDOUT;
    case ERR_RTE:
        return EDGE_LINUX_EHOSTUNREACH;
    case ERR_INPROGRESS:
        return EDGE_LINUX_EINPROGRESS;
    case ERR_VAL:
    case ERR_ARG:
        return EDGE_LINUX_EINVAL;
    case ERR_WOULDBLOCK:
        return EDGE_LINUX_EAGAIN;
    case ERR_USE:
        return EDGE_LINUX_EADDRINUSE;
    case ERR_ALREADY:
        return EDGE_LINUX_EALREADY;
    case ERR_ISCONN:
        return EDGE_LINUX_EISCONN;
    case ERR_CONN:
    case ERR_CLSD:
        return EDGE_LINUX_ENOTCONN;
    case ERR_IF:
        return EDGE_LINUX_ENETDOWN;
    case ERR_ABRT:
        return EDGE_LINUX_ECONNABORTED;
    case ERR_RST:
        return active_open ? EDGE_LINUX_ECONNREFUSED :
                             EDGE_LINUX_ECONNRESET;
    default:
        return EDGE_LINUX_EIO;
    }
}

int kernel_unix_socket_close_notifies_peer(uint32_t type,
                                           int peer_points_back) {
    if (type == EDGE_LINUX_SOCK_STREAM ||
        type == EDGE_LINUX_SOCK_SEQPACKET)
        return 1;
    return type == EDGE_LINUX_SOCK_DGRAM && peer_points_back;
}

static int unix_path_append(char *path, uint32_t capacity,
                            const char *suffix) {
    uint32_t length;
    if (!path || !suffix || capacity == 0) return -1;
    length = (uint32_t)strlen(path);
    while (*suffix) {
        if (length + 1u >= capacity) return -1;
        path[length++] = *suffix++;
    }
    path[length] = 0;
    return 0;
}

int kernel_unix_socket_resolve_path(const char *path, char *resolved,
                                    uint32_t capacity) {
    char current[256];
    char prefix[256];
    char target[256];
    char candidate[256];
    char cwd[256];
    char root[256];

    if (!path || !resolved || capacity < 2u) return -1;
    if (path[0] == '@') {
        if ((uint32_t)strlen(path) >= capacity) return -1;
        strcpy(resolved, path);
        return 0;
    }
    if (kernel_current_fs_snapshot(cwd, sizeof(cwd), root, sizeof(root)) < 0)
        return -1;
    if (kernel_fs_path_resolve(root, cwd, path, prefix, sizeof(prefix),
                               current, sizeof(current)) < 0)
        return -1;
    for (uint32_t depth = 0; depth < 40u; ++depth) {
        uint32_t length = (uint32_t)strlen(current);
        int changed = 0;
        for (uint32_t index = 1; index <= length; ++index) {
            int target_length;
            uint32_t parent_length;
            if (current[index] != '/' && current[index] != 0) continue;
            if (index >= sizeof(prefix)) return -1;
            memcpy(prefix, current, index);
            prefix[index] = 0;
            target_length = vfs_readlink(prefix, target,
                                         sizeof(target) - 1u);
            if (target_length < 0) continue;
            if ((uint32_t)target_length >= sizeof(target)) return -1;
            target[target_length] = 0;
            candidate[0] = 0;
            if (target[0] == '/') {
                if (kernel_fs_path_resolve(
                        root, cwd, target, prefix, sizeof(prefix), candidate,
                        sizeof(candidate)) < 0)
                    return -1;
            } else {
                parent_length = index;
                while (parent_length > 1u &&
                       current[parent_length - 1u] != '/')
                    --parent_length;
                if (parent_length > 1u) --parent_length;
                if (parent_length >= sizeof(candidate)) return -1;
                memcpy(candidate, current, parent_length);
                candidate[parent_length] = 0;
                if (strcmp(candidate, "/") != 0 &&
                    unix_path_append(candidate, sizeof(candidate), "/") < 0)
                    return -1;
                if (unix_path_append(candidate, sizeof(candidate), target) < 0)
                    return -1;
            }
            if (current[index] &&
                unix_path_append(candidate, sizeof(candidate),
                                 current + index) < 0)
                return -1;
            if (kernel_fs_path_normalize(0, candidate, current,
                                         sizeof(current)) < 0)
                return -1;
            changed = 1;
            break;
        }
        if (!changed) {
            if ((uint32_t)strlen(current) >= capacity) return -1;
            strcpy(resolved, current);
            return 0;
        }
    }
    return -1;
}

static struct netif *kernel_socket_multicast_netif(
    uint32_t interface_address, uint32_t interface_index) {
    struct netif *selected = 0;
    struct netif *candidate;

    if (interface_index) {
        if (interface_index > UINT8_MAX) return 0;
        selected = netif_get_by_index((uint8_t)interface_index);
        if (!selected) return 0;
    }
    if (interface_address) {
        NETIF_FOREACH(candidate) {
            if (ip4_addr_get_u32(netif_ip4_addr(candidate)) !=
                interface_address)
                continue;
            if (selected && selected != candidate) return 0;
            selected = candidate;
            break;
        }
        if (!selected) return 0;
    }
    return selected ? selected : netif_default;
}

static int kernel_socket_multicast_group_equal(
    const kernel_socket_multicast_membership_t *membership,
    uint32_t domain, const uint8_t *group, uint32_t interface_index) {
    uint32_t length = domain == EDGE_LINUX_AF_INET ? 4u : 16u;
    return membership && membership->used && membership->domain == domain &&
           membership->interface_index == interface_index &&
           memcmp(membership->group, group, length) == 0;
}

static int kernel_socket_multicast_lwip_update(
    uint32_t domain, const uint8_t *group, struct netif *netif,
    int joining) {
    err_t error;
    if (domain == EDGE_LINUX_AF_INET) {
        ip4_addr_t address;
        memcpy(&address.addr, group, sizeof(address.addr));
        if (!ip4_addr_ismulticast(&address)) return -EDGE_LINUX_EINVAL;
        error = joining ? igmp_joingroup_netif(netif, &address) :
                          igmp_leavegroup_netif(netif, &address);
    } else if (domain == EDGE_LINUX_AF_INET6) {
        ip6_addr_t address;
        memset(&address, 0, sizeof(address));
        memcpy(address.addr, group, 16u);
        if (!ip6_addr_ismulticast(&address)) return -EDGE_LINUX_EINVAL;
        error = joining ? mld6_joingroup_netif(netif, &address) :
                          mld6_leavegroup_netif(netif, &address);
    } else {
        return -EDGE_LINUX_EAFNOSUPPORT;
    }
    if (error == ERR_OK) return 0;
    if (error == ERR_MEM) return -EDGE_LINUX_ENOBUFS;
    if (error == ERR_IF) return -EDGE_LINUX_ENODEV;
    return joining ? -EDGE_LINUX_EINVAL : -EDGE_LINUX_EADDRNOTAVAIL;
}

int kernel_socket_multicast_state_update(
    kernel_socket_option_state_t *state, uint32_t domain,
    const uint8_t *group, uint32_t interface_address,
    uint32_t interface_index, int joining) {
    kernel_socket_multicast_membership_t *free_membership = 0;
    kernel_socket_multicast_membership_t *membership = 0;
    struct netif *netif;
    uint32_t selected_index;
    uint32_t group_length;
    int status;

    if (!state || !group) return -EDGE_LINUX_EINVAL;
    if (domain != EDGE_LINUX_AF_INET && domain != EDGE_LINUX_AF_INET6)
        return -EDGE_LINUX_EAFNOSUPPORT;
    netif = kernel_socket_multicast_netif(
        domain == EDGE_LINUX_AF_INET ? interface_address : 0,
        interface_index);
    if (!netif) return -EDGE_LINUX_ENODEV;
    selected_index = netif_get_index(netif);
    group_length = domain == EDGE_LINUX_AF_INET ? 4u : 16u;

    for (uint32_t index = 0;
         index < KERNEL_SOCKET_MULTICAST_MEMBERSHIP_MAX; ++index) {
        kernel_socket_multicast_membership_t *candidate =
            &state->multicast_memberships[index];
        if (!candidate->used) {
            if (!free_membership) free_membership = candidate;
            continue;
        }
        if (kernel_socket_multicast_group_equal(
                candidate, domain, group, selected_index)) {
            membership = candidate;
            break;
        }
    }
    if (joining && membership) return -EDGE_LINUX_EADDRINUSE;
    if (!joining && !membership) return -EDGE_LINUX_EADDRNOTAVAIL;
    if (joining && !free_membership) return -EDGE_LINUX_ENOBUFS;

    status = kernel_socket_multicast_lwip_update(
        domain, group, netif, joining);
    if (status < 0) return status;
    if (!joining) {
        memset(membership, 0, sizeof(*membership));
        return 0;
    }
    memset(free_membership, 0, sizeof(*free_membership));
    free_membership->used = 1;
    free_membership->domain = (uint8_t)domain;
    free_membership->interface_index = selected_index;
    memcpy(free_membership->group, group, group_length);
    return 0;
}

void kernel_socket_multicast_state_release(
    kernel_socket_option_state_t *state) {
    if (!state) return;
    for (uint32_t index = 0;
         index < KERNEL_SOCKET_MULTICAST_MEMBERSHIP_MAX; ++index) {
        kernel_socket_multicast_membership_t *membership =
            &state->multicast_memberships[index];
        struct netif *netif;
        if (!membership->used) continue;
        netif = membership->interface_index <= UINT8_MAX ?
            netif_get_by_index((uint8_t)membership->interface_index) : 0;
        if (netif)
            (void)kernel_socket_multicast_lwip_update(
                membership->domain, membership->group, netif, 0);
        memset(membership, 0, sizeof(*membership));
    }
}

int kernel_socket_option_set_integer(
    int32_t descriptor, kernel_socket_option_id_t option, int64_t value) {
    kernel_socket_option_runtime_view_t view;
    uint32_t effects = KERNEL_SOCKET_OPTION_EFFECT_NONE;
    int status;

    status = edge_socket_runtime_option_view(descriptor, &view);
    if (status < 0) return status;
    if (!view.state) return -EDGE_LINUX_EIO;
    status = kernel_socket_option_state_set_integer(
        view.state, option, value, &effects);
    if (status < 0) return status;
    if (view.apply_effects)
        view.apply_effects(view.context, effects);
    return 0;
}

int kernel_socket_option_get_integer(
    int32_t descriptor, kernel_socket_option_id_t option, int64_t *value) {
    kernel_socket_option_runtime_view_t view;
    int status;

    if (!value) return -EDGE_LINUX_EINVAL;
    status = edge_socket_runtime_option_view(descriptor, &view);
    if (status < 0) return status;
    if (!view.state) return -EDGE_LINUX_EIO;
    return kernel_socket_option_state_get_integer(view.state, option, value);
}

int kernel_socket_option_set_timestamping(
        int32_t descriptor, uint32_t flags, int32_t bind_phc,
        int new_layout) {
    kernel_socket_option_runtime_view_t view;
    uint32_t previous;
    int status;

    (void)bind_phc;
    if (flags & ~EDGE_LINUX_SOF_TIMESTAMPING_MASK)
        return -EDGE_LINUX_EINVAL;
    if ((flags & EDGE_LINUX_SOF_TIMESTAMPING_OPT_ID_TCP) &&
        !(flags & EDGE_LINUX_SOF_TIMESTAMPING_OPT_ID))
        return -EDGE_LINUX_EINVAL;
    if ((flags & EDGE_LINUX_SOF_TIMESTAMPING_OPT_STATS) &&
        !(flags & EDGE_LINUX_SOF_TIMESTAMPING_OPT_TSONLY))
        return -EDGE_LINUX_EINVAL;
    status = edge_socket_runtime_option_view(descriptor, &view);
    if (status < 0) return status;
    if (!view.state) return -EDGE_LINUX_EIO;
    if (flags & EDGE_LINUX_SOF_TIMESTAMPING_BIND_PHC) {
        if (!view.bound_interface_index ||
            *view.bound_interface_index <= 0)
            return -EDGE_LINUX_EOPNOTSUPP;
        /* No EdgeOS network device currently exports PHC virtual clocks. */
        return -EDGE_LINUX_EINVAL;
    }
    previous = view.state->timestamping_flags;
    if ((flags & EDGE_LINUX_SOF_TIMESTAMPING_OPT_ID) &&
        !(previous & EDGE_LINUX_SOF_TIMESTAMPING_OPT_ID))
        view.state->tx_timestamp_key = 0u;
    view.state->timestamping_flags = flags;
    view.state->timestamping_new = new_layout ? 1u : 0u;
    return 0;
}

int kernel_socket_option_get_timestamping(
        int32_t descriptor, int new_layout,
        struct edge_linux_so_timestamping *timestamping) {
    kernel_socket_option_runtime_view_t view;
    int status;

    if (!timestamping) return -EDGE_LINUX_EINVAL;
    memset(timestamping, 0, sizeof(*timestamping));
    status = edge_socket_runtime_option_view(descriptor, &view);
    if (status < 0) return status;
    if (!view.state) return -EDGE_LINUX_EIO;
    if (!new_layout || view.state->timestamping_new) {
        timestamping->flags =
            (int32_t)view.state->timestamping_flags;
        timestamping->bind_phc =
            view.state->timestamping_bind_phc;
    }
    return 0;
}

void kernel_socket_tx_timestamp_notify(int32_t descriptor) {
    kernel_socket_option_runtime_view_t view;
    uint64_t realtime_us;
    uint32_t key;

    if (edge_socket_runtime_option_view(descriptor, &view) < 0 ||
        !view.state || !view.open_description_identity)
        return;
    if ((view.state->timestamping_flags &
         (EDGE_LINUX_SOF_TIMESTAMPING_TX_SOFTWARE |
          EDGE_LINUX_SOF_TIMESTAMPING_SOFTWARE)) !=
        (EDGE_LINUX_SOF_TIMESTAMPING_TX_SOFTWARE |
         EDGE_LINUX_SOF_TIMESTAMPING_SOFTWARE))
        return;
    key = (view.state->timestamping_flags &
           EDGE_LINUX_SOF_TIMESTAMPING_OPT_ID) ?
        view.state->tx_timestamp_key++ : 0u;
    realtime_us = boottime_realtime_us();
    (void)kernel_io_uring_tx_timestamp_complete(
        view.open_description_identity, key, 0u,
        realtime_us / 1000000u,
        (realtime_us % 1000000u) * 1000u, 0);
}

static int kernel_socket_icmp6_filter_view(
    int32_t descriptor, kernel_socket_option_runtime_view_t *view) {
    int status;

    if (!view) return -EDGE_LINUX_EINVAL;
    status = edge_socket_runtime_option_view(descriptor, view);
    if (status < 0) return status;
    if (!view->state) return -EDGE_LINUX_EIO;
    if (view->domain != EDGE_LINUX_AF_INET6 ||
        view->type != EDGE_LINUX_SOCK_RAW ||
        view->protocol != EDGE_LINUX_IPPROTO_ICMPV6)
        return -EDGE_LINUX_ENOPROTOOPT;
    return 0;
}

int kernel_socket_option_set_icmp6_filter(
    int32_t descriptor,
    const uint32_t filter[KERNEL_SOCKET_ICMP6_FILTER_WORDS]) {
    kernel_socket_option_runtime_view_t view;
    int status;

    if (!filter) return -EDGE_LINUX_EINVAL;
    status = kernel_socket_icmp6_filter_view(descriptor, &view);
    if (status < 0) return status;
    memcpy(view.state->icmp6_filter, filter,
           sizeof(view.state->icmp6_filter));
    return 0;
}

int kernel_socket_option_get_icmp6_filter(
    int32_t descriptor,
    uint32_t filter[KERNEL_SOCKET_ICMP6_FILTER_WORDS]) {
    kernel_socket_option_runtime_view_t view;
    int status;

    if (!filter) return -EDGE_LINUX_EINVAL;
    status = kernel_socket_icmp6_filter_view(descriptor, &view);
    if (status < 0) return status;
    memcpy(filter, view.state->icmp6_filter,
           sizeof(view.state->icmp6_filter));
    return 0;
}

int kernel_socket_multicast_membership_update(
    int32_t descriptor, uint32_t domain, const uint8_t *group,
    uint32_t interface_address, uint32_t interface_index, int joining) {
    kernel_socket_option_runtime_view_t view;
    int status = edge_socket_runtime_option_view(descriptor, &view);

    if (status < 0) return status;
    if (!view.state) return -EDGE_LINUX_EIO;
    if (view.type != EDGE_LINUX_SOCK_DGRAM)
        return -EDGE_LINUX_ENOPROTOOPT;
    return kernel_socket_multicast_state_update(
        view.state, domain, group, interface_address,
        interface_index, joining);
}

int kernel_socket_multicast_interface_set(
    int32_t descriptor, uint32_t domain,
    uint32_t interface_address, uint32_t interface_index) {
    kernel_socket_option_runtime_view_t view;
    struct netif *netif = 0;
    int status;

    status = edge_socket_runtime_option_view(descriptor, &view);
    if (status < 0) return status;
    if (!view.state) return -EDGE_LINUX_EIO;
    if (view.type != EDGE_LINUX_SOCK_DGRAM)
        return -EDGE_LINUX_ENOPROTOOPT;
    if ((domain == EDGE_LINUX_AF_INET &&
         view.domain != EDGE_LINUX_AF_INET &&
         view.domain != EDGE_LINUX_AF_INET6) ||
        (domain == EDGE_LINUX_AF_INET6 &&
         view.domain != EDGE_LINUX_AF_INET6))
        return -EDGE_LINUX_ENOPROTOOPT;
    if (domain != EDGE_LINUX_AF_INET && domain != EDGE_LINUX_AF_INET6)
        return -EDGE_LINUX_EAFNOSUPPORT;
    if (interface_address || interface_index) {
        netif = kernel_socket_multicast_netif(
            domain == EDGE_LINUX_AF_INET ? interface_address : 0u,
            interface_index);
        if (!netif) return -EDGE_LINUX_ENODEV;
        interface_index = netif_get_index(netif);
        if (domain == EDGE_LINUX_AF_INET)
            interface_address = ip4_addr_get_u32(netif_ip4_addr(netif));
    }
    if (domain == EDGE_LINUX_AF_INET) {
        view.state->ip_multicast_interface_address = interface_address;
        view.state->ip_multicast_interface_index = interface_index;
    } else {
        view.state->ipv6_multicast_interface_index = interface_index;
    }
    if (view.apply_effects)
        view.apply_effects(
            view.context, KERNEL_SOCKET_OPTION_EFFECT_IP_TRANSPORT);
    return 0;
}

int kernel_socket_multicast_interface_get(
    int32_t descriptor, uint32_t domain,
    uint32_t *interface_address, uint32_t *interface_index) {
    kernel_socket_option_runtime_view_t view;
    int status;

    if (!interface_address || !interface_index)
        return -EDGE_LINUX_EINVAL;
    status = edge_socket_runtime_option_view(descriptor, &view);
    if (status < 0) return status;
    if (!view.state) return -EDGE_LINUX_EIO;
    if (view.type != EDGE_LINUX_SOCK_DGRAM &&
        view.type != EDGE_LINUX_SOCK_RAW)
        return -EDGE_LINUX_ENOPROTOOPT;
    if ((domain == EDGE_LINUX_AF_INET &&
         view.domain != EDGE_LINUX_AF_INET &&
         view.domain != EDGE_LINUX_AF_INET6) ||
        (domain == EDGE_LINUX_AF_INET6 &&
         view.domain != EDGE_LINUX_AF_INET6))
        return -EDGE_LINUX_ENOPROTOOPT;
    if (domain == EDGE_LINUX_AF_INET) {
        *interface_address =
            view.state->ip_multicast_interface_address;
        *interface_index = view.state->ip_multicast_interface_index;
    } else if (domain == EDGE_LINUX_AF_INET6) {
        *interface_address = 0u;
        *interface_index =
            view.state->ipv6_multicast_interface_index;
    } else {
        return -EDGE_LINUX_EAFNOSUPPORT;
    }
    return 0;
}

int kernel_socket_option_set_bound_device(
    int32_t descriptor, const char *name, uint32_t length) {
    kernel_socket_option_runtime_view_t view;
    edge_linux_network_interface_snapshot_t interface;
    char terminated[16];
    int32_t interface_index;
    int status = edge_socket_runtime_option_view(descriptor, &view);

    if (status < 0) return status;
    if (!view.bound_interface) return -EDGE_LINUX_EIO;
    status = kernel_socket_bound_device_parse(
        name, length, &interface_index);
    if (status == -EDGE_LINUX_ENODEV && name && length) {
        uint32_t copied = length < sizeof(terminated) - 1u ?
            length : sizeof(terminated) - 1u;

        memset(terminated, 0, sizeof(terminated));
        memcpy(terminated, name, copied);
        if (edge_linux_network_interface_by_name(
                view.network_namespace, terminated, &interface) == 0) {
            interface_index = interface.ifindex;
            status = 0;
        }
    }
    if (status < 0) return status;
    *view.bound_interface = interface_index;
    return status;
}

int kernel_socket_option_get_bound_device(
    int32_t descriptor, char *name, uint32_t capacity, uint32_t *length) {
    kernel_socket_option_runtime_view_t view;
    edge_linux_network_interface_snapshot_t interface;
    uint32_t required;
    int status = edge_socket_runtime_option_view(descriptor, &view);

    if (status < 0) return status;
    if (!view.bound_interface) return -EDGE_LINUX_EIO;
    if (*view.bound_interface > 2) {
        status = edge_linux_network_interface_by_index(
            view.network_namespace, *view.bound_interface, &interface);
        if (status < 0) return status;
        required = (uint32_t)strlen(interface.name) + 1u;
        if (capacity < required) return -EDGE_LINUX_EINVAL;
        memcpy(name, interface.name, required);
        *length = required;
        return 0;
    }
    return kernel_socket_bound_device_format(
        *view.bound_interface, name, capacity, length);
}

int kernel_socket_option_take_error(int32_t descriptor, int32_t *error) {
    kernel_socket_option_runtime_view_t view;
    int status;

    if (!error) return -EDGE_LINUX_EINVAL;
    status = edge_socket_runtime_option_view(descriptor, &view);
    if (status < 0) return status;
    if (!view.pending_error) return -EDGE_LINUX_EIO;
    if (view.prepare_error_take)
        view.prepare_error_take(view.context);
    return kernel_socket_error_take(view.pending_error, error);
}

int kernel_socket_option_get_mtu(int32_t descriptor, int32_t *mtu) {
    kernel_socket_option_runtime_view_t view;
    int status;

    if (!mtu) return -EDGE_LINUX_EINVAL;
    status = edge_socket_runtime_option_view(descriptor, &view);
    if (status < 0) return status;
    *mtu = kernel_socket_mtu_normalize(view.transport_mtu);
    return 0;
}

int kernel_socket_option_get_peer_credentials(
    int32_t descriptor, kernel_socket_peer_credentials_t *credentials) {
    kernel_socket_option_runtime_view_t view;
    int status;

    if (!credentials) return -EDGE_LINUX_EINVAL;
    status = edge_socket_runtime_option_view(descriptor, &view);
    if (status < 0) return status;
    if (view.domain != EDGE_LINUX_AF_UNIX)
        return -EDGE_LINUX_ENOPROTOOPT;
    if (!view.peer_credentials) return -EDGE_LINUX_EIO;
    return view.peer_credentials(view.context, credentials);
}

int64_t kernel_socket_option_get_peer_pidfd(int32_t descriptor) {
    kernel_socket_option_runtime_view_t view;
    int status = edge_socket_runtime_option_view(descriptor, &view);

    if (status < 0) return status;
    if (view.domain != EDGE_LINUX_AF_UNIX)
        return -EDGE_LINUX_ENOPROTOOPT;
    if (!view.peer_pidfd) return -EDGE_LINUX_ENOTCONN;
    return view.peer_pidfd(view.context);
}

int kernel_socket_option_get_peer_group_count(
    int32_t descriptor, uint32_t *count) {
    kernel_socket_option_runtime_view_t view;
    int status;

    if (!count) return -EDGE_LINUX_EINVAL;
    status = edge_socket_runtime_option_view(descriptor, &view);
    if (status < 0) return status;
    if (view.domain != EDGE_LINUX_AF_UNIX)
        return -EDGE_LINUX_ENOPROTOOPT;
    if (!view.peer_group_count) return -EDGE_LINUX_EIO;
    return view.peer_group_count(view.context, count);
}

int kernel_socket_option_get_peer_group(
    int32_t descriptor, uint32_t index, uint32_t *group_id) {
    kernel_socket_option_runtime_view_t view;
    int status;

    if (!group_id) return -EDGE_LINUX_EINVAL;
    status = edge_socket_runtime_option_view(descriptor, &view);
    if (status < 0) return status;
    if (view.domain != EDGE_LINUX_AF_UNIX)
        return -EDGE_LINUX_ENOPROTOOPT;
    if (!view.peer_group) return -EDGE_LINUX_EIO;
    return view.peer_group(view.context, index, group_id);
}

int kernel_socket_option_attach_filter(
    int32_t descriptor, uint64_t user_program, uint32_t program_length,
    void *copy_context, edge_linux_copy_from_user_fn copy_from_user_fn) {
    kernel_socket_option_runtime_view_t view;
    int status = edge_socket_runtime_option_view(descriptor, &view);

    if (status < 0) return status;
    if (!user_program || !program_length || !copy_from_user_fn ||
        program_length > EDGE_LINUX_PACKET_FILTER_MAX)
        return -EDGE_LINUX_EINVAL;
    if (!view.state) return -EDGE_LINUX_EIO;
    if (view.state->filter_locked) return -EDGE_LINUX_EPERM;
    if (!view.filter || !view.filter_length) return -EDGE_LINUX_EIO;
    *view.filter_length = 0;
    if (copy_from_user_fn(
            copy_context, view.filter, user_program,
            (uint64_t)program_length * sizeof(view.filter[0])) < 0)
        return -EDGE_LINUX_EFAULT;
    if (!edge_linux_bpf_validate(view.filter, program_length))
        return -EDGE_LINUX_EINVAL;
    if (view.packet_handle >= 0) {
        status = edge_linux_packet_attach_filter(
            view.packet_handle, view.filter, program_length);
        if (status < 0) return status;
    }
    if (view.bpf_filter_object_id && *view.bpf_filter_object_id >= 0) {
        kernel_bpf_object_release(*view.bpf_filter_object_id);
        *view.bpf_filter_object_id = -1;
    }
    *view.filter_length = (uint16_t)program_length;
    return 0;
}

int kernel_socket_option_attach_bpf_filter(
    int32_t descriptor, int32_t object_id) {
    kernel_socket_option_runtime_view_t view;
    kernel_bpf_program_info_t info;
    int32_t previous = -1;
    int status = edge_socket_runtime_option_view(descriptor, &view);

    if (status < 0) return status;
    if (!view.state) return -EDGE_LINUX_EIO;
    if (view.state->filter_locked) return -EDGE_LINUX_EPERM;
    if (!view.bpf_filter_object_id || !view.filter_length)
        return -EDGE_LINUX_EIO;
    status = kernel_bpf_program_info(object_id, &info);
    if (status < 0) return status;
    if (info.type != KERNEL_BPF_PROG_TYPE_SOCKET_FILTER)
        return -EDGE_LINUX_EINVAL;
    status = kernel_bpf_object_retain(object_id);
    if (status < 0) return status;
    if (view.packet_handle >= 0 && *view.filter_length) {
        status = edge_linux_packet_detach_filter(view.packet_handle);
        if (status < 0) {
            kernel_bpf_object_release(object_id);
            return status;
        }
    }
    previous = *view.bpf_filter_object_id;
    *view.filter_length = 0;
    *view.bpf_filter_object_id = object_id;
    if (previous >= 0) kernel_bpf_object_release(previous);
    return 0;
}

int kernel_socket_option_detach_filter(int32_t descriptor) {
    kernel_socket_option_runtime_view_t view;
    int status = edge_socket_runtime_option_view(descriptor, &view);

    if (status < 0) return status;
    if (!view.state) return -EDGE_LINUX_EIO;
    if (view.state->filter_locked) return -EDGE_LINUX_EPERM;
    if (!view.filter_length || !view.bpf_filter_object_id)
        return -EDGE_LINUX_EIO;
    if (!*view.filter_length && *view.bpf_filter_object_id < 0)
        return -EDGE_LINUX_ENOENT;
    if (view.packet_handle >= 0 && *view.filter_length) {
        status = edge_linux_packet_detach_filter(view.packet_handle);
        if (status < 0) return status;
    }
    *view.filter_length = 0;
    if (*view.bpf_filter_object_id >= 0) {
        int32_t object_id = *view.bpf_filter_object_id;
        *view.bpf_filter_object_id = -1;
        kernel_bpf_object_release(object_id);
    }
    return 0;
}

int kernel_socket_option_get_filter(
    int32_t descriptor, uint64_t user_program, uint32_t program_capacity,
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user_fn,
    uint32_t *program_length) {
    kernel_socket_option_runtime_view_t view;
    int status;

    if (!program_length) return -EDGE_LINUX_EINVAL;
    status = edge_socket_runtime_option_view(descriptor, &view);
    if (status < 0) return status;
    if (!view.filter_length || !view.bpf_filter_object_id)
        return -EDGE_LINUX_EIO;
    if (*view.bpf_filter_object_id >= 0)
        return -EDGE_LINUX_EACCES;
    *program_length = *view.filter_length;
    if (!*program_length || !program_capacity) return 0;
    if (program_capacity < *program_length)
        return -EDGE_LINUX_EINVAL;
    if (!user_program || !copy_to_user_fn)
        return -EDGE_LINUX_EFAULT;
    if (copy_to_user_fn(
            copy_context, user_program, view.filter,
            (uint64_t)*program_length * sizeof(view.filter[0])) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

int kernel_socket_packet_set_option(
    int32_t descriptor, uint32_t option, const void *value,
    uint32_t value_length) {
    kernel_socket_option_runtime_view_t view;
    int status = edge_socket_runtime_option_view(descriptor, &view);

    if (status < 0) return status;
    if (view.domain != EDGE_LINUX_AF_PACKET || view.packet_handle < 0)
        return -EDGE_LINUX_ENOPROTOOPT;
    if (!view.packet_page_allocator) return -EDGE_LINUX_EIO;
    return edge_linux_packet_setsockopt(
        view.packet_handle, option, value, value_length,
        view.packet_page_allocator);
}

int kernel_socket_packet_get_option(
    int32_t descriptor, uint32_t option, void *value,
    uint32_t value_capacity, uint32_t *value_length) {
    kernel_socket_option_runtime_view_t view;
    int status = edge_socket_runtime_option_view(descriptor, &view);

    if (status < 0) return status;
    if (view.domain != EDGE_LINUX_AF_PACKET || view.packet_handle < 0)
        return -EDGE_LINUX_ENOPROTOOPT;
    return edge_linux_packet_getsockopt(
        view.packet_handle, option, value, value_capacity, value_length);
}

int kernel_socket_netlink_membership_update(
    int32_t descriptor, uint32_t group, int join) {
    kernel_socket_option_runtime_view_t view;
    uint32_t mask;
    int status = edge_socket_runtime_option_view(descriptor, &view);

    if (status < 0) return status;
    if (view.domain != EDGE_LINUX_AF_NETLINK)
        return -EDGE_LINUX_ENOTSOCK;
    if (!view.netlink_groups)
        return -EDGE_LINUX_EIO;
    if (group == 0u || group > 32u)
        return -EDGE_LINUX_EINVAL;
    mask = 1u << (group - 1u);
    if (join)
        *view.netlink_groups |= mask;
    else
        *view.netlink_groups &= ~mask;
    return 0;
}

int kernel_socket_netlink_memberships_get(
    int32_t descriptor, uint32_t *groups) {
    kernel_socket_option_runtime_view_t view;
    int status;

    if (!groups) return -EDGE_LINUX_EINVAL;
    status = edge_socket_runtime_option_view(descriptor, &view);
    if (status < 0) return status;
    if (view.domain != EDGE_LINUX_AF_NETLINK)
        return -EDGE_LINUX_ENOTSOCK;
    if (!view.netlink_groups)
        return -EDGE_LINUX_EIO;
    *groups = *view.netlink_groups;
    return 0;
}
