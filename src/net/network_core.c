/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent network device and packet core.
 * Copyright (c) EdgeOS Contributors.
 */

#include "net/network_core.h"

#include "string.h"

#define EDGE_NET_DELIVERY_MAX EDGE_NET_DEVICE_MAX
#define EDGE_NET_OPERATION_MAX 8u

#define EDGE_NET_PACKET_TRANSFORM_NONE 0u
#define EDGE_NET_PACKET_TRANSFORM_VLAN_INSERT 1u
#define EDGE_NET_PACKET_TRANSFORM_VLAN_REMOVE 2u
#define EDGE_NET_BRIDGE_VLAN_BYTES 512u
#define EDGE_NET_AF_INET 2u
#define EDGE_NET_AF_INET6 10u

typedef struct edge_net_namespace_state {
    uint8_t used;
    uint8_t ipv4_forwarding;
    uint8_t ipv6_settings[4];
    uint8_t bridge_filters[3];
    uint32_t id;
} edge_net_namespace_state_t;

typedef struct edge_net_device_state {
    uint8_t used;
    uint32_t bond_sequence;
    uint16_t bridge_pvid;
    uint8_t bridge_vlans[EDGE_NET_BRIDGE_VLAN_BYTES];
    uint8_t bridge_untagged_vlans[EDGE_NET_BRIDGE_VLAN_BYTES];
    edge_net_qdisc_snapshot_t qdisc;
    edge_net_device_snapshot_t snapshot;
} edge_net_device_state_t;

typedef struct edge_net_fdb_state {
    uint8_t used;
    edge_net_bridge_fdb_entry_t entry;
} edge_net_fdb_state_t;

typedef struct edge_net_mdb_state {
    uint8_t used;
    edge_net_bridge_mdb_entry_t entry;
} edge_net_mdb_state_t;

typedef struct edge_net_delivery {
    edge_net_receive_fn receive;
    edge_net_transmit_fn transmit;
    void *context;
    int32_t ifindex;
    uint32_t network_namespace;
    edge_net_packet_metadata_t metadata;
    uint8_t packet_transform;
    uint16_t vlan_id;
    uint16_t vlan_protocol;
} edge_net_delivery_t;

typedef struct edge_net_operation {
    uint8_t used;
    uint32_t delivery_count;
    edge_net_delivery_t deliveries[EDGE_NET_DELIVERY_MAX];
} edge_net_operation_t;

typedef struct edge_net_hook_state {
    uint8_t used;
    uint32_t handle;
    edge_net_hook_registration_t registration;
} edge_net_hook_state_t;

static volatile uint32_t g_edge_net_lock;
static uint8_t g_edge_net_initialized;
static edge_net_namespace_state_t
    g_edge_net_namespaces[EDGE_NET_NAMESPACE_MAX];
static edge_net_device_state_t g_edge_net_devices[EDGE_NET_DEVICE_MAX];
static edge_net_fdb_state_t g_edge_net_fdb[EDGE_NET_BRIDGE_FDB_MAX];
static edge_net_mdb_state_t g_edge_net_mdb[EDGE_NET_BRIDGE_MDB_MAX];
static edge_net_operation_t g_edge_net_operations[EDGE_NET_OPERATION_MAX];
static edge_net_hook_state_t g_edge_net_hooks[EDGE_NET_HOOK_MAX];
static uint32_t g_edge_net_next_hook_handle = 1u;
static enum edge_net_hook_verdict edge_net_hook_run(
    uint32_t network_namespace, enum edge_net_hook_stage stage,
    edge_net_packet_t *packet);

static void edge_net_lock(void) {
    while (__atomic_exchange_n(
            &g_edge_net_lock, 1u, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&g_edge_net_lock, __ATOMIC_RELAXED)) {
        }
    }
}

static void edge_net_unlock(void) {
    __atomic_store_n(&g_edge_net_lock, 0u, __ATOMIC_RELEASE);
}

static void edge_net_initialize_locked(void) {
    if (g_edge_net_initialized) return;
    memset(g_edge_net_namespaces, 0, sizeof(g_edge_net_namespaces));
    memset(g_edge_net_devices, 0, sizeof(g_edge_net_devices));
    memset(g_edge_net_fdb, 0, sizeof(g_edge_net_fdb));
    memset(g_edge_net_mdb, 0, sizeof(g_edge_net_mdb));
    memset(g_edge_net_operations, 0, sizeof(g_edge_net_operations));
    memset(g_edge_net_hooks, 0, sizeof(g_edge_net_hooks));
    g_edge_net_next_hook_handle = 1u;
    g_edge_net_namespaces[0].used = 1u;
    g_edge_net_namespaces[0].id = 0u;
    g_edge_net_namespaces[0].ipv6_settings[2] = 1u;
    g_edge_net_namespaces[0].ipv6_settings[3] = 1u;
    g_edge_net_namespaces[0].bridge_filters[0] = 1u;
    g_edge_net_namespaces[0].bridge_filters[1] = 1u;
    g_edge_net_namespaces[0].bridge_filters[2] = 1u;
    g_edge_net_initialized = 1u;
}

static edge_net_operation_t *edge_net_operation_acquire_locked(void) {
    uint32_t index;

    for (index = 0; index < EDGE_NET_OPERATION_MAX; ++index) {
        edge_net_operation_t *operation = &g_edge_net_operations[index];

        if (operation->used) continue;
        memset(operation, 0, sizeof(*operation));
        operation->used = 1u;
        return operation;
    }
    return 0;
}

static void edge_net_operation_release(edge_net_operation_t *operation) {
    if (!operation) return;
    edge_net_lock();
    memset(operation, 0, sizeof(*operation));
    edge_net_unlock();
}

static int edge_net_name_valid(const char *name) {
    uint32_t length = 0;

    if (!name || !name[0]) return 0;
    while (length < EDGE_NET_DEVICE_NAME_MAX && name[length]) ++length;
    return length > 0u && length < EDGE_NET_DEVICE_NAME_MAX;
}

static int edge_net_mac_equal(
    const uint8_t first[6], const uint8_t second[6]) {
    return memcmp(first, second, 6u) == 0;
}

static int edge_net_mac_is_multicast(const uint8_t address[6]) {
    return (address[0] & 1u) != 0u;
}

static int edge_net_mac_is_zero(const uint8_t address[6]) {
    static const uint8_t zero[6];

    return edge_net_mac_equal(address, zero);
}

static int edge_net_mac_is_broadcast(const uint8_t address[6]) {
    static const uint8_t broadcast[6] = {
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu
    };

    return edge_net_mac_equal(address, broadcast);
}

static edge_net_namespace_state_t *edge_net_namespace_locked(
    uint32_t network_namespace) {
    uint32_t index;

    for (index = 0; index < EDGE_NET_NAMESPACE_MAX; ++index) {
        edge_net_namespace_state_t *state = &g_edge_net_namespaces[index];

        if (state->used && state->id == network_namespace) return state;
    }
    return 0;
}

static int edge_net_namespace_ensure_locked(uint32_t network_namespace) {
    uint32_t index;

    if (edge_net_namespace_locked(network_namespace)) return EDGE_NET_OK;
    for (index = 0; index < EDGE_NET_NAMESPACE_MAX; ++index) {
        edge_net_namespace_state_t *state = &g_edge_net_namespaces[index];

        if (state->used) continue;
        memset(state, 0, sizeof(*state));
        state->used = 1u;
        state->id = network_namespace;
        state->ipv6_settings[2] = 1u;
        state->ipv6_settings[3] = 1u;
        state->bridge_filters[0] = 1u;
        state->bridge_filters[1] = 1u;
        state->bridge_filters[2] = 1u;
        return EDGE_NET_OK;
    }
    return EDGE_NET_NO_SPACE;
}

static edge_net_device_state_t *edge_net_device_locked(int32_t ifindex) {
    uint32_t index;

    for (index = 0; index < EDGE_NET_DEVICE_MAX; ++index) {
        edge_net_device_state_t *device = &g_edge_net_devices[index];

        if (device->used &&
            device->snapshot.configuration.ifindex == ifindex)
            return device;
    }
    return 0;
}

static edge_net_device_state_t *edge_net_device_name_locked(
    uint32_t network_namespace, const char *name) {
    uint32_t index;

    for (index = 0; index < EDGE_NET_DEVICE_MAX; ++index) {
        edge_net_device_state_t *device = &g_edge_net_devices[index];

        if (device->used &&
            device->snapshot.configuration.network_namespace ==
                network_namespace &&
            strcmp(device->snapshot.configuration.name, name) == 0)
            return device;
    }
    return 0;
}

static edge_net_device_state_t *edge_net_vlan_child_locked(
    int32_t lower_ifindex, uint16_t vlan_id, uint16_t vlan_protocol) {
    uint32_t index;

    for (index = 0; index < EDGE_NET_DEVICE_MAX; ++index) {
        edge_net_device_state_t *device = &g_edge_net_devices[index];
        const edge_net_device_configuration_t *configuration;

        if (!device->used) continue;
        configuration = &device->snapshot.configuration;
        if (configuration->kind == EDGE_NET_DEVICE_VLAN &&
            configuration->lower_ifindex == lower_ifindex &&
            configuration->vlan_id == vlan_id &&
            configuration->vlan_protocol == vlan_protocol)
            return device;
    }
    return 0;
}

static void edge_net_lower_carrier_update_locked(int32_t lower_ifindex) {
    edge_net_device_state_t *lower = edge_net_device_locked(lower_ifindex);
    uint32_t index;

    if (!lower) return;
    for (index = 0; index < EDGE_NET_DEVICE_MAX; ++index) {
        edge_net_device_state_t *device = &g_edge_net_devices[index];

        if (device->used &&
            (device->snapshot.configuration.kind == EDGE_NET_DEVICE_VLAN ||
             device->snapshot.configuration.kind ==
                 EDGE_NET_DEVICE_MACVLAN ||
             device->snapshot.configuration.kind ==
                 EDGE_NET_DEVICE_IPVLAN) &&
            device->snapshot.configuration.lower_ifindex == lower_ifindex)
            device->snapshot.configuration.carrier =
                lower->snapshot.configuration.carrier;
    }
}

static void edge_net_bond_carrier_update_locked(int32_t bond_ifindex) {
    edge_net_device_state_t *bond = edge_net_device_locked(bond_ifindex);
    uint32_t index;
    int carrier = 0;

    if (!bond || bond->snapshot.configuration.kind != EDGE_NET_DEVICE_BOND)
        return;
    for (index = 0; index < EDGE_NET_DEVICE_MAX; ++index) {
        const edge_net_device_state_t *member = &g_edge_net_devices[index];

        if (!member->used ||
            member->snapshot.master_ifindex != bond_ifindex)
            continue;
        if ((member->snapshot.configuration.flags &
             EDGE_NET_DEVICE_FLAG_UP) &&
            member->snapshot.configuration.carrier) {
            carrier = 1;
            break;
        }
    }
    bond->snapshot.configuration.carrier = carrier ? 1u : 0u;
    edge_net_lower_carrier_update_locked(bond_ifindex);
}

static edge_net_device_state_t *edge_net_device_slot_locked(void) {
    uint32_t index;

    for (index = 0; index < EDGE_NET_DEVICE_MAX; ++index) {
        if (!g_edge_net_devices[index].used)
            return &g_edge_net_devices[index];
    }
    return 0;
}

static int edge_net_device_configuration_valid(
    const edge_net_device_configuration_t *configuration) {
    if (!configuration || configuration->ifindex <= 0 ||
        !edge_net_name_valid(configuration->name) ||
        configuration->mtu < 68u || configuration->mtu > 65535u)
        return 0;
    if (configuration->kind < EDGE_NET_DEVICE_LOOPBACK ||
        configuration->kind > EDGE_NET_DEVICE_VRF)
        return 0;
    if (configuration->kind == EDGE_NET_DEVICE_VLAN &&
        (configuration->lower_ifindex <= 0 ||
         !configuration->vlan_id || configuration->vlan_id > 4094u ||
         (configuration->vlan_protocol != 0x8100u &&
          configuration->vlan_protocol != 0x88a8u)))
        return 0;
    if (configuration->kind == EDGE_NET_DEVICE_MACVLAN &&
        (configuration->lower_ifindex <= 0 ||
         (configuration->virtual_mode != EDGE_NET_MACVLAN_MODE_PRIVATE &&
          configuration->virtual_mode != EDGE_NET_MACVLAN_MODE_VEPA &&
          configuration->virtual_mode != EDGE_NET_MACVLAN_MODE_BRIDGE &&
          configuration->virtual_mode != EDGE_NET_MACVLAN_MODE_PASSTHRU)))
        return 0;
    if (configuration->kind == EDGE_NET_DEVICE_IPVLAN &&
        (configuration->lower_ifindex <= 0 ||
         configuration->virtual_mode > EDGE_NET_IPVLAN_MODE_L3S ||
         configuration->virtual_flags > EDGE_NET_IPVLAN_FLAG_VEPA))
        return 0;
    if (configuration->kind == EDGE_NET_DEVICE_BOND &&
        (configuration->virtual_mode > EDGE_NET_BOND_MODE_BROADCAST ||
         configuration->virtual_flags >
             EDGE_NET_BOND_HASH_VLAN_SRCMAC))
        return 0;
    if (configuration->kind == EDGE_NET_DEVICE_VRF &&
        !configuration->routing_table)
        return 0;
    return configuration->kind == EDGE_NET_DEVICE_VLAN ||
           configuration->kind == EDGE_NET_DEVICE_MACVLAN ||
           configuration->kind == EDGE_NET_DEVICE_IPVLAN ||
           (!configuration->lower_ifindex && !configuration->vlan_id);
}

static void edge_net_dummy_transmit(
    int32_t ifindex, uint32_t network_namespace,
    edge_net_packet_t *packet, void *context) {
    (void)ifindex;
    (void)network_namespace;
    (void)packet;
    (void)context;
}

static int edge_net_bridge_vlan_valid(uint16_t vlan_id) {
    return vlan_id >= 1u && vlan_id <= EDGE_NET_BRIDGE_VLAN_MAX;
}

static int edge_net_bridge_vlan_test_locked(
    const edge_net_device_state_t *device, uint16_t vlan_id) {
    if (!device || !edge_net_bridge_vlan_valid(vlan_id)) return 0;
    return (device->bridge_vlans[vlan_id >> 3u] &
            (uint8_t)(1u << (vlan_id & 7u))) != 0u;
}

static int edge_net_bridge_vlan_untagged_locked(
    const edge_net_device_state_t *device, uint16_t vlan_id) {
    if (!device || !edge_net_bridge_vlan_valid(vlan_id)) return 0;
    return (device->bridge_untagged_vlans[vlan_id >> 3u] &
            (uint8_t)(1u << (vlan_id & 7u))) != 0u;
}

static void edge_net_bridge_vlan_write_locked(
    edge_net_device_state_t *device, uint16_t vlan_id,
    int member, int untagged) {
    uint8_t mask;

    if (!device || !edge_net_bridge_vlan_valid(vlan_id)) return;
    mask = (uint8_t)(1u << (vlan_id & 7u));
    if (member) {
        device->bridge_vlans[vlan_id >> 3u] |= mask;
        if (untagged)
            device->bridge_untagged_vlans[vlan_id >> 3u] |= mask;
        else
            device->bridge_untagged_vlans[vlan_id >> 3u] &=
                (uint8_t)~mask;
    } else {
        device->bridge_vlans[vlan_id >> 3u] &= (uint8_t)~mask;
        device->bridge_untagged_vlans[vlan_id >> 3u] &= (uint8_t)~mask;
        if (device->bridge_pvid == vlan_id) device->bridge_pvid = 0u;
    }
}

static void edge_net_bridge_port_defaults_locked(
    edge_net_device_state_t *device, int bridge_port) {
    if (!device) return;
    device->snapshot.hairpin = 0u;
    device->snapshot.bridge_state = bridge_port ?
        EDGE_NET_BRIDGE_STATE_FORWARDING : EDGE_NET_BRIDGE_STATE_DISABLED;
    device->snapshot.bridge_learning = bridge_port ? 1u : 0u;
    device->snapshot.bridge_unicast_flood = bridge_port ? 1u : 0u;
    device->snapshot.bridge_multicast_flood = bridge_port ? 1u : 0u;
    device->snapshot.bridge_broadcast_flood = bridge_port ? 1u : 0u;
    device->snapshot.bridge_isolated = 0u;
}

static void edge_net_device_install_locked(
    edge_net_device_state_t *device,
    const edge_net_device_configuration_t *configuration) {
    edge_net_namespace_state_t *network_namespace;

    memset(device, 0, sizeof(*device));
    device->used = 1u;
    memcpy(&device->snapshot.configuration, configuration,
           sizeof(*configuration));
    if (configuration->kind == EDGE_NET_DEVICE_BRIDGE) {
        device->bridge_pvid = 1u;
        edge_net_bridge_vlan_write_locked(device, 1u, 1, 1);
    }
    if (!device->snapshot.configuration.tx_queue_length)
        device->snapshot.configuration.tx_queue_length = 1000u;
    device->qdisc.configuration.kind = EDGE_NET_QDISC_NOQUEUE;
    device->qdisc.configuration.parent = UINT32_MAX;
    if (configuration->kind == EDGE_NET_DEVICE_DUMMY) {
        device->snapshot.configuration.carrier = 1u;
        if (!device->snapshot.configuration.transmit)
            device->snapshot.configuration.transmit =
                edge_net_dummy_transmit;
    } else if (configuration->kind == EDGE_NET_DEVICE_BOND) {
        device->snapshot.configuration.carrier = 0u;
    }
    network_namespace = edge_net_namespace_locked(
        configuration->network_namespace);
    if (network_namespace) {
        device->snapshot.ipv6_disabled =
            network_namespace->ipv6_settings[0];
        device->snapshot.ipv6_forwarding =
            network_namespace->ipv6_settings[1];
        device->snapshot.ipv6_accept_ra =
            network_namespace->ipv6_settings[2];
        device->snapshot.ipv6_autoconf =
            network_namespace->ipv6_settings[3];
    } else {
        device->snapshot.ipv6_accept_ra = 1u;
        device->snapshot.ipv6_autoconf = 1u;
    }
}

static void edge_net_fdb_remove_device_locked(int32_t ifindex) {
    uint32_t index;

    for (index = 0; index < EDGE_NET_BRIDGE_FDB_MAX; ++index) {
        edge_net_fdb_state_t *state = &g_edge_net_fdb[index];

        if (!state->used) continue;
        if (state->entry.bridge_ifindex == ifindex ||
            state->entry.port_ifindex == ifindex)
            memset(state, 0, sizeof(*state));
    }
    for (index = 0; index < EDGE_NET_BRIDGE_MDB_MAX; ++index) {
        edge_net_mdb_state_t *state = &g_edge_net_mdb[index];

        if (!state->used) continue;
        if (state->entry.bridge_ifindex == ifindex ||
            state->entry.port_ifindex == ifindex)
            memset(state, 0, sizeof(*state));
    }
}

static int edge_net_bridge_mdb_member_locked(
    int32_t bridge_ifindex, int32_t port_ifindex,
    const uint8_t hardware_address[6], uint16_t vlan_id) {
    uint32_t index;

    for (index = 0; index < EDGE_NET_BRIDGE_MDB_MAX; ++index) {
        const edge_net_mdb_state_t *state = &g_edge_net_mdb[index];

        if (state->used &&
            state->entry.bridge_ifindex == bridge_ifindex &&
            state->entry.port_ifindex == port_ifindex &&
            state->entry.vlan_id == vlan_id &&
            edge_net_mac_equal(
                state->entry.hardware_address, hardware_address))
            return 1;
    }
    return 0;
}

static int edge_net_bridge_mdb_group_locked(
    int32_t bridge_ifindex, const uint8_t hardware_address[6],
    uint16_t vlan_id) {
    uint32_t index;

    for (index = 0; index < EDGE_NET_BRIDGE_MDB_MAX; ++index) {
        const edge_net_mdb_state_t *state = &g_edge_net_mdb[index];

        if (state->used &&
            state->entry.bridge_ifindex == bridge_ifindex &&
            state->entry.vlan_id == vlan_id &&
            edge_net_mac_equal(
                state->entry.hardware_address, hardware_address))
            return 1;
    }
    return 0;
}

static uint32_t edge_net_bridge_mdb_address_length(uint8_t family) {
    if (family == EDGE_NET_AF_INET) return 4u;
    if (family == EDGE_NET_AF_INET6) return 16u;
    return 0u;
}

static int edge_net_bridge_mdb_entry_matches_locked(
    const edge_net_bridge_mdb_entry_t *first,
    const edge_net_bridge_mdb_entry_t *second) {
    uint32_t address_length;

    if (!first || !second ||
        first->bridge_ifindex != second->bridge_ifindex ||
        first->port_ifindex != second->port_ifindex ||
        first->vlan_id != second->vlan_id ||
        first->family != second->family ||
        !edge_net_mac_equal(
            first->hardware_address, second->hardware_address))
        return 0;
    address_length = edge_net_bridge_mdb_address_length(first->family);
    return address_length && memcmp(
        first->group_address, second->group_address,
        address_length) == 0;
}

static int edge_net_bridge_mdb_update_locked(
    const edge_net_bridge_mdb_entry_t *entry) {
    edge_net_mdb_state_t *free_state = 0;
    uint32_t index;

    if (!entry) return EDGE_NET_INVALID;
    for (index = 0; index < EDGE_NET_BRIDGE_MDB_MAX; ++index) {
        edge_net_mdb_state_t *state = &g_edge_net_mdb[index];

        if (!state->used) {
            if (!free_state) free_state = state;
            continue;
        }
        if (!edge_net_bridge_mdb_entry_matches_locked(
                &state->entry, entry))
            continue;
        if (state->entry.is_static && !entry->is_static) {
            state->entry.last_seen_ns = entry->last_seen_ns;
        } else {
            memcpy(&state->entry, entry, sizeof(*entry));
        }
        return EDGE_NET_OK;
    }
    if (!free_state) return EDGE_NET_NO_SPACE;
    free_state->used = 1u;
    memcpy(&free_state->entry, entry, sizeof(*entry));
    return EDGE_NET_OK;
}

static void edge_net_bridge_mdb_remove_dynamic_locked(
    const edge_net_bridge_mdb_entry_t *entry) {
    uint32_t index;

    if (!entry) return;
    for (index = 0; index < EDGE_NET_BRIDGE_MDB_MAX; ++index) {
        edge_net_mdb_state_t *state = &g_edge_net_mdb[index];

        if (!state->used || state->entry.is_static ||
            !edge_net_bridge_mdb_entry_matches_locked(
                &state->entry, entry))
            continue;
        memset(state, 0, sizeof(*state));
    }
}

static void edge_net_bridge_mdb_address(
    edge_net_bridge_mdb_entry_t *entry, uint8_t family,
    const uint8_t *group_address) {
    if (!entry || !group_address) return;
    entry->family = family;
    if (family == EDGE_NET_AF_INET) {
        memcpy(entry->group_address, group_address, 4u);
        entry->hardware_address[0] = 0x01u;
        entry->hardware_address[1] = 0x00u;
        entry->hardware_address[2] = 0x5eu;
        entry->hardware_address[3] = group_address[1] & 0x7fu;
        entry->hardware_address[4] = group_address[2];
        entry->hardware_address[5] = group_address[3];
    } else if (family == EDGE_NET_AF_INET6) {
        memcpy(entry->group_address, group_address, 16u);
        entry->hardware_address[0] = 0x33u;
        entry->hardware_address[1] = 0x33u;
        memcpy(entry->hardware_address + 2u, group_address + 12u, 4u);
    }
}

static void edge_net_lower_remove_dependents_locked(int32_t lower_ifindex) {
    uint32_t index;

    for (index = 0; index < EDGE_NET_DEVICE_MAX; ++index) {
        edge_net_device_state_t *device = &g_edge_net_devices[index];
        int32_t ifindex;

        if (!device->used ||
            (device->snapshot.configuration.kind != EDGE_NET_DEVICE_VLAN &&
             device->snapshot.configuration.kind !=
                 EDGE_NET_DEVICE_MACVLAN &&
             device->snapshot.configuration.kind !=
                 EDGE_NET_DEVICE_IPVLAN) ||
            device->snapshot.configuration.lower_ifindex != lower_ifindex)
            continue;
        ifindex = device->snapshot.configuration.ifindex;
        edge_net_lower_remove_dependents_locked(ifindex);
        edge_net_fdb_remove_device_locked(ifindex);
        memset(device, 0, sizeof(*device));
    }
}

static int edge_net_bridge_fdb_add_locked(
    int32_t bridge_ifindex, const uint8_t hardware_address[6],
    int32_t port_ifindex, uint16_t vlan_id, int is_static,
    uint64_t now_ns) {
    edge_net_fdb_state_t *free_state = 0;
    uint32_t index;

    for (index = 0; index < EDGE_NET_BRIDGE_FDB_MAX; ++index) {
        edge_net_fdb_state_t *state = &g_edge_net_fdb[index];

        if (!state->used) {
            if (!free_state) free_state = state;
            continue;
        }
        if (state->entry.bridge_ifindex == bridge_ifindex &&
            state->entry.vlan_id == vlan_id &&
            edge_net_mac_equal(
                state->entry.hardware_address, hardware_address)) {
            if (!state->entry.is_static || is_static)
                state->entry.port_ifindex = port_ifindex;
            state->entry.is_static = is_static ? 1u :
                state->entry.is_static;
            state->entry.last_seen_ns = now_ns;
            return EDGE_NET_OK;
        }
    }
    if (!free_state) return EDGE_NET_NO_SPACE;
    memset(free_state, 0, sizeof(*free_state));
    free_state->used = 1u;
    free_state->entry.bridge_ifindex = bridge_ifindex;
    free_state->entry.port_ifindex = port_ifindex;
    free_state->entry.vlan_id = vlan_id;
    memcpy(free_state->entry.hardware_address, hardware_address, 6u);
    free_state->entry.is_static = is_static ? 1u : 0u;
    free_state->entry.last_seen_ns = now_ns;
    return EDGE_NET_OK;
}

static int32_t edge_net_bridge_fdb_lookup_locked(
    int32_t bridge_ifindex, const uint8_t hardware_address[6],
    uint16_t vlan_id) {
    uint32_t index;

    for (index = 0; index < EDGE_NET_BRIDGE_FDB_MAX; ++index) {
        const edge_net_fdb_state_t *state = &g_edge_net_fdb[index];

        if (state->used &&
            state->entry.bridge_ifindex == bridge_ifindex &&
            state->entry.vlan_id == vlan_id &&
            edge_net_mac_equal(
                state->entry.hardware_address, hardware_address))
            return state->entry.port_ifindex;
    }
    return 0;
}

static int edge_net_packet_prefix(
    const edge_net_packet_t *packet, uint8_t *output, uint32_t length) {
    uint32_t copied = 0;
    uint8_t index;

    if (!packet || !output || packet->total_length < length) return -1;
    for (index = 0; index < packet->segment_count && copied < length;
         ++index) {
        uint32_t count = packet->segments[index].length;

        if (count > length - copied) count = length - copied;
        memcpy(output + copied, packet->segments[index].data, count);
        copied += count;
    }
    return copied == length ? 0 : -1;
}

static int edge_net_packet_has_vlan_header(
    const edge_net_packet_t *packet) {
    uint8_t header[14];
    uint16_t protocol;

    if (!packet) return 0;
    if (packet->metadata.vlan_tag_present) return 1;
    if (edge_net_packet_prefix(packet, header, sizeof(header)) < 0) return 0;
    protocol = (uint16_t)(((uint16_t)header[12] << 8u) | header[13]);
    return protocol == 0x8100u || protocol == 0x88a8u;
}

static void edge_net_delivery_add_receive_locked(
    edge_net_delivery_t *deliveries, uint32_t *delivery_count,
    edge_net_device_state_t *device, const edge_net_packet_t *packet,
    uint8_t packet_transform, uint16_t vlan_id,
    uint16_t vlan_protocol) {
    edge_net_device_snapshot_t *snapshot;

    if (!deliveries || !delivery_count || !device || !packet ||
        *delivery_count >= EDGE_NET_DELIVERY_MAX)
        return;
    snapshot = &device->snapshot;
    if (!snapshot->configuration.receive) return;
    deliveries[*delivery_count].receive = snapshot->configuration.receive;
    deliveries[*delivery_count].context =
        snapshot->configuration.receive_context ?
            snapshot->configuration.receive_context :
            snapshot->configuration.callback_context;
    deliveries[*delivery_count].ifindex =
        snapshot->configuration.ifindex;
    deliveries[*delivery_count].network_namespace =
        snapshot->configuration.network_namespace;
    memcpy(&deliveries[*delivery_count].metadata, &packet->metadata,
           sizeof(packet->metadata));
    deliveries[*delivery_count].packet_transform = packet_transform;
    deliveries[*delivery_count].vlan_id = vlan_id;
    deliveries[*delivery_count].vlan_protocol = vlan_protocol;
    ++*delivery_count;
}

static void edge_net_delivery_add_transmit_locked(
    edge_net_delivery_t *deliveries, uint32_t *delivery_count,
    edge_net_device_state_t *device, const edge_net_packet_t *packet,
    uint8_t packet_transform, uint16_t vlan_id,
    uint16_t vlan_protocol) {
    edge_net_device_snapshot_t *snapshot;

    if (!deliveries || !delivery_count || !device || !packet ||
        *delivery_count >= EDGE_NET_DELIVERY_MAX)
        return;
    snapshot = &device->snapshot;
    if (!snapshot->configuration.transmit) return;
    deliveries[*delivery_count].transmit = snapshot->configuration.transmit;
    deliveries[*delivery_count].context =
        snapshot->configuration.transmit_context ?
            snapshot->configuration.transmit_context :
            snapshot->configuration.callback_context;
    deliveries[*delivery_count].ifindex =
        snapshot->configuration.ifindex;
    deliveries[*delivery_count].network_namespace =
        snapshot->configuration.network_namespace;
    memcpy(&deliveries[*delivery_count].metadata, &packet->metadata,
           sizeof(packet->metadata));
    deliveries[*delivery_count].packet_transform = packet_transform;
    deliveries[*delivery_count].vlan_id = vlan_id;
    deliveries[*delivery_count].vlan_protocol = vlan_protocol;
    ++*delivery_count;
}

static int edge_net_device_can_forward_locked(
    edge_net_device_state_t *device, const edge_net_packet_t *packet) {
    edge_net_device_snapshot_t *snapshot;

    if (!device || !packet) return 0;
    snapshot = &device->snapshot;
    if (!(snapshot->configuration.flags & EDGE_NET_DEVICE_FLAG_UP) ||
        !snapshot->configuration.carrier)
        return 0;
    return packet->total_length <= snapshot->configuration.mtu + 18u +
        (edge_net_packet_has_vlan_header(packet) ? 4u : 0u);
}

static void edge_net_ingress_locked(
    edge_net_device_state_t *device, edge_net_packet_t *packet,
    edge_net_delivery_t *deliveries, uint32_t *delivery_count);
static void edge_net_bond_egress_locked(
    edge_net_device_state_t *bond, edge_net_packet_t *packet,
    edge_net_delivery_t *deliveries, uint32_t *delivery_count);

static int edge_net_macvlan_deliver_locked(
    edge_net_device_state_t *lower, int32_t source_ifindex,
    edge_net_packet_t *packet, edge_net_delivery_t *deliveries,
    uint32_t *delivery_count, int local_switch) {
    uint8_t ethernet[14];
    edge_net_packet_metadata_t original_metadata;
    int multicast;
    int delivered = 0;
    uint32_t index;

    if (!lower || !packet ||
        edge_net_packet_prefix(packet, ethernet, sizeof(ethernet)) < 0)
        return 0;
    memcpy(&original_metadata, &packet->metadata,
           sizeof(original_metadata));
    multicast = edge_net_mac_is_multicast(ethernet) ||
                edge_net_mac_is_broadcast(ethernet);
    for (index = 0; index < EDGE_NET_DEVICE_MAX; ++index) {
        edge_net_device_state_t *child = &g_edge_net_devices[index];
        const edge_net_device_configuration_t *configuration;

        if (!child->used) continue;
        configuration = &child->snapshot.configuration;
        if (configuration->kind != EDGE_NET_DEVICE_MACVLAN ||
            configuration->lower_ifindex !=
                lower->snapshot.configuration.ifindex ||
            configuration->ifindex == source_ifindex ||
            (local_switch && configuration->virtual_mode !=
                EDGE_NET_MACVLAN_MODE_BRIDGE) ||
            (!multicast && !edge_net_mac_equal(
                ethernet, configuration->hardware_address)))
            continue;
        if (!edge_net_device_can_forward_locked(child, packet)) {
            ++child->snapshot.rx_drops;
            continue;
        }
        edge_net_ingress_locked(
            child, packet, deliveries, delivery_count);
        memcpy(&packet->metadata, &original_metadata,
               sizeof(packet->metadata));
        delivered = 1;
        if (!multicast) break;
    }
    return delivered;
}

static int edge_net_ipvlan_packet_target(
    const edge_net_packet_t *packet, uint32_t *target, int *multicast) {
    uint8_t header[54];
    uint16_t protocol;

    if (!packet || !target || !multicast ||
        edge_net_packet_prefix(packet, header, 14u) < 0)
        return 0;
    *multicast = edge_net_mac_is_multicast(header) ||
                 edge_net_mac_is_broadcast(header);
    protocol = (uint16_t)(((uint16_t)header[12] << 8u) | header[13]);
    if (protocol == 0x0800u) {
        if (edge_net_packet_prefix(packet, header, 34u) < 0 ||
            (header[14] >> 4u) != 4u)
            return 0;
        memcpy(target, header + 30u, sizeof(*target));
        return 1;
    }
    if (protocol == 0x0806u) {
        if (edge_net_packet_prefix(packet, header, 42u) < 0)
            return 0;
        memcpy(target, header + 38u, sizeof(*target));
        return 1;
    }
    return *multicast;
}

static int edge_net_ipvlan_deliver_locked(
    edge_net_device_state_t *lower, int32_t source_ifindex,
    edge_net_packet_t *packet, edge_net_delivery_t *deliveries,
    uint32_t *delivery_count, int local_switch) {
    edge_net_packet_metadata_t original_metadata;
    uint32_t target = 0u;
    int multicast = 0;
    int target_known;
    int delivered = 0;
    uint32_t index;

    if (!lower || !packet) return 0;
    target_known = edge_net_ipvlan_packet_target(
        packet, &target, &multicast);
    memcpy(&original_metadata, &packet->metadata,
           sizeof(original_metadata));
    for (index = 0; index < EDGE_NET_DEVICE_MAX; ++index) {
        edge_net_device_state_t *child = &g_edge_net_devices[index];
        const edge_net_device_configuration_t *configuration;

        if (!child->used) continue;
        configuration = &child->snapshot.configuration;
        if (configuration->kind != EDGE_NET_DEVICE_IPVLAN ||
            configuration->lower_ifindex !=
                lower->snapshot.configuration.ifindex ||
            configuration->ifindex == source_ifindex ||
            configuration->virtual_mode != EDGE_NET_IPVLAN_MODE_L2 ||
            (local_switch && configuration->virtual_flags !=
                EDGE_NET_IPVLAN_FLAG_BRIDGE) ||
            (!multicast && (!target_known || !target ||
             child->snapshot.ipv4_address != target)))
            continue;
        if (!edge_net_device_can_forward_locked(child, packet)) {
            ++child->snapshot.rx_drops;
            continue;
        }
        edge_net_ingress_locked(
            child, packet, deliveries, delivery_count);
        memcpy(&packet->metadata, &original_metadata,
               sizeof(packet->metadata));
        delivered = 1;
        if (!multicast) break;
    }
    return delivered;
}

static void edge_net_port_egress_locked(
    edge_net_device_state_t *port, edge_net_packet_t *packet,
    edge_net_delivery_t *deliveries, uint32_t *delivery_count) {
    edge_net_device_snapshot_t *snapshot;

    if (!port || !packet) return;
    snapshot = &port->snapshot;
    if (!edge_net_device_can_forward_locked(port, packet)) {
        ++snapshot->tx_drops;
        return;
    }
    ++snapshot->tx_packets;
    snapshot->tx_bytes += packet->total_length;
    packet->metadata.output_ifindex = snapshot->configuration.ifindex;
    packet->metadata.network_namespace =
        snapshot->configuration.network_namespace;
    if (snapshot->configuration.kind == EDGE_NET_DEVICE_BOND) {
        edge_net_bond_egress_locked(
            port, packet, deliveries, delivery_count);
        return;
    }
    if (snapshot->configuration.kind == EDGE_NET_DEVICE_MACVLAN ||
        snapshot->configuration.kind == EDGE_NET_DEVICE_IPVLAN) {
        edge_net_device_state_t *lower = edge_net_device_locked(
            snapshot->configuration.lower_ifindex);
        uint8_t ethernet[14];
        int multicast = 0;
        int delivered = 0;

        if (!lower || !edge_net_device_can_forward_locked(lower, packet)) {
            ++snapshot->tx_drops;
            return;
        }
        if (edge_net_packet_prefix(packet, ethernet, sizeof(ethernet)) == 0)
            multicast = edge_net_mac_is_multicast(ethernet) ||
                        edge_net_mac_is_broadcast(ethernet);
        if (snapshot->configuration.kind == EDGE_NET_DEVICE_MACVLAN) {
            if (snapshot->configuration.virtual_mode ==
                    EDGE_NET_MACVLAN_MODE_BRIDGE)
                delivered = edge_net_macvlan_deliver_locked(
                    lower, snapshot->configuration.ifindex, packet,
                    deliveries, delivery_count, 1);
        } else if (snapshot->configuration.virtual_mode ==
                       EDGE_NET_IPVLAN_MODE_L2) {
            delivered = edge_net_ipvlan_deliver_locked(
                lower, snapshot->configuration.ifindex, packet,
                deliveries, delivery_count, 1);
        }
        if (!delivered || multicast)
            edge_net_port_egress_locked(
                lower, packet, deliveries, delivery_count);
        return;
    }
    if (snapshot->configuration.kind == EDGE_NET_DEVICE_VETH) {
        edge_net_device_state_t *peer =
            edge_net_device_locked(snapshot->peer_ifindex);

        if (!peer || !edge_net_device_can_forward_locked(peer, packet)) {
            ++snapshot->tx_drops;
            return;
        }
        edge_net_ingress_locked(
            peer, packet, deliveries, delivery_count);
        return;
    }
    edge_net_delivery_add_transmit_locked(
        deliveries, delivery_count, port, packet,
        packet->metadata.vlan_untagged ?
            (packet->metadata.vlan_tag_present ?
                EDGE_NET_PACKET_TRANSFORM_VLAN_REMOVE :
                EDGE_NET_PACKET_TRANSFORM_NONE) :
            (packet->metadata.vlan_id &&
             !packet->metadata.vlan_tag_present ?
                EDGE_NET_PACKET_TRANSFORM_VLAN_INSERT :
                EDGE_NET_PACKET_TRANSFORM_NONE),
        packet->metadata.vlan_id, packet->metadata.vlan_protocol);
}

static uint32_t edge_net_bond_packet_hash(
    const edge_net_device_state_t *bond,
    const edge_net_packet_t *packet) {
    uint8_t header[64];
    uint32_t length;
    uint32_t hash = 2166136261u;
    uint32_t offset;
    uint32_t index;
    uint16_t protocol;

    if (!bond || !packet) return 0u;
    length = packet->total_length < sizeof(header) ?
        packet->total_length : sizeof(header);
    if (edge_net_packet_read(packet, 0u, header, length) < 0 || length < 14u)
        return 0u;
    if (bond->snapshot.configuration.virtual_flags ==
            EDGE_NET_BOND_HASH_VLAN_SRCMAC) {
        for (index = 6u; index < 12u; ++index)
            hash = (hash ^ header[index]) * 16777619u;
        hash = (hash ^ packet->metadata.vlan_id) * 16777619u;
        return hash;
    }
    for (index = 0u; index < 12u; ++index)
        hash = (hash ^ header[index]) * 16777619u;
    if (bond->snapshot.configuration.virtual_flags ==
            EDGE_NET_BOND_HASH_LAYER2)
        return hash;
    protocol = (uint16_t)(((uint16_t)header[12] << 8u) | header[13]);
    offset = 14u;
    if ((protocol == 0x8100u || protocol == 0x88a8u) && length >= 18u) {
        protocol = (uint16_t)(((uint16_t)header[16] << 8u) | header[17]);
        offset = 18u;
    }
    if (protocol == 0x0800u && length >= offset + 20u) {
        uint32_t transport_offset;

        for (index = offset + 12u; index < offset + 20u; ++index)
            hash = (hash ^ header[index]) * 16777619u;
        if (bond->snapshot.configuration.virtual_flags !=
                EDGE_NET_BOND_HASH_LAYER34)
            return hash;
        transport_offset = offset + ((uint32_t)(header[offset] & 0x0fu) * 4u);
        if ((header[offset + 9u] == 6u || header[offset + 9u] == 17u) &&
            length >= transport_offset + 4u) {
            for (index = transport_offset;
                 index < transport_offset + 4u; ++index)
                hash = (hash ^ header[index]) * 16777619u;
        }
    } else if (protocol == 0x86ddu && length >= offset + 40u) {
        for (index = offset + 8u; index < offset + 40u; ++index)
            hash = (hash ^ header[index]) * 16777619u;
        if (bond->snapshot.configuration.virtual_flags ==
                EDGE_NET_BOND_HASH_LAYER34 &&
            (header[offset + 6u] == 6u || header[offset + 6u] == 17u) &&
            length >= offset + 44u) {
            for (index = offset + 40u; index < offset + 44u; ++index)
                hash = (hash ^ header[index]) * 16777619u;
        }
    }
    return hash;
}

static void edge_net_bond_egress_locked(
    edge_net_device_state_t *bond, edge_net_packet_t *packet,
    edge_net_delivery_t *deliveries, uint32_t *delivery_count) {
    edge_net_device_state_t *selected = 0;
    uint32_t usable = 0u;
    uint32_t wanted = 0u;
    uint32_t seen = 0u;
    uint32_t index;
    uint16_t mode;

    if (!bond || !packet) return;
    mode = bond->snapshot.configuration.virtual_mode;
    for (index = 0u; index < EDGE_NET_DEVICE_MAX; ++index) {
        edge_net_device_state_t *member = &g_edge_net_devices[index];

        if (!member->used ||
            member->snapshot.master_ifindex !=
                bond->snapshot.configuration.ifindex ||
            !edge_net_device_can_forward_locked(member, packet))
            continue;
        ++usable;
    }
    if (!usable) {
        ++bond->snapshot.tx_drops;
        return;
    }
    if (mode == EDGE_NET_BOND_MODE_ROUND_ROBIN)
        wanted = bond->bond_sequence++ % usable;
    else if (mode == EDGE_NET_BOND_MODE_XOR)
        wanted = edge_net_bond_packet_hash(bond, packet) % usable;
    for (index = 0u; index < EDGE_NET_DEVICE_MAX; ++index) {
        edge_net_device_state_t *member = &g_edge_net_devices[index];

        if (!member->used ||
            member->snapshot.master_ifindex !=
                bond->snapshot.configuration.ifindex ||
            !edge_net_device_can_forward_locked(member, packet))
            continue;
        if (mode == EDGE_NET_BOND_MODE_BROADCAST) {
            edge_net_port_egress_locked(
                member, packet, deliveries, delivery_count);
            continue;
        }
        if (seen++ == wanted) {
            selected = member;
            break;
        }
    }
    if (mode != EDGE_NET_BOND_MODE_BROADCAST && selected)
        edge_net_port_egress_locked(
            selected, packet, deliveries, delivery_count);
}

static void edge_net_bridge_snoop_group_locked(
    edge_net_device_state_t *bridge, int32_t ingress_ifindex,
    uint16_t vlan_id, uint8_t family, const uint8_t *group_address,
    int joining, uint64_t timestamp_ns) {
    edge_net_bridge_mdb_entry_t entry;

    if (!bridge || ingress_ifindex <= 0 || !group_address) return;
    if ((family == EDGE_NET_AF_INET &&
         (group_address[0] < 224u || group_address[0] > 239u)) ||
        (family == EDGE_NET_AF_INET6 && group_address[0] != 0xffu))
        return;
    memset(&entry, 0, sizeof(entry));
    entry.bridge_ifindex = bridge->snapshot.configuration.ifindex;
    entry.port_ifindex = ingress_ifindex;
    entry.vlan_id = vlan_id;
    entry.last_seen_ns = timestamp_ns;
    edge_net_bridge_mdb_address(&entry, family, group_address);
    if (joining)
        (void)edge_net_bridge_mdb_update_locked(&entry);
    else
        edge_net_bridge_mdb_remove_dynamic_locked(&entry);
}

static int edge_net_bridge_snoop_igmp_locked(
    edge_net_device_state_t *bridge, int32_t ingress_ifindex,
    uint16_t vlan_id, edge_net_packet_t *packet, uint32_t ip_offset) {
    uint8_t ip_header[20];
    uint8_t igmp_header[8];
    uint32_t igmp_offset;
    uint32_t record_offset;
    uint16_t record_count;
    uint16_t record_index;

    if (edge_net_packet_read(
            packet, ip_offset, ip_header, sizeof(ip_header)) != EDGE_NET_OK ||
        (ip_header[0] >> 4u) != 4u ||
        (ip_header[0] & 0x0fu) < 5u || ip_header[9] != 2u)
        return 0;
    igmp_offset = ip_offset + (uint32_t)(ip_header[0] & 0x0fu) * 4u;
    if (edge_net_packet_read(
            packet, igmp_offset, igmp_header,
            sizeof(igmp_header)) != EDGE_NET_OK)
        return 0;
    if (igmp_header[0] == 0x11u) return 1;
    if (igmp_header[0] == 0x12u || igmp_header[0] == 0x16u ||
        igmp_header[0] == 0x17u) {
        edge_net_bridge_snoop_group_locked(
            bridge, ingress_ifindex, vlan_id, EDGE_NET_AF_INET,
            igmp_header + 4u, igmp_header[0] != 0x17u,
            packet->metadata.timestamp_ns);
        return 1;
    }
    if (igmp_header[0] != 0x22u) return 0;
    record_count = (uint16_t)(
        ((uint16_t)igmp_header[6] << 8u) | igmp_header[7]);
    record_offset = igmp_offset + 8u;
    for (record_index = 0u; record_index < record_count; ++record_index) {
        uint8_t record[8];
        uint16_t source_count;
        uint32_t record_length;
        int joining;

        if (edge_net_packet_read(
                packet, record_offset, record, sizeof(record)) !=
                EDGE_NET_OK)
            break;
        source_count = (uint16_t)(
            ((uint16_t)record[2] << 8u) | record[3]);
        record_length = 8u + (uint32_t)source_count * 4u +
            (uint32_t)record[1] * 4u;
        if (record_length > packet->total_length - record_offset) break;
        joining = !((record[0] == 1u || record[0] == 3u) &&
                    source_count == 0u);
        edge_net_bridge_snoop_group_locked(
            bridge, ingress_ifindex, vlan_id, EDGE_NET_AF_INET,
            record + 4u, joining, packet->metadata.timestamp_ns);
        record_offset += record_length;
    }
    return 1;
}

static int edge_net_bridge_snoop_mld_locked(
    edge_net_device_state_t *bridge, int32_t ingress_ifindex,
    uint16_t vlan_id, edge_net_packet_t *packet, uint32_t ip_offset) {
    uint8_t ip_header[40];
    uint8_t control[24];
    uint8_t next_header;
    uint32_t control_offset;

    if (edge_net_packet_read(
            packet, ip_offset, ip_header, sizeof(ip_header)) != EDGE_NET_OK ||
        (ip_header[0] >> 4u) != 6u)
        return 0;
    next_header = ip_header[6];
    control_offset = ip_offset + 40u;
    while (next_header == 0u || next_header == 43u ||
           next_header == 60u) {
        uint8_t extension[2];
        uint32_t extension_length;

        if (edge_net_packet_read(
                packet, control_offset, extension,
                sizeof(extension)) != EDGE_NET_OK)
            return 0;
        next_header = extension[0];
        extension_length = ((uint32_t)extension[1] + 1u) * 8u;
        if (extension_length > packet->total_length - control_offset)
            return 0;
        control_offset += extension_length;
    }
    if (next_header != 58u || edge_net_packet_read(
            packet, control_offset, control, sizeof(control)) != EDGE_NET_OK)
        return 0;
    if (control[0] == 130u) return 1;
    if (control[0] == 131u || control[0] == 132u) {
        edge_net_bridge_snoop_group_locked(
            bridge, ingress_ifindex, vlan_id, EDGE_NET_AF_INET6,
            control + 8u, control[0] == 131u,
            packet->metadata.timestamp_ns);
        return 1;
    }
    if (control[0] == 143u) {
        uint16_t record_count = (uint16_t)(
            ((uint16_t)control[6] << 8u) | control[7]);
        uint32_t record_offset = control_offset + 8u;
        uint16_t record_index;

        for (record_index = 0u; record_index < record_count;
             ++record_index) {
            uint8_t record[20];
            uint16_t source_count;
            uint32_t record_length;
            int joining;

            if (edge_net_packet_read(
                    packet, record_offset, record,
                    sizeof(record)) != EDGE_NET_OK)
                break;
            source_count = (uint16_t)(
                ((uint16_t)record[2] << 8u) | record[3]);
            record_length = 20u + (uint32_t)source_count * 16u +
                (uint32_t)record[1] * 4u;
            if (record_length > packet->total_length - record_offset) break;
            joining = !((record[0] == 1u || record[0] == 3u) &&
                        source_count == 0u);
            edge_net_bridge_snoop_group_locked(
                bridge, ingress_ifindex, vlan_id, EDGE_NET_AF_INET6,
                record + 4u, joining, packet->metadata.timestamp_ns);
            record_offset += record_length;
        }
        return 1;
    }
    return 0;
}

static int edge_net_bridge_snoop_multicast_locked(
    edge_net_device_state_t *bridge, int32_t ingress_ifindex,
    uint16_t vlan_id, edge_net_packet_t *packet) {
    uint8_t ethernet[18];
    uint16_t protocol;
    uint32_t ip_offset = 14u;

    if (!bridge || ingress_ifindex <= 0 || !packet ||
        edge_net_packet_read(
            packet, 0u, ethernet, sizeof(ethernet)) != EDGE_NET_OK)
        return 0;
    protocol = (uint16_t)(
        ((uint16_t)ethernet[12] << 8u) | ethernet[13]);
    if (protocol == 0x8100u || protocol == 0x88a8u) {
        protocol = (uint16_t)(
            ((uint16_t)ethernet[16] << 8u) | ethernet[17]);
        ip_offset = 18u;
    }
    if (protocol == 0x0800u)
        return edge_net_bridge_snoop_igmp_locked(
            bridge, ingress_ifindex, vlan_id, packet, ip_offset);
    if (protocol == 0x86ddu)
        return edge_net_bridge_snoop_mld_locked(
            bridge, ingress_ifindex, vlan_id, packet, ip_offset);
    return 0;
}

static void edge_net_bridge_forward_locked(
    edge_net_device_state_t *bridge, int32_t ingress_ifindex,
    edge_net_packet_t *packet, edge_net_delivery_t *deliveries,
    uint32_t *delivery_count) {
    uint8_t ethernet[14];
    int32_t learned_port = 0;
    edge_net_device_state_t *ingress = ingress_ifindex > 0 ?
        edge_net_device_locked(ingress_ifindex) : bridge;
    uint16_t vlan_id = 0u;
    uint32_t index;
    int broadcast;
    int mdb_group;
    int multicast;
    int multicast_control;
    int flood;

    if (!bridge || !packet ||
        edge_net_packet_prefix(packet, ethernet, sizeof(ethernet)) < 0) {
        if (bridge) ++bridge->snapshot.rx_drops;
        return;
    }
    if (!packet->metadata.vlan_untagged && packet->metadata.vlan_id) {
        vlan_id = packet->metadata.vlan_id;
    } else if (!packet->metadata.vlan_untagged &&
               edge_net_packet_has_vlan_header(packet)) {
        uint8_t tagged[18];
        uint16_t tag;

        if (edge_net_packet_prefix(packet, tagged, sizeof(tagged)) < 0) {
            ++bridge->snapshot.rx_drops;
            return;
        }
        tag = (uint16_t)(((uint16_t)tagged[14] << 8u) | tagged[15]);
        vlan_id = tag & 0x0fffu;
        packet->metadata.vlan_id = vlan_id;
        packet->metadata.vlan_priority = (uint8_t)((tag >> 13u) & 7u);
        packet->metadata.vlan_protocol =
            (uint16_t)(((uint16_t)tagged[12] << 8u) | tagged[13]);
        packet->metadata.vlan_tag_present = 1u;
    }
    if (bridge->snapshot.bridge_vlan_filtering) {
        if (!ingress) {
            ++bridge->snapshot.rx_drops;
            return;
        }
        if (!vlan_id) vlan_id = ingress->bridge_pvid;
        if (!edge_net_bridge_vlan_test_locked(ingress, vlan_id)) {
            ++bridge->snapshot.rx_drops;
            ++ingress->snapshot.rx_drops;
            return;
        }
        packet->metadata.vlan_id = vlan_id;
        if (!packet->metadata.vlan_protocol)
            packet->metadata.vlan_protocol = 0x8100u;
    }
    packet->metadata.bridge_path = 1u;
    if (ingress_ifindex > 0 && ingress &&
        ingress->snapshot.bridge_state >= EDGE_NET_BRIDGE_STATE_LEARNING &&
        ingress->snapshot.bridge_state <= EDGE_NET_BRIDGE_STATE_FORWARDING &&
        ingress->snapshot.bridge_learning &&
        !edge_net_mac_is_multicast(ethernet + 6u) &&
        !edge_net_mac_is_zero(ethernet + 6u))
        (void)edge_net_bridge_fdb_add_locked(
            bridge->snapshot.configuration.ifindex, ethernet + 6u,
            ingress_ifindex, vlan_id, 0,
            packet->metadata.timestamp_ns);
    if (ingress_ifindex > 0 &&
        (!ingress || ingress->snapshot.bridge_state !=
            EDGE_NET_BRIDGE_STATE_FORWARDING))
        return;
    broadcast = edge_net_mac_is_broadcast(ethernet);
    multicast = !broadcast && edge_net_mac_is_multicast(ethernet);
    multicast_control = multicast &&
        edge_net_bridge_snoop_multicast_locked(
            bridge, ingress_ifindex, vlan_id, packet);
    mdb_group = multicast && !multicast_control &&
        edge_net_bridge_mdb_group_locked(
        bridge->snapshot.configuration.ifindex, ethernet, vlan_id);
    if (broadcast || multicast) {
        flood = 1;
    } else {
        learned_port = edge_net_bridge_fdb_lookup_locked(
            bridge->snapshot.configuration.ifindex, ethernet, vlan_id);
        flood = learned_port <= 0;
    }
    if (ingress_ifindex > 0 &&
        (edge_net_mac_is_multicast(ethernet) ||
         edge_net_mac_equal(
             ethernet, bridge->snapshot.configuration.hardware_address))) {
        ++bridge->snapshot.rx_packets;
        bridge->snapshot.rx_bytes += packet->total_length;
        edge_net_delivery_add_receive_locked(
            deliveries, delivery_count, bridge, packet,
            EDGE_NET_PACKET_TRANSFORM_NONE, 0u, 0u);
    }
    for (index = 0; index < EDGE_NET_DEVICE_MAX; ++index) {
        edge_net_device_state_t *port = &g_edge_net_devices[index];
        edge_net_device_snapshot_t *port_snapshot;

        if (!port->used) continue;
        port_snapshot = &port->snapshot;
        if (port_snapshot->master_ifindex !=
                bridge->snapshot.configuration.ifindex ||
            port_snapshot->configuration.network_namespace !=
                bridge->snapshot.configuration.network_namespace)
            continue;
        if (port_snapshot->bridge_state !=
                EDGE_NET_BRIDGE_STATE_FORWARDING)
            continue;
        if (!flood && port_snapshot->configuration.ifindex != learned_port)
            continue;
        if (port_snapshot->configuration.ifindex == ingress_ifindex &&
            !port_snapshot->hairpin)
            continue;
        if (ingress_ifindex > 0 && ingress &&
            ingress->snapshot.bridge_isolated &&
            port_snapshot->bridge_isolated)
            continue;
        if (flood && !broadcast && !multicast &&
            !port_snapshot->bridge_unicast_flood)
            continue;
        if (broadcast && !port_snapshot->bridge_broadcast_flood)
            continue;
        if (multicast) {
            if (mdb_group && !edge_net_bridge_mdb_member_locked(
                    bridge->snapshot.configuration.ifindex,
                    port_snapshot->configuration.ifindex,
                    ethernet, vlan_id))
                continue;
            if (!mdb_group && !port_snapshot->bridge_multicast_flood)
                continue;
        }
        if (bridge->snapshot.bridge_vlan_filtering &&
            !edge_net_bridge_vlan_test_locked(port, vlan_id))
            continue;
        {
            uint8_t saved_untagged = packet->metadata.vlan_untagged;

            packet->metadata.vlan_untagged =
                bridge->snapshot.bridge_vlan_filtering &&
                edge_net_bridge_vlan_untagged_locked(port, vlan_id) ?
                    1u : 0u;
            edge_net_port_egress_locked(
                port, packet, deliveries, delivery_count);
            packet->metadata.vlan_untagged = saved_untagged;
        }
    }
}

static edge_net_device_state_t *edge_net_vlan_ingress_target_locked(
    edge_net_device_state_t *lower, edge_net_packet_t *packet) {
    uint8_t header[18];
    uint16_t protocol;
    uint16_t tag;

    if (!lower || !packet ||
        lower->snapshot.configuration.kind == EDGE_NET_DEVICE_VLAN)
        return 0;
    if (packet->metadata.vlan_untagged) return 0;
    if (!packet->metadata.vlan_id) {
        if (edge_net_packet_prefix(packet, header, sizeof(header)) < 0)
            return 0;
        protocol = (uint16_t)(((uint16_t)header[12] << 8u) | header[13]);
        if (protocol != 0x8100u && protocol != 0x88a8u) return 0;
        tag = (uint16_t)(((uint16_t)header[14] << 8u) | header[15]);
        packet->metadata.vlan_id = tag & 0x0fffu;
        packet->metadata.vlan_priority = (uint8_t)((tag >> 13u) & 7u);
        packet->metadata.vlan_protocol = protocol;
        packet->metadata.vlan_tag_present = 1u;
    }
    if (!packet->metadata.vlan_id ||
        (packet->metadata.vlan_protocol != 0x8100u &&
         packet->metadata.vlan_protocol != 0x88a8u))
        return 0;
    return edge_net_vlan_child_locked(
        lower->snapshot.configuration.ifindex,
        packet->metadata.vlan_id, packet->metadata.vlan_protocol);
}

static void edge_net_ingress_locked(
    edge_net_device_state_t *device, edge_net_packet_t *packet,
    edge_net_delivery_t *deliveries, uint32_t *delivery_count) {
    edge_net_device_snapshot_t *snapshot;
    edge_net_device_state_t *vlan_child;

    if (!device || !packet) return;
    snapshot = &device->snapshot;
    if (!edge_net_device_can_forward_locked(device, packet)) {
        ++snapshot->rx_drops;
        return;
    }
    ++snapshot->rx_packets;
    snapshot->rx_bytes += packet->total_length;
    packet->metadata.input_ifindex = snapshot->configuration.ifindex;
    packet->metadata.network_namespace =
        snapshot->configuration.network_namespace;
    if (snapshot->configuration.kind != EDGE_NET_DEVICE_MACVLAN &&
        snapshot->configuration.kind != EDGE_NET_DEVICE_IPVLAN) {
        uint8_t ethernet[14];
        int multicast = 0;
        int delivered;

        if (edge_net_packet_prefix(packet, ethernet, sizeof(ethernet)) == 0)
            multicast = edge_net_mac_is_multicast(ethernet) ||
                        edge_net_mac_is_broadcast(ethernet);
        delivered = edge_net_macvlan_deliver_locked(
            device, 0, packet, deliveries, delivery_count, 0);
        if (delivered && !multicast) return;
    }
    if (snapshot->configuration.kind != EDGE_NET_DEVICE_IPVLAN) {
        uint8_t ethernet[14];
        int multicast = 0;
        int delivered;

        if (edge_net_packet_prefix(packet, ethernet, sizeof(ethernet)) == 0)
            multicast = edge_net_mac_is_multicast(ethernet) ||
                        edge_net_mac_is_broadcast(ethernet);
        delivered = edge_net_ipvlan_deliver_locked(
            device, 0, packet, deliveries, delivery_count, 0);
        if (delivered && !multicast) return;
    }
    vlan_child = edge_net_vlan_ingress_target_locked(device, packet);
    if (vlan_child) {
        edge_net_device_snapshot_t *vlan_snapshot = &vlan_child->snapshot;

        if (!edge_net_device_can_forward_locked(vlan_child, packet)) {
            ++vlan_snapshot->rx_drops;
            return;
        }
        ++vlan_snapshot->rx_packets;
        vlan_snapshot->rx_bytes += packet->total_length;
        packet->metadata.input_ifindex =
            vlan_snapshot->configuration.ifindex;
        packet->metadata.network_namespace =
            vlan_snapshot->configuration.network_namespace;
        if (vlan_snapshot->master_ifindex > 0) {
            edge_net_device_state_t *master = edge_net_device_locked(
                vlan_snapshot->master_ifindex);

            if (master && master->snapshot.configuration.kind ==
                    EDGE_NET_DEVICE_BRIDGE) {
                edge_net_bridge_forward_locked(
                    master, vlan_snapshot->configuration.ifindex, packet,
                    deliveries, delivery_count);
                return;
            }
        }
        edge_net_delivery_add_receive_locked(
            deliveries, delivery_count, vlan_child, packet,
            packet->metadata.vlan_tag_present ?
                EDGE_NET_PACKET_TRANSFORM_VLAN_REMOVE :
                EDGE_NET_PACKET_TRANSFORM_NONE,
            packet->metadata.vlan_id, packet->metadata.vlan_protocol);
        return;
    }
    if (snapshot->master_ifindex > 0) {
        edge_net_device_state_t *master =
            edge_net_device_locked(snapshot->master_ifindex);

        if (master && master->snapshot.configuration.kind ==
                EDGE_NET_DEVICE_BRIDGE) {
            edge_net_bridge_forward_locked(
                master, snapshot->configuration.ifindex, packet,
                deliveries, delivery_count);
            return;
        } else if (master && master->snapshot.configuration.kind ==
                       EDGE_NET_DEVICE_BOND) {
            edge_net_device_snapshot_t *bond_snapshot = &master->snapshot;

            if (!edge_net_device_can_forward_locked(master, packet)) {
                ++bond_snapshot->rx_drops;
                return;
            }
            ++bond_snapshot->rx_packets;
            bond_snapshot->rx_bytes += packet->total_length;
            packet->metadata.input_ifindex =
                bond_snapshot->configuration.ifindex;
            packet->metadata.network_namespace =
                bond_snapshot->configuration.network_namespace;
            if (bond_snapshot->master_ifindex > 0) {
                edge_net_device_state_t *upper = edge_net_device_locked(
                    bond_snapshot->master_ifindex);

                if (upper && upper->snapshot.configuration.kind ==
                        EDGE_NET_DEVICE_BRIDGE) {
                    edge_net_bridge_forward_locked(
                        upper, bond_snapshot->configuration.ifindex,
                        packet, deliveries, delivery_count);
                    return;
                }
            }
            edge_net_delivery_add_receive_locked(
                deliveries, delivery_count, master, packet,
                EDGE_NET_PACKET_TRANSFORM_NONE, 0u, 0u);
            return;
        }
    }
    edge_net_delivery_add_receive_locked(
        deliveries, delivery_count, device, packet,
        packet->metadata.vlan_untagged ?
            (packet->metadata.vlan_tag_present ?
                EDGE_NET_PACKET_TRANSFORM_VLAN_REMOVE :
                EDGE_NET_PACKET_TRANSFORM_NONE) :
            (packet->metadata.vlan_id &&
             !packet->metadata.vlan_tag_present ?
                EDGE_NET_PACKET_TRANSFORM_VLAN_INSERT :
                EDGE_NET_PACKET_TRANSFORM_NONE),
        packet->metadata.vlan_id, packet->metadata.vlan_protocol);
}

static int edge_net_packet_append_slice(
    const edge_net_packet_t *packet, uint32_t offset,
    edge_net_packet_segment_t *segments, uint8_t *segment_count) {
    uint32_t position = 0u;
    uint8_t index;

    if (!packet || !segments || !segment_count ||
        offset > packet->total_length)
        return EDGE_NET_INVALID;
    for (index = 0; index < packet->segment_count; ++index) {
        const edge_net_packet_segment_t *source = &packet->segments[index];
        uint32_t source_offset = 0u;

        if (offset >= position + source->length) {
            position += source->length;
            continue;
        }
        if (offset > position) source_offset = offset - position;
        if (*segment_count >= EDGE_NET_PACKET_SEGMENT_MAX)
            return EDGE_NET_NO_SPACE;
        segments[*segment_count].data = source->data + source_offset;
        segments[*segment_count].length = source->length - source_offset;
        ++*segment_count;
        position += source->length;
        offset = position;
    }
    return EDGE_NET_OK;
}

static int edge_net_packet_transform(
    const edge_net_delivery_t *delivery, edge_net_packet_t *source,
    edge_net_packet_t *view, uint8_t header[18]) {
    edge_net_packet_segment_t segments[EDGE_NET_PACKET_SEGMENT_MAX];
    edge_net_packet_metadata_t metadata;
    uint8_t ethernet[18];
    uint8_t segment_count = 1u;
    uint32_t payload_offset;
    uint32_t header_length;
    uint16_t protocol;
    uint16_t tag;

    if (!delivery || !source || !view || !header ||
        delivery->packet_transform == EDGE_NET_PACKET_TRANSFORM_NONE)
        return EDGE_NET_INVALID;
    memset(segments, 0, sizeof(segments));
    memcpy(&metadata, &delivery->metadata, sizeof(metadata));
    if (delivery->packet_transform ==
            EDGE_NET_PACKET_TRANSFORM_VLAN_INSERT) {
        if (edge_net_packet_read(source, 0u, ethernet, 14u) != EDGE_NET_OK)
            return EDGE_NET_INVALID;
        protocol = delivery->vlan_protocol ?
            delivery->vlan_protocol : 0x8100u;
        tag = (uint16_t)(delivery->vlan_id & 0x0fffu);
        tag |= (uint16_t)((metadata.vlan_priority & 7u) << 13u);
        memcpy(header, ethernet, 12u);
        header[12] = (uint8_t)(protocol >> 8u);
        header[13] = (uint8_t)protocol;
        header[14] = (uint8_t)(tag >> 8u);
        header[15] = (uint8_t)tag;
        header[16] = ethernet[12];
        header[17] = ethernet[13];
        header_length = 18u;
        payload_offset = 14u;
        metadata.vlan_tag_present = 1u;
        metadata.vlan_untagged = 0u;
        metadata.protocol = protocol;
        metadata.mac_header = 0u;
        metadata.network_header = 18u;
        if (metadata.transport_header >= 14u)
            metadata.transport_header += 4u;
    } else if (delivery->packet_transform ==
                   EDGE_NET_PACKET_TRANSFORM_VLAN_REMOVE) {
        if (edge_net_packet_read(source, 0u, ethernet, 18u) != EDGE_NET_OK)
            return EDGE_NET_INVALID;
        protocol = (uint16_t)(((uint16_t)ethernet[16] << 8u) |
                              ethernet[17]);
        memcpy(header, ethernet, 12u);
        header[12] = ethernet[16];
        header[13] = ethernet[17];
        header_length = 14u;
        payload_offset = 18u;
        metadata.vlan_tag_present = 0u;
        metadata.vlan_untagged = 0u;
        metadata.protocol = protocol;
        metadata.mac_header = 0u;
        metadata.network_header = 14u;
        if (metadata.transport_header >= 18u)
            metadata.transport_header -= 4u;
    } else {
        return EDGE_NET_INVALID;
    }
    segments[0].data = header;
    segments[0].length = header_length;
    if (edge_net_packet_append_slice(
            source, payload_offset, segments, &segment_count) != EDGE_NET_OK)
        return EDGE_NET_NO_SPACE;
    return edge_net_packet_initialize(
        view, segments, segment_count, &metadata, 0, 0);
}

static void edge_net_deliver(
    edge_net_delivery_t *deliveries, uint32_t delivery_count,
    edge_net_packet_t *packet) {
    uint32_t index;

    for (index = 0; index < delivery_count; ++index) {
        edge_net_delivery_t *delivery = &deliveries[index];
        edge_net_packet_t transformed_packet;
        edge_net_packet_t *delivered_packet = packet;
        uint8_t transformed_header[18];

        if (edge_net_packet_retain(packet) < 0) continue;
        if (delivery->packet_transform != EDGE_NET_PACKET_TRANSFORM_NONE) {
            if (edge_net_packet_transform(
                    delivery, packet, &transformed_packet,
                    transformed_header) != EDGE_NET_OK)
                goto delivery_complete;
            delivered_packet = &transformed_packet;
        } else {
            memcpy(&packet->metadata, &delivery->metadata,
                   sizeof(packet->metadata));
        }
        if (delivery->receive) {
            if (edge_net_hook_run(
                    delivered_packet->metadata.network_namespace,
                    EDGE_NET_HOOK_INGRESS, delivered_packet) !=
                    EDGE_NET_VERDICT_ACCEPT)
                goto delivery_complete;
            if (edge_net_hook_run(
                    delivered_packet->metadata.network_namespace,
                    EDGE_NET_HOOK_LOCAL_INPUT, delivered_packet) !=
                    EDGE_NET_VERDICT_ACCEPT)
                goto delivery_complete;
            delivery->receive(
                delivery->ifindex, delivery->network_namespace,
                delivered_packet, delivery->context);
        } else if (delivery->transmit) {
            if (delivered_packet->metadata.input_ifindex > 0) {
                if (edge_net_hook_run(
                        delivered_packet->metadata.network_namespace,
                        EDGE_NET_HOOK_FORWARD, delivered_packet) !=
                        EDGE_NET_VERDICT_ACCEPT)
                    goto delivery_complete;
            } else if (edge_net_hook_run(
                           delivered_packet->metadata.network_namespace,
                           EDGE_NET_HOOK_LOCAL_OUTPUT, delivered_packet) !=
                       EDGE_NET_VERDICT_ACCEPT) {
                goto delivery_complete;
            }
            if (edge_net_hook_run(
                    delivered_packet->metadata.network_namespace,
                    EDGE_NET_HOOK_EGRESS, delivered_packet) !=
                    EDGE_NET_VERDICT_ACCEPT)
                goto delivery_complete;
            delivery->transmit(
                delivery->ifindex, delivery->network_namespace,
                delivered_packet, delivery->context);
        }
delivery_complete:
        edge_net_packet_release(packet);
    }
}

void edge_net_core_reset(void) {
    __atomic_store_n(&g_edge_net_lock, 0u, __ATOMIC_RELEASE);
    edge_net_lock();
    g_edge_net_initialized = 0u;
    edge_net_initialize_locked();
    edge_net_unlock();
}

int edge_net_packet_initialize(
    edge_net_packet_t *packet, const edge_net_packet_segment_t *segments,
    uint8_t segment_count, const edge_net_packet_metadata_t *metadata,
    edge_net_packet_release_fn release, void *release_context) {
    uint32_t total = 0;
    uint8_t index;

    if (!packet || !segments || !segment_count ||
        segment_count > EDGE_NET_PACKET_SEGMENT_MAX)
        return EDGE_NET_INVALID;
    memset(packet, 0, sizeof(*packet));
    for (index = 0; index < segment_count; ++index) {
        if (!segments[index].data || !segments[index].length ||
            UINT32_MAX - total < segments[index].length)
            return EDGE_NET_INVALID;
        total += segments[index].length;
    }
    packet->references = 1u;
    packet->total_length = total;
    packet->segment_count = segment_count;
    memcpy(packet->segments, segments,
           (uint32_t)segment_count * sizeof(segments[0]));
    if (metadata) memcpy(&packet->metadata, metadata, sizeof(*metadata));
    packet->release = release;
    packet->release_context = release_context;
    return EDGE_NET_OK;
}

int edge_net_packet_retain(edge_net_packet_t *packet) {
    uint32_t current;

    if (!packet) return EDGE_NET_INVALID;
    current = __atomic_load_n(&packet->references, __ATOMIC_RELAXED);
    for (;;) {
        if (!current || current == UINT32_MAX) return EDGE_NET_INVALID;
        if (__atomic_compare_exchange_n(
                &packet->references, &current, current + 1u, 0,
                __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return EDGE_NET_OK;
    }
}

void edge_net_packet_release(edge_net_packet_t *packet) {
    uint32_t current;

    if (!packet) return;
    current = __atomic_load_n(&packet->references, __ATOMIC_RELAXED);
    for (;;) {
        if (!current) return;
        if (__atomic_compare_exchange_n(
                &packet->references, &current, current - 1u, 0,
                __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            if (current == 1u && packet->release)
                packet->release(packet->release_context);
            return;
        }
    }
}

static void edge_net_packet_clone_release(void *context) {
    edge_net_packet_release((edge_net_packet_t *)context);
}

int edge_net_packet_clone(
    edge_net_packet_t *clone, edge_net_packet_t *source) {
    edge_net_packet_segment_t segments[EDGE_NET_PACKET_SEGMENT_MAX];
    edge_net_packet_metadata_t metadata;
    uint8_t segment_count;

    if (!clone || !source || clone == source || !source->total_length ||
        !source->segment_count ||
        source->segment_count > EDGE_NET_PACKET_SEGMENT_MAX)
        return EDGE_NET_INVALID;
    segment_count = source->segment_count;
    memcpy(segments, source->segments,
           (uint32_t)segment_count * sizeof(segments[0]));
    memcpy(&metadata, &source->metadata, sizeof(metadata));
    if (edge_net_packet_retain(source) != EDGE_NET_OK)
        return EDGE_NET_INVALID;
    if (edge_net_packet_initialize(
            clone, segments, segment_count, &metadata,
            edge_net_packet_clone_release, source) != EDGE_NET_OK) {
        edge_net_packet_release(source);
        return EDGE_NET_INVALID;
    }
    return EDGE_NET_OK;
}

int edge_net_packet_linearize(
    const edge_net_packet_t *packet, void *output, uint32_t capacity) {
    uint8_t *bytes = (uint8_t *)output;
    uint32_t offset = 0;
    uint8_t index;

    if (!packet || !output || capacity < packet->total_length)
        return EDGE_NET_MESSAGE_TOO_LARGE;
    for (index = 0; index < packet->segment_count; ++index) {
        memcpy(bytes + offset, packet->segments[index].data,
               packet->segments[index].length);
        offset += packet->segments[index].length;
    }
    return (int)offset;
}

int edge_net_packet_read(
    const edge_net_packet_t *packet, uint32_t offset,
    void *output, uint32_t length) {
    uint8_t *bytes = (uint8_t *)output;
    uint32_t copied = 0u;
    uint32_t position = 0u;
    uint8_t index;

    if (!packet || (!output && length) || offset > packet->total_length ||
        length > packet->total_length - offset)
        return EDGE_NET_INVALID;
    for (index = 0; index < packet->segment_count && copied < length;
         ++index) {
        const edge_net_packet_segment_t *segment = &packet->segments[index];
        uint32_t segment_offset;
        uint32_t count;

        if (offset >= position + segment->length) {
            position += segment->length;
            continue;
        }
        segment_offset = offset > position ? offset - position : 0u;
        count = segment->length - segment_offset;
        if (count > length - copied) count = length - copied;
        memcpy(bytes + copied, segment->data + segment_offset, count);
        copied += count;
        offset += count;
        position += segment->length;
    }
    return copied == length ? EDGE_NET_OK : EDGE_NET_INVALID;
}

static enum edge_net_hook_verdict edge_net_hook_run(
    uint32_t network_namespace, enum edge_net_hook_stage stage,
    edge_net_packet_t *packet) {
    edge_net_hook_registration_t callbacks[EDGE_NET_HOOK_MAX];
    edge_net_namespace_state_t *namespace_state;
    uint8_t ethernet[18];
    uint16_t protocol = 0u;
    uint32_t family = UINT32_MAX;
    uint32_t callback_count = 0u;
    uint32_t index;

    if (!packet || stage < EDGE_NET_HOOK_INGRESS ||
        stage > EDGE_NET_HOOK_EGRESS)
        return EDGE_NET_VERDICT_DROP;
    if (packet->metadata.bridge_path &&
        edge_net_packet_prefix(packet, ethernet, 14u) == 0) {
        protocol = (uint16_t)(((uint16_t)ethernet[12] << 8u) | ethernet[13]);
        if ((protocol == 0x8100u || protocol == 0x88a8u) &&
            edge_net_packet_prefix(packet, ethernet, 18u) == 0)
            protocol = (uint16_t)(((uint16_t)ethernet[16] << 8u) |
                                  ethernet[17]);
        if (protocol == 0x0800u) family = 0u;
        else if (protocol == 0x86ddu) family = 1u;
        else if (protocol == 0x0806u) family = 2u;
    }
    edge_net_lock();
    edge_net_initialize_locked();
    namespace_state = edge_net_namespace_locked(network_namespace);
    if (family < 3u && namespace_state &&
        !namespace_state->bridge_filters[family]) {
        edge_net_unlock();
        return EDGE_NET_VERDICT_ACCEPT;
    }
    for (index = 0; index < EDGE_NET_HOOK_MAX; ++index) {
        const edge_net_hook_state_t *hook = &g_edge_net_hooks[index];
        uint32_t insert;

        if (!hook->used ||
            (hook->registration.network_namespace != EDGE_NET_NAMESPACE_ALL &&
             hook->registration.network_namespace != network_namespace) ||
            hook->registration.stage != stage)
            continue;
        insert = callback_count;
        while (insert > 0u &&
               callbacks[insert - 1u].priority >
                   hook->registration.priority) {
            callbacks[insert] = callbacks[insert - 1u];
            --insert;
        }
        callbacks[insert] = hook->registration;
        ++callback_count;
    }
    edge_net_unlock();
    for (index = 0; index < callback_count; ++index) {
        enum edge_net_hook_verdict verdict;
        uint32_t repeats = 0u;

        do {
            verdict = callbacks[index].callback(
                stage, packet, callbacks[index].context);
        } while (verdict == EDGE_NET_VERDICT_REPEAT && ++repeats < 8u);
        if (verdict == EDGE_NET_VERDICT_REPEAT)
            return EDGE_NET_VERDICT_DROP;
        if (verdict != EDGE_NET_VERDICT_ACCEPT) return verdict;
    }
    return EDGE_NET_VERDICT_ACCEPT;
}

int edge_net_hook_register(
    const edge_net_hook_registration_t *registration,
    uint32_t *handle) {
    uint32_t index;

    if (!registration || !handle || !registration->callback ||
        registration->stage < EDGE_NET_HOOK_INGRESS ||
        registration->stage > EDGE_NET_HOOK_EGRESS)
        return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    if (registration->network_namespace != EDGE_NET_NAMESPACE_ALL &&
        !edge_net_namespace_locked(registration->network_namespace)) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    for (index = 0; index < EDGE_NET_HOOK_MAX; ++index) {
        const edge_net_hook_state_t *hook = &g_edge_net_hooks[index];

        if (hook->used &&
            hook->registration.network_namespace ==
                registration->network_namespace &&
            hook->registration.stage == registration->stage &&
            hook->registration.priority == registration->priority &&
            hook->registration.callback == registration->callback &&
            hook->registration.context == registration->context) {
            *handle = hook->handle;
            edge_net_unlock();
            return EDGE_NET_OK;
        }
    }
    for (index = 0; index < EDGE_NET_HOOK_MAX; ++index) {
        edge_net_hook_state_t *hook = &g_edge_net_hooks[index];

        if (hook->used) continue;
        memset(hook, 0, sizeof(*hook));
        hook->used = 1u;
        hook->handle = g_edge_net_next_hook_handle++;
        if (!hook->handle) hook->handle = g_edge_net_next_hook_handle++;
        hook->registration = *registration;
        *handle = hook->handle;
        edge_net_unlock();
        return EDGE_NET_OK;
    }
    edge_net_unlock();
    return EDGE_NET_NO_SPACE;
}

int edge_net_hook_unregister(uint32_t handle) {
    uint32_t index;

    if (!handle) return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    for (index = 0; index < EDGE_NET_HOOK_MAX; ++index) {
        if (!g_edge_net_hooks[index].used ||
            g_edge_net_hooks[index].handle != handle)
            continue;
        memset(&g_edge_net_hooks[index], 0, sizeof(g_edge_net_hooks[index]));
        edge_net_unlock();
        return EDGE_NET_OK;
    }
    edge_net_unlock();
    return EDGE_NET_NOT_FOUND;
}

int edge_net_namespace_ensure(uint32_t network_namespace) {
    int result;

    edge_net_lock();
    edge_net_initialize_locked();
    result = edge_net_namespace_ensure_locked(network_namespace);
    edge_net_unlock();
    return result;
}

int edge_net_namespace_ipv4_forwarding_get(
    uint32_t network_namespace, int *enabled) {
    edge_net_namespace_state_t *state;

    if (!enabled) return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    state = edge_net_namespace_locked(network_namespace);
    if (!state) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    *enabled = state->ipv4_forwarding ? 1 : 0;
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_namespace_ipv4_forwarding_set(
    uint32_t network_namespace, int enabled) {
    edge_net_namespace_state_t *state;

    if (enabled != 0 && enabled != 1) return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    state = edge_net_namespace_locked(network_namespace);
    if (!state) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    state->ipv4_forwarding = enabled ? 1u : 0u;
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_namespace_ipv6_setting_get(
    uint32_t network_namespace, uint32_t setting, int *value) {
    edge_net_namespace_state_t *state;

    if (!value || setting > 3u) return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    state = edge_net_namespace_locked(network_namespace);
    if (!state) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    *value = state->ipv6_settings[setting];
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_namespace_ipv6_setting_set(
    uint32_t network_namespace, uint32_t setting, int value) {
    edge_net_namespace_state_t *state;

    if (setting > 3u || value < 0 ||
        value > (setting == 2u ? 2 : 1))
        return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    state = edge_net_namespace_locked(network_namespace);
    if (!state) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    state->ipv6_settings[setting] = (uint8_t)value;
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_namespace_bridge_filter_get(
    uint32_t network_namespace, uint32_t family, int *enabled) {
    edge_net_namespace_state_t *state;

    if (!enabled || family > 2u) return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    state = edge_net_namespace_locked(network_namespace);
    if (!state) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    *enabled = state->bridge_filters[family] ? 1 : 0;
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_namespace_bridge_filter_set(
    uint32_t network_namespace, uint32_t family, int enabled) {
    edge_net_namespace_state_t *state;

    if (family > 2u || (enabled != 0 && enabled != 1))
        return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    if (edge_net_namespace_ensure_locked(network_namespace) != EDGE_NET_OK) {
        edge_net_unlock();
        return EDGE_NET_NO_SPACE;
    }
    state = edge_net_namespace_locked(network_namespace);
    state->bridge_filters[family] = enabled ? 1u : 0u;
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_namespace_destroy(uint32_t network_namespace) {
    edge_net_namespace_state_t *state;
    uint32_t index;

    if (!network_namespace) return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    state = edge_net_namespace_locked(network_namespace);
    if (!state) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    for (index = 0; index < EDGE_NET_DEVICE_MAX; ++index) {
        edge_net_device_state_t *device = &g_edge_net_devices[index];
        int32_t ifindex;
        int32_t peer_ifindex;
        uint32_t candidate_index;

        if (!device->used ||
            device->snapshot.configuration.network_namespace !=
                network_namespace)
            continue;
        ifindex = device->snapshot.configuration.ifindex;
        peer_ifindex = device->snapshot.peer_ifindex;
        edge_net_lower_remove_dependents_locked(ifindex);
        edge_net_fdb_remove_device_locked(ifindex);
        memset(device, 0, sizeof(*device));
        if (peer_ifindex > 0) {
            edge_net_device_state_t *peer =
                edge_net_device_locked(peer_ifindex);

            if (peer) {
                edge_net_fdb_remove_device_locked(peer_ifindex);
                memset(peer, 0, sizeof(*peer));
            }
        }
        for (candidate_index = 0;
             candidate_index < EDGE_NET_DEVICE_MAX;
             ++candidate_index) {
            edge_net_device_state_t *candidate =
                &g_edge_net_devices[candidate_index];

            if (candidate->used &&
                candidate->snapshot.master_ifindex == ifindex)
                candidate->snapshot.master_ifindex = 0;
        }
    }
    for (index = 0; index < EDGE_NET_HOOK_MAX; ++index) {
        if (g_edge_net_hooks[index].used &&
            g_edge_net_hooks[index].registration.network_namespace ==
                network_namespace)
            memset(&g_edge_net_hooks[index], 0,
                   sizeof(g_edge_net_hooks[index]));
    }
    memset(state, 0, sizeof(*state));
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_device_register(
    const edge_net_device_configuration_t *configuration) {
    edge_net_device_configuration_t installed_configuration;
    edge_net_device_state_t *slot;
    int result;

    if (!edge_net_device_configuration_valid(configuration))
        return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    if (edge_net_device_locked(configuration->ifindex) ||
        edge_net_device_name_locked(
            configuration->network_namespace, configuration->name)) {
        edge_net_unlock();
        return EDGE_NET_EXISTS;
    }
    memcpy(&installed_configuration, configuration,
           sizeof(installed_configuration));
    if (configuration->kind == EDGE_NET_DEVICE_VLAN ||
        configuration->kind == EDGE_NET_DEVICE_MACVLAN ||
        configuration->kind == EDGE_NET_DEVICE_IPVLAN) {
        edge_net_device_state_t *lower = edge_net_device_locked(
            configuration->lower_ifindex);
        uint32_t index;

        if (!lower || lower->snapshot.configuration.network_namespace !=
                configuration->network_namespace ||
            lower->snapshot.configuration.kind == EDGE_NET_DEVICE_LOOPBACK ||
            lower->snapshot.configuration.kind == EDGE_NET_DEVICE_DUMMY ||
            lower->snapshot.configuration.kind == EDGE_NET_DEVICE_TUN ||
            lower->snapshot.configuration.kind ==
                EDGE_NET_DEVICE_MACVLAN ||
            lower->snapshot.configuration.kind ==
                EDGE_NET_DEVICE_IPVLAN) {
            edge_net_unlock();
            return EDGE_NET_NOT_FOUND;
        }
        if (configuration->kind == EDGE_NET_DEVICE_VLAN &&
            edge_net_vlan_child_locked(
                configuration->lower_ifindex, configuration->vlan_id,
                configuration->vlan_protocol)) {
            edge_net_unlock();
            return EDGE_NET_EXISTS;
        }
        if (configuration->kind == EDGE_NET_DEVICE_MACVLAN) {
            for (index = 0; index < EDGE_NET_DEVICE_MAX; ++index) {
                const edge_net_device_state_t *candidate =
                    &g_edge_net_devices[index];

                if (!candidate->used ||
                    candidate->snapshot.configuration.kind !=
                        EDGE_NET_DEVICE_MACVLAN ||
                    candidate->snapshot.configuration.lower_ifindex !=
                        configuration->lower_ifindex)
                    continue;
                if (edge_net_mac_equal(
                        candidate->snapshot.configuration.hardware_address,
                        configuration->hardware_address) ||
                    candidate->snapshot.configuration.virtual_mode ==
                        EDGE_NET_MACVLAN_MODE_PASSTHRU ||
                    configuration->virtual_mode ==
                        EDGE_NET_MACVLAN_MODE_PASSTHRU) {
                    edge_net_unlock();
                    return EDGE_NET_EXISTS;
                }
            }
        }
        installed_configuration.carrier =
            lower->snapshot.configuration.carrier;
    }
    result = edge_net_namespace_ensure_locked(
        configuration->network_namespace);
    if (result < 0) {
        edge_net_unlock();
        return result;
    }
    slot = edge_net_device_slot_locked();
    if (!slot) {
        edge_net_unlock();
        return EDGE_NET_NO_SPACE;
    }
    edge_net_device_install_locked(slot, &installed_configuration);
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_veth_register_pair(
    const edge_net_device_configuration_t *first,
    const edge_net_device_configuration_t *second) {
    edge_net_device_state_t *first_slot;
    edge_net_device_state_t *second_slot;
    int result;

    if (!edge_net_device_configuration_valid(first) ||
        !edge_net_device_configuration_valid(second) ||
        first->kind != EDGE_NET_DEVICE_VETH ||
        second->kind != EDGE_NET_DEVICE_VETH ||
        first->ifindex == second->ifindex)
        return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    if (edge_net_device_locked(first->ifindex) ||
        edge_net_device_locked(second->ifindex) ||
        edge_net_device_name_locked(
            first->network_namespace, first->name) ||
        edge_net_device_name_locked(
            second->network_namespace, second->name)) {
        edge_net_unlock();
        return EDGE_NET_EXISTS;
    }
    result = edge_net_namespace_ensure_locked(first->network_namespace);
    if (result == EDGE_NET_OK)
        result = edge_net_namespace_ensure_locked(
            second->network_namespace);
    if (result < 0) {
        edge_net_unlock();
        return result;
    }
    first_slot = edge_net_device_slot_locked();
    if (!first_slot) {
        edge_net_unlock();
        return EDGE_NET_NO_SPACE;
    }
    first_slot->used = 1u;
    second_slot = edge_net_device_slot_locked();
    first_slot->used = 0u;
    if (!second_slot || second_slot == first_slot) {
        edge_net_unlock();
        return EDGE_NET_NO_SPACE;
    }
    edge_net_device_install_locked(first_slot, first);
    edge_net_device_install_locked(second_slot, second);
    first_slot->snapshot.peer_ifindex = second->ifindex;
    second_slot->snapshot.peer_ifindex = first->ifindex;
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_device_unregister(int32_t ifindex) {
    edge_net_device_state_t *device;
    int32_t old_master_ifindex;
    int32_t peer_master_ifindex = 0;
    int32_t peer_ifindex;
    uint32_t index;

    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    peer_ifindex = device->snapshot.peer_ifindex;
    old_master_ifindex = device->snapshot.master_ifindex;
    edge_net_lower_remove_dependents_locked(ifindex);
    edge_net_fdb_remove_device_locked(ifindex);
    memset(device, 0, sizeof(*device));
    if (peer_ifindex > 0) {
        edge_net_device_state_t *peer =
            edge_net_device_locked(peer_ifindex);

        if (peer) {
            peer_master_ifindex = peer->snapshot.master_ifindex;
            edge_net_fdb_remove_device_locked(peer_ifindex);
            memset(peer, 0, sizeof(*peer));
        }
    }
    for (index = 0; index < EDGE_NET_DEVICE_MAX; ++index) {
        edge_net_device_state_t *candidate = &g_edge_net_devices[index];

        if (candidate->used && candidate->snapshot.master_ifindex == ifindex)
            candidate->snapshot.master_ifindex = 0;
    }
    if (old_master_ifindex > 0)
        edge_net_bond_carrier_update_locked(old_master_ifindex);
    if (peer_master_ifindex > 0)
        edge_net_bond_carrier_update_locked(peer_master_ifindex);
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_device_move(int32_t ifindex, uint32_t network_namespace) {
    edge_net_device_state_t *device;
    int32_t old_master_ifindex;
    uint32_t index;
    int result;

    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    if (device->snapshot.configuration.network_namespace ==
            network_namespace) {
        edge_net_unlock();
        return EDGE_NET_OK;
    }
    if (device->snapshot.configuration.kind == EDGE_NET_DEVICE_VLAN) {
        edge_net_unlock();
        return EDGE_NET_BUSY;
    }
    for (index = 0; index < EDGE_NET_DEVICE_MAX; ++index) {
        const edge_net_device_state_t *candidate =
            &g_edge_net_devices[index];

        if (candidate->used &&
            (candidate->snapshot.configuration.kind == EDGE_NET_DEVICE_VLAN ||
             candidate->snapshot.configuration.kind ==
                 EDGE_NET_DEVICE_MACVLAN ||
             candidate->snapshot.configuration.kind ==
                 EDGE_NET_DEVICE_IPVLAN) &&
            candidate->snapshot.configuration.lower_ifindex == ifindex) {
            edge_net_unlock();
            return EDGE_NET_BUSY;
        }
    }
    if (edge_net_device_name_locked(
            network_namespace, device->snapshot.configuration.name)) {
        edge_net_unlock();
        return EDGE_NET_EXISTS;
    }
    result = edge_net_namespace_ensure_locked(network_namespace);
    if (result < 0) {
        edge_net_unlock();
        return result;
    }
    edge_net_fdb_remove_device_locked(ifindex);
    old_master_ifindex = device->snapshot.master_ifindex;
    device->snapshot.configuration.network_namespace = network_namespace;
    device->snapshot.master_ifindex = 0;
    edge_net_bridge_port_defaults_locked(device, 0);
    if (device->snapshot.configuration.kind == EDGE_NET_DEVICE_BRIDGE ||
        device->snapshot.configuration.kind == EDGE_NET_DEVICE_BOND) {
        uint32_t index;

        for (index = 0; index < EDGE_NET_DEVICE_MAX; ++index) {
            edge_net_device_state_t *candidate = &g_edge_net_devices[index];

            if (candidate->used &&
                candidate->snapshot.master_ifindex == ifindex) {
                candidate->snapshot.master_ifindex = 0;
                edge_net_bridge_port_defaults_locked(candidate, 0);
            }
        }
    }
    if (old_master_ifindex > 0)
        edge_net_bond_carrier_update_locked(old_master_ifindex);
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_device_rename(
    int32_t ifindex, uint32_t network_namespace, const char *name) {
    edge_net_device_state_t *device;
    edge_net_device_state_t *named;

    if (!edge_net_name_valid(name)) return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device || device->snapshot.configuration.network_namespace !=
            network_namespace) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    named = edge_net_device_name_locked(network_namespace, name);
    if (named && named != device) {
        edge_net_unlock();
        return EDGE_NET_EXISTS;
    }
    memset(device->snapshot.configuration.name, 0,
           sizeof(device->snapshot.configuration.name));
    memcpy(device->snapshot.configuration.name, name, strlen(name) + 1u);
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_device_set_link(
    int32_t ifindex, uint32_t flags, uint32_t change,
    uint32_t mtu, int set_mtu) {
    edge_net_device_state_t *device;

    if (set_mtu && (mtu < 68u || mtu > 65535u))
        return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    device->snapshot.configuration.flags =
        (device->snapshot.configuration.flags & ~change) |
        (flags & change);
    if (set_mtu) device->snapshot.configuration.mtu = mtu;
    if (device->snapshot.configuration.kind == EDGE_NET_DEVICE_VETH &&
        device->snapshot.peer_ifindex > 0) {
        edge_net_device_state_t *peer =
            edge_net_device_locked(device->snapshot.peer_ifindex);

        if (peer) {
            int running =
                (device->snapshot.configuration.flags &
                 EDGE_NET_DEVICE_FLAG_UP) &&
                (peer->snapshot.configuration.flags &
                 EDGE_NET_DEVICE_FLAG_UP);

            device->snapshot.configuration.carrier = running ? 1u : 0u;
            peer->snapshot.configuration.carrier = running ? 1u : 0u;
            edge_net_lower_carrier_update_locked(
                peer->snapshot.configuration.ifindex);
            if (peer->snapshot.master_ifindex > 0)
                edge_net_bond_carrier_update_locked(
                    peer->snapshot.master_ifindex);
        }
    }
    edge_net_lower_carrier_update_locked(ifindex);
    if (device->snapshot.master_ifindex > 0)
        edge_net_bond_carrier_update_locked(
            device->snapshot.master_ifindex);
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_device_set_tx_queue_length(
    int32_t ifindex, uint32_t tx_queue_length) {
    edge_net_device_state_t *device;

    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    device->snapshot.configuration.tx_queue_length = tx_queue_length;
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_device_set_carrier(int32_t ifindex, int carrier) {
    edge_net_device_state_t *device;

    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    if (device->snapshot.configuration.kind == EDGE_NET_DEVICE_VETH) {
        edge_net_unlock();
        return EDGE_NET_NOT_SUPPORTED;
    }
    device->snapshot.configuration.carrier = carrier ? 1u : 0u;
    edge_net_lower_carrier_update_locked(ifindex);
    if (device->snapshot.master_ifindex > 0)
        edge_net_bond_carrier_update_locked(
            device->snapshot.master_ifindex);
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_device_set_callbacks(
    int32_t ifindex, edge_net_receive_fn receive,
    edge_net_transmit_fn transmit, void *context) {
    edge_net_device_state_t *device;

    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    device->snapshot.configuration.receive = receive;
    device->snapshot.configuration.transmit = transmit;
    device->snapshot.configuration.callback_context = context;
    device->snapshot.configuration.receive_context = context;
    device->snapshot.configuration.transmit_context = context;
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_device_set_receive_callback(
    int32_t ifindex, edge_net_receive_fn receive, void *context) {
    edge_net_device_state_t *device;

    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    device->snapshot.configuration.receive = receive;
    device->snapshot.configuration.receive_context = context;
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_device_set_transmit_callback(
    int32_t ifindex, edge_net_transmit_fn transmit, void *context) {
    edge_net_device_state_t *device;

    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    device->snapshot.configuration.transmit = transmit;
    device->snapshot.configuration.transmit_context = context;
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_device_set_master(int32_t ifindex, int32_t master_ifindex) {
    edge_net_device_state_t *device;
    edge_net_device_state_t *master = 0;
    int32_t old_master_ifindex;

    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    old_master_ifindex = device->snapshot.master_ifindex;
    if (master_ifindex > 0) {
        master = edge_net_device_locked(master_ifindex);
        if (!master ||
            (master->snapshot.configuration.kind !=
                 EDGE_NET_DEVICE_BRIDGE &&
             master->snapshot.configuration.kind !=
                 EDGE_NET_DEVICE_BOND &&
             master->snapshot.configuration.kind !=
                 EDGE_NET_DEVICE_VRF)) {
            edge_net_unlock();
            return EDGE_NET_NOT_SUPPORTED;
        }
        if (master->snapshot.configuration.network_namespace !=
                device->snapshot.configuration.network_namespace ||
            master == device) {
            edge_net_unlock();
            return EDGE_NET_WRONG_NAMESPACE;
        }
        if (master->snapshot.configuration.kind == EDGE_NET_DEVICE_BOND &&
            device->snapshot.configuration.kind !=
                EDGE_NET_DEVICE_PHYSICAL &&
            device->snapshot.configuration.kind != EDGE_NET_DEVICE_VETH &&
            device->snapshot.configuration.kind != EDGE_NET_DEVICE_TAP &&
            device->snapshot.configuration.kind != EDGE_NET_DEVICE_VLAN &&
            device->snapshot.configuration.kind != EDGE_NET_DEVICE_DUMMY) {
            edge_net_unlock();
            return EDGE_NET_NOT_SUPPORTED;
        }
        if (master->snapshot.configuration.kind == EDGE_NET_DEVICE_VRF &&
            (device->snapshot.configuration.kind ==
                 EDGE_NET_DEVICE_LOOPBACK ||
             device->snapshot.configuration.kind == EDGE_NET_DEVICE_BRIDGE ||
             device->snapshot.configuration.kind == EDGE_NET_DEVICE_VRF ||
             device->snapshot.configuration.kind == EDGE_NET_DEVICE_TUN)) {
            edge_net_unlock();
            return EDGE_NET_NOT_SUPPORTED;
        }
    }
    edge_net_fdb_remove_device_locked(ifindex);
    device->snapshot.master_ifindex = master_ifindex;
    if (old_master_ifindex != master_ifindex) {
        memset(device->bridge_vlans, 0, sizeof(device->bridge_vlans));
        memset(device->bridge_untagged_vlans, 0,
               sizeof(device->bridge_untagged_vlans));
        device->bridge_pvid = 0u;
        edge_net_bridge_port_defaults_locked(device, 0);
        if (master && master->snapshot.configuration.kind ==
                EDGE_NET_DEVICE_BRIDGE) {
            device->bridge_pvid = 1u;
            edge_net_bridge_vlan_write_locked(device, 1u, 1, 1);
            edge_net_bridge_port_defaults_locked(device, 1);
        }
    }
    if (old_master_ifindex > 0)
        edge_net_bond_carrier_update_locked(old_master_ifindex);
    if (master_ifindex > 0)
        edge_net_bond_carrier_update_locked(master_ifindex);
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_device_set_hairpin(int32_t ifindex, int enabled) {
    return edge_net_device_set_bridge_port_controls(
        ifindex, EDGE_NET_BRIDGE_PORT_HAIRPIN, 0u, enabled,
        0, 0, 0, 0, 0);
}

int edge_net_device_set_bridge_port_controls(
    int32_t ifindex, uint32_t mask, uint8_t state, int hairpin,
    int learning, int unicast_flood, int multicast_flood,
    int broadcast_flood, int isolated) {
    edge_net_device_state_t *device;
    edge_net_device_state_t *master;
    const uint32_t supported =
        EDGE_NET_BRIDGE_PORT_STATE | EDGE_NET_BRIDGE_PORT_HAIRPIN |
        EDGE_NET_BRIDGE_PORT_LEARNING |
        EDGE_NET_BRIDGE_PORT_UNICAST_FLOOD |
        EDGE_NET_BRIDGE_PORT_MULTICAST_FLOOD |
        EDGE_NET_BRIDGE_PORT_BROADCAST_FLOOD |
        EDGE_NET_BRIDGE_PORT_ISOLATED;

    if (!mask || (mask & ~supported) ||
        ((mask & EDGE_NET_BRIDGE_PORT_STATE) &&
         state > EDGE_NET_BRIDGE_STATE_BLOCKING))
        return EDGE_NET_INVALID;

    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    master = edge_net_device_locked(device->snapshot.master_ifindex);
    if (!master || master->snapshot.configuration.kind !=
            EDGE_NET_DEVICE_BRIDGE) {
        edge_net_unlock();
        return EDGE_NET_NOT_SUPPORTED;
    }
    if (mask & EDGE_NET_BRIDGE_PORT_STATE)
        device->snapshot.bridge_state = state;
    if (mask & EDGE_NET_BRIDGE_PORT_HAIRPIN)
        device->snapshot.hairpin = hairpin ? 1u : 0u;
    if (mask & EDGE_NET_BRIDGE_PORT_LEARNING)
        device->snapshot.bridge_learning = learning ? 1u : 0u;
    if (mask & EDGE_NET_BRIDGE_PORT_UNICAST_FLOOD)
        device->snapshot.bridge_unicast_flood = unicast_flood ? 1u : 0u;
    if (mask & EDGE_NET_BRIDGE_PORT_MULTICAST_FLOOD)
        device->snapshot.bridge_multicast_flood =
            multicast_flood ? 1u : 0u;
    if (mask & EDGE_NET_BRIDGE_PORT_BROADCAST_FLOOD)
        device->snapshot.bridge_broadcast_flood =
            broadcast_flood ? 1u : 0u;
    if (mask & EDGE_NET_BRIDGE_PORT_ISOLATED)
        device->snapshot.bridge_isolated = isolated ? 1u : 0u;
    if ((mask & (EDGE_NET_BRIDGE_PORT_STATE |
                 EDGE_NET_BRIDGE_PORT_LEARNING)) != 0u)
        edge_net_fdb_remove_device_locked(
            master->snapshot.configuration.ifindex);
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_bridge_vlan_filtering_set(int32_t ifindex, int enabled) {
    edge_net_device_state_t *bridge;

    if (enabled != 0 && enabled != 1) return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    bridge = edge_net_device_locked(ifindex);
    if (!bridge) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    if (bridge->snapshot.configuration.kind != EDGE_NET_DEVICE_BRIDGE) {
        edge_net_unlock();
        return EDGE_NET_NOT_SUPPORTED;
    }
    bridge->snapshot.bridge_vlan_filtering = enabled ? 1u : 0u;
    edge_net_fdb_remove_device_locked(ifindex);
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_bridge_vlan_update(
    int32_t ifindex, uint16_t first_vlan, uint16_t last_vlan,
    int pvid, int untagged, int add) {
    edge_net_device_state_t *device;
    edge_net_device_state_t *bridge;
    uint16_t vlan_id;

    if (!edge_net_bridge_vlan_valid(first_vlan) ||
        !edge_net_bridge_vlan_valid(last_vlan) ||
        first_vlan > last_vlan || (pvid != 0 && pvid != 1) ||
        (untagged != 0 && untagged != 1) ||
        (add != 0 && add != 1) || (pvid && first_vlan != last_vlan))
        return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    if (device->snapshot.configuration.kind == EDGE_NET_DEVICE_BRIDGE) {
        bridge = device;
    } else {
        bridge = edge_net_device_locked(device->snapshot.master_ifindex);
        if (!bridge || bridge->snapshot.configuration.kind !=
                EDGE_NET_DEVICE_BRIDGE) {
            edge_net_unlock();
            return EDGE_NET_NOT_SUPPORTED;
        }
    }
    for (vlan_id = first_vlan; vlan_id <= last_vlan; ++vlan_id) {
        edge_net_bridge_vlan_write_locked(
            device, vlan_id, add, add && untagged);
        if (vlan_id == UINT16_MAX) break;
    }
    if (add && pvid) device->bridge_pvid = first_vlan;
    edge_net_fdb_remove_device_locked(
        bridge->snapshot.configuration.ifindex);
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_bridge_vlan_snapshot(
    int32_t ifindex, uint32_t ordinal,
    edge_net_bridge_vlan_entry_t *entry) {
    edge_net_device_state_t *device;
    uint32_t match = 0u;
    uint16_t vlan_id;

    if (!entry) return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    if (device->snapshot.configuration.kind != EDGE_NET_DEVICE_BRIDGE) {
        edge_net_device_state_t *bridge = edge_net_device_locked(
            device->snapshot.master_ifindex);

        if (!bridge || bridge->snapshot.configuration.kind !=
                EDGE_NET_DEVICE_BRIDGE) {
            edge_net_unlock();
            return EDGE_NET_NOT_SUPPORTED;
        }
    }
    for (vlan_id = 1u; vlan_id <= EDGE_NET_BRIDGE_VLAN_MAX; ++vlan_id) {
        if (!edge_net_bridge_vlan_test_locked(device, vlan_id)) continue;
        if (match++ != ordinal) continue;
        memset(entry, 0, sizeof(*entry));
        entry->ifindex = ifindex;
        entry->vlan_id = vlan_id;
        entry->pvid = device->bridge_pvid == vlan_id ? 1u : 0u;
        entry->untagged = edge_net_bridge_vlan_untagged_locked(
            device, vlan_id) ? 1u : 0u;
        edge_net_unlock();
        return EDGE_NET_OK;
    }
    edge_net_unlock();
    return EDGE_NET_NOT_FOUND;
}

int edge_net_device_set_ipv4(
    int32_t ifindex, uint32_t address, uint8_t prefix_length,
    uint32_t gateway) {
    edge_net_device_state_t *device;

    if (prefix_length > 32u) return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    device->snapshot.ipv4_address = address;
    device->snapshot.ipv4_prefix_length = prefix_length;
    device->snapshot.ipv4_gateway = gateway;
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_device_get_ipv6_setting(
    int32_t ifindex, uint32_t setting, int *value) {
    edge_net_device_state_t *device;

    if (!value || setting > 3u) return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    switch (setting) {
        case 0u:
            *value = device->snapshot.ipv6_disabled;
            break;
        case 1u:
            *value = device->snapshot.ipv6_forwarding;
            break;
        case 2u:
            *value = device->snapshot.ipv6_accept_ra;
            break;
        default:
            *value = device->snapshot.ipv6_autoconf;
            break;
    }
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_device_set_ipv6_setting(
    int32_t ifindex, uint32_t setting, int value) {
    edge_net_device_state_t *device;
    uint8_t normalized;

    if (setting > 3u || value < 0 ||
        value > (setting == 2u ? 2 : 1))
        return EDGE_NET_INVALID;
    normalized = (uint8_t)value;
    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    switch (setting) {
        case 0u:
            device->snapshot.ipv6_disabled = normalized;
            break;
        case 1u:
            device->snapshot.ipv6_forwarding = normalized;
            break;
        case 2u:
            device->snapshot.ipv6_accept_ra = normalized;
            break;
        default:
            device->snapshot.ipv6_autoconf = normalized;
            break;
    }
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_device_snapshot(
    int32_t ifindex, edge_net_device_snapshot_t *snapshot) {
    edge_net_device_state_t *device;

    if (!snapshot) return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    memcpy(snapshot, &device->snapshot, sizeof(*snapshot));
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_route_interface_snapshot(
    int32_t ifindex, uint32_t network_namespace,
    edge_net_device_snapshot_t *snapshot) {
    int result;

    if (!snapshot || ifindex <= 0) return EDGE_NET_INVALID;
    if (ifindex == 1) {
        memset(snapshot, 0, sizeof(*snapshot));
        snapshot->configuration.ifindex = 1;
        snapshot->configuration.network_namespace = network_namespace;
        snapshot->configuration.kind = EDGE_NET_DEVICE_LOOPBACK;
        snapshot->configuration.flags = EDGE_NET_DEVICE_FLAG_UP |
            EDGE_NET_DEVICE_FLAG_RUNNING |
            EDGE_NET_DEVICE_FLAG_LOOPBACK;
        snapshot->configuration.mtu = 65536u;
        snapshot->configuration.carrier = 1u;
        memcpy(snapshot->configuration.name, "lo", sizeof("lo"));
        return EDGE_NET_OK;
    }
    result = edge_net_device_snapshot(ifindex, snapshot);
    if (result != EDGE_NET_OK) return result;
    if (snapshot->configuration.network_namespace != network_namespace)
        return EDGE_NET_WRONG_NAMESPACE;
    return EDGE_NET_OK;
}

int edge_net_device_snapshot_at(
    uint32_t network_namespace, uint32_t ordinal,
    edge_net_device_snapshot_t *snapshot) {
    uint32_t index;
    uint32_t match = 0;

    if (!snapshot) return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    for (index = 0; index < EDGE_NET_DEVICE_MAX; ++index) {
        edge_net_device_state_t *device = &g_edge_net_devices[index];

        if (!device->used ||
            device->snapshot.configuration.network_namespace !=
                network_namespace)
            continue;
        if (match++ != ordinal) continue;
        memcpy(snapshot, &device->snapshot, sizeof(*snapshot));
        edge_net_unlock();
        return EDGE_NET_OK;
    }
    edge_net_unlock();
    return EDGE_NET_NOT_FOUND;
}

int edge_net_device_find(
    uint32_t network_namespace, const char *name, int32_t *ifindex) {
    edge_net_device_state_t *device;

    if (!edge_net_name_valid(name) || !ifindex) return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_name_locked(network_namespace, name);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    *ifindex = device->snapshot.configuration.ifindex;
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_qdisc_replace(
    int32_t ifindex,
    const edge_net_qdisc_configuration_t *configuration) {
    edge_net_device_state_t *device;

    if (!configuration || configuration->parent != UINT32_MAX ||
        (configuration->kind != EDGE_NET_QDISC_PFIFO &&
         configuration->kind != EDGE_NET_QDISC_BFIFO) ||
        !configuration->handle ||
        (configuration->handle & 0xffffu) != 0u ||
        !configuration->limit)
        return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    memset(&device->qdisc, 0, sizeof(device->qdisc));
    memcpy(&device->qdisc.configuration, configuration,
           sizeof(*configuration));
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_qdisc_delete(int32_t ifindex, uint32_t handle) {
    edge_net_device_state_t *device;

    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    if (device->qdisc.configuration.kind == EDGE_NET_QDISC_NOQUEUE ||
        (handle && device->qdisc.configuration.handle != handle)) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    memset(&device->qdisc, 0, sizeof(device->qdisc));
    device->qdisc.configuration.kind = EDGE_NET_QDISC_NOQUEUE;
    device->qdisc.configuration.parent = UINT32_MAX;
    edge_net_unlock();
    return EDGE_NET_OK;
}

int edge_net_qdisc_snapshot(
    int32_t ifindex, edge_net_qdisc_snapshot_t *snapshot) {
    edge_net_device_state_t *device;

    if (!snapshot) return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    memcpy(snapshot, &device->qdisc, sizeof(*snapshot));
    edge_net_unlock();
    return EDGE_NET_OK;
}

static int edge_net_qdisc_admit_locked(
    edge_net_device_state_t *device, const edge_net_packet_t *packet,
    uint32_t *handle) {
    edge_net_qdisc_snapshot_t *qdisc;

    if (!device || !packet || !handle) return EDGE_NET_INVALID;
    qdisc = &device->qdisc;
    *handle = qdisc->configuration.handle;
    if (qdisc->configuration.kind == EDGE_NET_QDISC_NOQUEUE)
        return EDGE_NET_OK;
    if ((qdisc->configuration.kind == EDGE_NET_QDISC_PFIFO &&
         qdisc->queue_length >= qdisc->configuration.limit) ||
        (qdisc->configuration.kind == EDGE_NET_QDISC_BFIFO &&
         (packet->total_length > qdisc->configuration.limit ||
          qdisc->backlog >
              qdisc->configuration.limit - packet->total_length))) {
        ++qdisc->drops;
        return EDGE_NET_NO_SPACE;
    }
    ++qdisc->queue_length;
    qdisc->backlog += packet->total_length;
    ++qdisc->packets;
    qdisc->bytes += packet->total_length;
    return EDGE_NET_OK;
}

static void edge_net_qdisc_complete(
    int32_t ifindex, uint32_t handle, uint32_t length) {
    edge_net_device_state_t *device;

    if (!handle) return;
    edge_net_lock();
    device = edge_net_device_locked(ifindex);
    if (device && device->qdisc.configuration.handle == handle) {
        if (device->qdisc.queue_length) --device->qdisc.queue_length;
        if (device->qdisc.backlog >= length)
            device->qdisc.backlog -= length;
        else
            device->qdisc.backlog = 0u;
    }
    edge_net_unlock();
}

int edge_net_device_transmit(int32_t ifindex, edge_net_packet_t *packet) {
    edge_net_operation_t *operation;
    edge_net_packet_metadata_t original_metadata;
    edge_net_device_state_t *device;
    uint32_t qdisc_handle = 0u;
    int result = EDGE_NET_OK;

    if (!packet || !packet->total_length) return EDGE_NET_INVALID;
    memcpy(&original_metadata, &packet->metadata, sizeof(original_metadata));
    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    operation = edge_net_operation_acquire_locked();
    if (!operation) {
        ++device->snapshot.tx_drops;
        result = EDGE_NET_NO_SPACE;
    } else if (!edge_net_device_can_forward_locked(device, packet)) {
        ++device->snapshot.tx_drops;
        result = packet->total_length >
                device->snapshot.configuration.mtu + 18u ?
            EDGE_NET_MESSAGE_TOO_LARGE : EDGE_NET_LINK_DOWN;
    } else if (edge_net_qdisc_admit_locked(
                   device, packet, &qdisc_handle) != EDGE_NET_OK) {
        ++device->snapshot.tx_drops;
        result = EDGE_NET_NO_SPACE;
    } else if (device->snapshot.configuration.kind ==
               EDGE_NET_DEVICE_BRIDGE) {
        ++device->snapshot.tx_packets;
        device->snapshot.tx_bytes += packet->total_length;
        packet->metadata.output_ifindex = ifindex;
        edge_net_bridge_forward_locked(
            device, 0, packet, operation->deliveries,
            &operation->delivery_count);
    } else if (device->snapshot.configuration.kind ==
               EDGE_NET_DEVICE_VLAN) {
        edge_net_device_state_t *lower = edge_net_device_locked(
            device->snapshot.configuration.lower_ifindex);

        if (!lower || !edge_net_device_can_forward_locked(lower, packet)) {
            ++device->snapshot.tx_drops;
            result = lower && packet->total_length >
                    lower->snapshot.configuration.mtu + 18u ?
                EDGE_NET_MESSAGE_TOO_LARGE : EDGE_NET_LINK_DOWN;
        } else {
            ++device->snapshot.tx_packets;
            device->snapshot.tx_bytes += packet->total_length;
            packet->metadata.output_ifindex = ifindex;
            packet->metadata.network_namespace =
                device->snapshot.configuration.network_namespace;
            packet->metadata.vlan_id =
                device->snapshot.configuration.vlan_id;
            packet->metadata.vlan_protocol =
                device->snapshot.configuration.vlan_protocol;
            edge_net_port_egress_locked(
                lower, packet, operation->deliveries,
                &operation->delivery_count);
        }
    } else {
        edge_net_port_egress_locked(
            device, packet, operation->deliveries,
            &operation->delivery_count);
    }
    edge_net_unlock();
    if (operation && result == EDGE_NET_OK)
        edge_net_deliver(
            operation->deliveries, operation->delivery_count, packet);
    edge_net_qdisc_complete(ifindex, qdisc_handle,
                            packet->total_length);
    memcpy(&packet->metadata, &original_metadata, sizeof(packet->metadata));
    edge_net_operation_release(operation);
    return result;
}

int edge_net_device_receive(int32_t ifindex, edge_net_packet_t *packet) {
    edge_net_operation_t *operation;
    edge_net_packet_metadata_t original_metadata;
    edge_net_device_state_t *device;

    if (!packet || !packet->total_length) return EDGE_NET_INVALID;
    memcpy(&original_metadata, &packet->metadata, sizeof(original_metadata));
    edge_net_lock();
    edge_net_initialize_locked();
    device = edge_net_device_locked(ifindex);
    if (!device) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    operation = edge_net_operation_acquire_locked();
    if (!operation) {
        ++device->snapshot.rx_drops;
        edge_net_unlock();
        return EDGE_NET_NO_SPACE;
    }
    if (!edge_net_device_can_forward_locked(device, packet)) {
        ++device->snapshot.rx_drops;
        edge_net_unlock();
        edge_net_operation_release(operation);
        return packet->total_length >
                device->snapshot.configuration.mtu + 18u ?
            EDGE_NET_MESSAGE_TOO_LARGE : EDGE_NET_LINK_DOWN;
    }
    edge_net_ingress_locked(
        device, packet, operation->deliveries,
        &operation->delivery_count);
    edge_net_unlock();
    edge_net_deliver(
        operation->deliveries, operation->delivery_count, packet);
    memcpy(&packet->metadata, &original_metadata, sizeof(packet->metadata));
    edge_net_operation_release(operation);
    return EDGE_NET_OK;
}

int edge_net_bridge_fdb_add(
    int32_t bridge_ifindex, const uint8_t hardware_address[6],
    int32_t port_ifindex, int is_static, uint64_t now_ns) {
    return edge_net_bridge_fdb_add_vlan(
        bridge_ifindex, hardware_address, port_ifindex, 0u,
        is_static, now_ns);
}

int edge_net_bridge_fdb_add_vlan(
    int32_t bridge_ifindex, const uint8_t hardware_address[6],
    int32_t port_ifindex, uint16_t vlan_id, int is_static,
    uint64_t now_ns) {
    edge_net_device_state_t *bridge;
    edge_net_device_state_t *port;
    int result;

    if (!hardware_address ||
        (vlan_id && !edge_net_bridge_vlan_valid(vlan_id)) ||
        edge_net_mac_is_multicast(hardware_address) ||
        edge_net_mac_is_zero(hardware_address))
        return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    bridge = edge_net_device_locked(bridge_ifindex);
    port = edge_net_device_locked(port_ifindex);
    if (!bridge || !port) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    if (bridge->snapshot.configuration.kind != EDGE_NET_DEVICE_BRIDGE ||
        port->snapshot.master_ifindex != bridge_ifindex) {
        edge_net_unlock();
        return EDGE_NET_INVALID;
    }
    if (vlan_id &&
        (!bridge->snapshot.bridge_vlan_filtering ||
         !edge_net_bridge_vlan_test_locked(port, vlan_id))) {
        edge_net_unlock();
        return EDGE_NET_INVALID;
    }
    result = edge_net_bridge_fdb_add_locked(
        bridge_ifindex, hardware_address, port_ifindex,
        vlan_id, is_static, now_ns);
    edge_net_unlock();
    return result;
}

int edge_net_bridge_fdb_delete(
    int32_t bridge_ifindex, const uint8_t hardware_address[6]) {
    return edge_net_bridge_fdb_delete_vlan(
        bridge_ifindex, hardware_address, 0u);
}

int edge_net_bridge_fdb_delete_vlan(
    int32_t bridge_ifindex, const uint8_t hardware_address[6],
    uint16_t vlan_id) {
    uint32_t index;

    if (!hardware_address ||
        (vlan_id && !edge_net_bridge_vlan_valid(vlan_id)))
        return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    for (index = 0; index < EDGE_NET_BRIDGE_FDB_MAX; ++index) {
        edge_net_fdb_state_t *state = &g_edge_net_fdb[index];

        if (!state->used ||
            state->entry.bridge_ifindex != bridge_ifindex ||
            (vlan_id && state->entry.vlan_id != vlan_id) ||
            !edge_net_mac_equal(
                state->entry.hardware_address, hardware_address))
            continue;
        memset(state, 0, sizeof(*state));
        edge_net_unlock();
        return EDGE_NET_OK;
    }
    edge_net_unlock();
    return EDGE_NET_NOT_FOUND;
}

int edge_net_bridge_fdb_snapshot(
    int32_t bridge_ifindex, uint32_t ordinal,
    edge_net_bridge_fdb_entry_t *entry) {
    uint32_t index;
    uint32_t match = 0;

    if (!entry) return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    for (index = 0; index < EDGE_NET_BRIDGE_FDB_MAX; ++index) {
        const edge_net_fdb_state_t *state = &g_edge_net_fdb[index];

        if (!state->used ||
            state->entry.bridge_ifindex != bridge_ifindex)
            continue;
        if (match++ != ordinal) continue;
        memcpy(entry, &state->entry, sizeof(*entry));
        edge_net_unlock();
        return EDGE_NET_OK;
    }
    edge_net_unlock();
    return EDGE_NET_NOT_FOUND;
}

int edge_net_bridge_mdb_add(
    const edge_net_bridge_mdb_entry_t *entry) {
    edge_net_device_state_t *bridge;
    edge_net_device_state_t *port;
    uint32_t address_length;
    int result;

    address_length = entry ?
        edge_net_bridge_mdb_address_length(entry->family) : 0u;
    if (!entry || !address_length ||
        !edge_net_mac_is_multicast(entry->hardware_address) ||
        edge_net_mac_is_broadcast(entry->hardware_address) ||
        (entry->family == EDGE_NET_AF_INET &&
         (entry->group_address[0] < 224u ||
          entry->group_address[0] > 239u)) ||
        (entry->family == EDGE_NET_AF_INET6 &&
         entry->group_address[0] != 0xffu) ||
        (entry->vlan_id &&
         !edge_net_bridge_vlan_valid(entry->vlan_id)))
        return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    bridge = edge_net_device_locked(entry->bridge_ifindex);
    port = edge_net_device_locked(entry->port_ifindex);
    if (!bridge || !port) {
        edge_net_unlock();
        return EDGE_NET_NOT_FOUND;
    }
    if (bridge->snapshot.configuration.kind != EDGE_NET_DEVICE_BRIDGE ||
        port->snapshot.master_ifindex != entry->bridge_ifindex) {
        edge_net_unlock();
        return EDGE_NET_INVALID;
    }
    if (entry->vlan_id &&
        (!bridge->snapshot.bridge_vlan_filtering ||
         !edge_net_bridge_vlan_test_locked(port, entry->vlan_id))) {
        edge_net_unlock();
        return EDGE_NET_INVALID;
    }
    result = edge_net_bridge_mdb_update_locked(entry);
    edge_net_unlock();
    return result;
}

int edge_net_bridge_mdb_delete(
    int32_t bridge_ifindex, int32_t port_ifindex,
    const uint8_t hardware_address[6], uint16_t vlan_id) {
    uint32_t index;

    if (!hardware_address ||
        (vlan_id && !edge_net_bridge_vlan_valid(vlan_id)))
        return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    for (index = 0; index < EDGE_NET_BRIDGE_MDB_MAX; ++index) {
        edge_net_mdb_state_t *state = &g_edge_net_mdb[index];

        if (!state->used ||
            state->entry.bridge_ifindex != bridge_ifindex ||
            state->entry.port_ifindex != port_ifindex ||
            state->entry.vlan_id != vlan_id ||
            !edge_net_mac_equal(
                state->entry.hardware_address, hardware_address))
            continue;
        memset(state, 0, sizeof(*state));
        edge_net_unlock();
        return EDGE_NET_OK;
    }
    edge_net_unlock();
    return EDGE_NET_NOT_FOUND;
}

int edge_net_bridge_mdb_delete_group(
    int32_t bridge_ifindex, int32_t port_ifindex,
    uint8_t family, const uint8_t *group_address, uint16_t vlan_id) {
    edge_net_bridge_mdb_entry_t entry;
    uint32_t index;

    if (!group_address ||
        !edge_net_bridge_mdb_address_length(family) ||
        (vlan_id && !edge_net_bridge_vlan_valid(vlan_id)))
        return EDGE_NET_INVALID;
    memset(&entry, 0, sizeof(entry));
    entry.bridge_ifindex = bridge_ifindex;
    entry.port_ifindex = port_ifindex;
    entry.vlan_id = vlan_id;
    edge_net_bridge_mdb_address(&entry, family, group_address);
    edge_net_lock();
    edge_net_initialize_locked();
    for (index = 0; index < EDGE_NET_BRIDGE_MDB_MAX; ++index) {
        edge_net_mdb_state_t *state = &g_edge_net_mdb[index];

        if (!state->used ||
            !edge_net_bridge_mdb_entry_matches_locked(
                &state->entry, &entry))
            continue;
        memset(state, 0, sizeof(*state));
        edge_net_unlock();
        return EDGE_NET_OK;
    }
    edge_net_unlock();
    return EDGE_NET_NOT_FOUND;
}

int edge_net_bridge_mdb_snapshot(
    int32_t bridge_ifindex, uint32_t ordinal,
    edge_net_bridge_mdb_entry_t *entry) {
    uint32_t index;
    uint32_t match = 0u;

    if (!entry) return EDGE_NET_INVALID;
    edge_net_lock();
    edge_net_initialize_locked();
    for (index = 0; index < EDGE_NET_BRIDGE_MDB_MAX; ++index) {
        const edge_net_mdb_state_t *state = &g_edge_net_mdb[index];

        if (!state->used ||
            state->entry.bridge_ifindex != bridge_ifindex)
            continue;
        if (match++ != ordinal) continue;
        memcpy(entry, &state->entry, sizeof(*entry));
        edge_net_unlock();
        return EDGE_NET_OK;
    }
    edge_net_unlock();
    return EDGE_NET_NOT_FOUND;
}

void edge_net_bridge_mdb_age(
    uint64_t now_ns, uint64_t maximum_age_ns) {
    uint32_t index;

    edge_net_lock();
    edge_net_initialize_locked();
    for (index = 0; index < EDGE_NET_BRIDGE_MDB_MAX; ++index) {
        edge_net_mdb_state_t *state = &g_edge_net_mdb[index];

        if (!state->used || state->entry.is_static ||
            now_ns < state->entry.last_seen_ns ||
            now_ns - state->entry.last_seen_ns <= maximum_age_ns)
            continue;
        memset(state, 0, sizeof(*state));
    }
    edge_net_unlock();
}

void edge_net_bridge_fdb_age(uint64_t now_ns, uint64_t maximum_age_ns) {
    uint32_t index;

    edge_net_lock();
    edge_net_initialize_locked();
    for (index = 0; index < EDGE_NET_BRIDGE_FDB_MAX; ++index) {
        edge_net_fdb_state_t *state = &g_edge_net_fdb[index];

        if (!state->used || state->entry.is_static ||
            now_ns < state->entry.last_seen_ns ||
            now_ns - state->entry.last_seen_ns <= maximum_age_ns)
            continue;
        memset(state, 0, sizeof(*state));
    }
    edge_net_unlock();
}
