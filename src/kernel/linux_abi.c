/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux userspace ABI helpers.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/linux_abi.h"
#include "string.h"

#define EDGE_LINUX_E2BIG 7
#define EDGE_LINUX_EFAULT 14
#define EDGE_LINUX_EBUSY 16
#define EDGE_LINUX_EINVAL 22
#define EDGE_LINUX_EPERM 1
#define EDGE_LINUX_EOPNOTSUPP 95

int edge_linux_user_range_valid(uint64_t address, uint64_t size,
                                uint64_t minimum, uint64_t limit) {
    if (minimum >= limit || address >= limit) return 0;
    if (!size) return 1;
    if (address < minimum || size > limit - address) return 0;
    return 1;
}

int edge_linux_copy_struct_from_user(
    void *kernel_destination, uint64_t kernel_size, uint64_t minimum_size,
    uint64_t user_source, uint64_t user_size,
    edge_linux_copy_from_user_fn copy_from_user, void *copy_context) {
    uint8_t trailing[64];
    uint64_t copied;

    if (!kernel_destination || !kernel_size || minimum_size > kernel_size ||
        !copy_from_user)
        return -EDGE_LINUX_EINVAL;
    if (!user_source) return -EDGE_LINUX_EFAULT;
    if (user_size < minimum_size) return -EDGE_LINUX_EINVAL;

    memset(kernel_destination, 0, kernel_size);
    copied = user_size < kernel_size ? user_size : kernel_size;
    if (copy_from_user(copy_context, kernel_destination, user_source,
                       copied) < 0)
        return -EDGE_LINUX_EFAULT;

    while (copied < user_size) {
        uint64_t count = user_size - copied;
        if (count > sizeof(trailing)) count = sizeof(trailing);
        if (copy_from_user(copy_context, trailing, user_source + copied,
                           count) < 0)
            return -EDGE_LINUX_EFAULT;
        for (uint64_t index = 0; index < count; ++index)
            if (trailing[index] != 0) return -EDGE_LINUX_E2BIG;
        copied += count;
    }
    return 0;
}

void edge_linux_rseq_state_reset(struct edge_linux_rseq_state *state) {
    if (!state) return;
    state->address = 0;
    state->length = 0;
    state->signature = 0;
    state->cpu_id = 0;
    state->node_id = 0;
    state->mm_cid = 0;
    state->ids_valid = 0;
}

static int edge_linux_rseq_write_u32(
    const struct edge_linux_rseq_state *state, uint32_t offset,
    uint32_t value, edge_linux_copy_to_user_fn copy_to_user,
    void *copy_context) {
    if (!state || !state->address || !copy_to_user)
        return -EDGE_LINUX_EFAULT;
    return copy_to_user(copy_context, state->address + offset, &value,
                        sizeof(value)) < 0 ?
           -EDGE_LINUX_EFAULT : 0;
}

static int edge_linux_rseq_update_ids(
    struct edge_linux_rseq_state *state, uint32_t cpu_id,
    uint32_t node_id, uint32_t mm_cid,
    edge_linux_copy_to_user_fn copy_to_user, void *copy_context) {
    if (!state || !state->address) return 0;
    if (state->ids_valid && state->cpu_id == cpu_id &&
        state->node_id == node_id && state->mm_cid == mm_cid)
        return 0;
    if (edge_linux_rseq_write_u32(state, 0u, cpu_id, copy_to_user,
                                  copy_context) < 0 ||
        edge_linux_rseq_write_u32(state, 4u, cpu_id, copy_to_user,
                                  copy_context) < 0 ||
        edge_linux_rseq_write_u32(state, 20u, node_id, copy_to_user,
                                  copy_context) < 0 ||
        edge_linux_rseq_write_u32(state, 24u, mm_cid, copy_to_user,
                                  copy_context) < 0)
        return -EDGE_LINUX_EFAULT;
    state->cpu_id = cpu_id;
    state->node_id = node_id;
    state->mm_cid = mm_cid;
    state->ids_valid = 1;
    return 0;
}

int edge_linux_rseq_register(
    struct edge_linux_rseq_state *state, uint64_t user_address,
    uint64_t user_length, uint64_t flags, uint64_t signature,
    uint32_t cpu_id, uint32_t node_id, uint32_t mm_cid,
    edge_linux_copy_to_user_fn copy_to_user, void *copy_context) {
    uint32_t zero32 = 0;
    uint32_t uninitialized = UINT32_MAX;
    uint64_t zero64 = 0;

    if (!state || !copy_to_user) return -EDGE_LINUX_EINVAL;
    if (flags & ~EDGE_LINUX_RSEQ_FLAG_UNREGISTER)
        return -EDGE_LINUX_EINVAL;
    if (flags & EDGE_LINUX_RSEQ_FLAG_UNREGISTER) {
        if (flags != EDGE_LINUX_RSEQ_FLAG_UNREGISTER || !state->address ||
            state->address != user_address || state->length != user_length)
            return -EDGE_LINUX_EINVAL;
        if (state->signature != (uint32_t)signature)
            return -EDGE_LINUX_EPERM;
        if (copy_to_user(copy_context, user_address, &zero32,
                         sizeof(zero32)) < 0 ||
            copy_to_user(copy_context, user_address + 4u, &uninitialized,
                         sizeof(uninitialized)) < 0)
            return -EDGE_LINUX_EFAULT;
        edge_linux_rseq_state_reset(state);
        return 0;
    }
    if (state->address) {
        if (state->address != user_address || state->length != user_length)
            return -EDGE_LINUX_EINVAL;
        if (state->signature != (uint32_t)signature)
            return -EDGE_LINUX_EPERM;
        return -EDGE_LINUX_EBUSY;
    }
    if (!user_address) return -EDGE_LINUX_EFAULT;
    if (user_length != sizeof(struct edge_linux_rseq) ||
        (user_address & (EDGE_LINUX_RSEQ_ALIGN - 1u)))
        return -EDGE_LINUX_EINVAL;
    if (copy_to_user(copy_context, user_address + 8u, &zero64,
                     sizeof(zero64)) < 0 ||
        copy_to_user(copy_context, user_address + 16u, &zero32,
                     sizeof(zero32)) < 0 ||
        copy_to_user(copy_context, user_address + 20u, &zero32,
                     sizeof(zero32)) < 0 ||
        copy_to_user(copy_context, user_address + 24u, &zero32,
                     sizeof(zero32)) < 0)
        return -EDGE_LINUX_EFAULT;

    state->address = user_address;
    state->length = (uint32_t)user_length;
    state->signature = (uint32_t)signature;
    if (edge_linux_rseq_update_ids(state, cpu_id, node_id, mm_cid,
                                   copy_to_user, copy_context) < 0) {
        edge_linux_rseq_state_reset(state);
        return -EDGE_LINUX_EFAULT;
    }
    return 0;
}

int edge_linux_rseq_prepare_user_return(
    struct edge_linux_rseq_state *state, uint64_t *instruction_pointer,
    uint32_t cpu_id, uint32_t node_id, uint32_t mm_cid,
    edge_linux_copy_from_user_fn copy_from_user,
    edge_linux_copy_to_user_fn copy_to_user, void *copy_context) {
    struct edge_linux_rseq_cs critical;
    uint64_t critical_address;
    uint64_t critical_end;
    uint64_t zero = 0;
    uint32_t observed_signature;

    if (!state || !instruction_pointer || !state->address) return 0;
    if (!copy_from_user || !copy_to_user)
        return -EDGE_LINUX_EINVAL;
    if (edge_linux_rseq_update_ids(state, cpu_id, node_id, mm_cid,
                                   copy_to_user, copy_context) < 0 ||
        copy_from_user(copy_context, &critical_address,
                       state->address + 8u,
                       sizeof(critical_address)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (!critical_address) return 0;
    if (copy_from_user(copy_context, &critical, critical_address,
                       sizeof(critical)) < 0 ||
        copy_to_user(copy_context, state->address + 8u, &zero,
                     sizeof(zero)) < 0)
        return -EDGE_LINUX_EFAULT;

    critical_end = critical.start_ip + critical.post_commit_offset;
    if (critical.version != 0 || critical.flags != 0 ||
        critical_end < critical.start_ip)
        return -EDGE_LINUX_EINVAL;
    if (*instruction_pointer < critical.start_ip ||
        *instruction_pointer >= critical_end)
        return 0;
    if (critical.abort_ip < sizeof(observed_signature) ||
        copy_from_user(copy_context, &observed_signature,
                       critical.abort_ip - sizeof(observed_signature),
                       sizeof(observed_signature)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (observed_signature != state->signature)
        return -EDGE_LINUX_EINVAL;
    *instruction_pointer = critical.abort_ip;
    return 0;
}

static void edge_linux_ethtool_copy_string(char *destination,
                                           uint64_t destination_size,
                                           const char *source) {
    uint64_t index = 0;

    if (!destination || !destination_size) return;
    memset(destination, 0, destination_size);
    if (!source) return;
    while (index + 1u < destination_size && source[index]) {
        destination[index] = source[index];
        ++index;
    }
}

static void edge_linux_ethtool_fill_legacy(
    struct edge_linux_ethtool_cmd *settings,
    const struct edge_linux_netdev_info *device) {
    uint32_t speed;

    memset(settings, 0, sizeof(*settings));
    settings->cmd = EDGE_LINUX_ETHTOOL_GSET;
    speed = device->speed_mbps;
    settings->speed = (uint16_t)(speed & 0xffffu);
    settings->speed_hi = (uint16_t)(speed >> 16);
    settings->duplex = device->duplex;
    settings->port = device->port;
    settings->phy_address = device->phy_address;
    settings->autoneg = device->autoneg;
}

int edge_linux_ethtool_ioctl(
    uint64_t user_data, const struct edge_linux_netdev_info *device,
    edge_linux_copy_from_user_fn copy_from_user,
    edge_linux_copy_to_user_fn copy_to_user, void *copy_context) {
    uint32_t command;

    if (!user_data || !device || !copy_from_user || !copy_to_user)
        return -EDGE_LINUX_EFAULT;
    if (copy_from_user(copy_context, &command, user_data,
                       sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;

    if (command == EDGE_LINUX_ETHTOOL_GLINK) {
        struct edge_linux_ethtool_value value;
        value.cmd = command;
        value.data = device->link_up ? 1u : 0u;
        return copy_to_user(copy_context, user_data, &value,
                            sizeof(value)) < 0 ?
               -EDGE_LINUX_EFAULT : 0;
    }

    if (command == EDGE_LINUX_ETHTOOL_GDRVINFO) {
        struct edge_linux_ethtool_drvinfo information;
        memset(&information, 0, sizeof(information));
        information.cmd = command;
        edge_linux_ethtool_copy_string(information.driver,
                                       sizeof(information.driver),
                                       device->driver);
        edge_linux_ethtool_copy_string(information.version,
                                       sizeof(information.version),
                                       device->driver_version);
        edge_linux_ethtool_copy_string(information.bus_info,
                                       sizeof(information.bus_info),
                                       device->bus_info);
        return copy_to_user(copy_context, user_data, &information,
                            sizeof(information)) < 0 ?
               -EDGE_LINUX_EFAULT : 0;
    }

    if (command == EDGE_LINUX_ETHTOOL_GSET) {
        struct edge_linux_ethtool_cmd settings;
        edge_linux_ethtool_fill_legacy(&settings, device);
        return copy_to_user(copy_context, user_data, &settings,
                            sizeof(settings)) < 0 ?
               -EDGE_LINUX_EFAULT : 0;
    }

    if (command == EDGE_LINUX_ETHTOOL_GLINKSETTINGS) {
        struct {
            struct edge_linux_ethtool_link_settings base;
            uint32_t link_mode_masks[EDGE_LINUX_ETHTOOL_LINK_MODE_WORDS * 3];
        } settings;
        struct edge_linux_ethtool_link_settings requested;

        if (copy_from_user(copy_context, &requested, user_data,
                           sizeof(requested)) < 0)
            return -EDGE_LINUX_EFAULT;
        memset(&settings, 0, sizeof(settings));
        settings.base.cmd = command;
        if (requested.link_mode_masks_nwords == 0) {
            settings.base.link_mode_masks_nwords =
                -EDGE_LINUX_ETHTOOL_LINK_MODE_WORDS;
            return copy_to_user(copy_context, user_data, &settings.base,
                                sizeof(settings.base)) < 0 ?
                   -EDGE_LINUX_EFAULT : 0;
        }
        if (requested.link_mode_masks_nwords !=
            EDGE_LINUX_ETHTOOL_LINK_MODE_WORDS)
            return -EDGE_LINUX_EINVAL;
        settings.base.speed = device->speed_mbps;
        settings.base.duplex = device->duplex;
        settings.base.port = device->port;
        settings.base.phy_address = device->phy_address;
        settings.base.autoneg = device->autoneg;
        settings.base.link_mode_masks_nwords =
            EDGE_LINUX_ETHTOOL_LINK_MODE_WORDS;
        return copy_to_user(copy_context, user_data, &settings,
                            sizeof(settings)) < 0 ?
               -EDGE_LINUX_EFAULT : 0;
    }

    return -EDGE_LINUX_EOPNOTSUPP;
}
