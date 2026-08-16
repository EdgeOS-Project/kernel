/* SPDX-License-Identifier: MPL-2.0 */
/* Shared network-device registry for architecture-neutral drivers. */

#include "net/netdev.h"

#include <stddef.h>
#include <stdint.h>

#define EDGE_NETDEV_EINVAL 22
#define EDGE_NETDEV_EBUSY 16
#define EDGE_NETDEV_ENOENT 2
#define EDGE_NETDEV_ENOSPC 28
#define EDGE_NETDEV_ENAMETOOLONG 63

typedef struct edge_netdev_slot {
    uint32_t generation;
    uint32_t inflight;
    uint8_t present;
    uint8_t up;
    uint8_t link_up;
    char name[EDGE_NETDEV_NAME_MAX];
    uint8_t mac[EDGE_NETDEV_MAC_LENGTH];
    uint32_t mtu;
    edge_netdev_ops_t ops;
    void *context;
    edge_netdev_receive_fn receive;
    void *receive_context;
    edge_netdev_link_fn link_change;
    void *link_change_context;
} edge_netdev_slot_t;

static edge_netdev_slot_t g_netdev_slots[EDGE_NETDEV_MAX];
static edge_netdev_handle_t g_active_netdev;
static volatile uint8_t g_netdev_lock;

static void
edge_netdev_lock(void)
{
    while (__atomic_test_and_set(&g_netdev_lock, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
edge_netdev_unlock(void)
{
    __atomic_clear(&g_netdev_lock, __ATOMIC_RELEASE);
}

static size_t
edge_netdev_name_length(const char *name)
{
    size_t length = 0;

    if (!name)
        return 0;
    while (length < EDGE_NETDEV_NAME_MAX && name[length])
        length++;
    return length;
}

static void
edge_netdev_copy(void *destination, const void *source, size_t length)
{
    uint8_t *out = destination;
    const uint8_t *in = source;

    while (length--)
        *out++ = *in++;
}

static void
edge_netdev_zero(void *destination, size_t length)
{
    uint8_t *out = destination;

    while (length--)
        *out++ = 0;
}

static edge_netdev_handle_t
edge_netdev_make_handle(size_t index, uint32_t generation)
{
    return ((uint64_t)generation << 32) | (uint64_t)(index + 1u);
}

static edge_netdev_slot_t *
edge_netdev_find_locked(edge_netdev_handle_t handle, size_t *index_out)
{
    uint32_t low = (uint32_t)handle;
    uint32_t generation = (uint32_t)(handle >> 32);
    size_t index;
    edge_netdev_slot_t *slot;

    if (low == 0 || low > EDGE_NETDEV_MAX || generation == 0)
        return 0;
    index = (size_t)(low - 1u);
    slot = &g_netdev_slots[index];
    if (!slot->present || slot->generation != generation)
        return 0;
    if (index_out)
        *index_out = index;
    return slot;
}

int
edge_netdev_register(const edge_netdev_config_t *config,
    edge_netdev_handle_t *handle)
{
    size_t name_length;
    size_t free_index = EDGE_NETDEV_MAX;
    edge_netdev_slot_t *slot;

    if (handle)
        *handle = 0;
    if (!config || !handle || !config->name || !config->ops.transmit ||
        config->mtu == 0 || config->mtu > EDGE_NETDEV_FRAME_MAX)
        return EDGE_NETDEV_EINVAL;
    name_length = edge_netdev_name_length(config->name);
    if (name_length == 0)
        return EDGE_NETDEV_EINVAL;
    if (name_length == EDGE_NETDEV_NAME_MAX)
        return EDGE_NETDEV_ENAMETOOLONG;

    edge_netdev_lock();
    for (size_t index = 0; index < EDGE_NETDEV_MAX; ++index) {
        if (g_netdev_slots[index].present) {
            size_t current_length =
                edge_netdev_name_length(g_netdev_slots[index].name);
            if (current_length == name_length) {
                size_t offset;

                for (offset = 0; offset < name_length; ++offset) {
                    if (g_netdev_slots[index].name[offset] !=
                        config->name[offset])
                        break;
                }
                if (offset == name_length) {
                    edge_netdev_unlock();
                    return EDGE_NETDEV_EBUSY;
                }
            }
        } else if (free_index == EDGE_NETDEV_MAX) {
            free_index = index;
        }
    }
    if (free_index == EDGE_NETDEV_MAX) {
        edge_netdev_unlock();
        return EDGE_NETDEV_ENOSPC;
    }

    slot = &g_netdev_slots[free_index];
    {
        uint32_t generation = slot->generation + 1u;

        if (generation == 0)
            generation = 1;
        edge_netdev_zero(slot, sizeof(*slot));
        slot->generation = generation;
    }
    edge_netdev_copy(slot->name, config->name, name_length);
    slot->name[name_length] = 0;
    edge_netdev_copy(slot->mac, config->mac, sizeof(slot->mac));
    slot->mtu = config->mtu;
    slot->link_up = config->link_up ? 1u : 0u;
    slot->ops = config->ops;
    slot->context = config->context;
    slot->present = 1;
    *handle = edge_netdev_make_handle(free_index, slot->generation);
    if (g_active_netdev == 0)
        g_active_netdev = *handle;
    edge_netdev_unlock();
    return 0;
}

int
edge_netdev_unregister(edge_netdev_handle_t handle)
{
    edge_netdev_slot_t *slot;

    edge_netdev_lock();
    slot = edge_netdev_find_locked(handle, 0);
    if (!slot) {
        edge_netdev_unlock();
        return EDGE_NETDEV_ENOENT;
    }
    if (slot->inflight != 0 || slot->up) {
        edge_netdev_unlock();
        return EDGE_NETDEV_EBUSY;
    }
    edge_netdev_zero(&slot->ops, sizeof(slot->ops));
    slot->context = 0;
    slot->receive = 0;
    slot->receive_context = 0;
    slot->link_change = 0;
    slot->link_change_context = 0;
    slot->present = 0;
    slot->link_up = 0;
    slot->name[0] = 0;
    if (g_active_netdev == handle) {
        g_active_netdev = 0;
        for (size_t index = 0; index < EDGE_NETDEV_MAX; ++index) {
            if (g_netdev_slots[index].present) {
                g_active_netdev = edge_netdev_make_handle(index,
                    g_netdev_slots[index].generation);
                break;
            }
        }
    }
    edge_netdev_unlock();
    return 0;
}

int
edge_netdev_set_active(edge_netdev_handle_t handle)
{
    edge_netdev_lock();
    if (!edge_netdev_find_locked(handle, 0)) {
        edge_netdev_unlock();
        return EDGE_NETDEV_ENOENT;
    }
    g_active_netdev = handle;
    edge_netdev_unlock();
    return 0;
}

edge_netdev_handle_t
edge_netdev_get_active(void)
{
    edge_netdev_handle_t handle;

    edge_netdev_lock();
    handle = g_active_netdev;
    edge_netdev_unlock();
    return handle;
}

int
edge_netdev_set_receive_callback(edge_netdev_handle_t handle,
    edge_netdev_receive_fn callback, void *context)
{
    edge_netdev_slot_t *slot;

    edge_netdev_lock();
    slot = edge_netdev_find_locked(handle, 0);
    if (!slot) {
        edge_netdev_unlock();
        return EDGE_NETDEV_ENOENT;
    }
    slot->receive = callback;
    slot->receive_context = context;
    edge_netdev_unlock();
    return 0;
}

int
edge_netdev_set_link_callback(edge_netdev_handle_t handle,
    edge_netdev_link_fn callback, void *context)
{
    edge_netdev_slot_t *slot;
    int link_up = 0;

    edge_netdev_lock();
    slot = edge_netdev_find_locked(handle, 0);
    if (!slot) {
        edge_netdev_unlock();
        return EDGE_NETDEV_ENOENT;
    }
    slot->link_change = callback;
    slot->link_change_context = callback ? context : 0;
    if (callback) {
        slot->inflight++;
        link_up = slot->link_up ? 1 : 0;
    }
    edge_netdev_unlock();

    if (callback) {
        callback(link_up, context);
        edge_netdev_lock();
        slot = edge_netdev_find_locked(handle, 0);
        if (slot && slot->inflight != 0)
            slot->inflight--;
        edge_netdev_unlock();
    }
    return 0;
}

int
edge_netdev_receive(edge_netdev_handle_t handle, const void *frame,
    uint32_t length)
{
    edge_netdev_slot_t *slot;
    edge_netdev_receive_fn receive;
    void *context;

    if (!frame || length == 0 || length > EDGE_NETDEV_FRAME_MAX)
        return EDGE_NETDEV_EINVAL;
    edge_netdev_lock();
    slot = edge_netdev_find_locked(handle, 0);
    if (!slot || !slot->up || !slot->link_up || !slot->receive) {
        edge_netdev_unlock();
        return EDGE_NETDEV_ENOENT;
    }
    slot->inflight++;
    receive = slot->receive;
    context = slot->receive_context;
    edge_netdev_unlock();

    receive(frame, length, context);

    edge_netdev_lock();
    slot = edge_netdev_find_locked(handle, 0);
    if (slot && slot->inflight != 0)
        slot->inflight--;
    edge_netdev_unlock();
    return 0;
}

int
edge_netdev_transmit(edge_netdev_handle_t handle, const void *frame,
    uint32_t length)
{
    edge_netdev_slot_t *slot;
    int (*transmit)(void *, const void *, uint32_t);
    void *context;
    int result;

    if (!frame || length == 0 || length > EDGE_NETDEV_FRAME_MAX)
        return -EDGE_NETDEV_EINVAL;
    edge_netdev_lock();
    slot = edge_netdev_find_locked(handle, 0);
    if (!slot || !slot->up || !slot->link_up) {
        edge_netdev_unlock();
        return -EDGE_NETDEV_ENOENT;
    }
    slot->inflight++;
    transmit = slot->ops.transmit;
    context = slot->context;
    edge_netdev_unlock();

    result = transmit(context, frame, length);

    edge_netdev_lock();
    slot = edge_netdev_find_locked(handle, 0);
    if (slot && slot->inflight != 0)
        slot->inflight--;
    edge_netdev_unlock();
    return result;
}

void
edge_netdev_poll(edge_netdev_handle_t handle)
{
    edge_netdev_slot_t *slot;
    void (*poll)(void *);
    void *context;

    edge_netdev_lock();
    slot = edge_netdev_find_locked(handle, 0);
    if (!slot || !slot->ops.poll) {
        edge_netdev_unlock();
        return;
    }
    slot->inflight++;
    poll = slot->ops.poll;
    context = slot->context;
    edge_netdev_unlock();

    poll(context);

    edge_netdev_lock();
    slot = edge_netdev_find_locked(handle, 0);
    if (slot && slot->inflight != 0)
        slot->inflight--;
    edge_netdev_unlock();
}

int
edge_netdev_set_up(edge_netdev_handle_t handle, int up)
{
    edge_netdev_slot_t *slot;
    int (*set_up)(void *, int);
    void *context;
    int result = 0;

    edge_netdev_lock();
    slot = edge_netdev_find_locked(handle, 0);
    if (!slot) {
        edge_netdev_unlock();
        return EDGE_NETDEV_ENOENT;
    }
    if (slot->up == (up ? 1u : 0u)) {
        edge_netdev_unlock();
        return 0;
    }
    if (!slot->ops.set_up) {
        slot->up = up ? 1u : 0u;
        edge_netdev_unlock();
        return 0;
    }
    slot->inflight++;
    set_up = slot->ops.set_up;
    context = slot->context;
    edge_netdev_unlock();

    result = set_up(context, up ? 1 : 0);

    edge_netdev_lock();
    slot = edge_netdev_find_locked(handle, 0);
    if (slot) {
        if (slot->inflight != 0)
            slot->inflight--;
        if (result == 0)
            slot->up = up ? 1u : 0u;
    }
    edge_netdev_unlock();
    return result;
}

int
edge_netdev_set_link(edge_netdev_handle_t handle, int link_up)
{
    edge_netdev_slot_t *slot;
    edge_netdev_link_fn callback = 0;
    void *context = 0;
    int selected = link_up ? 1 : 0;

    edge_netdev_lock();
    slot = edge_netdev_find_locked(handle, 0);
    if (!slot) {
        edge_netdev_unlock();
        return EDGE_NETDEV_ENOENT;
    }
    if (slot->link_up != (uint8_t)selected) {
        slot->link_up = (uint8_t)selected;
        callback = slot->link_change;
        context = slot->link_change_context;
        if (callback)
            slot->inflight++;
    }
    edge_netdev_unlock();

    if (callback) {
        callback(selected, context);
        edge_netdev_lock();
        slot = edge_netdev_find_locked(handle, 0);
        if (slot && slot->inflight != 0)
            slot->inflight--;
        edge_netdev_unlock();
    }
    return 0;
}

int
edge_netdev_get_info(edge_netdev_handle_t handle, char *name,
    size_t name_size, uint8_t mac[EDGE_NETDEV_MAC_LENGTH], uint32_t *mtu,
    int *link_up, int *up)
{
    edge_netdev_slot_t *slot;
    size_t length;

    edge_netdev_lock();
    slot = edge_netdev_find_locked(handle, 0);
    if (!slot) {
        edge_netdev_unlock();
        return EDGE_NETDEV_ENOENT;
    }
    length = edge_netdev_name_length(slot->name);
    if (name) {
        if (name_size <= length) {
            edge_netdev_unlock();
            return EDGE_NETDEV_ENOSPC;
        }
        edge_netdev_copy(name, slot->name, length + 1u);
    }
    if (mac)
        edge_netdev_copy(mac, slot->mac, EDGE_NETDEV_MAC_LENGTH);
    if (mtu)
        *mtu = slot->mtu;
    if (link_up)
        *link_up = slot->link_up ? 1 : 0;
    if (up)
        *up = slot->up ? 1 : 0;
    edge_netdev_unlock();
    return 0;
}

int
edge_netdev_snapshot(edge_netdev_handle_t *handles, size_t capacity,
    size_t *count)
{
    size_t found = 0;

    if (!count || (!handles && capacity != 0))
        return EDGE_NETDEV_EINVAL;
    edge_netdev_lock();
    for (size_t index = 0; index < EDGE_NETDEV_MAX; ++index) {
        if (!g_netdev_slots[index].present)
            continue;
        if (found < capacity)
            handles[found] = edge_netdev_make_handle(index,
                g_netdev_slots[index].generation);
        found++;
    }
    edge_netdev_unlock();
    *count = found;
    return found <= capacity ? 0 : EDGE_NETDEV_ENOSPC;
}

int
edge_netdev_count(void)
{
    int count = 0;

    edge_netdev_lock();
    for (size_t index = 0; index < EDGE_NETDEV_MAX; ++index) {
        if (g_netdev_slots[index].present)
            count++;
    }
    edge_netdev_unlock();
    return count;
}
