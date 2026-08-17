/* SPDX-License-Identifier: MPL-2.0 */
/* Runtime adaptations that preserve imported BSD driver sources. */

#include <stdint.h>

#include "compat/freebsd/edgeos/bus_dma.h"
#include "compat/freebsd/edgeos/bus_space.h"
#include "compat/freebsd/edgeos/driver_adapters.h"
#include "compat/freebsd/edgeos/driver_hooks.h"
#include "compat/freebsd/edgeos/mfi_adapter.h"
#include "compat/freebsd/edgeos/pci.h"

#define BSD_DRIVER_ADAPTER_ENXIO 6
#define BSD_MFI_QUEUE_PORT 0x40u
#define BSD_MFI_OUTBOUND_STATUS 0x30u
#define BSD_MFI_CONTROLLER_CAPACITY 8u

typedef enum {
    BSD_MFI_POST_NONE,
    BSD_MFI_POST_XSCALE,
    BSD_MFI_POST_PPC,
} bsd_mfi_post_mode_t;

typedef struct {
    bus_space_handle_t handle;
    uint64_t reply_queue_address;
    uint64_t producer_address;
    uint64_t consumer_address;
    uint32_t reply_queue_entries;
    uint32_t interrupt_status;
    bsd_mfi_post_mode_t post_mode;
    uint8_t context64;
    uint8_t active;
} bsd_mfi_controller_t;

extern int e1000_use_pause_delay;

static volatile unsigned int g_e1000_guard;
static unsigned int g_e1000_attach_depth;
static int g_e1000_saved_pause_delay;
static volatile unsigned int g_mfi_guard;
static unsigned int g_mfi_attach_depth;
static bsd_mfi_post_mode_t g_mfi_post_mode;
static uint32_t g_mfi_interrupt_status;
static bsd_mfi_controller_t
    g_mfi_controllers[BSD_MFI_CONTROLLER_CAPACITY];
static volatile int g_adapter_state;
static int g_adapter_error;

static void
adapter_relax(void)
{
#if defined(__x86_64__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__)
    __asm__ __volatile__("yield");
#endif
}

static void
e1000_guard_lock(void)
{
    while (__atomic_test_and_set(&g_e1000_guard, __ATOMIC_ACQUIRE))
        adapter_relax();
}

static void
e1000_guard_unlock(void)
{
    __atomic_clear(&g_e1000_guard, __ATOMIC_RELEASE);
}

static void
mfi_guard_lock(void)
{
    while (__atomic_test_and_set(&g_mfi_guard, __ATOMIC_ACQUIRE))
        adapter_relax();
}

static void
mfi_guard_unlock(void)
{
    __atomic_clear(&g_mfi_guard, __ATOMIC_RELEASE);
}

static bsd_mfi_post_mode_t
mfi_post_mode_for_device(device_t device, uint32_t *interrupt_status)
{
    uint32_t identity = bsd_pci_read_config(device, 0, 4);
    uint16_t vendor = (uint16_t)(identity & 0xffffu);
    uint16_t product = (uint16_t)(identity >> 16);

    if (interrupt_status)
        *interrupt_status = 1;
    if ((vendor == 0x1000 &&
        (product == 0x0411 || product == 0x0413)) ||
        (vendor == 0x1028 && product == 0x0015)) {
        if (interrupt_status)
            *interrupt_status = 2;
        return BSD_MFI_POST_XSCALE;
    }
    if (vendor == 0x1000 &&
        (product == 0x005b || product == 0x005d || product == 0x005f)) {
        if (interrupt_status)
            *interrupt_status = 0;
        return BSD_MFI_POST_NONE;
    }
    if (vendor == 0x1000 &&
        (product == 0x0060 || product == 0x007c) &&
        interrupt_status)
        *interrupt_status = UINT32_C(0x80000000);
    return BSD_MFI_POST_PPC;
}

static int
mfi_attach_begin(device_t device, uintptr_t *cookie, void *context)
{
    bsd_mfi_post_mode_t mode;
    uint32_t interrupt_status;

    (void)context;
    mode = mfi_post_mode_for_device(device, &interrupt_status);
    mfi_guard_lock();
    if (g_mfi_attach_depth != 0 && g_mfi_post_mode != mode) {
        mfi_guard_unlock();
        return BSD_DRIVER_ADAPTER_ENXIO;
    }
    g_mfi_post_mode = mode;
    g_mfi_interrupt_status = interrupt_status;
    g_mfi_attach_depth++;
    if (cookie)
        *cookie = (uintptr_t)mode;
    mfi_guard_unlock();
    return 0;
}

static void
mfi_attach_end(device_t device, uintptr_t cookie, int result, void *context)
{
    (void)device;
    (void)cookie;
    (void)result;
    (void)context;
    mfi_guard_lock();
    if (g_mfi_attach_depth != 0 && --g_mfi_attach_depth == 0)
        g_mfi_post_mode = BSD_MFI_POST_NONE;
    mfi_guard_unlock();
}

static uint64_t
mfi_join_address(uint32_t low, uint32_t high)
{
    return (uint64_t)low | ((uint64_t)high << 32);
}

static void
mfi_controller_record(bus_space_handle_t handle,
    const bsd_mfi_init_queue_info_t *queue_info)
{
    bsd_mfi_controller_t *available = 0;

    if (!queue_info)
        return;
    mfi_guard_lock();
    for (size_t index = 0;
        index < BSD_MFI_CONTROLLER_CAPACITY; ++index) {
        bsd_mfi_controller_t *controller = &g_mfi_controllers[index];

        if (controller->active && controller->handle == handle) {
            available = controller;
            break;
        }
        if (!controller->active && !available)
            available = controller;
    }
    if (available) {
        available->handle = handle;
        available->reply_queue_address = mfi_join_address(
            queue_info->reply_queue_address_low,
            queue_info->reply_queue_address_high);
        available->producer_address = mfi_join_address(
            queue_info->producer_address_low,
            queue_info->producer_address_high);
        available->consumer_address = mfi_join_address(
            queue_info->consumer_address_low,
            queue_info->consumer_address_high);
        available->reply_queue_entries =
            queue_info->reply_queue_entries;
        available->interrupt_status = g_mfi_interrupt_status;
        available->post_mode = g_mfi_post_mode;
        available->context64 =
            (queue_info->flags & BSD_MFI_QUEUE_CONTEXT64) != 0;
        available->active = 1;
    }
    mfi_guard_unlock();
}

static int
mfi_controller_lookup(bus_space_handle_t handle,
    bsd_mfi_controller_t *controller_out)
{
    int found = 0;

    if (!controller_out)
        return -1;
    mfi_guard_lock();
    for (size_t index = 0;
        index < BSD_MFI_CONTROLLER_CAPACITY; ++index) {
        if (!g_mfi_controllers[index].active ||
            g_mfi_controllers[index].handle != handle)
            continue;
        *controller_out = g_mfi_controllers[index];
        found = 1;
        break;
    }
    mfi_guard_unlock();
    return found ? 0 : -1;
}

static void
mfi_discard_unposted_reply(bus_space_handle_t handle,
    const bsd_mfi_frame_header_t *header)
{
    bsd_mfi_controller_t controller;
    volatile uint32_t *producer;
    volatile uint32_t *consumer;
    uint64_t queued_context;
    uint32_t producer_index;
    uint32_t consumer_index;
    uint32_t next_index;
    size_t context_size;
    void *pointer;

    if (!header ||
        (header->flags & BSD_MFI_FRAME_DONT_POST) == 0 ||
        mfi_controller_lookup(handle, &controller) != 0 ||
        controller.reply_queue_entries < 2)
        return;
    if (bsd_bus_dma_virtual_address(controller.producer_address,
        sizeof(*producer), &pointer) != 0)
        return;
    producer = pointer;
    if (bsd_bus_dma_virtual_address(controller.consumer_address,
        sizeof(*consumer), &pointer) != 0)
        return;
    consumer = pointer;
    producer_index = __atomic_load_n(producer, __ATOMIC_ACQUIRE);
    consumer_index = __atomic_load_n(consumer, __ATOMIC_ACQUIRE);
    if (producer_index >= controller.reply_queue_entries ||
        consumer_index >= controller.reply_queue_entries)
        return;
    next_index = consumer_index + 1u;
    if (next_index == controller.reply_queue_entries)
        next_index = 0;
    if (producer_index != next_index)
        return;
    context_size = controller.context64 ?
        sizeof(uint64_t) : sizeof(uint32_t);
    if (bsd_bus_dma_virtual_address(
        controller.reply_queue_address +
        (uint64_t)consumer_index * context_size,
        context_size, &pointer) != 0)
        return;
    queued_context = controller.context64 ?
        __atomic_load_n((volatile uint64_t *)pointer, __ATOMIC_ACQUIRE) :
        __atomic_load_n((volatile uint32_t *)pointer, __ATOMIC_ACQUIRE);
    if (queued_context != header->context)
        return;
    /*
     * Some virtual MFI controllers post a reply even when the command sets
     * DONT_POST_IN_REPLY_QUEUE.  Consume only a single pending entry whose
     * context proves that it belongs to this synchronous command.
     */
    __atomic_store_n(consumer, producer_index, __ATOMIC_RELEASE);
}

static int
mfi_frame_address(uint64_t value, bsd_mfi_post_mode_t mode,
    uint64_t *address)
{
    if (!address)
        return -1;
    if (mode == BSD_MFI_POST_XSCALE) {
        if (value > (UINT64_MAX >> 3))
            return -1;
        *address = (value & ~UINT64_C(7)) << 3;
        return 0;
    }
    if (mode == BSD_MFI_POST_PPC) {
        *address = value & ~UINT64_C(63);
        return 0;
    }
    return -1;
}

static void
mfi_post_write(bus_space_tag_t tag, bus_space_handle_t handle,
    bus_size_t offset, unsigned int width, uint64_t value, void *context)
{
    bsd_mfi_dcmd_frame_t *frame;
    bsd_mfi_event_list_header_t *events;
    bsd_mfi_controller_t controller;
    bsd_mfi_post_mode_t mode;
    uint64_t frame_address;
    uint64_t data_address;
    uint32_t data_length;
    void *pointer;

    (void)tag;
    (void)handle;
    (void)context;
    if (width != 4 || offset != BSD_MFI_QUEUE_PORT)
        return;
    if (__atomic_load_n(&g_mfi_attach_depth, __ATOMIC_ACQUIRE) != 0)
        mode = __atomic_load_n(&g_mfi_post_mode, __ATOMIC_ACQUIRE);
    else if (mfi_controller_lookup(handle, &controller) == 0)
        mode = controller.post_mode;
    else
        return;
    if (mfi_frame_address(value, mode, &frame_address) != 0 ||
        bsd_bus_dma_virtual_address(frame_address,
            sizeof(bsd_mfi_init_frame_t), &pointer) != 0)
        return;
    frame = pointer;
    if (frame->header.cmd == BSD_MFI_CMD_INIT) {
        bsd_mfi_init_frame_t *init = pointer;
        bsd_mfi_init_queue_info_t *queue_info;
        uint64_t queue_info_address = mfi_join_address(
            init->queue_info_address_low,
            init->queue_info_address_high);

        if (bsd_bus_dma_virtual_address(queue_info_address,
            sizeof(*queue_info), &pointer) == 0) {
            queue_info = pointer;
            mfi_controller_record(handle, queue_info);
        }
        mfi_discard_unposted_reply(handle, &frame->header);
        return;
    }
    if (frame->header.cmd != BSD_MFI_CMD_DCMD) {
        mfi_discard_unposted_reply(handle, &frame->header);
        return;
    }
    if (frame->opcode == BSD_MFI_DCMD_CTRL_EVENT_GET &&
        frame->header.command_status == BSD_MFI_STAT_OK &&
        frame->header.sg_count != 0) {
        data_length = frame->header.data_length;
        if (data_length >= sizeof(*events)) {
            if ((frame->header.flags & BSD_MFI_FRAME_SGL64) != 0)
                data_address = frame->sgl.sg64[0].address;
            else
                data_address = frame->sgl.sg32[0].address;
            if (bsd_bus_dma_virtual_address(data_address,
                sizeof(*events), &pointer) == 0) {
                events = pointer;
                if (events->count == 0)
                    frame->header.command_status =
                        BSD_MFI_STAT_NOT_FOUND;
            }
        }
    }
    mfi_discard_unposted_reply(handle, &frame->header);
}

static void
mfi_post_read(bus_space_tag_t tag, bus_space_handle_t handle,
    bus_size_t offset, unsigned int width, uint64_t *value, void *context)
{
    uint64_t producer_address = 0;
    uint64_t consumer_address = 0;
    uint32_t interrupt_status = 0;
    volatile uint32_t *producer;
    volatile uint32_t *consumer;
    void *pointer;

    (void)tag;
    (void)context;
    if (!value || *value != 0 || width != 4 ||
        offset != BSD_MFI_OUTBOUND_STATUS)
        return;
    mfi_guard_lock();
    for (size_t index = 0;
        index < BSD_MFI_CONTROLLER_CAPACITY; ++index) {
        bsd_mfi_controller_t *controller = &g_mfi_controllers[index];

        if (!controller->active || controller->handle != handle)
            continue;
        producer_address = controller->producer_address;
        consumer_address = controller->consumer_address;
        interrupt_status = controller->interrupt_status;
        break;
    }
    mfi_guard_unlock();
    if (!interrupt_status ||
        bsd_bus_dma_virtual_address(producer_address,
            sizeof(*producer), &pointer) != 0)
        return;
    producer = pointer;
    if (bsd_bus_dma_virtual_address(consumer_address,
        sizeof(*consumer), &pointer) != 0)
        return;
    consumer = pointer;
    if (*producer != *consumer)
        *value = interrupt_status;
}

static int
e1000_attach_begin(device_t device, uintptr_t *cookie, void *context)
{
    (void)device;
    (void)context;
    e1000_guard_lock();
    if (g_e1000_attach_depth == 0)
        g_e1000_saved_pause_delay = e1000_use_pause_delay;
    g_e1000_attach_depth++;
    e1000_use_pause_delay = 0;
    if (cookie)
        *cookie = g_e1000_attach_depth;
    e1000_guard_unlock();
    return 0;
}

static void
e1000_attach_end(device_t device, uintptr_t cookie, int result,
    void *context)
{
    (void)device;
    (void)cookie;
    (void)result;
    (void)context;
    e1000_guard_lock();
    if (g_e1000_attach_depth != 0) {
        g_e1000_attach_depth--;
        if (g_e1000_attach_depth == 0)
            e1000_use_pause_delay = g_e1000_saved_pause_delay;
    }
    e1000_guard_unlock();
}

int
bsd_driver_adapters_initialize(void)
{
    int expected = 0;
    int state;
    int error;

    if (!__atomic_compare_exchange_n(&g_adapter_state, &expected, 1, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        do {
            state = __atomic_load_n(&g_adapter_state, __ATOMIC_ACQUIRE);
            if (state != 1)
                return state == 2 ? 0 : g_adapter_error;
            adapter_relax();
        } while (1);
    }

    error = bsd_driver_attach_hook_register("em", e1000_attach_begin,
        e1000_attach_end, 0);
    if (!error) {
        error = bsd_driver_attach_hook_register("igb",
            e1000_attach_begin, e1000_attach_end, 0);
    }
    if (!error) {
        error = bsd_driver_attach_hook_register("mfi",
            mfi_attach_begin, mfi_attach_end, 0);
    }
    if (!error)
        error = bsd_bus_space_post_write_hook_register(mfi_post_write, 0);
    if (!error)
        error = bsd_bus_space_post_read_hook_register(mfi_post_read, 0);
    if (error) {
        g_adapter_error = error > 0 ? error : BSD_DRIVER_ADAPTER_ENXIO;
        __atomic_store_n(&g_adapter_state, 3, __ATOMIC_RELEASE);
        return g_adapter_error;
    }
    __atomic_store_n(&g_adapter_state, 2, __ATOMIC_RELEASE);
    return 0;
}
