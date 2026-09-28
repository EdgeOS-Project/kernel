/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for BSD driver family runtime adapters. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "compat/freebsd/edgeos/driver_adapters.h"
#include "compat/freebsd/edgeos/driver_hooks.h"
#include "compat/freebsd/edgeos/bus_space.h"
#include "compat/freebsd/edgeos/mfi_adapter.h"

typedef struct test_hook {
    const char *name;
    bsd_driver_attach_begin_t begin;
    bsd_driver_attach_end_t end;
    void *context;
} test_hook_t;

int e1000_use_pause_delay = 1;

static test_hook_t g_hooks[3];
static size_t g_hook_count;
static bsd_bus_space_post_write_fn g_post_write;
static void *g_post_write_context;
static bsd_bus_space_post_read_fn g_post_read;
static void *g_post_read_context;
static union {
    bsd_mfi_dcmd_frame_t dcmd;
    bsd_mfi_init_frame_t init;
} g_test_frame;
static bsd_mfi_event_list_header_t g_test_events;
static bsd_mfi_init_queue_info_t g_test_queue_info;
static uint32_t g_test_reply_queue[4];
static uint32_t g_test_producer;
static uint32_t g_test_consumer;

#define TEST_FRAME_PHYSICAL UINT64_C(0x100000)
#define TEST_EVENTS_PHYSICAL UINT64_C(0x200000)
#define TEST_QUEUE_INFO_PHYSICAL UINT64_C(0x300000)
#define TEST_PRODUCER_PHYSICAL UINT64_C(0x400000)
#define TEST_CONSUMER_PHYSICAL UINT64_C(0x500000)
#define TEST_REPLY_QUEUE_PHYSICAL UINT64_C(0x600000)

int
bsd_driver_attach_hook_register(const char *driver_name,
    bsd_driver_attach_begin_t begin, bsd_driver_attach_end_t end,
    void *context)
{
    assert(driver_name != 0);
    assert(begin != 0);
    assert(end != 0);
    assert(g_hook_count < sizeof(g_hooks) / sizeof(g_hooks[0]));
    g_hooks[g_hook_count++] = (test_hook_t) {
        .name = driver_name,
        .begin = begin,
        .end = end,
        .context = context,
    };
    return 0;
}

int
bsd_bus_space_post_read_hook_register(
    bsd_bus_space_post_read_fn function, void *context)
{
    assert(function != 0);
    g_post_read = function;
    g_post_read_context = context;
    return 0;
}

int
bsd_bus_space_post_write_hook_register(
    bsd_bus_space_post_write_fn function, void *context)
{
    assert(function != 0);
    g_post_write = function;
    g_post_write_context = context;
    return 0;
}

int
bsd_bus_dma_virtual_address(uint64_t physical_address, size_t length,
    void **virtual_address)
{
    assert(length != 0);
    assert(virtual_address != 0);
    if (physical_address == TEST_FRAME_PHYSICAL)
        *virtual_address = &g_test_frame;
    else if (physical_address == TEST_EVENTS_PHYSICAL)
        *virtual_address = &g_test_events;
    else if (physical_address == TEST_QUEUE_INFO_PHYSICAL)
        *virtual_address = &g_test_queue_info;
    else if (physical_address == TEST_PRODUCER_PHYSICAL)
        *virtual_address = &g_test_producer;
    else if (physical_address == TEST_CONSUMER_PHYSICAL)
        *virtual_address = &g_test_consumer;
    else if (physical_address >= TEST_REPLY_QUEUE_PHYSICAL &&
        physical_address + length <= TEST_REPLY_QUEUE_PHYSICAL +
        sizeof(g_test_reply_queue))
        *virtual_address = (uint8_t *)g_test_reply_queue +
            (physical_address - TEST_REPLY_QUEUE_PHYSICAL);
    else
        return -1;
    return 0;
}

uint32_t
bsd_pci_read_config(device_t device, int register_offset, int width)
{
    assert(register_offset == 0);
    assert(width == 4);
    return (uint32_t)(uintptr_t)device;
}

int
main(void)
{
    uintptr_t em_cookie = 0;
    uintptr_t igb_cookie = 0;
    uintptr_t mfi_cookie = 0;
    device_t mfi_device =
        (device_t)(uintptr_t)UINT32_C(0x00601000);

    assert(bsd_driver_adapters_initialize() == 0);
    assert(bsd_driver_adapters_initialize() == 0);
    assert(g_hook_count == 3);
    assert(strcmp(g_hooks[0].name, "em") == 0);
    assert(strcmp(g_hooks[1].name, "igb") == 0);
    assert(strcmp(g_hooks[2].name, "mfi") == 0);
    assert(g_post_write != 0);
    assert(g_post_read != 0);

    assert(g_hooks[0].begin((device_t)(uintptr_t)1, &em_cookie,
        g_hooks[0].context) == 0);
    assert(e1000_use_pause_delay == 0);
    assert(em_cookie == 1);
    assert(g_hooks[1].begin((device_t)(uintptr_t)2, &igb_cookie,
        g_hooks[1].context) == 0);
    assert(e1000_use_pause_delay == 0);
    assert(igb_cookie == 2);
    g_hooks[0].end((device_t)(uintptr_t)1, em_cookie, 0,
        g_hooks[0].context);
    assert(e1000_use_pause_delay == 0);
    g_hooks[1].end((device_t)(uintptr_t)2, igb_cookie, 5,
        g_hooks[1].context);
    assert(e1000_use_pause_delay == 1);

    e1000_use_pause_delay = 0;
    assert(g_hooks[0].begin((device_t)(uintptr_t)3, &em_cookie,
        g_hooks[0].context) == 0);
    g_hooks[0].end((device_t)(uintptr_t)3, em_cookie, 0,
        g_hooks[0].context);
    assert(e1000_use_pause_delay == 0);

    memset(&g_test_frame, 0, sizeof(g_test_frame));
    memset(&g_test_events, 0, sizeof(g_test_events));
    memset(&g_test_queue_info, 0, sizeof(g_test_queue_info));
    g_test_frame.init.header.cmd = BSD_MFI_CMD_INIT;
    g_test_frame.init.header.flags = BSD_MFI_FRAME_DONT_POST;
    g_test_frame.init.header.context = 7;
    g_test_frame.init.queue_info_address_low =
        TEST_QUEUE_INFO_PHYSICAL;
    g_test_queue_info.reply_queue_entries = 4;
    g_test_queue_info.reply_queue_address_low =
        TEST_REPLY_QUEUE_PHYSICAL;
    g_test_queue_info.producer_address_low = TEST_PRODUCER_PHYSICAL;
    g_test_queue_info.consumer_address_low = TEST_CONSUMER_PHYSICAL;
    g_test_producer = 1;
    g_test_consumer = 0;
    g_test_reply_queue[0] = 7;
    assert(g_hooks[2].begin(mfi_device, &mfi_cookie,
        g_hooks[2].context) == 0);
    g_post_write(0, 0x600000, 0x40, 4, TEST_FRAME_PHYSICAL | 1,
        g_post_write_context);
    assert(g_test_consumer == 1);
    g_test_producer = 1;
    g_test_consumer = 0;
    {
        uint64_t status = 0;

        g_post_read(0, 0x600000, 0x30, 4, &status,
            g_post_read_context);
        assert(status == UINT32_C(0x80000000));
    }

    memset(&g_test_frame, 0, sizeof(g_test_frame));
    g_test_frame.dcmd.header.cmd = BSD_MFI_CMD_DCMD;
    g_test_frame.dcmd.header.flags = BSD_MFI_FRAME_DONT_POST |
        BSD_MFI_FRAME_SGL64;
    g_test_frame.dcmd.header.context = 9;
    g_test_frame.dcmd.header.command_status = BSD_MFI_STAT_OK;
    g_test_frame.dcmd.header.sg_count = 1;
    g_test_frame.dcmd.header.data_length = sizeof(g_test_events);
    g_test_frame.dcmd.opcode = BSD_MFI_DCMD_CTRL_EVENT_GET;
    g_test_frame.dcmd.sgl.sg64[0].address = TEST_EVENTS_PHYSICAL;
    g_test_frame.dcmd.sgl.sg64[0].length = sizeof(g_test_events);
    g_test_producer = 2;
    g_test_consumer = 1;
    g_test_reply_queue[1] = 9;
    g_post_write(0, 0x600000, 0x40, 4, TEST_FRAME_PHYSICAL | 1,
        g_post_write_context);
    assert(g_test_frame.dcmd.header.command_status ==
        BSD_MFI_STAT_NOT_FOUND);
    assert(g_test_consumer == 2);

    g_test_frame.dcmd.header.command_status = BSD_MFI_STAT_OK;
    g_test_events.count = 1;
    g_test_producer = 3;
    g_test_consumer = 2;
    g_test_reply_queue[2] = 8;
    g_post_write(0, 0x600000, 0x40, 4, TEST_FRAME_PHYSICAL | 1,
        g_post_write_context);
    assert(g_test_frame.dcmd.header.command_status == BSD_MFI_STAT_OK);
    assert(g_test_consumer == 2);
    g_hooks[2].end(mfi_device, mfi_cookie, 0, g_hooks[2].context);

    g_test_events.count = 0;
    g_test_frame.dcmd.header.command_status = BSD_MFI_STAT_OK;
    g_post_write(0, 0, 0x40, 4, TEST_FRAME_PHYSICAL | 1,
        g_post_write_context);
    assert(g_test_frame.dcmd.header.command_status == BSD_MFI_STAT_OK);

    puts("bsd_bridge_driver_adapters_unit: PASS");
    return 0;
}
