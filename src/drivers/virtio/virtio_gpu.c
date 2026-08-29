/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * VirtIO GPU protocol definitions in this file are derived from FreeBSD
 * sys/dev/virtio/gpu/virtio_gpu.h.
 *
 * Copyright Red Hat, Inc. 2013-2014
 *
 * Authors:
 *     Dave Airlie <airlied@redhat.com>
 *     Gerd Hoffmann <kraxel@redhat.com>
 *
 * This header is BSD licensed so anyone can use the definitions
 * to implement compatible drivers/servers:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The EdgeOS transport/initialization glue is original EdgeOS code using the
 * existing in-tree VirtIO block/network driver style.  FreeBSD's
 * sys/dev/virtio/gpu/virtio_gpu.c was used as the BSD implementation reference
 * for the display init sequence: GET_DISPLAY_INFO, RESOURCE_CREATE_2D,
 * RESOURCE_ATTACH_BACKING, SET_SCANOUT, TRANSFER_TO_HOST_2D, RESOURCE_FLUSH.
 *
 * Modifications for EdgeOS.
 * Copyright (c) EdgeOS Contributors.
 */

#include "drivers/virtio_gpu.h"
#include "drivers/virtio_gpu_damage.h"
#include "drivers/virtio_gpu_sync.h"
#if defined(__x86_64__)
#include "arch/x86_64/isr.h"
#include "arch/x86_64/pic.h"
#include "drivers/pci.h"
#include "drivers/apic.h"
#include "arch/x86_64/io_ports.h"
#elif defined(__aarch64__)
#include "arch/arm64/bootinfo.h"
#include "arch/arm64/interrupt.h"
#include "drivers/virtio_net_mmio.h"
#endif
#include "kernel/boot_command_line.h"
#include "kernel/deferred_work.h"
#include "kernel/process_runtime.h"
#include "kernel/virtgpu_runtime.h"
#include "mm/arch_vm.h"

#include "display.h"
#include "fb.h"
#include "serial_console.h"
#include "stdio.h"
#include "string.h"
#include "sys/boottime.h"
#include "sys/mmio.h"
#include "sys/spinlock.h"

#define VIRTIO_PCI_VENDORID 0x1AF4u
#define VIRTIO_PCI_DEVICEID_GPU_LEGACY 0x1010u
#define VIRTIO_PCI_DEVICEID_MODERN_GPU 0x1050u

#define PCI_COMMAND_MEM 0x0002u
#define PCI_COMMAND_BUSMASTER 0x0004u
#define PCI_STATUS_CAP_LIST 0x0010u
#define PCI_CAP_ID_VENDOR 0x09u

#define VIRTIO_CONFIG_STATUS_RESET       0x00u
#define VIRTIO_CONFIG_STATUS_ACK         0x01u
#define VIRTIO_CONFIG_STATUS_DRIVER      0x02u
#define VIRTIO_CONFIG_STATUS_DRIVER_OK   0x04u
#define VIRTIO_CONFIG_STATUS_FEATURES_OK 0x08u
#define VIRTIO_CONFIG_STATUS_FAILED      0x80u

#define VIRTIO_F_VERSION_1 (1ull << 32)
#define VIRTIO_GPU_F_VIRGL         (1ull << 0)
#define VIRTIO_GPU_F_EDID          (1ull << 1)
#define VIRTIO_GPU_F_RESOURCE_UUID (1ull << 2)
#define VIRTIO_GPU_F_RESOURCE_BLOB (1ull << 3)
#define VIRTIO_GPU_F_CONTEXT_INIT  (1ull << 4)

#define VIRTIO_PCI_CAP_COMMON_CFG 1u
#define VIRTIO_PCI_CAP_NOTIFY_CFG 2u
#define VIRTIO_PCI_CAP_ISR_CFG    3u
#define VIRTIO_PCI_CAP_DEVICE_CFG 4u

#define VIRTIO_PCI_CAP_VNDR       0u
#define VIRTIO_PCI_CAP_NEXT       1u
#define VIRTIO_PCI_CAP_LEN        2u
#define VIRTIO_PCI_CAP_CFG_TYPE   3u
#define VIRTIO_PCI_CAP_BAR        4u
#define VIRTIO_PCI_CAP_OFFSET     8u
#define VIRTIO_PCI_CAP_LENGTH     12u
#define VIRTIO_PCI_NOTIFY_CAP_MULT 16u

#define VIRTIO_PCI_COMMON_DFSELECT      0u
#define VIRTIO_PCI_COMMON_DF            4u
#define VIRTIO_PCI_COMMON_GFSELECT      8u
#define VIRTIO_PCI_COMMON_GF            12u
#define VIRTIO_PCI_COMMON_MSIX_CONFIG   16u
#define VIRTIO_PCI_COMMON_NUMQ          18u
#define VIRTIO_PCI_COMMON_STATUS        20u
#define VIRTIO_PCI_COMMON_CFGGENERATION 21u
#define VIRTIO_PCI_COMMON_Q_SELECT      22u
#define VIRTIO_PCI_COMMON_Q_SIZE        24u
#define VIRTIO_PCI_COMMON_Q_MSIX_VECTOR 26u
#define VIRTIO_PCI_COMMON_Q_ENABLE      28u
#define VIRTIO_PCI_COMMON_Q_NOFF        30u
#define VIRTIO_PCI_COMMON_Q_DESCLO      32u
#define VIRTIO_PCI_COMMON_Q_DESCHI      36u
#define VIRTIO_PCI_COMMON_Q_AVAILLO     40u
#define VIRTIO_PCI_COMMON_Q_AVAILHI     44u
#define VIRTIO_PCI_COMMON_Q_USEDLO      48u
#define VIRTIO_PCI_COMMON_Q_USEDHI      52u

#define VIRTIO_PCI_VRING_ALIGN 4096u
#define VIRTIO_MODERN_COMMON_MIN_SIZE 56u
#define VIRTIO_MODERN_NOTIFY_MIN_SIZE 2u
#define VIRTIO_MODERN_ISR_MIN_SIZE 1u

#define VIRTIO_MMIO_MAGIC_VALUE         0x74726976u
#define VIRTIO_MMIO_VERSION_MODERN      2u
#define VIRTIO_MMIO_DEVICE_ID_GPU       16u
#define VIRTIO_MMIO_MAGIC               0x000u
#define VIRTIO_MMIO_VERSION             0x004u
#define VIRTIO_MMIO_DEVICE_ID           0x008u
#define VIRTIO_MMIO_DEVICE_FEATURES     0x010u
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL 0x014u
#define VIRTIO_MMIO_DRIVER_FEATURES     0x020u
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL 0x024u
#define VIRTIO_MMIO_QUEUE_SEL           0x030u
#define VIRTIO_MMIO_QUEUE_NUM_MAX       0x034u
#define VIRTIO_MMIO_QUEUE_NUM           0x038u
#define VIRTIO_MMIO_QUEUE_READY         0x044u
#define VIRTIO_MMIO_QUEUE_NOTIFY        0x050u
#define VIRTIO_MMIO_INTERRUPT_STATUS    0x060u
#define VIRTIO_MMIO_INTERRUPT_ACK       0x064u
#define VIRTIO_MMIO_STATUS              0x070u
#define VIRTIO_MMIO_QUEUE_DESC_LOW      0x080u
#define VIRTIO_MMIO_QUEUE_DESC_HIGH     0x084u
#define VIRTIO_MMIO_QUEUE_AVAIL_LOW     0x090u
#define VIRTIO_MMIO_QUEUE_AVAIL_HIGH    0x094u
#define VIRTIO_MMIO_QUEUE_USED_LOW      0x0a0u
#define VIRTIO_MMIO_QUEUE_USED_HIGH     0x0a4u
#define VIRTIO_MMIO_CONFIG_GENERATION   0x0fcu
#define VIRTIO_MMIO_CONFIG              0x100u

#define VRING_DESC_F_NEXT  1u
#define VRING_DESC_F_WRITE 2u

#define VIRTIO_GPU_CTRL_QUEUE 0u
#define VIRTIO_GPU_CURSOR_QUEUE 1u
#define VIRTIO_MSI_NO_VECTOR 0xffffu
#define VIRTIO_GPU_QUEUE_SIZE 64u
#define VIRTIO_GPU_CURSOR_QUEUE_SIZE 16u
#define VIRTIO_GPU_RING_BYTES 16384u
#define VIRTIO_GPU_RESOURCE_ID 1u
#define VIRTIO_GPU_FB_MAX_WIDTH 7680u
#define VIRTIO_GPU_FB_MAX_HEIGHT 4320u
#define VIRTIO_GPU_BOOT_FB_WIDTH 1920u
#define VIRTIO_GPU_BOOT_FB_HEIGHT 1080u
#define VIRTIO_GPU_BOOT_FB_BYTES \
    (VIRTIO_GPU_BOOT_FB_WIDTH * VIRTIO_GPU_BOOT_FB_HEIGHT * 4u)
#define VIRTIO_GPU_PAGE_SIZE 4096u
#define VIRTIO_GPU_PRESENT_BATCH_RECTS 8u
#define VIRTIO_GPU_PRESENT_INFLIGHT_SLOTS 2u
#define VIRTIO_GPU_PRESENT_PENDING_SLOT 2u
#define VIRTIO_GPU_PRESENT_SLOT_COUNT 3u
#define VIRTIO_GPU_PRESENT_DESC_FIRST 4u
#define VIRTIO_GPU_PRESENT_DESC_COUNT 18u
#define VIRTIO_GPU_PRESENT_TIMEOUT_US 250000u
#define VIRTIO_GPU_SYNC_TIMEOUT_US 5000000u
#define VIRTIO_GPU_SYNC_POLL_US 1000u
#define VIRTIO_GPU_RENDER_DESC_FIRST 40u
#define VIRTIO_GPU_RENDER_SLOT_COUNT 8u
#define VIRTIO_GPU_RENDER_PENDING_COUNT 256u
#define VIRTIO_GPU_RENDER_DESC_COUNT 3u
#define VIRTIO_GPU_SYNC_REQUEST_BYTES 256u
#define VIRTIO_GPU_SYNC_SECONDARY_BYTES 4096u
#define VIRTIO_GPU_SYNC_RESPONSE_BYTES \
    (sizeof(struct virtio_gpu_ctrl_hdr) + VIRTIO_GPU_CAPSET_MAX_SIZE)
#define VIRTIO_GPU_CURSOR_RESOURCE_ID 0xfffffffeu
#define VIRTIO_GPU_CURSOR_WIDTH 64u
#define VIRTIO_GPU_CURSOR_HEIGHT 64u
#define VIRTIO_GPU_CURSOR_BYTES \
    (VIRTIO_GPU_CURSOR_WIDTH * VIRTIO_GPU_CURSOR_HEIGHT * 4u)
#define VIRTIO_GPU_CURSOR_SLOT_COUNT 16u

#define VIRTIO_GPU_FLAG_FENCE (1u << 0)
#define VIRTIO_GPU_EVENT_DISPLAY                  (1u << 0)
#define VIRTIO_GPU_CMD_GET_DISPLAY_INFO       0x0100u
#define VIRTIO_GPU_CMD_RESOURCE_CREATE_2D     0x0101u
#define VIRTIO_GPU_CMD_RESOURCE_UNREF          0x0102u
#define VIRTIO_GPU_CMD_SET_SCANOUT            0x0103u
#define VIRTIO_GPU_CMD_RESOURCE_FLUSH         0x0104u
#define VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D    0x0105u
#define VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING 0x0106u
#define VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING 0x0107u
#define VIRTIO_GPU_CMD_GET_CAPSET_INFO        0x0108u
#define VIRTIO_GPU_CMD_GET_CAPSET             0x0109u
#define VIRTIO_GPU_CMD_GET_EDID               0x010au
#define VIRTIO_GPU_CMD_CTX_CREATE             0x0200u
#define VIRTIO_GPU_CMD_CTX_DESTROY            0x0201u
#define VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE    0x0202u
#define VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE    0x0203u
#define VIRTIO_GPU_CMD_RESOURCE_CREATE_3D     0x0204u
#define VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D    0x0205u
#define VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D  0x0206u
#define VIRTIO_GPU_CMD_SUBMIT_3D              0x0207u
#define VIRTIO_GPU_CMD_UPDATE_CURSOR          0x0300u
#define VIRTIO_GPU_CMD_MOVE_CURSOR            0x0301u
#define VIRTIO_GPU_RESP_OK_NODATA             0x1100u
#define VIRTIO_GPU_RESP_OK_DISPLAY_INFO       0x1101u
#define VIRTIO_GPU_RESP_OK_CAPSET_INFO        0x1102u
#define VIRTIO_GPU_RESP_OK_CAPSET             0x1103u
#define VIRTIO_GPU_RESP_OK_EDID               0x1104u

#define VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM 2u
#define VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM 1u
#define VIRTIO_GPU_MAX_SCANOUTS 16u
#define VIRTIO_GPU_CAPSET_VIRGL 1u
#define VIRTIO_GPU_CAPSET_VIRGL2 2u
#define VIRTIO_GPU_CAPSET_COUNT 8u
#define VIRTIO_GPU_CAPSET_MAX_SIZE (256u * 1024u)

struct vring_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed));

struct vring_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[];
} __attribute__((packed));

struct vring_used_elem {
    uint32_t id;
    uint32_t len;
} __attribute__((packed));

struct vring_used {
    uint16_t flags;
    uint16_t idx;
    struct vring_used_elem ring[];
} __attribute__((packed));

struct virtio_gpu_ctrl_hdr {
    uint32_t type;
    uint32_t flags;
    uint64_t fence_id;
    uint32_t ctx_id;
    uint8_t ring_idx;
    uint8_t padding[3];
} __attribute__((packed));

struct virtio_gpu_rect {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} __attribute__((packed));

struct virtio_gpu_resource_create_2d {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t format;
    uint32_t width;
    uint32_t height;
} __attribute__((packed));

struct virtio_gpu_set_scanout {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;
    uint32_t scanout_id;
    uint32_t resource_id;
} __attribute__((packed));

struct virtio_gpu_resource_flush {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_transfer_to_host_2d {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;
    uint64_t offset;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_cursor_position {
    uint32_t scanout_id;
    uint32_t x;
    uint32_t y;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_update_cursor {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_cursor_position position;
    uint32_t resource_id;
    uint32_t hot_x;
    uint32_t hot_y;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_mem_entry {
    uint64_t addr;
    uint32_t length;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_resource_attach_backing {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t nr_entries;
} __attribute__((packed));

struct virtio_gpu_resource_reference {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_resp_display_info {
    struct virtio_gpu_ctrl_hdr hdr;
    struct {
        struct virtio_gpu_rect r;
        uint32_t enabled;
        uint32_t flags;
    } pmodes[VIRTIO_GPU_MAX_SCANOUTS];
} __attribute__((packed));

struct virtio_gpu_get_edid {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t scanout;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_resp_edid {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t size;
    uint32_t padding;
    uint8_t edid[DISPLAY_MODE_EDID_MAX_BYTES];
} __attribute__((packed));

struct virtio_gpu_get_capset_info {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t capset_index;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_resp_capset_info {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t capset_id;
    uint32_t capset_max_version;
    uint32_t capset_max_size;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_get_capset {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t capset_id;
    uint32_t capset_version;
} __attribute__((packed));

struct virtio_gpu_box {
    uint32_t x;
    uint32_t y;
    uint32_t z;
    uint32_t width;
    uint32_t height;
    uint32_t depth;
} __attribute__((packed));

struct virtio_gpu_resource_create_3d {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t target;
    uint32_t format;
    uint32_t bind;
    uint32_t width;
    uint32_t height;
    uint32_t depth;
    uint32_t array_size;
    uint32_t last_level;
    uint32_t nr_samples;
    uint32_t flags;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_transfer_host_3d {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_box box;
    uint64_t offset;
    uint32_t resource_id;
    uint32_t level;
    uint32_t stride;
    uint32_t layer_stride;
} __attribute__((packed));

struct virtio_gpu_ctx_create {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t name_length;
    uint32_t context_init;
    char debug_name[64];
} __attribute__((packed));

struct virtio_gpu_ctx_destroy {
    struct virtio_gpu_ctrl_hdr hdr;
} __attribute__((packed));

struct virtio_gpu_cmd_submit {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t size;
    uint32_t padding;
} __attribute__((packed));

typedef struct {
    uint32_t id;
    uint32_t maximum_version;
    uint32_t maximum_size;
} virtio_gpu_capset_t;

typedef struct {
    uint8_t bar;
    uint32_t offset;
    uint32_t length;
} virtio_modern_cap_t;

typedef enum {
    VIRTIO_GPU_TRANSPORT_NONE = 0,
    VIRTIO_GPU_TRANSPORT_PCI,
    VIRTIO_GPU_TRANSPORT_MMIO,
} virtio_gpu_transport_t;

typedef struct {
    uint8_t ring[VIRTIO_GPU_RING_BYTES] __attribute__((aligned(VIRTIO_PCI_VRING_ALIGN)));
    struct vring_desc *desc;
    struct vring_avail *avail;
    struct vring_used *used;
    uint16_t size;
    uint16_t avail_idx;
    uint16_t used_idx;
    uint16_t notify_off;
} virtio_gpu_queue_t;

typedef struct {
    virtio_gpu_transport_t transport;
    volatile uint8_t *common_base;
    volatile uint8_t *notify_base;
    volatile uint8_t *isr_base;
    volatile uint8_t *device_base;
    volatile uint8_t *mmio_base;
    uint32_t notify_multiplier;
    uint32_t interrupt;
    uint32_t interrupt_flags;
    uint8_t bus;
    uint8_t dev;
    uint8_t fn;
    uint8_t irq_mode;
    uint8_t irq_vector;
    void *irq_cookie;
    int present;
    int virgl;
    uint32_t num_scanouts;
    uint32_t num_capsets;
    uint32_t width;
    uint32_t height;
    uint32_t refresh_millihz;
    uint32_t scanout_id;
    uint32_t mode_count;
    uint32_t width_mm;
    uint32_t height_mm;
    uint32_t edid_size;
    uint32_t scanout_resource_id;
    uint32_t scanout_width;
    uint32_t scanout_height;
    uint64_t next_fence;
    uint64_t next_event_poll_us;
    uint64_t supported_capsets;
    uint32_t maximum_capset_size;
    uint64_t negotiated_features;
    display_mode_t modes[DISPLAY_MODE_EDID_MAX_MODES];
    uint8_t edid[DISPLAY_MODE_EDID_MAX_BYTES];
    virtio_gpu_capset_t capsets[VIRTIO_GPU_CAPSET_COUNT];
    virtio_gpu_queue_t ctrlq;
    virtio_gpu_queue_t cursorq;
} virtio_gpu_dev_t;

typedef struct {
    struct virtio_gpu_update_cursor command;
    uint8_t in_flight;
} virtio_gpu_cursor_slot_t;

typedef enum {
    VIRTIO_GPU_PRESENT_FREE = 0,
    VIRTIO_GPU_PRESENT_IN_FLIGHT,
    VIRTIO_GPU_PRESENT_PENDING,
} virtio_gpu_present_state_t;

typedef struct virtio_gpu_present_slot {
    virtio_gpu_damage_t damage;
    struct virtio_gpu_set_scanout scanout;
    struct virtio_gpu_ctrl_hdr scanout_response;
    struct virtio_gpu_transfer_to_host_2d
        transfers[VIRTIO_GPU_PRESENT_BATCH_RECTS];
    struct virtio_gpu_ctrl_hdr
        transfer_responses[VIRTIO_GPU_PRESENT_BATCH_RECTS];
    struct virtio_gpu_resource_flush flush;
    struct virtio_gpu_ctrl_hdr flush_response;
    uint64_t submitted_us;
    uint32_t resource_id;
    uint32_t resource_width;
    uint32_t resource_height;
    uint16_t descriptor_base;
    uint16_t command_count;
    uint16_t completed_commands;
    uint8_t state;
    uint8_t timeout_recorded;
    uint8_t flush_only;
    uint8_t set_scanout;
} virtio_gpu_present_slot_t;

typedef struct {
    struct virtio_gpu_cmd_submit request;
    struct virtio_gpu_ctrl_hdr response;
    const void *commands;
    uint64_t completion_id;
    uint64_t submitted_us;
    uint32_t command_size;
    uint8_t in_flight;
} virtio_gpu_render_slot_t;

typedef struct {
    uint64_t completion_id;
    int status;
} virtio_gpu_render_completion_t;

typedef struct {
    const void *commands;
    uint64_t completion_id;
    uint32_t context_id;
    uint32_t command_size;
} virtio_gpu_render_pending_t;

typedef struct {
    uint8_t request[VIRTIO_GPU_SYNC_REQUEST_BYTES]
        __attribute__((aligned(64)));
    uint8_t secondary[VIRTIO_GPU_SYNC_SECONDARY_BYTES]
        __attribute__((aligned(64)));
    uint8_t response[VIRTIO_GPU_SYNC_RESPONSE_BYTES]
        __attribute__((aligned(4096)));
} virtio_gpu_sync_slot_t;

static virtio_gpu_dev_t g_vtgpu;
static spinlock_t g_vtgpu_cmd_lock;
static spinlock_t g_vtgpu_cursor_lock;
static volatile unsigned int g_vtgpu_mode_guard;
static volatile unsigned int g_vtgpu_cursor_update_guard;
static virtio_gpu_present_slot_t
    g_vtgpu_present_slots[VIRTIO_GPU_PRESENT_SLOT_COUNT]
        __attribute__((aligned(64)));
static virtio_gpu_present_stats_t g_vtgpu_present_stats;
static uint8_t g_vtgpu_runtime_present_ready;
static virtio_gpu_sync_state_t g_vtgpu_sync_state;
static virtio_gpu_sync_slot_t g_vtgpu_sync_slot;
static volatile uint64_t g_vtgpu_sync_sequence;
static volatile uint64_t g_vtgpu_present_sequence;
static int g_vtgpu_submit_trace_budget;
static virtio_gpu_render_slot_t
    g_vtgpu_render_slots[VIRTIO_GPU_RENDER_SLOT_COUNT]
        __attribute__((aligned(64)));
static virtio_gpu_render_completion_t
    g_vtgpu_render_completions[VIRTIO_GPU_RENDER_SLOT_COUNT];
static uint32_t g_vtgpu_render_completion_count;
static volatile uint64_t g_vtgpu_render_sequence;
static virtio_gpu_render_pending_t
    g_vtgpu_render_pending[VIRTIO_GPU_RENDER_PENDING_COUNT];
static uint32_t g_vtgpu_render_pending_head;
static uint32_t g_vtgpu_render_pending_tail;
static uint32_t g_vtgpu_render_pending_count;
static virtio_gpu_cursor_slot_t
    g_vtgpu_cursor_slots[VIRTIO_GPU_CURSOR_SLOT_COUNT];
static struct virtio_gpu_update_cursor g_vtgpu_cursor_pending;
static uint8_t g_vtgpu_cursor_pending_valid;
static uint8_t g_vtgpu_cursor_resource_ready;
static uint8_t g_vtgpu_cursor_image_valid;
static uint8_t g_vtgpu_cursor_visible;
static uint32_t g_vtgpu_cursor_hot_x;
static uint32_t g_vtgpu_cursor_hot_y;
static uint8_t g_vtgpu_cursor_image[VIRTIO_GPU_CURSOR_BYTES]
    __attribute__((aligned(VIRTIO_GPU_PAGE_SIZE)));
#if defined(__x86_64__)
static int g_vtgpu_dma_alias_log_budget;
#endif
static uint8_t
    g_vtgpu_capset_response[
        sizeof(struct virtio_gpu_ctrl_hdr) +
        VIRTIO_GPU_CAPSET_MAX_SIZE] __attribute__((aligned(4096)));

static int virtio_gpu_register_display_backend(void);
static void virtio_gpu_init_hdr(struct virtio_gpu_ctrl_hdr *hdr,
                                uint32_t type);
static void virtio_gpu_init_sync_hdr(struct virtio_gpu_ctrl_hdr *hdr,
                                     uint32_t type);

static void
virtio_gpu_display_present(void *context, uint32_t x, uint32_t y,
                           uint32_t width, uint32_t height)
{
    (void)context;
    virtio_gpu_flush_rect(x, y, width, height);
}

static void
virtio_gpu_display_present_batch(void *context,
                                 const display_rect_t *rects,
                                 uint32_t count)
{
    (void)context;
    virtio_gpu_flush_rects(rects, count);
}

static void virtio_gpu_serial_puts(const char *text) {
    if (!text) return;
    while (*text) serial_console_write_raw(*text++);
}

static void virtio_gpu_serial_hex32(uint32_t value) {
    static const char digits[] = "0123456789abcdef";
    int started = 0;

    virtio_gpu_serial_puts("0x");
    for (int shift = 28; shift >= 0; shift -= 4) {
        uint32_t digit = (value >> (uint32_t)shift) & 0xfu;
        if (digit || started || shift == 0) {
            serial_console_write_raw(digits[digit]);
            started = 1;
        }
    }
}

static void virtio_gpu_cpu_relax(void) {
#if defined(__aarch64__)
    __asm__ __volatile__("yield");
#else
    __asm__ __volatile__("pause");
#endif
}
/*
 * Xorg's fbdev path may use the address reported by FBIOGET_FSCREENINFO
 * directly.  EdgeOS maps user page tables with 2 MiB PDEs, so keep the virtio
 * GPU backing buffer 2 MiB aligned before process.c exposes exactly the
 * framebuffer PDEs to userspace.  Red flag: lowering this to 4 KiB alignment
 * can make the user fbdev aperture share a PDE with unrelated kernel .bss.
 */
#if defined(__x86_64__)
#define VIRTIO_GPU_FB_ALIGNMENT (2u * 1024u * 1024u)
#else
#define VIRTIO_GPU_FB_ALIGNMENT 4096u
#endif
static uint8_t g_vtgpu_boot_fb[VIRTIO_GPU_BOOT_FB_BYTES]
    __attribute__((aligned(VIRTIO_GPU_FB_ALIGNMENT)));
static uint8_t *g_vtgpu_fb = g_vtgpu_boot_fb;
static uint32_t g_vtgpu_fb_capacity = sizeof(g_vtgpu_boot_fb);
static uint8_t *g_vtgpu_fb_allocation;
static uint32_t g_vtgpu_fb_allocation_pages;

static uint32_t
virtio_gpu_framebuffer_bytes(uint32_t width, uint32_t height)
{
    uint64_t bytes = (uint64_t)width * height * 4u;

    return bytes && bytes <= UINT32_MAX ? (uint32_t)bytes : 0u;
}

static uint8_t *
virtio_gpu_framebuffer_allocate(uint32_t bytes, uint8_t **allocation_out,
                                uint32_t *allocation_pages_out,
                                uint32_t *capacity_out)
{
    uint32_t data_pages;
    uint32_t alignment_pages;
    uint32_t allocation_pages;
    uint8_t *allocation;
    uintptr_t aligned;

    if (!bytes || !allocation_out || !allocation_pages_out || !capacity_out)
        return 0;
    data_pages =
        (bytes + VIRTIO_GPU_PAGE_SIZE - 1u) / VIRTIO_GPU_PAGE_SIZE;
    alignment_pages = VIRTIO_GPU_FB_ALIGNMENT / VIRTIO_GPU_PAGE_SIZE;
    allocation_pages = data_pages + alignment_pages - 1u;
    allocation = arch_vm_alloc_pages(allocation_pages);
    if (!allocation)
        return 0;
    aligned = ((uintptr_t)allocation + VIRTIO_GPU_FB_ALIGNMENT - 1u) &
        ~((uintptr_t)VIRTIO_GPU_FB_ALIGNMENT - 1u);
    *allocation_out = allocation;
    *allocation_pages_out = allocation_pages;
    *capacity_out = data_pages * VIRTIO_GPU_PAGE_SIZE;
    return (uint8_t *)aligned;
}

static void
virtio_gpu_framebuffer_release(uint8_t *allocation, uint32_t pages)
{
    if (!allocation)
        return;
    for (uint32_t page = 0; page < pages; ++page)
        arch_vm_free_page(
            allocation + (uint64_t)page * VIRTIO_GPU_PAGE_SIZE);
}

static uint64_t virtio_gpu_dma_addr(const void *ptr) {
    uintptr_t va = (uintptr_t)ptr;

#if defined(__x86_64__)
    /*
     * Virtio descriptors carry guest physical addresses, not kernel virtual
     * aliases.  EdgeOS maps low physical memory twice: identity-mapped for
     * early/static kernel objects and through EDGE_MMIO_LOW_ALIAS_BASE for
     * runtime kernel objects that must stay visible while a user CR3 is loaded.
     * Command buffers and response buffers can live on either kind of kernel
     * stack, so normalize the alias before handing the pointer to QEMU.
     */
    if (va >= EDGE_MMIO_LOW_ALIAS_BASE &&
        va < EDGE_MMIO_LOW_ALIAS_BASE + EDGE_MMIO_LOW_ALIAS_SIZE) {
        uint64_t phys = (uint64_t)(va - EDGE_MMIO_LOW_ALIAS_BASE);
        if (g_vtgpu_dma_alias_log_budget > 0) {
            printf("[virtio-gpu] dma alias va=0x%x phys=0x%x budget=%d\n",
                   (uint32_t)va, (uint32_t)phys,
                   g_vtgpu_dma_alias_log_budget - 1);
            g_vtgpu_dma_alias_log_budget--;
        }
        return phys;
    }
#endif
    return (uint64_t)va;
}

#if defined(__x86_64__)
static uint64_t pci_bar_base(uint8_t bus, uint8_t slot, uint8_t func, uint8_t bar, int *is_io) {
    uint8_t off;
    uint32_t lo;
    if (bar >= 6) return 0;
    off = (uint8_t)(0x10u + bar * 4u);
    lo = pci_cfg_read32(bus, slot, func, off);
    if (lo & 1u) {
        if (is_io) *is_io = 1;
        return (uint64_t)(lo & ~3u);
    }
    if (is_io) *is_io = 0;
    if ((lo & 0x6u) == 0x4u && bar < 5) {
        uint32_t hi = pci_cfg_read32(bus, slot, func, (uint8_t)(off + 4u));
        return ((uint64_t)hi << 32) | (uint64_t)(lo & ~0xFULL);
    }
    return (uint64_t)(lo & ~0xFULL);
}
#endif

static uint8_t mmio_read8(volatile uint8_t *base, uint32_t off) {
    return *(volatile uint8_t *)(base + off);
}

static uint16_t mmio_read16(volatile uint8_t *base, uint32_t off) {
    return *(volatile uint16_t *)(base + off);
}

static uint32_t mmio_read32(volatile uint8_t *base, uint32_t off) {
    return *(volatile uint32_t *)(base + off);
}

static void mmio_write8(volatile uint8_t *base, uint32_t off, uint8_t v) {
    *(volatile uint8_t *)(base + off) = v;
}

static void mmio_write16(volatile uint8_t *base, uint32_t off, uint16_t v) {
    *(volatile uint16_t *)(base + off) = v;
}

static void mmio_write32(volatile uint8_t *base, uint32_t off, uint32_t v) {
    *(volatile uint32_t *)(base + off) = v;
}

static uint8_t virtio_status_get(void) {
    if (g_vtgpu.transport == VIRTIO_GPU_TRANSPORT_MMIO)
        return (uint8_t)mmio_read32(g_vtgpu.mmio_base,
                                    VIRTIO_MMIO_STATUS);
    return mmio_read8(g_vtgpu.common_base, VIRTIO_PCI_COMMON_STATUS);
}

static void virtio_status_set(uint8_t status) {
    if (g_vtgpu.transport == VIRTIO_GPU_TRANSPORT_MMIO) {
        mmio_write32(g_vtgpu.mmio_base, VIRTIO_MMIO_STATUS, status);
        return;
    }
    mmio_write8(g_vtgpu.common_base, VIRTIO_PCI_COMMON_STATUS, status);
}

static uint64_t virtio_features_read(void) {
    uint32_t lo;
    uint32_t hi;
    if (g_vtgpu.transport == VIRTIO_GPU_TRANSPORT_MMIO) {
        mmio_write32(g_vtgpu.mmio_base,
                     VIRTIO_MMIO_DEVICE_FEATURES_SEL, 0u);
        lo = mmio_read32(g_vtgpu.mmio_base,
                         VIRTIO_MMIO_DEVICE_FEATURES);
        mmio_write32(g_vtgpu.mmio_base,
                     VIRTIO_MMIO_DEVICE_FEATURES_SEL, 1u);
        hi = mmio_read32(g_vtgpu.mmio_base,
                         VIRTIO_MMIO_DEVICE_FEATURES);
        return (uint64_t)lo | ((uint64_t)hi << 32);
    }
    mmio_write32(g_vtgpu.common_base, VIRTIO_PCI_COMMON_DFSELECT, 0);
    lo = mmio_read32(g_vtgpu.common_base, VIRTIO_PCI_COMMON_DF);
    mmio_write32(g_vtgpu.common_base, VIRTIO_PCI_COMMON_DFSELECT, 1);
    hi = mmio_read32(g_vtgpu.common_base, VIRTIO_PCI_COMMON_DF);
    return (uint64_t)lo | ((uint64_t)hi << 32);
}

static void virtio_features_write(uint64_t features) {
    if (g_vtgpu.transport == VIRTIO_GPU_TRANSPORT_MMIO) {
        mmio_write32(g_vtgpu.mmio_base,
                     VIRTIO_MMIO_DRIVER_FEATURES_SEL, 0u);
        mmio_write32(g_vtgpu.mmio_base,
                     VIRTIO_MMIO_DRIVER_FEATURES, (uint32_t)features);
        mmio_write32(g_vtgpu.mmio_base,
                     VIRTIO_MMIO_DRIVER_FEATURES_SEL, 1u);
        mmio_write32(g_vtgpu.mmio_base,
                     VIRTIO_MMIO_DRIVER_FEATURES,
                     (uint32_t)(features >> 32));
        return;
    }
    mmio_write32(g_vtgpu.common_base, VIRTIO_PCI_COMMON_GFSELECT, 0);
    mmio_write32(g_vtgpu.common_base, VIRTIO_PCI_COMMON_GF, (uint32_t)features);
    mmio_write32(g_vtgpu.common_base, VIRTIO_PCI_COMMON_GFSELECT, 1);
    mmio_write32(g_vtgpu.common_base, VIRTIO_PCI_COMMON_GF, (uint32_t)(features >> 32));
}

static uint32_t virtio_device_config_read32(uint32_t off) {
    uint8_t gen;
    uint32_t v;
    if (g_vtgpu.transport == VIRTIO_GPU_TRANSPORT_MMIO) {
        do {
            gen = (uint8_t)mmio_read32(
                g_vtgpu.mmio_base, VIRTIO_MMIO_CONFIG_GENERATION);
            v = mmio_read32(g_vtgpu.mmio_base,
                            VIRTIO_MMIO_CONFIG + off);
        } while (gen != (uint8_t)mmio_read32(
                     g_vtgpu.mmio_base,
                     VIRTIO_MMIO_CONFIG_GENERATION));
        return v;
    }
    do {
        gen = mmio_read8(g_vtgpu.common_base, VIRTIO_PCI_COMMON_CFGGENERATION);
        v = mmio_read32(g_vtgpu.device_base, off);
    } while (gen != mmio_read8(g_vtgpu.common_base, VIRTIO_PCI_COMMON_CFGGENERATION));
    return v;
}

static void virtio_device_config_write32(uint32_t off, uint32_t value) {
    if (g_vtgpu.transport == VIRTIO_GPU_TRANSPORT_MMIO) {
        mmio_write32(g_vtgpu.mmio_base, VIRTIO_MMIO_CONFIG + off,
                     value);
        return;
    }
    mmio_write32(g_vtgpu.device_base, off, value);
}

static void virtio_queue_select(uint16_t idx) {
    if (g_vtgpu.transport == VIRTIO_GPU_TRANSPORT_MMIO) {
        mmio_write32(g_vtgpu.mmio_base, VIRTIO_MMIO_QUEUE_SEL, idx);
        return;
    }
    mmio_write16(g_vtgpu.common_base, VIRTIO_PCI_COMMON_Q_SELECT, idx);
}

static uint16_t virtio_queue_size_read(void) {
    if (g_vtgpu.transport == VIRTIO_GPU_TRANSPORT_MMIO)
        return (uint16_t)mmio_read32(
            g_vtgpu.mmio_base, VIRTIO_MMIO_QUEUE_NUM_MAX);
    return mmio_read16(g_vtgpu.common_base, VIRTIO_PCI_COMMON_Q_SIZE);
}

static uint32_t vring_used_offset(uint32_t num) {
    uint32_t off = num * (uint32_t)sizeof(struct vring_desc);
    off += (uint32_t)sizeof(struct vring_avail) + num * (uint32_t)sizeof(uint16_t) + (uint32_t)sizeof(uint16_t);
    return (off + VIRTIO_PCI_VRING_ALIGN - 1u) & ~(VIRTIO_PCI_VRING_ALIGN - 1u);
}

static int virtio_queue_ring_fits(uint16_t qsz) {
    uint32_t used_off = vring_used_offset(qsz);
    uint32_t used_bytes = (uint32_t)sizeof(struct vring_used) +
                          (uint32_t)qsz * (uint32_t)sizeof(struct vring_used_elem) +
                          (uint32_t)sizeof(uint16_t);
    return qsz >= 4 && qsz <= VIRTIO_GPU_QUEUE_SIZE &&
           used_off + used_bytes <= VIRTIO_GPU_RING_BYTES;
}

static void virtio_queue_setup(virtio_gpu_queue_t *q, uint16_t qsz) {
    uint32_t used_off;
    memset(q->ring, 0, sizeof(q->ring));
    q->desc = (struct vring_desc *)q->ring;
    q->avail = (struct vring_avail *)(q->ring + qsz * sizeof(struct vring_desc));
    used_off = vring_used_offset(qsz);
    q->used = (struct vring_used *)(q->ring + used_off);
    q->size = qsz;
    q->avail_idx = 0;
    q->used_idx = 0;
}

static int virtio_queue_program(uint16_t index, virtio_gpu_queue_t *q, uint16_t qsz) {
    uintptr_t desc;
    uintptr_t avail;
    uintptr_t used;
    uint16_t max_qsz;

    virtio_queue_select(index);
    if (g_vtgpu.transport == VIRTIO_GPU_TRANSPORT_MMIO &&
        mmio_read32(g_vtgpu.mmio_base, VIRTIO_MMIO_QUEUE_READY))
        return -1;
    max_qsz = virtio_queue_size_read();
    if (max_qsz < qsz || !virtio_queue_ring_fits(qsz)) return -1;

    virtio_queue_setup(q, qsz);
    desc = (uintptr_t)virtio_gpu_dma_addr(q->desc);
    avail = (uintptr_t)virtio_gpu_dma_addr(q->avail);
    used = (uintptr_t)virtio_gpu_dma_addr(q->used);
    if (g_vtgpu.transport == VIRTIO_GPU_TRANSPORT_MMIO) {
        mmio_write32(g_vtgpu.mmio_base, VIRTIO_MMIO_QUEUE_NUM, qsz);
        mmio_write32(g_vtgpu.mmio_base, VIRTIO_MMIO_QUEUE_DESC_LOW,
                     (uint32_t)desc);
        mmio_write32(g_vtgpu.mmio_base, VIRTIO_MMIO_QUEUE_DESC_HIGH,
                     (uint32_t)((uint64_t)desc >> 32));
        mmio_write32(g_vtgpu.mmio_base, VIRTIO_MMIO_QUEUE_AVAIL_LOW,
                     (uint32_t)avail);
        mmio_write32(g_vtgpu.mmio_base, VIRTIO_MMIO_QUEUE_AVAIL_HIGH,
                     (uint32_t)((uint64_t)avail >> 32));
        mmio_write32(g_vtgpu.mmio_base, VIRTIO_MMIO_QUEUE_USED_LOW,
                     (uint32_t)used);
        mmio_write32(g_vtgpu.mmio_base, VIRTIO_MMIO_QUEUE_USED_HIGH,
                     (uint32_t)((uint64_t)used >> 32));
        mmio_write32(g_vtgpu.mmio_base, VIRTIO_MMIO_QUEUE_READY, 1u);
        q->notify_off = index;
        return 0;
    }
    mmio_write16(g_vtgpu.common_base, VIRTIO_PCI_COMMON_Q_SIZE, qsz);
    q->notify_off = mmio_read16(g_vtgpu.common_base, VIRTIO_PCI_COMMON_Q_NOFF);
    mmio_write32(g_vtgpu.common_base, VIRTIO_PCI_COMMON_Q_DESCLO, (uint32_t)desc);
    mmio_write32(g_vtgpu.common_base, VIRTIO_PCI_COMMON_Q_DESCHI, (uint32_t)((uint64_t)desc >> 32));
    mmio_write32(g_vtgpu.common_base, VIRTIO_PCI_COMMON_Q_AVAILLO, (uint32_t)avail);
    mmio_write32(g_vtgpu.common_base, VIRTIO_PCI_COMMON_Q_AVAILHI, (uint32_t)((uint64_t)avail >> 32));
    mmio_write32(g_vtgpu.common_base, VIRTIO_PCI_COMMON_Q_USEDLO, (uint32_t)used);
    mmio_write32(g_vtgpu.common_base, VIRTIO_PCI_COMMON_Q_USEDHI, (uint32_t)((uint64_t)used >> 32));
    mmio_write16(g_vtgpu.common_base, VIRTIO_PCI_COMMON_Q_ENABLE, 1);
    return 0;
}

static void virtio_queue_notify(const virtio_gpu_queue_t *q, uint16_t queue_index) {
    if (g_vtgpu.transport == VIRTIO_GPU_TRANSPORT_MMIO) {
        (void)q;
        mmio_write32(g_vtgpu.mmio_base, VIRTIO_MMIO_QUEUE_NOTIFY,
                     queue_index);
        return;
    }
    uint32_t off = (uint32_t)q->notify_off * g_vtgpu.notify_multiplier;
    mmio_write16(g_vtgpu.notify_base, off, queue_index);
}

static uint32_t virtio_ack_isr(void) {
    if (g_vtgpu.transport == VIRTIO_GPU_TRANSPORT_MMIO) {
        uint32_t status = mmio_read32(
            g_vtgpu.mmio_base, VIRTIO_MMIO_INTERRUPT_STATUS);
        if (status)
            mmio_write32(g_vtgpu.mmio_base,
                         VIRTIO_MMIO_INTERRUPT_ACK, status);
        return status;
    }
    return mmio_read8(g_vtgpu.isr_base, 0);
}

#if defined(__x86_64__)
static int virtio_gpu_set_queue_msix(uint16_t queue_index,
                                     uint16_t table_index)
{
    if (g_vtgpu.transport != VIRTIO_GPU_TRANSPORT_PCI)
        return -1;
    virtio_queue_select(queue_index);
    mmio_write16(g_vtgpu.common_base,
                 VIRTIO_PCI_COMMON_Q_MSIX_VECTOR, table_index);
    return mmio_read16(g_vtgpu.common_base,
                       VIRTIO_PCI_COMMON_Q_MSIX_VECTOR) == table_index ?
        0 : -1;
}

static int virtio_gpu_set_config_msix(uint16_t table_index)
{
    if (g_vtgpu.transport != VIRTIO_GPU_TRANSPORT_PCI)
        return -1;
    mmio_write16(g_vtgpu.common_base,
                 VIRTIO_PCI_COMMON_MSIX_CONFIG, table_index);
    return mmio_read16(g_vtgpu.common_base,
                       VIRTIO_PCI_COMMON_MSIX_CONFIG) == table_index ?
        0 : -1;
}
#endif

#if defined(__x86_64__)
static void virtio_gpu_irq_wake(void *context)
{
    if (context != &g_vtgpu) return;
    (void)virtio_ack_isr();
    kernel_display_work_request();
}
#elif defined(__aarch64__)
static void virtio_gpu_irq_wake(uint32_t interrupt, void *context)
{
    (void)interrupt;
    if (context != &g_vtgpu) return;
    (void)virtio_ack_isr();
    kernel_display_work_request();
}
#endif

static void virtio_gpu_setup_interrupts(void)
{
#if defined(__x86_64__)
    uint8_t irq_line = pci_cfg_read8(
        g_vtgpu.bus, g_vtgpu.dev, g_vtgpu.fn, 0x3cu);
    int vector = apic_allocate_msi_vector();
    uint32_t allocated_vector;
    void *old_cookie = g_vtgpu.irq_cookie;
    void *new_cookie = 0;
    uint8_t old_mode = g_vtgpu.irq_mode;

    if (old_mode >= 2u) return;
    (void)virtio_gpu_set_config_msix(VIRTIO_MSI_NO_VECTOR);
    (void)virtio_gpu_set_queue_msix(
        VIRTIO_GPU_CTRL_QUEUE, VIRTIO_MSI_NO_VECTOR);
    (void)virtio_gpu_set_queue_msix(
        VIRTIO_GPU_CURSOR_QUEUE, VIRTIO_MSI_NO_VECTOR);

    if (vector >= 0) {
        allocated_vector = (uint32_t)vector;
        if (pci_enable_msix_vector(
                g_vtgpu.bus, g_vtgpu.dev, g_vtgpu.fn,
                0u, (uint8_t)vector) == 0 &&
            isr_register_context_interrupt_handler(
                vector, virtio_gpu_irq_wake, &g_vtgpu,
                &new_cookie) == 0 &&
            virtio_gpu_set_queue_msix(VIRTIO_GPU_CTRL_QUEUE, 0u) == 0 &&
            virtio_gpu_set_queue_msix(VIRTIO_GPU_CURSOR_QUEUE, 0u) == 0) {
            if (old_cookie)
                (void)isr_unregister_context_interrupt_handler(old_cookie);
            g_vtgpu.irq_mode = 3u;
            g_vtgpu.irq_vector = (uint8_t)vector;
            g_vtgpu.irq_cookie = new_cookie;
            printf("[virtio-gpu] msix queue vector=%u table=0 irq_line=%u\n",
                   (uint32_t)vector, (uint32_t)irq_line);
            return;
        }
        (void)virtio_gpu_set_queue_msix(
            VIRTIO_GPU_CTRL_QUEUE, VIRTIO_MSI_NO_VECTOR);
        (void)virtio_gpu_set_queue_msix(
            VIRTIO_GPU_CURSOR_QUEUE, VIRTIO_MSI_NO_VECTOR);
        if (new_cookie)
            (void)isr_unregister_context_interrupt_handler(
                new_cookie);
        (void)pci_disable_msix_vectors(
            g_vtgpu.bus, g_vtgpu.dev, g_vtgpu.fn);
        apic_release_msi_vectors(&allocated_vector, 1u);
        new_cookie = 0;
    }

    if (old_mode == 1u) return;

    vector = apic_allocate_msi_vector();

    if (vector >= 0 && pci_enable_msi_vector(
            g_vtgpu.bus, g_vtgpu.dev, g_vtgpu.fn,
            (uint8_t)vector) == 0) {
        if (isr_register_context_interrupt_handler(
                vector, virtio_gpu_irq_wake, &g_vtgpu,
                &new_cookie) == 0) {
            g_vtgpu.irq_mode = 2u;
            g_vtgpu.irq_vector = (uint8_t)vector;
            g_vtgpu.irq_cookie = new_cookie;
            printf("[virtio-gpu] msi vector=%u\n", (uint32_t)vector);
            return;
        }
        (void)pci_disable_msi_vectors(
            g_vtgpu.bus, g_vtgpu.dev, g_vtgpu.fn);
    }
    if (vector >= 0) {
        allocated_vector = (uint32_t)vector;
        apic_release_msi_vectors(&allocated_vector, 1u);
    }
    (void)pci_disable_msix_vectors(
        g_vtgpu.bus, g_vtgpu.dev, g_vtgpu.fn);
    if (irq_line < 16u && isr_register_context_interrupt_handler(
            IRQ_BASE + irq_line, virtio_gpu_irq_wake, &g_vtgpu,
            &new_cookie) == 0) {
        pic8259_unmask_irq(irq_line);
        g_vtgpu.irq_mode = 1u;
        g_vtgpu.irq_vector = (uint8_t)(IRQ_BASE + irq_line);
        g_vtgpu.irq_cookie = new_cookie;
        printf("[virtio-gpu] intx irq line %u handler installed\n",
               (uint32_t)irq_line);
        return;
    }
    printf("[virtio-gpu] completion polling enabled\n");
#elif defined(__aarch64__)
    if (g_vtgpu.irq_mode) return;
    virtio_ack_isr();
    if (edgeos_arm64_irq_register(
            g_vtgpu.interrupt, g_vtgpu.interrupt_flags,
            virtio_gpu_irq_wake, &g_vtgpu) == 0) {
        g_vtgpu.irq_mode = 1u;
        printf("[virtio-gpu] mmio irq %u handler installed\n",
               g_vtgpu.interrupt);
    } else {
        printf("[virtio-gpu] completion polling enabled\n");
    }
#endif
}

#if defined(__x86_64__)
static int virtio_modern_cap_valid(const virtio_modern_cap_t *cap, uint32_t min_len, uint32_t align) {
    if (!cap || cap->bar >= 6 || cap->length < min_len) return 0;
    if (align && (cap->offset % align) != 0) return 0;
    return 1;
}

static int virtio_modern_cap_addr(uint8_t bus, uint8_t dev, uint8_t fn,
                                  const virtio_modern_cap_t *cap,
                                  volatile uint8_t **out) {
    int is_io = 0;
    uint64_t base;
    uint64_t address;
    if (!virtio_modern_cap_valid(cap, 1, 1) || !out) return -1;
    base = pci_bar_base(bus, dev, fn, cap->bar, &is_io);
    if (is_io || base == 0 || base > UINT64_MAX - cap->offset) return -1;
    address = base + cap->offset;
    if (address >= 0x0000800000000000ULL ||
        !edge_mmio_phys_range_mapped(address, cap->length)) return -1;
    *out = (volatile uint8_t *)edge_mmio_low_alias(address);
    return 0;
}

static int virtio_modern_read_cap(uint8_t bus, uint8_t dev, uint8_t fn,
                                  uint8_t cap_off, virtio_modern_cap_t *cap) {
    uint8_t len;
    if (!cap) return -1;
    if (pci_cfg_read8(bus, dev, fn, (uint8_t)(cap_off + VIRTIO_PCI_CAP_VNDR)) != PCI_CAP_ID_VENDOR) return -1;
    len = pci_cfg_read8(bus, dev, fn, (uint8_t)(cap_off + VIRTIO_PCI_CAP_LEN));
    if (len < 16) return -1;
    cap->bar = pci_cfg_read8(bus, dev, fn, (uint8_t)(cap_off + VIRTIO_PCI_CAP_BAR));
    cap->offset = pci_cfg_read32(bus, dev, fn, (uint8_t)(cap_off + VIRTIO_PCI_CAP_OFFSET));
    cap->length = pci_cfg_read32(bus, dev, fn, (uint8_t)(cap_off + VIRTIO_PCI_CAP_LENGTH));
    return 0;
}

static int virtio_modern_find_caps(uint8_t bus, uint8_t dev, uint8_t fn,
                                   virtio_modern_cap_t *common,
                                   virtio_modern_cap_t *notify,
                                   virtio_modern_cap_t *isr,
                                   virtio_modern_cap_t *device_cfg,
                                   uint32_t *notify_multiplier) {
    uint16_t status = pci_cfg_read16(bus, dev, fn, 0x06);
    uint8_t cap = pci_cfg_read8(bus, dev, fn, 0x34) & 0xFCu;
    int have_common = 0, have_notify = 0, have_isr = 0, have_device = 0;

    if ((status & PCI_STATUS_CAP_LIST) == 0) return -1;
    for (uint32_t guard = 0; cap >= 0x40 && guard < 48; ++guard) {
        uint8_t id = pci_cfg_read8(bus, dev, fn, cap);
        uint8_t next = pci_cfg_read8(bus, dev, fn, (uint8_t)(cap + 1u)) & 0xFCu;
        if (id == PCI_CAP_ID_VENDOR) {
            uint8_t cfg_type = pci_cfg_read8(bus, dev, fn, (uint8_t)(cap + VIRTIO_PCI_CAP_CFG_TYPE));
            virtio_modern_cap_t tmp;
            if (virtio_modern_read_cap(bus, dev, fn, cap, &tmp) == 0) {
                if (cfg_type == VIRTIO_PCI_CAP_COMMON_CFG) { *common = tmp; have_common = 1; }
                else if (cfg_type == VIRTIO_PCI_CAP_NOTIFY_CFG) {
                    *notify = tmp;
                    *notify_multiplier = pci_cfg_read32(bus, dev, fn, (uint8_t)(cap + VIRTIO_PCI_NOTIFY_CAP_MULT));
                    have_notify = 1;
                } else if (cfg_type == VIRTIO_PCI_CAP_ISR_CFG) { *isr = tmp; have_isr = 1; }
                else if (cfg_type == VIRTIO_PCI_CAP_DEVICE_CFG) { *device_cfg = tmp; have_device = 1; }
            }
        }
        if (next == 0 || next == cap) break;
        cap = next;
    }

    if (!have_common || !have_notify || !have_isr || !have_device) return -1;
    if (!virtio_modern_cap_valid(common, VIRTIO_MODERN_COMMON_MIN_SIZE, 4)) return -1;
    if (!virtio_modern_cap_valid(notify, VIRTIO_MODERN_NOTIFY_MIN_SIZE, 2)) return -1;
    if (!virtio_modern_cap_valid(isr, VIRTIO_MODERN_ISR_MIN_SIZE, 1)) return -1;
    if (!virtio_modern_cap_valid(device_cfg, 16, 4)) return -1;
    return 0;
}

static int virtio_gpu_find_modern(void) {
    for (uint16_t bus = 0; bus < 256; ++bus) {
        for (uint8_t dev = 0; dev < 32; ++dev) {
            for (uint8_t fn = 0; fn < 8; ++fn) {
                uint32_t id = pci_cfg_read32((uint8_t)bus, dev, fn, 0x00);
                virtio_modern_cap_t common, notify, isr, device_cfg;
                uint32_t notify_multiplier = 0;
                if ((id & 0xFFFFu) != VIRTIO_PCI_VENDORID) continue;
                if ((id >> 16) != VIRTIO_PCI_DEVICEID_MODERN_GPU) continue;
                if (virtio_modern_find_caps((uint8_t)bus, dev, fn, &common, &notify,
                                            &isr, &device_cfg, &notify_multiplier) < 0) {
                    printf("[virtio-gpu] modern device %u:%u.%u missing usable PCI capabilities\n",
                           bus, dev, fn);
                    continue;
                }
                if (virtio_modern_cap_addr((uint8_t)bus, dev, fn, &common, &g_vtgpu.common_base) < 0 ||
                    virtio_modern_cap_addr((uint8_t)bus, dev, fn, &notify, &g_vtgpu.notify_base) < 0 ||
                    virtio_modern_cap_addr((uint8_t)bus, dev, fn, &isr, &g_vtgpu.isr_base) < 0 ||
                    virtio_modern_cap_addr((uint8_t)bus, dev, fn, &device_cfg, &g_vtgpu.device_base) < 0) {
                    printf("[virtio-gpu] modern device %u:%u.%u has unsupported BAR mapping\n",
                           bus, dev, fn);
                    continue;
                }
                g_vtgpu.bus = (uint8_t)bus;
                g_vtgpu.dev = dev;
                g_vtgpu.fn = fn;
                g_vtgpu.notify_multiplier = notify_multiplier;
                return 0;
            }
        }
    }
    return -1;
}
#endif

static void virtio_gpu_fail(void) {
    virtio_status_set((uint8_t)(virtio_status_get() | VIRTIO_CONFIG_STATUS_FAILED));
}

static void virtio_gpu_present_reset_slot(
    virtio_gpu_present_slot_t *slot, uint16_t descriptor_base)
{
    if (!slot) return;
    memset(slot, 0, sizeof(*slot));
    slot->descriptor_base = descriptor_base;
}

static void virtio_gpu_present_initialize(void)
{
    memset(&g_vtgpu_present_stats, 0, sizeof(g_vtgpu_present_stats));
    memset(g_vtgpu_render_slots, 0, sizeof(g_vtgpu_render_slots));
    memset(g_vtgpu_render_completions, 0,
           sizeof(g_vtgpu_render_completions));
    memset(g_vtgpu_render_pending, 0, sizeof(g_vtgpu_render_pending));
    g_vtgpu_render_completion_count = 0u;
    g_vtgpu_render_pending_head = 0u;
    g_vtgpu_render_pending_tail = 0u;
    g_vtgpu_render_pending_count = 0u;
    for (uint32_t index = 0;
         index < VIRTIO_GPU_PRESENT_INFLIGHT_SLOTS; ++index) {
        virtio_gpu_present_reset_slot(
            &g_vtgpu_present_slots[index],
            (uint16_t)(VIRTIO_GPU_PRESENT_DESC_FIRST +
                index * VIRTIO_GPU_PRESENT_DESC_COUNT));
    }
    virtio_gpu_present_reset_slot(
        &g_vtgpu_present_slots[VIRTIO_GPU_PRESENT_PENDING_SLOT], 0u);
    virtio_gpu_sync_state_reset(&g_vtgpu_sync_state);
    memset(&g_vtgpu_sync_slot, 0, sizeof(g_vtgpu_sync_slot));
}

static void virtio_gpu_queue_publish(virtio_gpu_queue_t *queue,
                                     uint16_t head)
{
    queue->avail->ring[queue->avail_idx % queue->size] = head;
    queue->avail_idx++;
}

static int virtio_gpu_cursor_free_slot_locked(void)
{
    for (uint32_t index = 0; index < VIRTIO_GPU_CURSOR_SLOT_COUNT;
         ++index)
        if (!g_vtgpu_cursor_slots[index].in_flight)
            return (int)index;
    return -1;
}

static void virtio_gpu_cursor_publish_locked(
    const struct virtio_gpu_update_cursor *command)
{
    virtio_gpu_queue_t *queue = &g_vtgpu.cursorq;
    int slot_index = virtio_gpu_cursor_free_slot_locked();
    virtio_gpu_cursor_slot_t *slot;
    uint16_t head;

    if (slot_index < 0 || !command) return;
    slot = &g_vtgpu_cursor_slots[(uint32_t)slot_index];
    head = (uint16_t)slot_index;
    slot->command = *command;
    slot->in_flight = 1u;
    memset(&queue->desc[head], 0, sizeof(queue->desc[head]));
    queue->desc[head].addr = virtio_gpu_dma_addr(&slot->command);
    queue->desc[head].len = sizeof(slot->command);
    virtio_gpu_queue_publish(queue, head);
    __sync_synchronize();
    queue->avail->idx = queue->avail_idx;
    __sync_synchronize();
    virtio_queue_notify(queue, VIRTIO_GPU_CURSOR_QUEUE);
}

static void virtio_gpu_cursor_reap_locked(void)
{
    virtio_gpu_queue_t *queue = &g_vtgpu.cursorq;

    __sync_synchronize();
    while (queue->used_idx != queue->used->idx) {
        const struct vring_used_elem *used =
            &queue->used->ring[queue->used_idx % queue->size];

        queue->used_idx++;
        if (used->id < VIRTIO_GPU_CURSOR_SLOT_COUNT)
            g_vtgpu_cursor_slots[used->id].in_flight = 0u;
    }
    if (g_vtgpu_cursor_pending_valid &&
        virtio_gpu_cursor_free_slot_locked() >= 0) {
        struct virtio_gpu_update_cursor command =
            g_vtgpu_cursor_pending;

        g_vtgpu_cursor_pending_valid = 0u;
        virtio_gpu_cursor_publish_locked(&command);
    }
}

static void virtio_gpu_cursor_enqueue(
    const struct virtio_gpu_update_cursor *command)
{
    uint64_t flags;

    if (!command || !g_vtgpu.present || !g_vtgpu.cursorq.size) return;
    flags = spin_lock_irqsave(&g_vtgpu_cursor_lock);
    virtio_gpu_cursor_reap_locked();
    if (virtio_gpu_cursor_free_slot_locked() >= 0) {
        virtio_gpu_cursor_publish_locked(command);
    } else if (g_vtgpu_cursor_pending_valid &&
               g_vtgpu_cursor_pending.hdr.type ==
                   VIRTIO_GPU_CMD_UPDATE_CURSOR &&
               command->hdr.type == VIRTIO_GPU_CMD_MOVE_CURSOR) {
        g_vtgpu_cursor_pending.position = command->position;
    } else {
        g_vtgpu_cursor_pending = *command;
        g_vtgpu_cursor_pending_valid = 1u;
    }
    spin_unlock_irqrestore(&g_vtgpu_cursor_lock, flags);
}

static void virtio_gpu_present_submit_locked(
    virtio_gpu_present_slot_t *slot)
{
    virtio_gpu_queue_t *queue = &g_vtgpu.ctrlq;
    uint32_t count = slot->damage.count;
    uint32_t transfer_count = slot->flush_only ? 0u : count;
    uint32_t command_offset = slot->set_scanout ? 1u : 0u;
    uint32_t command_count = command_offset + transfer_count + 1u;

    if (!count || count > VIRTIO_GPU_PRESENT_BATCH_RECTS ||
        slot->descriptor_base + command_count * 2u > queue->size)
        return;
    memset(&slot->scanout, 0, sizeof(slot->scanout));
    memset(&slot->scanout_response, 0,
           sizeof(slot->scanout_response));
    memset(slot->transfers, 0, sizeof(slot->transfers));
    memset(slot->transfer_responses, 0,
           sizeof(slot->transfer_responses));
    memset(&slot->flush, 0, sizeof(slot->flush));
    memset(&slot->flush_response, 0, sizeof(slot->flush_response));
    slot->flush.r.x = slot->damage.rects[0].x;
    slot->flush.r.y = slot->damage.rects[0].y;
    slot->flush.r.width = slot->damage.rects[0].width;
    slot->flush.r.height = slot->damage.rects[0].height;
    if (slot->set_scanout) {
        uint16_t head = slot->descriptor_base;

        virtio_gpu_init_hdr(
            &slot->scanout.hdr, VIRTIO_GPU_CMD_SET_SCANOUT);
        slot->scanout.r.width = slot->resource_width;
        slot->scanout.r.height = slot->resource_height;
        slot->scanout.scanout_id = 0u;
        slot->scanout.resource_id = slot->resource_id;
        memset(&queue->desc[head], 0, 2u * sizeof(queue->desc[0]));
        queue->desc[head].addr = virtio_gpu_dma_addr(&slot->scanout);
        queue->desc[head].len = sizeof(slot->scanout);
        queue->desc[head].flags = VRING_DESC_F_NEXT;
        queue->desc[head].next = (uint16_t)(head + 1u);
        queue->desc[head + 1u].addr =
            virtio_gpu_dma_addr(&slot->scanout_response);
        queue->desc[head + 1u].len = sizeof(slot->scanout_response);
        queue->desc[head + 1u].flags = VRING_DESC_F_WRITE;
        virtio_gpu_queue_publish(queue, head);
    }
    for (uint32_t index = 0; index < count; ++index) {
        display_rect_t *rect = &slot->damage.rects[index];
        struct virtio_gpu_transfer_to_host_2d *transfer =
            &slot->transfers[index];
        uint32_t right = rect->x + rect->width;
        uint32_t bottom = rect->y + rect->height;
        uint32_t flush_right = slot->flush.r.x + slot->flush.r.width;
        uint32_t flush_bottom = slot->flush.r.y + slot->flush.r.height;
        if (rect->x < slot->flush.r.x) slot->flush.r.x = rect->x;
        if (rect->y < slot->flush.r.y) slot->flush.r.y = rect->y;
        if (right > flush_right) flush_right = right;
        if (bottom > flush_bottom) flush_bottom = bottom;
        slot->flush.r.width = flush_right - slot->flush.r.x;
        slot->flush.r.height = flush_bottom - slot->flush.r.y;
        if (!slot->flush_only) {
            uint16_t head =
                (uint16_t)(slot->descriptor_base +
                    (command_offset + index) * 2u);

            virtio_gpu_init_sync_hdr(
                &transfer->hdr, VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D);
            transfer->r.x = rect->x;
            transfer->r.y = rect->y;
            transfer->r.width = rect->width;
            transfer->r.height = rect->height;
            transfer->offset =
                ((uint64_t)rect->y * slot->resource_width + rect->x) *
                4ull;
            transfer->resource_id = slot->resource_id;
            memset(&queue->desc[head], 0,
                   2u * sizeof(queue->desc[0]));
            queue->desc[head].addr = virtio_gpu_dma_addr(transfer);
            queue->desc[head].len = sizeof(*transfer);
            queue->desc[head].flags = VRING_DESC_F_NEXT;
            queue->desc[head].next = (uint16_t)(head + 1u);
            queue->desc[head + 1u].addr =
                virtio_gpu_dma_addr(&slot->transfer_responses[index]);
            queue->desc[head + 1u].len =
                sizeof(slot->transfer_responses[index]);
            queue->desc[head + 1u].flags = VRING_DESC_F_WRITE;
            virtio_gpu_queue_publish(queue, head);
        }
    }
    {
        uint16_t head =
            (uint16_t)(slot->descriptor_base +
                (command_offset + transfer_count) * 2u);

        virtio_gpu_init_hdr(
            &slot->flush.hdr, VIRTIO_GPU_CMD_RESOURCE_FLUSH);
        slot->flush.resource_id = slot->resource_id;
        memset(&queue->desc[head], 0, 2u * sizeof(queue->desc[0]));
        queue->desc[head].addr = virtio_gpu_dma_addr(&slot->flush);
        queue->desc[head].len = sizeof(slot->flush);
        queue->desc[head].flags = VRING_DESC_F_NEXT;
        queue->desc[head].next = (uint16_t)(head + 1u);
        queue->desc[head + 1u].addr =
            virtio_gpu_dma_addr(&slot->flush_response);
        queue->desc[head + 1u].len = sizeof(slot->flush_response);
        queue->desc[head + 1u].flags = VRING_DESC_F_WRITE;
        virtio_gpu_queue_publish(queue, head);
    }
    slot->command_count = (uint16_t)command_count;
    slot->completed_commands = 0u;
    slot->submitted_us = boottime_monotonic_us();
    slot->state = VIRTIO_GPU_PRESENT_IN_FLIGHT;
    g_vtgpu_present_stats.submitted_frames++;
    g_vtgpu_present_stats.submitted_rects += count;
    if (!slot->flush_only)
        g_vtgpu_present_stats.transferred_bytes +=
            virtio_gpu_damage_area(&slot->damage) * 4u;
    if (slot->damage.full_screen)
        g_vtgpu_present_stats.full_screen_frames++;
    g_vtgpu_present_stats.in_flight++;
    __sync_synchronize();
    queue->avail->idx = queue->avail_idx;
    __sync_synchronize();
    virtio_queue_notify(queue, VIRTIO_GPU_CTRL_QUEUE);
}

static void virtio_gpu_present_submit_pending_locked(void)
{
    virtio_gpu_present_slot_t *pending =
        &g_vtgpu_present_slots[VIRTIO_GPU_PRESENT_PENDING_SLOT];

    if (pending->state != VIRTIO_GPU_PRESENT_PENDING ||
        !pending->damage.count)
        return;
    for (uint32_t index = 0;
         index < VIRTIO_GPU_PRESENT_INFLIGHT_SLOTS; ++index) {
        virtio_gpu_present_slot_t *slot = &g_vtgpu_present_slots[index];
        uint16_t descriptor_base = slot->descriptor_base;

        if (slot->state != VIRTIO_GPU_PRESENT_FREE) continue;
        virtio_gpu_present_reset_slot(slot, descriptor_base);
        slot->damage = pending->damage;
        slot->resource_id = pending->resource_id;
        slot->resource_width = pending->resource_width;
        slot->resource_height = pending->resource_height;
        slot->flush_only = pending->flush_only;
        slot->set_scanout = pending->set_scanout;
        virtio_gpu_present_reset_slot(pending, 0u);
        virtio_gpu_present_submit_locked(slot);
        g_vtgpu_present_stats.pending = 0u;
        return;
    }
}

static int virtio_gpu_present_slot_for_head(uint32_t head)
{
    for (uint32_t index = 0;
         index < VIRTIO_GPU_PRESENT_INFLIGHT_SLOTS; ++index) {
        const virtio_gpu_present_slot_t *slot =
            &g_vtgpu_present_slots[index];
        uint32_t first = slot->descriptor_base;
        uint32_t end = first + slot->command_count * 2u;

        if (slot->state == VIRTIO_GPU_PRESENT_IN_FLIGHT &&
            head >= first && head < end && ((head - first) & 1u) == 0u)
            return (int)index;
    }
    return -1;
}

static int virtio_gpu_render_slot_for_head(uint32_t head)
{
    if (head < VIRTIO_GPU_RENDER_DESC_FIRST ||
        head >= VIRTIO_GPU_RENDER_DESC_FIRST +
            VIRTIO_GPU_RENDER_SLOT_COUNT * VIRTIO_GPU_RENDER_DESC_COUNT ||
        (head - VIRTIO_GPU_RENDER_DESC_FIRST) %
            VIRTIO_GPU_RENDER_DESC_COUNT != 0u)
        return -1;
    return (int)((head - VIRTIO_GPU_RENDER_DESC_FIRST) /
                 VIRTIO_GPU_RENDER_DESC_COUNT);
}

static int virtio_gpu_render_free_slot_locked(void)
{
    for (uint32_t index = 0; index < VIRTIO_GPU_RENDER_SLOT_COUNT;
         ++index)
        if (!g_vtgpu_render_slots[index].in_flight)
            return (int)index;
    return -1;
}

static void virtio_gpu_render_publish_locked(
    uint32_t slot_index, const virtio_gpu_render_pending_t *pending)
{
    virtio_gpu_queue_t *queue = &g_vtgpu.ctrlq;
    virtio_gpu_render_slot_t *slot = &g_vtgpu_render_slots[slot_index];
    uint16_t head = (uint16_t)(VIRTIO_GPU_RENDER_DESC_FIRST +
        slot_index * VIRTIO_GPU_RENDER_DESC_COUNT);

    memset(slot, 0, sizeof(*slot));
    virtio_gpu_init_hdr(&slot->request.hdr, VIRTIO_GPU_CMD_SUBMIT_3D);
    slot->request.hdr.ctx_id = pending->context_id;
    slot->request.size = pending->command_size;
    slot->commands = pending->commands;
    slot->command_size = pending->command_size;
    slot->completion_id = pending->completion_id;
    slot->submitted_us = boottime_monotonic_us();
    slot->in_flight = 1u;
    memset(&queue->desc[head], 0,
           VIRTIO_GPU_RENDER_DESC_COUNT * sizeof(queue->desc[0]));
    queue->desc[head].addr = virtio_gpu_dma_addr(&slot->request);
    queue->desc[head].len = sizeof(slot->request);
    queue->desc[head].flags = VRING_DESC_F_NEXT;
    queue->desc[head].next = (uint16_t)(head + 1u);
    queue->desc[head + 1u].addr =
        virtio_gpu_dma_addr((void *)pending->commands);
    queue->desc[head + 1u].len = pending->command_size;
    queue->desc[head + 1u].flags = VRING_DESC_F_NEXT;
    queue->desc[head + 1u].next = (uint16_t)(head + 2u);
    queue->desc[head + 2u].addr = virtio_gpu_dma_addr(&slot->response);
    queue->desc[head + 2u].len = sizeof(slot->response);
    queue->desc[head + 2u].flags = VRING_DESC_F_WRITE;
    virtio_gpu_queue_publish(queue, head);
}

static void virtio_gpu_render_dispatch_pending_locked(void)
{
    virtio_gpu_queue_t *queue = &g_vtgpu.ctrlq;
    int published = 0;

    while (g_vtgpu_render_pending_count) {
        virtio_gpu_render_pending_t *pending;
        int slot_index = virtio_gpu_render_free_slot_locked();

        if (slot_index < 0) break;
        pending = &g_vtgpu_render_pending[g_vtgpu_render_pending_head];
        virtio_gpu_render_publish_locked((uint32_t)slot_index, pending);
        memset(pending, 0, sizeof(*pending));
        g_vtgpu_render_pending_head =
            (g_vtgpu_render_pending_head + 1u) %
            VIRTIO_GPU_RENDER_PENDING_COUNT;
        g_vtgpu_render_pending_count--;
        published = 1;
    }
    if (!published) return;
    __sync_synchronize();
    queue->avail->idx = queue->avail_idx;
    __sync_synchronize();
    virtio_queue_notify(queue, VIRTIO_GPU_CTRL_QUEUE);
}

static void virtio_gpu_render_complete_locked(
    virtio_gpu_render_slot_t *slot, int status)
{
    virtio_gpu_render_completion_t *completion;

    if (!slot || !slot->in_flight ||
        g_vtgpu_render_completion_count >= VIRTIO_GPU_RENDER_SLOT_COUNT)
        return;
    completion = &g_vtgpu_render_completions[
        g_vtgpu_render_completion_count++];
    completion->completion_id = slot->completion_id;
    completion->status = status;
    memset(slot, 0, sizeof(*slot));
    __atomic_add_fetch(&g_vtgpu_render_sequence, 1u, __ATOMIC_RELEASE);
    kernel_runtime_notify_sequence(&g_vtgpu_render_sequence);
}

static void virtio_gpu_render_dispatch_completions(void)
{
    virtio_gpu_render_completion_t completions[
        VIRTIO_GPU_RENDER_SLOT_COUNT];
    uint32_t count;
    uint64_t flags;

    flags = spin_lock_irqsave(&g_vtgpu_cmd_lock);
    count = g_vtgpu_render_completion_count;
    if (count)
        memcpy(completions, g_vtgpu_render_completions,
               count * sizeof(completions[0]));
    g_vtgpu_render_completion_count = 0u;
    spin_unlock_irqrestore(&g_vtgpu_cmd_lock, flags);
    for (uint32_t index = 0; index < count; ++index)
        edge_virtgpu_backend_submission_complete(
            completions[index].completion_id,
            completions[index].status);
}

static void virtio_gpu_reap_completions_locked(void)
{
    virtio_gpu_queue_t *queue = &g_vtgpu.ctrlq;
    uint64_t now_us;

    __sync_synchronize();
    while (queue->used_idx != queue->used->idx) {
        struct vring_used_elem *used =
            &queue->used->ring[queue->used_idx % queue->size];
        uint32_t head = used->id;
        int render_slot_index;
        int slot_index;

        queue->used_idx++;
        if (head == 0u && g_vtgpu_sync_state.busy) {
            (void)virtio_gpu_sync_state_device_complete(
                &g_vtgpu_sync_state);
            __atomic_add_fetch(
                &g_vtgpu_sync_sequence, 1u, __ATOMIC_RELEASE);
            kernel_runtime_notify_sequence(&g_vtgpu_sync_sequence);
            continue;
        }
        render_slot_index = virtio_gpu_render_slot_for_head(head);
        if (render_slot_index >= 0) {
            virtio_gpu_render_slot_t *render_slot =
                &g_vtgpu_render_slots[(uint32_t)render_slot_index];
            int status;

            __sync_synchronize();
            status = render_slot->response.type ==
                VIRTIO_GPU_RESP_OK_NODATA ? 0 : -1;
            if (status < 0) {
                virtio_gpu_serial_puts(
                    "[virtio-gpu] SUBMIT_3D failed resp=");
                virtio_gpu_serial_hex32(render_slot->response.type);
                virtio_gpu_serial_puts("\n");
            }
            virtio_gpu_render_complete_locked(render_slot, status);
            continue;
        }
        slot_index = virtio_gpu_present_slot_for_head(head);
        if (slot_index >= 0) {
            virtio_gpu_present_slot_t *slot =
                &g_vtgpu_present_slots[(uint32_t)slot_index];

            slot->completed_commands++;
            if (slot->completed_commands >= slot->command_count) {
                uint64_t completed_us = boottime_monotonic_us();
                uint64_t latency_us = completed_us >= slot->submitted_us ?
                    completed_us - slot->submitted_us : 0u;
                uint16_t descriptor_base = slot->descriptor_base;
                int failed;

                __sync_synchronize();
                failed =
                    slot->flush_response.type !=
                        VIRTIO_GPU_RESP_OK_NODATA;
                if (slot->set_scanout &&
                    slot->scanout_response.type !=
                        VIRTIO_GPU_RESP_OK_NODATA)
                    failed = 1;
                if (!slot->flush_only)
                    for (uint32_t index = 0;
                         index < slot->damage.count; ++index)
                        if (slot->transfer_responses[index].type !=
                            VIRTIO_GPU_RESP_OK_NODATA)
                            failed = 1;
                if (slot->set_scanout &&
                    slot->scanout_response.type ==
                        VIRTIO_GPU_RESP_OK_NODATA) {
                    g_vtgpu.scanout_resource_id = slot->resource_id;
                    g_vtgpu.scanout_width = slot->resource_width;
                    g_vtgpu.scanout_height = slot->resource_height;
                }

                g_vtgpu_present_stats.completed_frames++;
                if (failed) g_vtgpu_present_stats.failed_frames++;
                g_vtgpu_present_stats.completion_latency_total_us +=
                    latency_us;
                if (latency_us >
                    g_vtgpu_present_stats.completion_latency_max_us)
                    g_vtgpu_present_stats.completion_latency_max_us =
                        latency_us;
                if (latency_us > 16700u)
                    g_vtgpu_present_stats.completion_latency_over_16ms++;
                if (latency_us > 33000u)
                    g_vtgpu_present_stats.completion_latency_over_33ms++;
                if (latency_us > 100000u)
                    g_vtgpu_present_stats.completion_latency_over_100ms++;
                if (g_vtgpu_present_stats.in_flight)
                    g_vtgpu_present_stats.in_flight--;
                virtio_gpu_present_reset_slot(slot, descriptor_base);
                __atomic_add_fetch(
                    &g_vtgpu_present_sequence, 1u, __ATOMIC_RELEASE);
                kernel_runtime_notify_sequence(
                    &g_vtgpu_present_sequence);
            }
        }
    }
    virtio_gpu_render_dispatch_pending_locked();
    now_us = boottime_monotonic_us();
    for (uint32_t index = 0;
         index < VIRTIO_GPU_PRESENT_INFLIGHT_SLOTS; ++index) {
        virtio_gpu_present_slot_t *slot = &g_vtgpu_present_slots[index];

        if (slot->state == VIRTIO_GPU_PRESENT_IN_FLIGHT &&
            !slot->timeout_recorded && now_us >= slot->submitted_us &&
            now_us - slot->submitted_us >= VIRTIO_GPU_PRESENT_TIMEOUT_US) {
            slot->timeout_recorded = 1u;
            g_vtgpu_present_stats.timed_out_frames++;
            virtio_gpu_serial_puts(
                "[virtio-gpu] runtime present completion delayed\n");
        }
    }
    virtio_gpu_present_submit_pending_locked();
}

static int virtio_gpu_present_drain(void)
{
    uint64_t deadline = boottime_monotonic_us() +
        VIRTIO_GPU_PRESENT_TIMEOUT_US;

    for (;;) {
        uint64_t flags;
        int idle;

        virtio_ack_isr();
        flags = spin_lock_irqsave(&g_vtgpu_cmd_lock);
        virtio_gpu_reap_completions_locked();
        idle = g_vtgpu_present_stats.in_flight == 0u &&
            g_vtgpu_present_stats.pending == 0u;
        spin_unlock_irqrestore(&g_vtgpu_cmd_lock, flags);
        if (idle) return 0;
        if (boottime_monotonic_us() >= deadline) return -1;
        virtio_gpu_cpu_relax();
    }
}

static int virtio_gpu_present_resource_drain(uint32_t resource_id)
{
    uint64_t deadline;

    if (!resource_id) return -1;
    deadline = boottime_monotonic_us() +
        VIRTIO_GPU_PRESENT_TIMEOUT_US;
    for (;;) {
        virtio_gpu_present_slot_t *pending;
        uint64_t flags;
        uint64_t observed;
        uint64_t now_us;
        int in_flight = 0;

        virtio_ack_isr();
        flags = spin_lock_irqsave(&g_vtgpu_cmd_lock);
        virtio_gpu_reap_completions_locked();
        pending = &g_vtgpu_present_slots[
            VIRTIO_GPU_PRESENT_PENDING_SLOT];
        if (pending->state == VIRTIO_GPU_PRESENT_PENDING &&
            pending->resource_id == resource_id) {
            virtio_gpu_present_reset_slot(pending, 0u);
            g_vtgpu_present_stats.pending = 0u;
            g_vtgpu_present_stats.replaced_frames++;
        }
        for (uint32_t index = 0;
             index < VIRTIO_GPU_PRESENT_INFLIGHT_SLOTS; ++index)
            if (g_vtgpu_present_slots[index].state ==
                    VIRTIO_GPU_PRESENT_IN_FLIGHT &&
                g_vtgpu_present_slots[index].resource_id == resource_id) {
                in_flight = 1;
                break;
            }
        observed = __atomic_load_n(
            &g_vtgpu_present_sequence, __ATOMIC_ACQUIRE);
        spin_unlock_irqrestore(&g_vtgpu_cmd_lock, flags);
        if (!in_flight) return 0;
        now_us = boottime_monotonic_us();
        if (now_us >= deadline) return -1;
#if defined(__x86_64__)
        {
            uint64_t wait_deadline_us =
                now_us + VIRTIO_GPU_SYNC_POLL_US;

            if (wait_deadline_us > deadline)
                wait_deadline_us = deadline;
            (void)kernel_runtime_wait_sequence(
                &g_vtgpu_present_sequence, observed,
                wait_deadline_us);
        }
#else
        virtio_gpu_cpu_relax();
#endif
    }
}

static int virtio_gpu_command_requires_completion(uint32_t type)
{
    return type != VIRTIO_GPU_CMD_GET_DISPLAY_INFO &&
        type != VIRTIO_GPU_CMD_GET_CAPSET_INFO &&
        type != VIRTIO_GPU_CMD_GET_CAPSET &&
        type != VIRTIO_GPU_CMD_GET_EDID;
}

static int virtio_gpu_submit_internal(
    void *req1, uint32_t req1_len, void *req2, uint32_t req2_len,
    void *resp, uint32_t resp_len,
    const edge_virtgpu_backing_t *backing) {
    virtio_gpu_queue_t *q = &g_vtgpu.ctrlq;
    uint16_t head = 0;
    uint16_t idx;
    uint32_t command_type;
    uint32_t polls = 0u;
    uint64_t deadline_us;
    uint64_t start_us;
    uint64_t end_us;
    uint64_t flags;
    int delayed = 0;
    int requires_completion;
    int ret = -1;
    uint32_t secondary_len = req2_len;

    if (backing) {
        if (req2 || req2_len || !backing->segments ||
            !backing->segment_count ||
            backing->segment_count > EDGE_VIRTGPU_BACKING_SEGMENT_MAX)
            return -1;
        secondary_len =
            backing->segment_count * sizeof(struct virtio_gpu_mem_entry);
    }
    if (!req1 || !req1_len || !resp || !resp_len || q->size < 4 ||
        req1_len > sizeof(g_vtgpu_sync_slot.request) ||
        secondary_len > sizeof(g_vtgpu_sync_slot.secondary) ||
        resp_len > sizeof(g_vtgpu_sync_slot.response) ||
        (!backing && (!!req2 != !!req2_len)))
        return -1;
    command_type = ((struct virtio_gpu_ctrl_hdr *)req1)->type;
    requires_completion =
        virtio_gpu_command_requires_completion(command_type);

    /* Reserve descriptor zero for one ordered setup or render command. */
    deadline_us = boottime_monotonic_us() + VIRTIO_GPU_SYNC_TIMEOUT_US;
    for (;;) {
        uint64_t observed;
        uint64_t now_us;
        uint64_t wait_deadline_us;

        flags = spin_lock_irqsave(&g_vtgpu_cmd_lock);
        virtio_gpu_reap_completions_locked();
        if (!g_vtgpu_render_pending_count &&
            virtio_gpu_sync_state_begin(&g_vtgpu_sync_state)) {
            break;
        }
        observed = __atomic_load_n(
            &g_vtgpu_sync_sequence, __ATOMIC_ACQUIRE);
        spin_unlock_irqrestore(&g_vtgpu_cmd_lock, flags);
        now_us = boottime_monotonic_us();
        if (now_us >= deadline_us) return -1;
        wait_deadline_us = now_us + VIRTIO_GPU_SYNC_POLL_US;
        if (wait_deadline_us > deadline_us)
            wait_deadline_us = deadline_us;
        if (kernel_runtime_wait_sequence(
                &g_vtgpu_sync_sequence, observed,
                wait_deadline_us) < 0)
            return -1;
        polls++;
    }
    start_us = boottime_monotonic_us();
    memcpy(g_vtgpu_sync_slot.request, req1, req1_len);
    if (backing) {
        struct virtio_gpu_mem_entry *entries =
            (struct virtio_gpu_mem_entry *)
                g_vtgpu_sync_slot.secondary;

        for (uint32_t index = 0; index < backing->segment_count;
             ++index) {
            const edge_virtgpu_backing_segment_t *segment =
                &backing->segments[index];

            entries[index].addr = virtio_gpu_dma_addr(segment->address);
            entries[index].length =
                segment->page_count * VIRTIO_GPU_PAGE_SIZE;
            entries[index].padding = 0u;
        }
    } else if (req2) {
        memcpy(g_vtgpu_sync_slot.secondary, req2, req2_len);
    }
    memset(g_vtgpu_sync_slot.response, 0, resp_len);
    memset(q->desc, 0, 3u * sizeof(q->desc[0]));
    q->desc[0].addr = virtio_gpu_dma_addr(g_vtgpu_sync_slot.request);
    q->desc[0].len = req1_len;
    q->desc[0].flags = VRING_DESC_F_NEXT;
    q->desc[0].next = secondary_len ? 1 : 2;
    if (secondary_len) {
        q->desc[1].addr =
            virtio_gpu_dma_addr(g_vtgpu_sync_slot.secondary);
        q->desc[1].len = secondary_len;
        q->desc[1].flags = VRING_DESC_F_NEXT;
        q->desc[1].next = 2;
    }
    q->desc[2].addr = virtio_gpu_dma_addr(g_vtgpu_sync_slot.response);
    q->desc[2].len = resp_len;
    q->desc[2].flags = VRING_DESC_F_WRITE;
    q->desc[2].next = 0;

    idx = q->avail_idx++;
    q->avail->ring[idx % q->size] = head;
    __sync_synchronize();
    q->avail->idx = q->avail_idx;
    __sync_synchronize();
    virtio_queue_notify(q, VIRTIO_GPU_CTRL_QUEUE);

    spin_unlock_irqrestore(&g_vtgpu_cmd_lock, flags);

    deadline_us = start_us + VIRTIO_GPU_SYNC_TIMEOUT_US;
    for (;;) {
        uint64_t now_us;
#if defined(__x86_64__)
        uint64_t observed;
#endif

        virtio_ack_isr();
        flags = spin_lock_irqsave(&g_vtgpu_cmd_lock);
        virtio_gpu_reap_completions_locked();
        if (g_vtgpu_sync_state.complete) {
            memcpy(resp, g_vtgpu_sync_slot.response, resp_len);
            (void)virtio_gpu_sync_state_take(&g_vtgpu_sync_state);
            __atomic_add_fetch(
                &g_vtgpu_sync_sequence, 1u, __ATOMIC_RELEASE);
            kernel_runtime_notify_sequence(&g_vtgpu_sync_sequence);
            ret = 0;
            spin_unlock_irqrestore(&g_vtgpu_cmd_lock, flags);
            break;
        }
#if defined(__x86_64__)
        observed = __atomic_load_n(
            &g_vtgpu_sync_sequence, __ATOMIC_ACQUIRE);
#endif
        spin_unlock_irqrestore(&g_vtgpu_cmd_lock, flags);
        now_us = boottime_monotonic_us();
        if (now_us >= deadline_us) {
            if (!requires_completion) break;
            if (!delayed) {
                virtio_gpu_serial_puts(
                    "[virtio-gpu] state command completion delayed type=");
                virtio_gpu_serial_hex32(command_type);
                virtio_gpu_serial_puts("\n");
                delayed = 1;
            }
            deadline_us = now_us + VIRTIO_GPU_SYNC_TIMEOUT_US;
        }
#if defined(__x86_64__)
        {
            uint64_t wait_deadline_us =
                now_us + VIRTIO_GPU_SYNC_POLL_US;

            if (wait_deadline_us > deadline_us)
                wait_deadline_us = deadline_us;
            if (kernel_runtime_wait_sequence(
                    &g_vtgpu_sync_sequence, observed,
                    wait_deadline_us) < 0)
                break;
        }
#else
        virtio_gpu_cpu_relax();
#endif
        polls++;
    }
    if (ret < 0) {
        flags = spin_lock_irqsave(&g_vtgpu_cmd_lock);
        virtio_gpu_reap_completions_locked();
        if (g_vtgpu_sync_state.complete) {
            memcpy(resp, g_vtgpu_sync_slot.response, resp_len);
            (void)virtio_gpu_sync_state_take(&g_vtgpu_sync_state);
            ret = 0;
        } else {
            /*
             * The device owns descriptor zero until it posts the used-ring
             * entry.  Keep the persistent DMA buffers and descriptor reserved
             * after a diagnostic-command timeout.  Reusing them would let a
             * late response complete a different command and write into a
             * returned caller stack.
             */
            (void)virtio_gpu_sync_state_abandon(
                &g_vtgpu_sync_state);
        }
        __atomic_add_fetch(
            &g_vtgpu_sync_sequence, 1u, __ATOMIC_RELEASE);
        kernel_runtime_notify_sequence(&g_vtgpu_sync_sequence);
        spin_unlock_irqrestore(&g_vtgpu_cmd_lock, flags);
        /*
         * A framebuffer present can run while fbcon owns its console lock.
         * Logging a queue timeout through printf() from here recursively enters
         * fbcon and deadlocks the only vCPU.  Keep transport failures visible
         * on the independent serial console, which is also the authoritative
         * development console for EdgeOS.
         */
        if (ret < 0) {
            virtio_gpu_serial_puts("[virtio-gpu] command timeout type=");
            virtio_gpu_serial_hex32(command_type);
            virtio_gpu_serial_puts("\n");
        }
    } else if (g_vtgpu_submit_trace_budget > 0) {
        end_us = boottime_monotonic_us();
        if (end_us - start_us >= 1000ull) {
            printf("[virtio-gpu] submit type=0x%x us=%u spins=%u used=%u budget=%d\n",
                   command_type,
                   (uint32_t)(end_us - start_us), polls, q->used_idx,
                   g_vtgpu_submit_trace_budget - 1);
            g_vtgpu_submit_trace_budget--;
        }
    }
    return ret;
}

static int virtio_gpu_submit(void *req1, uint32_t req1_len,
                             void *req2, uint32_t req2_len,
                             void *resp, uint32_t resp_len) {
    return virtio_gpu_submit_internal(
        req1, req1_len, req2, req2_len, resp, resp_len, 0);
}

static int virtio_gpu_submit_backing(
    void *request, uint32_t request_length,
    const edge_virtgpu_backing_t *backing,
    void *response, uint32_t response_length) {
    return virtio_gpu_submit_internal(
        request, request_length, 0, 0,
        response, response_length, backing);
}

static int virtio_gpu_req(void *req, uint32_t req_len, void *resp, uint32_t resp_len) {
    return virtio_gpu_submit(req, req_len, 0, 0, resp, resp_len);
}

static void virtio_gpu_init_hdr(struct virtio_gpu_ctrl_hdr *hdr, uint32_t type) {
    uint64_t fence;

    memset(hdr, 0, sizeof(*hdr));
    hdr->type = type;
    hdr->flags = VIRTIO_GPU_FLAG_FENCE;
    fence = __atomic_fetch_add(
        &g_vtgpu.next_fence, 1u, __ATOMIC_RELAXED);
    hdr->fence_id = fence ? fence : __atomic_fetch_add(
        &g_vtgpu.next_fence, 1u, __ATOMIC_RELAXED);
}

static void virtio_gpu_init_sync_hdr(struct virtio_gpu_ctrl_hdr *hdr,
                                     uint32_t type) {
    memset(hdr, 0, sizeof(*hdr));
    hdr->type = type;
}

static int virtio_gpu_expect_ok(const struct virtio_gpu_ctrl_hdr *resp, const char *what) {
    if (resp->type == VIRTIO_GPU_RESP_OK_NODATA) return 0;
    virtio_gpu_serial_puts("[virtio-gpu] ");
    virtio_gpu_serial_puts(what);
    virtio_gpu_serial_puts(" failed resp=");
    virtio_gpu_serial_hex32(resp->type);
    virtio_gpu_serial_puts("\n");
    return -1;
}

static int virtio_gpu_digit(char c) {
    return c >= '0' && c <= '9';
}

static int virtio_gpu_parse_u32(const char **sp, uint32_t *out) {
    const char *s = *sp;
    uint32_t v = 0;
    int saw = 0;

    while (virtio_gpu_digit(*s)) {
        uint32_t d = (uint32_t)(*s - '0');
        if (v > (UINT32_MAX - d) / 10u) return -1;
        v = v * 10u + d;
        saw = 1;
        s++;
    }
    if (!saw) return -1;
    *sp = s;
    *out = v;
    return 0;
}

static int virtio_gpu_parse_mode(const char *s, uint32_t *width_out,
                                 uint32_t *height_out,
                                 uint32_t *refresh_out) {
    uint32_t w = 0;
    uint32_t h = 0;
    uint32_t refresh = 0;
    const char *p = s;

    while (*p && !virtio_gpu_digit(*p)) p++;
    if (virtio_gpu_parse_u32(&p, &w) < 0) return -1;
    if (*p != 'x' && *p != 'X') return -1;
    p++;
    if (virtio_gpu_parse_u32(&p, &h) < 0) return -1;
    if (*p == '@') {
        p++;
        if (virtio_gpu_parse_u32(&p, &refresh) < 0 ||
            !refresh || refresh > UINT32_MAX / 1000u)
            return -1;
    }

    if (w < 320u || h < 200u ||
        w > VIRTIO_GPU_FB_MAX_WIDTH || h > VIRTIO_GPU_FB_MAX_HEIGHT) {
        return -1;
    }
    *width_out = w;
    *height_out = h;
    if (refresh_out) *refresh_out = refresh * 1000u;
    return 0;
}

static int virtio_gpu_cmdline_mode(uint32_t *width_out, uint32_t *height_out,
                                   uint32_t *refresh_out) {
    const char *cmd = kernel_boot_command_line_get();
    const char *p = cmd;

    if (!cmd) return -1;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;

        if (strncmp(p, "edgeos.video=", 13) == 0) {
            if (virtio_gpu_parse_mode(
                    p + 13, width_out, height_out, refresh_out) == 0)
                return 0;
        } else if (strncmp(p, "video=", 6) == 0) {
            const char *mode = p + 6;
            const char *colon = mode;

            while (*colon && *colon != ' ' && *colon != ':') colon++;
            if (*colon == ':') mode = colon + 1;
            if (virtio_gpu_parse_mode(
                    mode, width_out, height_out, refresh_out) == 0)
                return 0;
        }

        while (*p && *p != ' ') p++;
    }
    return -1;
}

static void virtio_gpu_apply_cmdline_mode(void) {
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t refresh_millihz = 0;

    if (virtio_gpu_cmdline_mode(
            &width, &height, &refresh_millihz) < 0) return;
    g_vtgpu.width = width;
    g_vtgpu.height = height;
    if (refresh_millihz)
        g_vtgpu.refresh_millihz = refresh_millihz;
    printf("[virtio-gpu] cmdline mode %ux%u@%u\n", width, height,
           g_vtgpu.refresh_millihz / 1000u);
}

static int virtio_gpu_get_display_info(void) {
    struct virtio_gpu_ctrl_hdr req;
    struct virtio_gpu_resp_display_info resp;
    uint32_t scanouts = g_vtgpu.num_scanouts;
    if (scanouts == 0 || scanouts > VIRTIO_GPU_MAX_SCANOUTS) scanouts = VIRTIO_GPU_MAX_SCANOUTS;

    memset(&resp, 0, sizeof(resp));
    virtio_gpu_init_sync_hdr(&req, VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
    if (virtio_gpu_req(&req, sizeof(req), &resp, sizeof(resp)) < 0) return -1;
    if (resp.hdr.type != VIRTIO_GPU_RESP_OK_DISPLAY_INFO) {
        printf("[virtio-gpu] GET_DISPLAY_INFO resp=0x%x\n", resp.hdr.type);
        return -1;
    }
    for (uint32_t i = 0; i < scanouts; ++i) {
        if (!resp.pmodes[i].enabled) continue;
        g_vtgpu.scanout_id = i;
        g_vtgpu.width = resp.pmodes[i].r.width;
        g_vtgpu.height = resp.pmodes[i].r.height;
        if (g_vtgpu.width == 0 || g_vtgpu.height == 0) continue;
        if (g_vtgpu.width > VIRTIO_GPU_FB_MAX_WIDTH || g_vtgpu.height > VIRTIO_GPU_FB_MAX_HEIGHT) {
            printf("[virtio-gpu] scanout %ux%u too large for static boot fb, using 1024x768\n",
                   g_vtgpu.width, g_vtgpu.height);
            g_vtgpu.width = 1024;
            g_vtgpu.height = 768;
        }
        virtio_gpu_apply_cmdline_mode();
        return 0;
    }
    g_vtgpu.width = 1024;
    g_vtgpu.height = 768;
    virtio_gpu_apply_cmdline_mode();
    return 0;
}

static void
virtio_gpu_select_edid_refresh(void)
{
    g_vtgpu.refresh_millihz = DISPLAY_MODE_DEFAULT_REFRESH_MILLIHZ;
    for (uint32_t index = 0; index < g_vtgpu.mode_count; ++index) {
        const display_mode_t *mode = &g_vtgpu.modes[index];

        if (mode->width != g_vtgpu.width || mode->height != g_vtgpu.height)
            continue;
        g_vtgpu.refresh_millihz = mode->refresh_millihz;
        if (mode->flags & DISPLAY_MODE_PREFERRED)
            return;
    }
}

static int
virtio_gpu_get_edid(void)
{
    struct virtio_gpu_get_edid request;
    struct virtio_gpu_resp_edid response;
    int count;

    g_vtgpu.mode_count = 0u;
    g_vtgpu.width_mm = 0u;
    g_vtgpu.height_mm = 0u;
    g_vtgpu.edid_size = 0u;
    if ((g_vtgpu.negotiated_features & VIRTIO_GPU_F_EDID) == 0) {
        g_vtgpu.refresh_millihz = DISPLAY_MODE_DEFAULT_REFRESH_MILLIHZ;
        return -1;
    }
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    virtio_gpu_init_sync_hdr(&request.hdr, VIRTIO_GPU_CMD_GET_EDID);
    request.scanout = g_vtgpu.scanout_id;
    if (virtio_gpu_req(&request, sizeof(request),
                       &response, sizeof(response)) < 0 ||
        response.hdr.type != VIRTIO_GPU_RESP_OK_EDID ||
        response.size < 128u ||
        response.size > sizeof(response.edid)) {
        g_vtgpu.refresh_millihz = DISPLAY_MODE_DEFAULT_REFRESH_MILLIHZ;
        return -1;
    }
    count = display_edid_parse(
        response.edid, response.size, g_vtgpu.modes,
        DISPLAY_MODE_EDID_MAX_MODES,
        &g_vtgpu.width_mm, &g_vtgpu.height_mm);
    if (count < 0) {
        g_vtgpu.refresh_millihz = DISPLAY_MODE_DEFAULT_REFRESH_MILLIHZ;
        return -1;
    }
    g_vtgpu.mode_count = (uint32_t)count;
    g_vtgpu.edid_size = response.size;
    memcpy(g_vtgpu.edid, response.edid, response.size);
    virtio_gpu_select_edid_refresh();
    printf("[virtio-gpu] EDID modes=%u preferred=%ux%u@%u\n",
           g_vtgpu.mode_count, g_vtgpu.width, g_vtgpu.height,
           g_vtgpu.refresh_millihz / 1000u);
    return 0;
}

static int virtio_gpu_create_2d_resource(uint32_t resource_id,
                                         uint32_t format,
                                         uint32_t width,
                                         uint32_t height,
                                         const char *name) {
    struct virtio_gpu_resource_create_2d req;
    struct virtio_gpu_ctrl_hdr resp;

    if (!resource_id || !width || !height) return -1;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    virtio_gpu_init_sync_hdr(&req.hdr, VIRTIO_GPU_CMD_RESOURCE_CREATE_2D);
    req.resource_id = resource_id;
    req.format = format;
    req.width = width;
    req.height = height;
    if (virtio_gpu_req(&req, sizeof(req), &resp, sizeof(resp)) < 0) return -1;
    return virtio_gpu_expect_ok(&resp, name);
}

static int virtio_gpu_create_2d(void) {
    return virtio_gpu_create_2d_resource(
        VIRTIO_GPU_RESOURCE_ID, VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM,
        g_vtgpu.width, g_vtgpu.height, "RESOURCE_CREATE_2D");
}

static int virtio_gpu_attach_resource_backing_segments(
    uint32_t resource_id, const edge_virtgpu_backing_t *backing) {
    struct virtio_gpu_resource_attach_backing req;
    struct virtio_gpu_ctrl_hdr resp;
    uint64_t total_pages = 0u;

    if (!resource_id || !backing || !backing->segments ||
        !backing->segment_count ||
        backing->segment_count > EDGE_VIRTGPU_BACKING_SEGMENT_MAX)
        return -1;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    virtio_gpu_init_sync_hdr(
        &req.hdr, VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING);
    req.resource_id = resource_id;
    req.nr_entries = backing->segment_count;
    for (uint32_t index = 0; index < backing->segment_count; ++index) {
        const edge_virtgpu_backing_segment_t *segment =
            &backing->segments[index];
        uint64_t length =
            (uint64_t)segment->page_count * VIRTIO_GPU_PAGE_SIZE;

        if (!segment->address || !segment->page_count ||
            length > UINT32_MAX)
            return -1;
        total_pages += segment->page_count;
    }
    if (total_pages != backing->page_count) return -1;
    if (virtio_gpu_submit_backing(
            &req, sizeof(req), backing, &resp, sizeof(resp)) < 0)
        return -1;
    return virtio_gpu_expect_ok(&resp, "RESOURCE_ATTACH_BACKING");
}

static int virtio_gpu_attach_resource_backing(
    uint32_t resource_id, void *storage, uint32_t length) {
    edge_virtgpu_backing_segment_t segment;
    edge_virtgpu_backing_t backing;

    if (!storage || !length) return -1;
    memset(&segment, 0, sizeof(segment));
    segment.address = storage;
    segment.page_count =
        (length + VIRTIO_GPU_PAGE_SIZE - 1u) /
        VIRTIO_GPU_PAGE_SIZE;
    memset(&backing, 0, sizeof(backing));
    backing.segments = &segment;
    backing.segment_count = 1u;
    backing.page_count = segment.page_count;
    return virtio_gpu_attach_resource_backing_segments(
        resource_id, &backing);
}

static int virtio_gpu_attach_backing(void) {
    uint32_t bytes = virtio_gpu_framebuffer_bytes(
        g_vtgpu.width, g_vtgpu.height);

    if (!bytes || bytes > g_vtgpu_fb_capacity)
        return -1;
    return virtio_gpu_attach_resource_backing(
        VIRTIO_GPU_RESOURCE_ID, g_vtgpu_fb, bytes);
}

static int virtio_gpu_resource_reference_id(
    uint32_t command, uint32_t resource_id, const char *name) {
    struct virtio_gpu_resource_reference req;
    struct virtio_gpu_ctrl_hdr resp;

    if (!resource_id) return -1;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    virtio_gpu_init_sync_hdr(&req.hdr, command);
    req.resource_id = resource_id;
    if (virtio_gpu_req(&req, sizeof(req), &resp, sizeof(resp)) < 0)
        return -1;
    return virtio_gpu_expect_ok(&resp, name);
}

static int virtio_gpu_context_resource_reference(
    uint32_t command, uint32_t context_id, uint32_t resource_id,
    const char *name) {
    struct virtio_gpu_resource_reference request;
    struct virtio_gpu_ctrl_hdr response;

    if (!context_id || !resource_id) return -1;
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    virtio_gpu_init_sync_hdr(&request.hdr, command);
    request.hdr.ctx_id = context_id;
    request.resource_id = resource_id;
    if (virtio_gpu_req(
            &request, sizeof(request),
            &response, sizeof(response)) < 0)
        return -1;
    return virtio_gpu_expect_ok(&response, name);
}

static int virtio_gpu_resource_reference(uint32_t command,
                                         const char *name) {
    return virtio_gpu_resource_reference_id(
        command, VIRTIO_GPU_RESOURCE_ID, name);
}

static int virtio_gpu_set_scanout_resource(
    uint32_t resource_id, uint32_t width, uint32_t height) {
    struct virtio_gpu_set_scanout req;
    struct virtio_gpu_ctrl_hdr resp;
    int result;

    if (!resource_id || !width || !height) return -1;
    if (g_vtgpu.scanout_resource_id == resource_id &&
        g_vtgpu.scanout_width == width &&
        g_vtgpu.scanout_height == height)
        return 0;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    virtio_gpu_init_sync_hdr(&req.hdr, VIRTIO_GPU_CMD_SET_SCANOUT);
    req.r.width = width;
    req.r.height = height;
    req.scanout_id = 0;
    req.resource_id = resource_id;
    if (virtio_gpu_req(&req, sizeof(req), &resp, sizeof(resp)) < 0)
        return -1;
    result = virtio_gpu_expect_ok(&resp, "SET_SCANOUT");
    if (result == 0) {
        g_vtgpu.scanout_resource_id = resource_id;
        g_vtgpu.scanout_width = width;
        g_vtgpu.scanout_height = height;
    }
    return result;
}

static int virtio_gpu_set_scanout(void) {
    return virtio_gpu_set_scanout_resource(
        VIRTIO_GPU_RESOURCE_ID, g_vtgpu.width, g_vtgpu.height);
}

static int virtio_gpu_disable_scanout(void) {
    struct virtio_gpu_set_scanout req;
    struct virtio_gpu_ctrl_hdr resp;

    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    virtio_gpu_init_sync_hdr(&req.hdr, VIRTIO_GPU_CMD_SET_SCANOUT);
    req.scanout_id = 0;
    req.resource_id = 0;
    if (virtio_gpu_req(&req, sizeof(req), &resp, sizeof(resp)) < 0)
        return -1;
    if (virtio_gpu_expect_ok(&resp, "DISABLE_SCANOUT") < 0)
        return -1;
    g_vtgpu.scanout_resource_id = 0u;
    g_vtgpu.scanout_width = 0u;
    g_vtgpu.scanout_height = 0u;
    return 0;
}

static int virtio_gpu_transfer_resource(
    uint32_t resource_id, uint32_t resource_width,
    uint32_t resource_height, uint32_t x, uint32_t y,
    uint32_t width, uint32_t height, const char *name) {
    struct virtio_gpu_transfer_to_host_2d req;
    struct virtio_gpu_ctrl_hdr resp;

    if (!resource_id || !width || !height ||
        x >= resource_width || y >= resource_height)
        return 0;
    if (x + width > resource_width) width = resource_width - x;
    if (y + height > resource_height) height = resource_height - y;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    virtio_gpu_init_sync_hdr(&req.hdr, VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D);
    req.r.x = x;
    req.r.y = y;
    req.r.width = width;
    req.r.height = height;
    req.offset = ((uint64_t)y * resource_width + x) * 4ull;
    req.resource_id = resource_id;
    if (virtio_gpu_req(&req, sizeof(req), &resp, sizeof(resp)) < 0) return -1;
    return virtio_gpu_expect_ok(&resp, name);
}

static int virtio_gpu_transfer(uint32_t x, uint32_t y,
                               uint32_t width, uint32_t height) {
    return virtio_gpu_transfer_resource(
        VIRTIO_GPU_RESOURCE_ID, g_vtgpu.width, g_vtgpu.height,
        x, y, width, height, "TRANSFER_TO_HOST_2D");
}

static int virtio_gpu_resource_flush_id(
    uint32_t resource_id, uint32_t resource_width,
    uint32_t resource_height, uint32_t x, uint32_t y,
    uint32_t width, uint32_t height) {
    struct virtio_gpu_resource_flush req;
    struct virtio_gpu_ctrl_hdr resp;
    if (!resource_id || !width || !height ||
        x >= resource_width || y >= resource_height)
        return 0;
    if (x + width > resource_width) width = resource_width - x;
    if (y + height > resource_height) height = resource_height - y;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    virtio_gpu_init_sync_hdr(&req.hdr, VIRTIO_GPU_CMD_RESOURCE_FLUSH);
    req.r.x = x;
    req.r.y = y;
    req.r.width = width;
    req.r.height = height;
    req.resource_id = resource_id;
    if (virtio_gpu_req(&req, sizeof(req), &resp, sizeof(resp)) < 0) return -1;
    return virtio_gpu_expect_ok(&resp, "RESOURCE_FLUSH");
}

static int virtio_gpu_resource_flush(
    uint32_t x, uint32_t y, uint32_t width, uint32_t height) {
    return virtio_gpu_resource_flush_id(
        VIRTIO_GPU_RESOURCE_ID, g_vtgpu.width, g_vtgpu.height,
        x, y, width, height);
}

static void virtio_gpu_present_enqueue_resource(
    uint32_t resource_id, uint32_t resource_width,
    uint32_t resource_height, int flush_only, int set_scanout,
    const display_rect_t *rects, uint32_t count)
{
    virtio_gpu_present_slot_t *pending =
        &g_vtgpu_present_slots[VIRTIO_GPU_PRESENT_PENDING_SLOT];
    uint64_t flags;
    uint32_t previous_count;

    if (!g_vtgpu.present || !resource_id || !resource_width ||
        !resource_height || !rects || !count)
        return;
    flags = spin_lock_irqsave(&g_vtgpu_cmd_lock);
    virtio_gpu_reap_completions_locked();
    if (pending->state != VIRTIO_GPU_PRESENT_PENDING ||
        pending->resource_id != resource_id ||
        pending->resource_width != resource_width ||
        pending->resource_height != resource_height ||
        pending->flush_only != (flush_only ? 1u : 0u) ||
        pending->set_scanout != (set_scanout ? 1u : 0u)) {
        if (pending->state == VIRTIO_GPU_PRESENT_PENDING) {
            g_vtgpu_present_stats.coalesced_frames++;
            g_vtgpu_present_stats.replaced_frames++;
        }
        virtio_gpu_present_reset_slot(pending, 0u);
        pending->state = VIRTIO_GPU_PRESENT_PENDING;
        pending->resource_id = resource_id;
        pending->resource_width = resource_width;
        pending->resource_height = resource_height;
        pending->flush_only = flush_only ? 1u : 0u;
        pending->set_scanout = set_scanout ? 1u : 0u;
        g_vtgpu_present_stats.pending = 1u;
    } else {
        g_vtgpu_present_stats.coalesced_frames++;
        g_vtgpu_present_stats.replaced_frames++;
    }
    previous_count = pending->damage.count;
    virtio_gpu_damage_add(&pending->damage, rects, count,
                          resource_width, resource_height);
    if (!pending->damage.count) {
        if (!previous_count) {
            virtio_gpu_present_reset_slot(pending, 0u);
            g_vtgpu_present_stats.pending = 0u;
        }
        spin_unlock_irqrestore(&g_vtgpu_cmd_lock, flags);
        return;
    }
    virtio_gpu_present_submit_pending_locked();
    spin_unlock_irqrestore(&g_vtgpu_cmd_lock, flags);
}

static void virtio_gpu_present_enqueue(const display_rect_t *rects,
                                       uint32_t count)
{
    virtio_gpu_present_enqueue_resource(
        VIRTIO_GPU_RESOURCE_ID, g_vtgpu.width, g_vtgpu.height, 0, 0,
        rects, count);
}

static void virtio_gpu_log_capsets(void) {
    memset(g_vtgpu.capsets, 0, sizeof(g_vtgpu.capsets));
    g_vtgpu.supported_capsets = 0;
    g_vtgpu.maximum_capset_size = 0;
    for (uint32_t i = 0;
         i < g_vtgpu.num_capsets && i < VIRTIO_GPU_CAPSET_COUNT; ++i) {
        struct virtio_gpu_get_capset_info req;
        struct virtio_gpu_resp_capset_info resp;
        memset(&req, 0, sizeof(req));
        memset(&resp, 0, sizeof(resp));
        virtio_gpu_init_sync_hdr(
            &req.hdr, VIRTIO_GPU_CMD_GET_CAPSET_INFO);
        req.capset_index = i;
        if (virtio_gpu_req(&req, sizeof(req), &resp, sizeof(resp)) < 0) return;
        if (resp.hdr.type != VIRTIO_GPU_RESP_OK_CAPSET_INFO) continue;
        g_vtgpu.capsets[i].id = resp.capset_id;
        g_vtgpu.capsets[i].maximum_version =
            resp.capset_max_version;
        g_vtgpu.capsets[i].maximum_size = resp.capset_max_size;
        if (resp.capset_id < 64u &&
            (resp.capset_id == VIRTIO_GPU_CAPSET_VIRGL ||
             resp.capset_id == VIRTIO_GPU_CAPSET_VIRGL2))
            g_vtgpu.supported_capsets |= 1ull << resp.capset_id;
        if (resp.capset_max_size > g_vtgpu.maximum_capset_size &&
            resp.capset_max_size <= VIRTIO_GPU_CAPSET_MAX_SIZE)
            g_vtgpu.maximum_capset_size = resp.capset_max_size;
        printf("[virtio-gpu] capset index=%u id=%u version=%u size=%u%s\n",
               i, resp.capset_id, resp.capset_max_version, resp.capset_max_size,
               (resp.capset_id == VIRTIO_GPU_CAPSET_VIRGL ||
                resp.capset_id == VIRTIO_GPU_CAPSET_VIRGL2) ? " virgl" : "");
    }
}

static int virtio_gpu_render_context_create(
    void *context, uint32_t context_id, uint32_t capset_id,
    const char *name) {
    struct virtio_gpu_ctx_create request;
    struct virtio_gpu_ctrl_hdr response;
    uint32_t length = 0;

    if (context != &g_vtgpu || !context_id || !name) return -1;
    while (name[length] && length < sizeof(request.debug_name) - 1u)
        length++;
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    virtio_gpu_init_sync_hdr(&request.hdr, VIRTIO_GPU_CMD_CTX_CREATE);
    request.hdr.ctx_id = context_id;
    request.name_length = length;
    if (g_vtgpu.negotiated_features & VIRTIO_GPU_F_CONTEXT_INIT)
        request.context_init = capset_id & 0xffu;
    memcpy(request.debug_name, name, length);
    if (virtio_gpu_req(
            &request, sizeof(request),
            &response, sizeof(response)) < 0)
        return -1;
    return virtio_gpu_expect_ok(&response, "CTX_CREATE");
}

static int virtio_gpu_render_context_destroy(
    void *context, uint32_t context_id) {
    struct virtio_gpu_ctx_destroy request;
    struct virtio_gpu_ctrl_hdr response;

    if (context != &g_vtgpu || !context_id) return -1;
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    virtio_gpu_init_sync_hdr(&request.hdr, VIRTIO_GPU_CMD_CTX_DESTROY);
    request.hdr.ctx_id = context_id;
    if (virtio_gpu_req(
            &request, sizeof(request),
            &response, sizeof(response)) < 0)
        return -1;
    return virtio_gpu_expect_ok(&response, "CTX_DESTROY");
}

static int virtio_gpu_render_resource_create(
    void *context, uint32_t context_id, uint32_t resource_id,
    const edge_virtgpu_resource_create_t *create,
    const edge_virtgpu_backing_t *backing, uint64_t size) {
    struct virtio_gpu_resource_create_3d request;
    struct virtio_gpu_ctrl_hdr response;

    if (context != &g_vtgpu || !context_id || !resource_id || !create ||
        !backing || !size || size > UINT32_MAX)
        return -1;
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    virtio_gpu_init_sync_hdr(
        &request.hdr, VIRTIO_GPU_CMD_RESOURCE_CREATE_3D);
    request.resource_id = resource_id;
    request.target = create->target;
    request.format = create->format;
    request.bind = create->bind;
    request.width = create->width;
    request.height = create->height;
    request.depth = create->depth;
    request.array_size = create->array_size;
    request.last_level = create->last_level;
    request.nr_samples = create->nr_samples;
    request.flags = create->flags;
    if (virtio_gpu_req(
            &request, sizeof(request),
            &response, sizeof(response)) < 0 ||
        virtio_gpu_expect_ok(
            &response, "RESOURCE_CREATE_3D") < 0)
        return -1;
    if (virtio_gpu_attach_resource_backing_segments(
            resource_id, backing) < 0) {
        (void)virtio_gpu_resource_reference_id(
            VIRTIO_GPU_CMD_RESOURCE_UNREF, resource_id,
            "RESOURCE_UNREF_RECOVERY");
        return -1;
    }
    if (virtio_gpu_context_resource_reference(
            VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE, context_id, resource_id,
            "CTX_ATTACH_RESOURCE") < 0) {
        (void)virtio_gpu_resource_reference_id(
            VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING, resource_id,
            "RESOURCE_DETACH_BACKING_RECOVERY");
        (void)virtio_gpu_resource_reference_id(
            VIRTIO_GPU_CMD_RESOURCE_UNREF, resource_id,
            "RESOURCE_UNREF_RECOVERY");
        return -1;
    }
    return 0;
}

static int virtio_gpu_render_resource_destroy(
    void *context, uint32_t context_id, uint32_t resource_id) {
    int result = 0;

    if (context != &g_vtgpu || !context_id || !resource_id) return -1;
    if (virtio_gpu_present_resource_drain(resource_id) < 0) return -1;
    if (g_vtgpu.scanout_resource_id == resource_id &&
        virtio_gpu_set_scanout() < 0)
        result = -1;
    if (virtio_gpu_context_resource_reference(
            VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE, context_id, resource_id,
            "CTX_DETACH_RESOURCE") < 0)
        result = -1;
    if (virtio_gpu_resource_reference_id(
            VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING, resource_id,
            "RESOURCE_DETACH_BACKING_3D") < 0)
        result = -1;
    if (virtio_gpu_resource_reference_id(
            VIRTIO_GPU_CMD_RESOURCE_UNREF, resource_id,
            "RESOURCE_UNREF_3D") < 0)
        result = -1;
    return result;
}

static int virtio_gpu_render_resource_attach(
    void *context, uint32_t context_id, uint32_t resource_id) {
    if (context != &g_vtgpu || !context_id || !resource_id)
        return -1;
    return virtio_gpu_context_resource_reference(
        VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE, context_id, resource_id,
        "CTX_ATTACH_IMPORTED_RESOURCE");
}

static int virtio_gpu_render_resource_detach(
    void *context, uint32_t context_id, uint32_t resource_id) {
    if (context != &g_vtgpu || !context_id || !resource_id)
        return -1;
    if (virtio_gpu_present_resource_drain(resource_id) < 0) return -1;
    return virtio_gpu_context_resource_reference(
        VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE, context_id, resource_id,
        "CTX_DETACH_IMPORTED_RESOURCE");
}

static int virtio_gpu_render_present_resource(
    void *context, uint32_t resource_id,
    uint32_t resource_width, uint32_t resource_height,
    uint32_t x, uint32_t y, uint32_t width, uint32_t height) {
    if (context != &g_vtgpu || !g_vtgpu.present)
        return -1;
    if (!resource_id)
        return virtio_gpu_set_scanout();
    if (!resource_width || !resource_height ||
        !width || !height || x >= resource_width ||
        y >= resource_height ||
        width > resource_width - x ||
        height > resource_height - y)
        return -1;
    if (g_vtgpu_runtime_present_ready) {
        display_rect_t rect = { x, y, width, height };

        virtio_gpu_present_enqueue_resource(
            resource_id, resource_width, resource_height, 1, 1,
            &rect, 1u);
        return 0;
    }
    if (virtio_gpu_set_scanout_resource(
            resource_id, resource_width, resource_height) < 0)
        return -1;
    return virtio_gpu_resource_flush_id(
        resource_id, resource_width, resource_height,
        x, y, width, height);
}

static int virtio_gpu_render_transfer(
    uint32_t command, void *context, uint32_t context_id,
    uint32_t resource_id, const edge_virtgpu_transfer_t *transfer) {
    struct virtio_gpu_transfer_host_3d request;
    struct virtio_gpu_ctrl_hdr response;

    if (context != &g_vtgpu || !context_id || !resource_id ||
        !transfer)
        return -1;
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    virtio_gpu_init_hdr(&request.hdr, command);
    request.hdr.ctx_id = context_id;
    request.box.x = transfer->x;
    request.box.y = transfer->y;
    request.box.z = transfer->z;
    request.box.width = transfer->width;
    request.box.height = transfer->height;
    request.box.depth = transfer->depth;
    request.offset = transfer->offset;
    request.resource_id = resource_id;
    request.level = transfer->level;
    request.stride = transfer->stride;
    request.layer_stride = transfer->layer_stride;
    if (virtio_gpu_req(
            &request, sizeof(request),
            &response, sizeof(response)) < 0)
        return -1;
    return virtio_gpu_expect_ok(
        &response, command == VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D ?
            "TRANSFER_TO_HOST_3D" : "TRANSFER_FROM_HOST_3D");
}

static int virtio_gpu_render_transfer_to(
    void *context, uint32_t context_id, uint32_t resource_id,
    const edge_virtgpu_transfer_t *transfer) {
    return virtio_gpu_render_transfer(
        VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D, context, context_id,
        resource_id, transfer);
}

static int virtio_gpu_render_transfer_from(
    void *context, uint32_t context_id, uint32_t resource_id,
    const edge_virtgpu_transfer_t *transfer) {
    return virtio_gpu_render_transfer(
        VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D, context, context_id,
        resource_id, transfer);
}

static int virtio_gpu_render_submit(
    void *context, uint32_t context_id,
    const void *commands, uint32_t size, uint64_t completion_id) {
    virtio_gpu_render_pending_t *pending;
    uint64_t flags;

    if (context != &g_vtgpu || !context_id || !commands || !size ||
        !completion_id)
        return -1;
    flags = spin_lock_irqsave(&g_vtgpu_cmd_lock);
    virtio_gpu_reap_completions_locked();
    if (g_vtgpu_render_pending_count >=
        VIRTIO_GPU_RENDER_PENDING_COUNT) {
        spin_unlock_irqrestore(&g_vtgpu_cmd_lock, flags);
        virtio_gpu_render_dispatch_completions();
        return -1;
    }
    pending = &g_vtgpu_render_pending[g_vtgpu_render_pending_tail];
    pending->commands = commands;
    pending->completion_id = completion_id;
    pending->context_id = context_id;
    pending->command_size = size;
    g_vtgpu_render_pending_tail =
        (g_vtgpu_render_pending_tail + 1u) %
        VIRTIO_GPU_RENDER_PENDING_COUNT;
    g_vtgpu_render_pending_count++;
    virtio_gpu_render_dispatch_pending_locked();
    spin_unlock_irqrestore(&g_vtgpu_cmd_lock, flags);
    virtio_gpu_render_dispatch_completions();
    return 0;
}

static const virtio_gpu_capset_t *virtio_gpu_capset(
    uint32_t id, uint32_t version) {
    for (uint32_t index = 0; index < VIRTIO_GPU_CAPSET_COUNT; ++index)
        if (g_vtgpu.capsets[index].id == id &&
            version <= g_vtgpu.capsets[index].maximum_version)
            return &g_vtgpu.capsets[index];
    return 0;
}

static int virtio_gpu_render_get_capset(
    void *context, uint32_t capset_id, uint32_t version,
    void *data, uint32_t size, uint32_t *actual_size) {
    const virtio_gpu_capset_t *capset;
    struct virtio_gpu_get_capset request;
    struct virtio_gpu_ctrl_hdr *response;
    uint32_t count;

    if (context != &g_vtgpu || !data || !size || !actual_size)
        return -1;
    capset = virtio_gpu_capset(capset_id, version);
    if (!capset || capset->maximum_size > VIRTIO_GPU_CAPSET_MAX_SIZE)
        return -1;
    memset(&request, 0, sizeof(request));
    memset(g_vtgpu_capset_response, 0,
           sizeof(struct virtio_gpu_ctrl_hdr) + capset->maximum_size);
    virtio_gpu_init_sync_hdr(&request.hdr, VIRTIO_GPU_CMD_GET_CAPSET);
    request.capset_id = capset_id;
    request.capset_version = version;
    if (virtio_gpu_req(
            &request, sizeof(request), g_vtgpu_capset_response,
            sizeof(struct virtio_gpu_ctrl_hdr) +
                capset->maximum_size) < 0)
        return -1;
    response =
        (struct virtio_gpu_ctrl_hdr *)g_vtgpu_capset_response;
    if (response->type != VIRTIO_GPU_RESP_OK_CAPSET)
        return virtio_gpu_expect_ok(response, "GET_CAPSET");
    count = size < capset->maximum_size ?
        size : capset->maximum_size;
    memcpy(data,
           g_vtgpu_capset_response +
               sizeof(struct virtio_gpu_ctrl_hdr),
           count);
    *actual_size = count;
    return 0;
}

static int virtio_gpu_register_render_backend(void) {
    edge_virtgpu_backend_t backend;

    if (!g_vtgpu.virgl || !g_vtgpu.supported_capsets ||
        !g_vtgpu.maximum_capset_size)
        return -1;
    memset(&backend, 0, sizeof(backend));
    backend.name = "virtio_gpu";
    backend.owner = &g_vtgpu;
    backend.context = &g_vtgpu;
    backend.info.flags =
        EDGE_VIRTGPU_BACKEND_VIRGL |
        EDGE_VIRTGPU_BACKEND_CAPSET_QUERY_FIX;
    if (g_vtgpu.negotiated_features & VIRTIO_GPU_F_CONTEXT_INIT)
        backend.info.flags |= EDGE_VIRTGPU_BACKEND_CONTEXT_INIT;
    backend.info.supported_capsets = g_vtgpu.supported_capsets;
    backend.info.maximum_command_size = 4u * 1024u * 1024u;
    backend.info.maximum_capset_size = g_vtgpu.maximum_capset_size;
    backend.operations.context_create =
        virtio_gpu_render_context_create;
    backend.operations.context_destroy =
        virtio_gpu_render_context_destroy;
    backend.operations.resource_create =
        virtio_gpu_render_resource_create;
    backend.operations.resource_destroy =
        virtio_gpu_render_resource_destroy;
    backend.operations.resource_attach =
        virtio_gpu_render_resource_attach;
    backend.operations.resource_detach =
        virtio_gpu_render_resource_detach;
    backend.operations.transfer_to_host =
        virtio_gpu_render_transfer_to;
    backend.operations.transfer_from_host =
        virtio_gpu_render_transfer_from;
    backend.operations.submit_3d = virtio_gpu_render_submit;
    backend.operations.get_capset = virtio_gpu_render_get_capset;
    backend.operations.present_resource =
        virtio_gpu_render_present_resource;
    return edge_virtgpu_backend_register(&backend);
}

static int
virtio_gpu_display_get_mode(void *context, display_mode_t *mode)
{
    virtio_gpu_dev_t *device = context;

    if (!device || !mode || !device->present)
        return -1;
    *mode = (display_mode_t) {
        .width = device->width,
        .height = device->height,
        .refresh_millihz = device->refresh_millihz ?
            device->refresh_millihz :
            DISPLAY_MODE_DEFAULT_REFRESH_MILLIHZ,
    };
    return 0;
}

static uint32_t
virtio_gpu_display_get_modes(void *context, display_mode_t *modes,
                             uint32_t capacity)
{
    virtio_gpu_dev_t *device = context;
    uint32_t count;

    if (!device || !device->present)
        return 0;
    count = device->mode_count < capacity ? device->mode_count : capacity;
    for (uint32_t index = 0; modes && index < count; ++index)
        modes[index] = device->modes[index];
    return device->mode_count;
}

static uint32_t
virtio_gpu_display_get_edid(void *context, uint8_t *edid,
                            uint32_t capacity)
{
    virtio_gpu_dev_t *device = context;
    uint32_t count;

    if (!device || !device->present || !device->edid_size)
        return 0;
    count = device->edid_size < capacity ? device->edid_size : capacity;
    if (edid && count)
        memcpy(edid, device->edid, count);
    return device->edid_size;
}

static int
virtio_gpu_rebuild_mode(const display_mode_t *requested)
{
    uint32_t old_width = g_vtgpu.width;
    uint32_t old_height = g_vtgpu.height;
    uint32_t old_refresh_millihz = g_vtgpu.refresh_millihz;
    uint32_t width;
    uint32_t height;
    uint32_t required_bytes;
    uint8_t *old_fb = g_vtgpu_fb;
    uint32_t old_fb_capacity = g_vtgpu_fb_capacity;
    uint8_t *old_fb_allocation = g_vtgpu_fb_allocation;
    uint32_t old_fb_allocation_pages = g_vtgpu_fb_allocation_pages;
    uint8_t *new_fb = old_fb;
    uint32_t new_fb_capacity = old_fb_capacity;
    uint8_t *new_fb_allocation = old_fb_allocation;
    uint32_t new_fb_allocation_pages = old_fb_allocation_pages;
    int allocated_fb = 0;
    int detached = 0;
    int old_unreferenced = 0;
    int new_created = 0;
    int error = -1;

    if (!display_mode_valid(requested))
        return -1;
    width = requested->width;
    height = requested->height;
    if (width < 320u || height < 200u ||
        width > VIRTIO_GPU_FB_MAX_WIDTH ||
        height > VIRTIO_GPU_FB_MAX_HEIGHT)
        return -1;
    required_bytes = virtio_gpu_framebuffer_bytes(width, height);
    if (!required_bytes)
        return -1;
    if (width == old_width && height == old_height) {
        g_vtgpu.refresh_millihz = requested->refresh_millihz;
        return 0;
    }
    if (__atomic_test_and_set(&g_vtgpu_mode_guard, __ATOMIC_ACQUIRE))
        return -1;
    if (required_bytes > old_fb_capacity) {
        new_fb = virtio_gpu_framebuffer_allocate(
            required_bytes, &new_fb_allocation,
            &new_fb_allocation_pages, &new_fb_capacity);
        if (!new_fb) {
            __atomic_clear(&g_vtgpu_mode_guard, __ATOMIC_RELEASE);
            return -1;
        }
        allocated_fb = 1;
    }
    g_vtgpu_runtime_present_ready = 0u;
    if (virtio_gpu_present_drain() < 0) {
        g_vtgpu_runtime_present_ready = 1u;
        if (allocated_fb)
            virtio_gpu_framebuffer_release(
                new_fb_allocation, new_fb_allocation_pages);
        __atomic_clear(&g_vtgpu_mode_guard, __ATOMIC_RELEASE);
        return -1;
    }

    g_vtgpu.present = 0;
    display_backend_unregister(&g_vtgpu);
    if (virtio_gpu_disable_scanout() < 0)
        goto restore;
    if (virtio_gpu_resource_reference(
        VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING,
        "RESOURCE_DETACH_BACKING") < 0)
        goto restore;
    detached = 1;
    if (virtio_gpu_resource_reference(VIRTIO_GPU_CMD_RESOURCE_UNREF,
        "RESOURCE_UNREF") < 0)
        goto restore;
    old_unreferenced = 1;

    g_vtgpu.width = width;
    g_vtgpu.height = height;
    g_vtgpu.refresh_millihz = requested->refresh_millihz;
    g_vtgpu_fb = new_fb;
    g_vtgpu_fb_capacity = new_fb_capacity;
    g_vtgpu_fb_allocation = new_fb_allocation;
    g_vtgpu_fb_allocation_pages = new_fb_allocation_pages;
    memset(g_vtgpu_fb, 0, required_bytes);
    if (virtio_gpu_create_2d() < 0)
        goto restore;
    new_created = 1;
    if (virtio_gpu_attach_backing() < 0 ||
        virtio_gpu_set_scanout() < 0)
        goto restore;
    error = 0;

restore:
    if (error != 0) {
        g_vtgpu.width = old_width;
        g_vtgpu.height = old_height;
        g_vtgpu.refresh_millihz = old_refresh_millihz;
        g_vtgpu_fb = old_fb;
        g_vtgpu_fb_capacity = old_fb_capacity;
        g_vtgpu_fb_allocation = old_fb_allocation;
        g_vtgpu_fb_allocation_pages = old_fb_allocation_pages;
        if (old_unreferenced) {
            if (new_created) {
                (void)virtio_gpu_resource_reference(
                    VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING,
                    "RESOURCE_DETACH_BACKING_RECOVERY");
                (void)virtio_gpu_resource_reference(
                    VIRTIO_GPU_CMD_RESOURCE_UNREF,
                    "RESOURCE_UNREF_RECOVERY");
            }
            if (virtio_gpu_create_2d() < 0 ||
                virtio_gpu_attach_backing() < 0 ||
                virtio_gpu_set_scanout() < 0)
                goto failed;
        } else {
            if (detached && virtio_gpu_attach_backing() < 0)
                goto failed;
            if (virtio_gpu_set_scanout() < 0)
                goto failed;
        }
    }

    fb_install_physical(virtio_gpu_dma_addr(g_vtgpu_fb), g_vtgpu_fb,
                        g_vtgpu.width, g_vtgpu.height,
                        g_vtgpu.width * 4u, 32, 16, 8, 0,
                        0x00FF0000u, 0x0000FF00u, 0x000000FFu);
    g_vtgpu.present = 1;
    if (virtio_gpu_register_display_backend() < 0) {
        g_vtgpu.present = 0;
        __atomic_clear(&g_vtgpu_mode_guard, __ATOMIC_RELEASE);
        return -1;
    }
    virtio_gpu_flush_rect(0, 0, g_vtgpu.width, g_vtgpu.height);
    g_vtgpu_runtime_present_ready = 1u;
    if (error == 0 && allocated_fb)
        virtio_gpu_framebuffer_release(
            old_fb_allocation, old_fb_allocation_pages);
    else if (error != 0 && allocated_fb)
        virtio_gpu_framebuffer_release(
            new_fb_allocation, new_fb_allocation_pages);
    if (error == 0)
        printf("[virtio-gpu] live mode changed to %ux%u@%u\n",
               g_vtgpu.width, g_vtgpu.height,
               g_vtgpu.refresh_millihz / 1000u);
    __atomic_clear(&g_vtgpu_mode_guard, __ATOMIC_RELEASE);
    return error;

failed:
    if (allocated_fb) {
        g_vtgpu_fb = old_fb;
        g_vtgpu_fb_capacity = old_fb_capacity;
        g_vtgpu_fb_allocation = old_fb_allocation;
        g_vtgpu_fb_allocation_pages = old_fb_allocation_pages;
        virtio_gpu_framebuffer_release(
            new_fb_allocation, new_fb_allocation_pages);
    }
    __atomic_clear(&g_vtgpu_mode_guard, __ATOMIC_RELEASE);
    return -1;
}

static int
virtio_gpu_display_set_mode(void *context, const display_mode_t *mode)
{
    if (context != &g_vtgpu || !mode)
        return -1;
    return virtio_gpu_rebuild_mode(mode);
}

static int
virtio_gpu_display_poll(void *context)
{
    virtio_gpu_dev_t *device = context;
    uint64_t now_us;
    uint32_t events;
    uint32_t old_width;
    uint32_t old_height;
    uint32_t requested_width;
    uint32_t requested_height;
    uint32_t old_refresh_millihz;
    display_mode_t requested_mode;

    if (device != &g_vtgpu || !device->present)
        return 0;
    virtio_gpu_poll_presents();
    now_us = boottime_monotonic_us();
    if (device->next_event_poll_us && now_us < device->next_event_poll_us)
        return 0;
    device->next_event_poll_us = now_us + 50000ull;
    events = virtio_device_config_read32(0);
    if ((events & VIRTIO_GPU_EVENT_DISPLAY) == 0)
        return 0;

    old_width = device->width;
    old_height = device->height;
    old_refresh_millihz = device->refresh_millihz;
    if (virtio_gpu_get_display_info() < 0) {
        device->width = old_width;
        device->height = old_height;
        virtio_device_config_write32(4, VIRTIO_GPU_EVENT_DISPLAY);
        return -1;
    }
    (void)virtio_gpu_get_edid();
    virtio_gpu_apply_cmdline_mode();
    requested_width = device->width;
    requested_height = device->height;
    memset(&requested_mode, 0, sizeof(requested_mode));
    requested_mode.width = requested_width;
    requested_mode.height = requested_height;
    requested_mode.refresh_millihz = device->refresh_millihz;
    device->width = old_width;
    device->height = old_height;
    device->refresh_millihz = old_refresh_millihz;
    virtio_device_config_write32(4, VIRTIO_GPU_EVENT_DISPLAY);
    if (requested_width == old_width && requested_height == old_height &&
        requested_mode.refresh_millihz == old_refresh_millihz)
        return 0;
    return virtio_gpu_rebuild_mode(&requested_mode);
}

static int
virtio_gpu_register_display_backend(void)
{
    display_backend_t backend = {
        .name = "virtio-gpu",
        .owner = &g_vtgpu,
        .context = &g_vtgpu,
        .flags = DISPLAY_BACKEND_EXPLICIT_PRESENT |
                 DISPLAY_BACKEND_DYNAMIC_MODE,
        .operations = {
            .present_rect = virtio_gpu_display_present,
            .present_rects = virtio_gpu_display_present_batch,
            .get_mode = virtio_gpu_display_get_mode,
            .get_modes = virtio_gpu_display_get_modes,
            .get_edid = virtio_gpu_display_get_edid,
            .set_mode = virtio_gpu_display_set_mode,
            .poll = virtio_gpu_display_poll,
        },
    };

    return display_backend_register(&backend);
}

static int virtio_gpu_initialize_device(void) {
    uint64_t host_features;
    uint64_t guest_features;

    printf("[virtio-gpu] init reset\n");
    g_vtgpu.refresh_millihz = DISPLAY_MODE_DEFAULT_REFRESH_MILLIHZ;
    virtio_status_set(VIRTIO_CONFIG_STATUS_RESET);
    for (uint32_t spin = 0; spin < 1000000u && virtio_status_get() != VIRTIO_CONFIG_STATUS_RESET; ++spin) {
        virtio_gpu_cpu_relax();
    }
    virtio_status_set(VIRTIO_CONFIG_STATUS_ACK);
    virtio_status_set((uint8_t)(VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER));

    printf("[virtio-gpu] init negotiate\n");
    host_features = virtio_features_read();
    if ((host_features & VIRTIO_F_VERSION_1) == 0) {
        printf("[virtio-gpu] modern device missing VERSION_1 feature\n");
        virtio_gpu_fail();
        return -1;
    }

    guest_features = VIRTIO_F_VERSION_1;
    if (host_features & VIRTIO_GPU_F_VIRGL) {
        guest_features |= VIRTIO_GPU_F_VIRGL;
        g_vtgpu.virgl = 1;
    }
    if (host_features & VIRTIO_GPU_F_EDID) guest_features |= VIRTIO_GPU_F_EDID;
    if (host_features & VIRTIO_GPU_F_RESOURCE_UUID) guest_features |= VIRTIO_GPU_F_RESOURCE_UUID;
    if (host_features & VIRTIO_GPU_F_RESOURCE_BLOB) guest_features |= VIRTIO_GPU_F_RESOURCE_BLOB;
    if (host_features & VIRTIO_GPU_F_CONTEXT_INIT) guest_features |= VIRTIO_GPU_F_CONTEXT_INIT;
    g_vtgpu.negotiated_features = guest_features;

    virtio_features_write(guest_features);
    virtio_status_set((uint8_t)(VIRTIO_CONFIG_STATUS_ACK |
                                VIRTIO_CONFIG_STATUS_DRIVER |
                                VIRTIO_CONFIG_STATUS_FEATURES_OK));
    if ((virtio_status_get() & VIRTIO_CONFIG_STATUS_FEATURES_OK) == 0) {
        printf("[virtio-gpu] feature negotiation rejected host=0x%x:%x guest=0x%x:%x\n",
               (uint32_t)(host_features >> 32), (uint32_t)host_features,
               (uint32_t)(guest_features >> 32), (uint32_t)guest_features);
        virtio_gpu_fail();
        return -1;
    }

    g_vtgpu.num_scanouts = virtio_device_config_read32(8);
    g_vtgpu.num_capsets = virtio_device_config_read32(12);
    printf("[virtio-gpu] init queues scanouts=%u capsets=%u\n",
           g_vtgpu.num_scanouts, g_vtgpu.num_capsets);
    if (virtio_queue_program(VIRTIO_GPU_CTRL_QUEUE, &g_vtgpu.ctrlq, VIRTIO_GPU_QUEUE_SIZE) < 0) {
        printf("[virtio-gpu] unsupported queue layout\n");
        virtio_gpu_fail();
        return -1;
    }
    if (virtio_queue_program(VIRTIO_GPU_CURSOR_QUEUE,
                             &g_vtgpu.cursorq,
                             VIRTIO_GPU_CURSOR_QUEUE_SIZE) < 0) {
        printf("[virtio-gpu] unsupported cursor queue layout\n");
        virtio_gpu_fail();
        return -1;
    }
    virtio_gpu_present_initialize();
    g_vtgpu.next_fence = 1;

    /* The device must not consume queue entries before DRIVER_OK. */
    virtio_status_set((uint8_t)(VIRTIO_CONFIG_STATUS_ACK |
                                VIRTIO_CONFIG_STATUS_DRIVER |
                                VIRTIO_CONFIG_STATUS_FEATURES_OK |
                                VIRTIO_CONFIG_STATUS_DRIVER_OK));

    printf("[virtio-gpu] init display-info\n");
    if (virtio_gpu_get_display_info() < 0) {
        virtio_gpu_fail();
        return -1;
    }
    (void)virtio_gpu_get_edid();
    virtio_gpu_apply_cmdline_mode();
    {
        uint32_t bytes = virtio_gpu_framebuffer_bytes(
            g_vtgpu.width, g_vtgpu.height);

        if (!bytes || bytes > g_vtgpu_fb_capacity) {
            printf("[virtio-gpu] boot mode %ux%u needs runtime memory; "
                   "starting at 1024x768\n",
                   g_vtgpu.width, g_vtgpu.height);
            g_vtgpu.width = 1024u;
            g_vtgpu.height = 768u;
            virtio_gpu_select_edid_refresh();
        }
    }
    if (virtio_gpu_create_2d() < 0 ||
        virtio_gpu_attach_backing() < 0 ||
        virtio_gpu_set_scanout() < 0) {
        virtio_gpu_fail();
        return -1;
    }

    memset(g_vtgpu_fb, 0, g_vtgpu.width * g_vtgpu.height * 4u);
    fb_install_physical(virtio_gpu_dma_addr(g_vtgpu_fb), g_vtgpu_fb,
                        g_vtgpu.width, g_vtgpu.height, g_vtgpu.width * 4u, 32,
                        16, 8, 0, 0x00FF0000u, 0x0000FF00u, 0x000000FFu);
    g_vtgpu.present = 1;
    if (virtio_gpu_register_display_backend() < 0) {
        virtio_gpu_fail();
        return -1;
    }

#if defined(__x86_64__)
    virtio_gpu_setup_interrupts();
#endif
    virtio_gpu_flush_rect(0, 0, g_vtgpu.width, g_vtgpu.height);
    g_vtgpu_runtime_present_ready = 1u;
    if (g_vtgpu.transport == VIRTIO_GPU_TRANSPORT_MMIO) {
        printf("[virtio-gpu] modern MMIO GPU at 0x%x %ux%u scanouts=%u capsets=%u virgl=%s features=0x%x:%x\n",
               (uint32_t)(uintptr_t)g_vtgpu.mmio_base,
               g_vtgpu.width, g_vtgpu.height, g_vtgpu.num_scanouts,
               g_vtgpu.num_capsets, g_vtgpu.virgl ? "yes" : "no",
               (uint32_t)(guest_features >> 32),
               (uint32_t)guest_features);
    } else {
        printf("[virtio-gpu] modern PCI GPU at %u:%u.%u %ux%u scanouts=%u capsets=%u virgl=%s features=0x%x:%x\n",
               g_vtgpu.bus, g_vtgpu.dev, g_vtgpu.fn,
               g_vtgpu.width, g_vtgpu.height, g_vtgpu.num_scanouts,
               g_vtgpu.num_capsets, g_vtgpu.virgl ? "yes" : "no",
               (uint32_t)(guest_features >> 32),
               (uint32_t)guest_features);
    }
    if (g_vtgpu.num_capsets) virtio_gpu_log_capsets();
    if (g_vtgpu.virgl &&
        virtio_gpu_register_render_backend() < 0)
        printf("[virtio-gpu] virgl render ABI unavailable\n");
    return 0;
}

int virtio_gpu_init(void) {
#if defined(__x86_64__)
    uint16_t command;

    memset(&g_vtgpu, 0, sizeof(g_vtgpu));
    spinlock_init(&g_vtgpu_cmd_lock);
    spinlock_init(&g_vtgpu_cursor_lock);
    printf("[virtio-gpu] probe PCI\n");
    if (virtio_gpu_find_modern() < 0) return -1;
    printf("[virtio-gpu] PCI device %u:%u.%u common=%p notify=%p device=%p\n",
           g_vtgpu.bus, g_vtgpu.dev, g_vtgpu.fn,
           (void *)g_vtgpu.common_base, (void *)g_vtgpu.notify_base,
           (void *)g_vtgpu.device_base);
    g_vtgpu.transport = VIRTIO_GPU_TRANSPORT_PCI;
    command = pci_cfg_read16(
        g_vtgpu.bus, g_vtgpu.dev, g_vtgpu.fn, 0x04);
    command |= PCI_COMMAND_MEM | PCI_COMMAND_BUSMASTER;
    pci_cfg_write16(
        g_vtgpu.bus, g_vtgpu.dev, g_vtgpu.fn, 0x04, command);
    return virtio_gpu_initialize_device();
#else
    return -1;
#endif
}

int virtio_gpu_mmio_init(const struct edgeos_arm64_bootinfo *bootinfo) {
#if defined(__aarch64__)
    uint64_t base;
    uint32_t interrupt;
    uint32_t interrupt_flags;

    memset(&g_vtgpu, 0, sizeof(g_vtgpu));
    spinlock_init(&g_vtgpu_cmd_lock);
    spinlock_init(&g_vtgpu_cursor_lock);
    if (!bootinfo || edgeos_arm64_virtio_mmio_find_nth_irq(
            bootinfo, VIRTIO_MMIO_DEVICE_ID_GPU, 0u, &base,
            &interrupt, &interrupt_flags) < 0)
        return -1;
    g_vtgpu.transport = VIRTIO_GPU_TRANSPORT_MMIO;
    g_vtgpu.mmio_base = (volatile uint8_t *)(uintptr_t)base;
    g_vtgpu.interrupt = interrupt;
    g_vtgpu.interrupt_flags = interrupt_flags;
    if (mmio_read32(g_vtgpu.mmio_base, VIRTIO_MMIO_MAGIC) !=
            VIRTIO_MMIO_MAGIC_VALUE ||
        mmio_read32(g_vtgpu.mmio_base, VIRTIO_MMIO_VERSION) !=
            VIRTIO_MMIO_VERSION_MODERN ||
        mmio_read32(g_vtgpu.mmio_base, VIRTIO_MMIO_DEVICE_ID) !=
            VIRTIO_MMIO_DEVICE_ID_GPU) {
        memset(&g_vtgpu, 0, sizeof(g_vtgpu));
        return -1;
    }
    return virtio_gpu_initialize_device();
#else
    (void)bootinfo;
    return -1;
#endif
}

int virtio_gpu_enable_interrupts(void)
{
    if (!g_vtgpu.present) return -1;
    virtio_gpu_setup_interrupts();
    return g_vtgpu.irq_mode ? 0 : -1;
}

int virtio_gpu_present(void) {
    return g_vtgpu.present;
}

int virtio_gpu_has_virgl(void) {
    return g_vtgpu.present && g_vtgpu.virgl;
}

int virtio_gpu_cursor_available(void)
{
    return g_vtgpu.present && g_vtgpu.cursorq.size >=
        VIRTIO_GPU_CURSOR_SLOT_COUNT;
}

static int virtio_gpu_cursor_resource_prepare(void)
{
    if (g_vtgpu_cursor_resource_ready) return 0;
    memset(g_vtgpu_cursor_image, 0, sizeof(g_vtgpu_cursor_image));
    if (virtio_gpu_create_2d_resource(
            VIRTIO_GPU_CURSOR_RESOURCE_ID,
            VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM,
            VIRTIO_GPU_CURSOR_WIDTH, VIRTIO_GPU_CURSOR_HEIGHT,
            "CURSOR_RESOURCE_CREATE_2D") < 0)
        return -1;
    if (virtio_gpu_attach_resource_backing(
            VIRTIO_GPU_CURSOR_RESOURCE_ID, g_vtgpu_cursor_image,
            sizeof(g_vtgpu_cursor_image)) < 0) {
        (void)virtio_gpu_resource_reference_id(
            VIRTIO_GPU_CMD_RESOURCE_UNREF,
            VIRTIO_GPU_CURSOR_RESOURCE_ID,
            "CURSOR_RESOURCE_UNREF");
        return -1;
    }
    g_vtgpu_cursor_resource_ready = 1u;
    g_vtgpu_cursor_image_valid = 0u;
    return 0;
}

static void virtio_gpu_cursor_position(
    struct virtio_gpu_update_cursor *command, int32_t x, int32_t y,
    uint32_t cursor_width, uint32_t cursor_height,
    uint32_t hotspot_x, uint32_t hotspot_y)
{
    uint32_t hot_x = hotspot_x;
    uint32_t hot_y = hotspot_y;

    if (x < 0) {
        uint64_t offset = (uint64_t)(-(int64_t)x);
        hot_x += offset < cursor_width ? (uint32_t)offset : cursor_width;
        x = 0;
    }
    if (y < 0) {
        uint64_t offset = (uint64_t)(-(int64_t)y);
        hot_y += offset < cursor_height ? (uint32_t)offset : cursor_height;
        y = 0;
    }
    if (hot_x >= VIRTIO_GPU_CURSOR_WIDTH)
        hot_x = VIRTIO_GPU_CURSOR_WIDTH - 1u;
    if (hot_y >= VIRTIO_GPU_CURSOR_HEIGHT)
        hot_y = VIRTIO_GPU_CURSOR_HEIGHT - 1u;
    command->position.scanout_id = g_vtgpu.scanout_id;
    command->position.x = (uint32_t)x;
    command->position.y = (uint32_t)y;
    command->hot_x = hot_x;
    command->hot_y = hot_y;
}

int virtio_gpu_cursor_update(const uint8_t *pixels, uint32_t width,
                             uint32_t height, uint32_t pitch,
                             uint32_t source_x, uint32_t source_y,
                             uint32_t cursor_width, uint32_t cursor_height,
                             int32_t x, int32_t y,
                             uint32_t hotspot_x, uint32_t hotspot_y)
{
    struct virtio_gpu_update_cursor command;
    uint32_t hot_x;
    uint32_t hot_y;
    int image_changed = 0;
    int result = -1;

    if (!virtio_gpu_cursor_available() || !pixels || !width || !height ||
        pitch < width * 4u || !cursor_width || !cursor_height ||
        cursor_width > VIRTIO_GPU_CURSOR_WIDTH ||
        cursor_height > VIRTIO_GPU_CURSOR_HEIGHT ||
        hotspot_x >= cursor_width || hotspot_y >= cursor_height ||
        source_x > width || source_y > height ||
        cursor_width > width - source_x ||
        cursor_height > height - source_y)
        return -1;
    while (__atomic_test_and_set(
               &g_vtgpu_cursor_update_guard, __ATOMIC_ACQUIRE))
        virtio_gpu_cpu_relax();
    if ((int64_t)x + cursor_width <= 0 ||
        (int64_t)y + cursor_height <= 0 ||
        x >= (int32_t)g_vtgpu.width || y >= (int32_t)g_vtgpu.height) {
        result = virtio_gpu_cursor_hide();
        goto out;
    }
    if (virtio_gpu_cursor_resource_prepare() < 0) goto out;

    for (uint32_t row = 0; row < VIRTIO_GPU_CURSOR_HEIGHT; ++row) {
        uint8_t *destination = g_vtgpu_cursor_image +
            (uint64_t)row * VIRTIO_GPU_CURSOR_WIDTH * 4u;

        if (row < cursor_height) {
            const uint8_t *source = pixels +
                (uint64_t)(source_y + row) * pitch +
                (uint64_t)source_x * 4u;
            uint32_t bytes = cursor_width * 4u;
            uint32_t padding =
                (VIRTIO_GPU_CURSOR_WIDTH - cursor_width) * 4u;

            if (memcmp(destination, source, bytes) != 0) {
                memcpy(destination, source, bytes);
                image_changed = 1;
            }
            if (padding) {
                for (uint32_t index = 0; index < padding; ++index)
                    if (destination[bytes + index] != 0u) {
                        memset(destination + bytes, 0, padding);
                        image_changed = 1;
                        break;
                    }
            }
        } else {
            for (uint32_t index = 0;
                 index < VIRTIO_GPU_CURSOR_WIDTH * 4u; ++index)
                if (destination[index] != 0u) {
                    memset(destination, 0,
                           VIRTIO_GPU_CURSOR_WIDTH * 4u);
                    image_changed = 1;
                    break;
                }
        }
    }
    if (!g_vtgpu_cursor_image_valid) image_changed = 1;
    if (image_changed) {
        if (virtio_gpu_transfer_resource(
                VIRTIO_GPU_CURSOR_RESOURCE_ID,
                VIRTIO_GPU_CURSOR_WIDTH, VIRTIO_GPU_CURSOR_HEIGHT,
                0u, 0u, VIRTIO_GPU_CURSOR_WIDTH,
                VIRTIO_GPU_CURSOR_HEIGHT,
                "CURSOR_TRANSFER_TO_HOST_2D") < 0)
            goto out;
        g_vtgpu_cursor_image_valid = 1u;
    }

    memset(&command, 0, sizeof(command));
    virtio_gpu_cursor_position(
        &command, x, y, cursor_width, cursor_height,
        hotspot_x, hotspot_y);
    hot_x = command.hot_x;
    hot_y = command.hot_y;
    virtio_gpu_init_sync_hdr(
        &command.hdr,
        image_changed || !g_vtgpu_cursor_visible ||
                hot_x != g_vtgpu_cursor_hot_x ||
                hot_y != g_vtgpu_cursor_hot_y ?
            VIRTIO_GPU_CMD_UPDATE_CURSOR :
            VIRTIO_GPU_CMD_MOVE_CURSOR);
    command.resource_id = VIRTIO_GPU_CURSOR_RESOURCE_ID;
    command.hot_x = hot_x;
    command.hot_y = hot_y;
    virtio_gpu_cursor_enqueue(&command);
    g_vtgpu_cursor_visible = 1u;
    g_vtgpu_cursor_hot_x = hot_x;
    g_vtgpu_cursor_hot_y = hot_y;
    result = 0;
out:
    __atomic_clear(&g_vtgpu_cursor_update_guard, __ATOMIC_RELEASE);
    return result;
}

int virtio_gpu_cursor_hide(void)
{
    struct virtio_gpu_update_cursor command;

    if (!virtio_gpu_cursor_available()) return -1;
    memset(&command, 0, sizeof(command));
    virtio_gpu_init_sync_hdr(&command.hdr, VIRTIO_GPU_CMD_UPDATE_CURSOR);
    command.position.scanout_id = g_vtgpu.scanout_id;
    virtio_gpu_cursor_enqueue(&command);
    g_vtgpu_cursor_visible = 0u;
    return 0;
}

int virtio_gpu_pci_device_name(char *out, uint32_t capacity) {
    static const char hex[] = "0123456789abcdef";

    if (!out || capacity < 13u || !g_vtgpu.present ||
        g_vtgpu.transport != VIRTIO_GPU_TRANSPORT_PCI)
        return -1;
    out[0] = '0';
    out[1] = '0';
    out[2] = '0';
    out[3] = '0';
    out[4] = ':';
    out[5] = hex[g_vtgpu.bus >> 4];
    out[6] = hex[g_vtgpu.bus & 0x0fu];
    out[7] = ':';
    out[8] = hex[g_vtgpu.dev >> 4];
    out[9] = hex[g_vtgpu.dev & 0x0fu];
    out[10] = '.';
    out[11] = hex[g_vtgpu.fn & 0x07u];
    out[12] = 0;
    return 0;
}

void virtio_gpu_flush_rect(uint32_t x, uint32_t y, uint32_t width, uint32_t height) {
    display_rect_t rect = { x, y, width, height };

    if (!g_vtgpu.present) return;
    if (g_vtgpu_runtime_present_ready) {
        virtio_gpu_present_enqueue(&rect, 1u);
        return;
    }
    if (virtio_gpu_transfer(x, y, width, height) == 0) {
        (void)virtio_gpu_resource_flush(x, y, width, height);
    }
}

void virtio_gpu_flush_rects(const display_rect_t *rects, uint32_t count) {
    if (!g_vtgpu.present || !rects)
        return;
    if (g_vtgpu_runtime_present_ready) {
        virtio_gpu_present_enqueue(rects, count);
        return;
    }
    for (uint32_t index = 0; index < count; ++index)
        virtio_gpu_flush_rect(rects[index].x, rects[index].y,
                              rects[index].width, rects[index].height);
}

void virtio_gpu_poll_presents(void)
{
    uint64_t flags;

    if (!g_vtgpu.present) return;
    virtio_ack_isr();
    if (g_vtgpu_runtime_present_ready) {
        flags = spin_lock_irqsave(&g_vtgpu_cmd_lock);
        virtio_gpu_reap_completions_locked();
        spin_unlock_irqrestore(&g_vtgpu_cmd_lock, flags);
        virtio_gpu_render_dispatch_completions();
    }
    flags = spin_lock_irqsave(&g_vtgpu_cursor_lock);
    virtio_gpu_cursor_reap_locked();
    spin_unlock_irqrestore(&g_vtgpu_cursor_lock, flags);
}

int virtio_gpu_presents_pending(void)
{
    if (!g_vtgpu.present || !g_vtgpu_runtime_present_ready) return 0;
    if (__atomic_load_n(&g_vtgpu_present_stats.in_flight,
                        __ATOMIC_ACQUIRE) != 0u ||
        __atomic_load_n(&g_vtgpu_present_stats.pending,
                        __ATOMIC_ACQUIRE) != 0u ||
        __atomic_load_n(&g_vtgpu_render_completion_count,
                        __ATOMIC_ACQUIRE) != 0u ||
        __atomic_load_n(&g_vtgpu_render_pending_count,
                        __ATOMIC_ACQUIRE) != 0u)
        return 1;
    /*
     * A render completion normally requests display work through the device
     * interrupt. Keep the timer fallback armed while any fenced 3D command is
     * outstanding so a coalesced interrupt cannot leave EGL or a browser
     * blocked forever with no 2D present pending.
     */
    for (uint32_t index = 0;
         index < VIRTIO_GPU_RENDER_SLOT_COUNT; ++index)
        if (__atomic_load_n(
                &g_vtgpu_render_slots[index].in_flight,
                __ATOMIC_ACQUIRE) != 0u)
            return 1;
    return 0;
}

void virtio_gpu_get_present_stats(virtio_gpu_present_stats_t *stats)
{
    uint64_t flags;

    if (!stats) return;
    flags = spin_lock_irqsave(&g_vtgpu_cmd_lock);
    *stats = g_vtgpu_present_stats;
    spin_unlock_irqrestore(&g_vtgpu_cmd_lock, flags);
}
