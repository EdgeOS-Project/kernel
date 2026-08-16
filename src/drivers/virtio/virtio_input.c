/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This file contains VirtIO ring and PCI transport definitions derived from
 * FreeBSD sys/dev/virtio/virtio_ring.h, sys/dev/virtio/pci,
 * sys/dev/virtio/virtio_config.h, and
 * sys/dev/virtio/pci/virtio_pci_modern_var.h.
 *
 * Copyright Rusty Russell IBM Corporation 2007.
 *
 * This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
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
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Copyright (c) 2011, 2014, 2017, Bryan Venteicher <bryanv@FreeBSD.org>
 * All rights reserved.
 *
 * Modifications for EdgeOS.
 * Copyright (c) EdgeOS Contributors.
 *
 * The VirtIO input protocol handling below is original EdgeOS code written
 * against the public VirtIO input specification and Linux input UAPI event
 * numbers.  It intentionally does not copy Linux implementation code.
 */

#include "drivers/virtio_input.h"
#include "drivers/pci.h"

#include "arch/x86_64/io_ports.h"
#include "fb.h"
#include "keyboard.h"
#include "stdio.h"
#include "string.h"
#include "sys/mmio.h"

#include <stdint.h>

#define VIRTIO_PCI_VENDORID 0x1AF4u
#define VIRTIO_PCI_DEVICEID_MODERN_INPUT 0x1052u

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

#define VIRTIO_PCI_COMMON_DFSELECT 0u
#define VIRTIO_PCI_COMMON_DF       4u
#define VIRTIO_PCI_COMMON_GFSELECT 8u
#define VIRTIO_PCI_COMMON_GF       12u
#define VIRTIO_PCI_COMMON_STATUS   20u
#define VIRTIO_PCI_COMMON_Q_SELECT 22u
#define VIRTIO_PCI_COMMON_Q_SIZE   24u
#define VIRTIO_PCI_COMMON_Q_ENABLE 28u
#define VIRTIO_PCI_COMMON_Q_NOFF   30u
#define VIRTIO_PCI_COMMON_Q_DESCLO 32u
#define VIRTIO_PCI_COMMON_Q_DESCHI 36u
#define VIRTIO_PCI_COMMON_Q_AVAILLO 40u
#define VIRTIO_PCI_COMMON_Q_AVAILHI 44u
#define VIRTIO_PCI_COMMON_Q_USEDLO 48u
#define VIRTIO_PCI_COMMON_Q_USEDHI 52u

#define VIRTIO_INPUT_CFG_SELECT_NAME 0x01u
#define VIRTIO_INPUT_CFG_SELECT_DEVIDS 0x03u
#define VIRTIO_INPUT_CFG_SELECT_PROP_BITS 0x10u
#define VIRTIO_INPUT_CFG_SELECT_EV_BITS 0x11u
#define VIRTIO_INPUT_CFG_SELECT_ABS_INFO 0x12u

#define VIRTIO_INPUT_EVENTQ 0u
#define VIRTIO_INPUT_STATUSQ 1u
#define VIRTIO_INPUT_MAX_DEVICES 4u
#define VIRTIO_INPUT_QUEUE_SIZE 64u
#define VIRTIO_INPUT_RING_BYTES 16384u
#define VIRTIO_INPUT_EVENT_BYTES 8u
#define VIRTIO_PCI_VRING_ALIGN 4096u
#define VRING_DESC_F_WRITE 2u
#define VIRTIO_MODERN_COMMON_MIN_SIZE 56u
#define VIRTIO_MODERN_NOTIFY_MIN_SIZE 2u
#define VIRTIO_MODERN_ISR_MIN_SIZE 1u
#define VIRTIO_MODERN_DEVICE_MIN_SIZE 136u

#define LINUX_EV_SYN 0x00u
#define LINUX_EV_KEY 0x01u
#define LINUX_EV_REL 0x02u
#define LINUX_EV_ABS 0x03u
#define LINUX_SYN_REPORT 0u
#define LINUX_REL_X 0u
#define LINUX_REL_Y 1u
#define LINUX_REL_WHEEL 8u
#define LINUX_ABS_X 0u
#define LINUX_ABS_Y 1u
#define LINUX_BTN_LEFT 0x110u
#define LINUX_BTN_RIGHT 0x111u
#define LINUX_BTN_MIDDLE 0x112u
#define LINUX_BTN_TOOL_FINGER 0x145u
#define LINUX_BTN_TOUCH 0x14au

#define EDGE_INPUT_MOUSE EDGE_INPUT_POINTER

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

struct virtio_input_event {
    uint16_t type;
    uint16_t code;
    int32_t value;
} __attribute__((packed));

typedef struct {
    uint8_t bar;
    uint32_t offset;
    uint32_t length;
} virtio_modern_cap_t;

typedef struct {
    uint8_t ring[VIRTIO_INPUT_RING_BYTES] __attribute__((aligned(VIRTIO_PCI_VRING_ALIGN)));
    struct vring_desc *desc;
    struct vring_avail *avail;
    struct vring_used *used;
    uint16_t size;
    uint16_t avail_idx;
    uint16_t used_idx;
    uint16_t notify_off;
} virtio_input_queue_t;

typedef struct {
    volatile uint8_t *common_base;
    volatile uint8_t *notify_base;
    volatile uint8_t *isr_base;
    volatile uint8_t *device_base;
    uint32_t notify_multiplier;
    uint8_t bus;
    uint8_t dev;
    uint8_t fn;
    int ready;
    int has_key;
    int has_rel;
    int has_abs;
    int pointer_down;
    int abs_x;
    int abs_y;
    int last_abs_x;
    int last_abs_y;
    int abs_initialized;
    int64_t abs_x_remainder;
    int64_t abs_y_remainder;
    int rel_x;
    int rel_y;
    int rel_wheel;
    uint8_t buttons;
    char name[64];
    uint16_t bustype;
    uint16_t vendor;
    uint16_t product;
    uint16_t version;
    uint8_t prop_bits[128];
    uint8_t key_bits[128];
    uint8_t rel_bits[128];
    uint8_t abs_bits[128];
    input_absinfo_t abs_info[64];
    uint32_t repeat_delay_ms;
    uint32_t repeat_period_ms;
    input_device_description_t input_description;
    virtio_input_queue_t eventq;
    virtio_input_queue_t statusq;
    struct virtio_input_event event_buf[VIRTIO_INPUT_QUEUE_SIZE] __attribute__((aligned(16)));
    struct virtio_input_event status_buf[VIRTIO_INPUT_QUEUE_SIZE] __attribute__((aligned(16)));
} virtio_input_dev_t;

static virtio_input_dev_t g_vtinput[VIRTIO_INPUT_MAX_DEVICES];
static int g_vtinput_count;
static uint32_t g_poll_active;

static void virtio_input_bitmap_set(uint8_t *bitmap, uint32_t bit) {
    if (!bitmap || bit >= EDGE_INPUT_BITMAP_BYTES * 8u) return;
    bitmap[bit >> 3] |= (uint8_t)(1u << (bit & 7u));
}

static int virtio_input_publish_device(virtio_input_dev_t *device) {
    static const char *const physical_paths[EDGE_INPUT_DEVICE_MAX] = {
        "virtio-pci/input0", "virtio-pci/input1"
    };
    input_device_description_t *description;
    uint32_t event_index;
    if (!device) return -22;
    description = &device->input_description;
    if (device->has_key && !device->has_rel && !device->has_abs) {
        event_index = EDGE_INPUT_KEYBOARD;
        memset(description, 0, sizeof(*description));
        description->role = EDGE_INPUT_ROLE_KEYBOARD;
    } else if (device->has_rel || device->has_abs) {
        event_index = EDGE_INPUT_POINTER;
        memset(description, 0, sizeof(*description));
        description->role = EDGE_INPUT_ROLE_POINTER;
    } else {
        return -19;
    }
    description->name = device->name;
    description->physical_path = physical_paths[event_index];
    description->driver = "virtio_input";
    description->bustype = device->bustype;
    description->vendor = device->vendor;
    description->product = device->product;
    description->version = device->version;
    description->repeat_delay_ms = device->repeat_delay_ms;
    description->repeat_period_ms = device->repeat_period_ms;
    memcpy(description->properties, device->prop_bits,
           sizeof(description->properties));
    memcpy(description->key_bits, device->key_bits,
           sizeof(description->key_bits));
    memcpy(description->relative_bits, device->rel_bits,
           sizeof(description->relative_bits));
    memcpy(description->absolute_bits, device->abs_bits,
           sizeof(description->absolute_bits));
    memcpy(description->absolute, device->abs_info,
           sizeof(description->absolute));
    virtio_input_bitmap_set(description->event_bits, LINUX_EV_SYN);
    if (device->has_key)
        virtio_input_bitmap_set(description->event_bits, LINUX_EV_KEY);
    if (device->has_rel)
        virtio_input_bitmap_set(description->event_bits, LINUX_EV_REL);
    if (device->has_abs)
        virtio_input_bitmap_set(description->event_bits, LINUX_EV_ABS);
    return input_device_register(event_index, description, device);
}

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

static void virtio_mb(void) {
    __asm__ __volatile__("" ::: "memory");
}

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
    if (!virtio_modern_cap_valid(cap, 1, 1) || !out) return -1;
    base = pci_bar_base(bus, dev, fn, cap->bar, &is_io);
    if (is_io || base == 0 || base + cap->offset >= 0x0000800000000000ULL) return -1;
    *out = (volatile uint8_t *)edge_mmio_low_alias(base + cap->offset);
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
                                   virtio_modern_cap_t *device,
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
                else if (cfg_type == VIRTIO_PCI_CAP_DEVICE_CFG) { *device = tmp; have_device = 1; }
            }
        }
        if (next == 0 || next == cap) break;
        cap = next;
    }
    if (!have_common || !have_notify || !have_isr || !have_device) return -1;
    if (!virtio_modern_cap_valid(common, VIRTIO_MODERN_COMMON_MIN_SIZE, 4)) return -1;
    if (!virtio_modern_cap_valid(notify, VIRTIO_MODERN_NOTIFY_MIN_SIZE, 2)) return -1;
    if (!virtio_modern_cap_valid(isr, VIRTIO_MODERN_ISR_MIN_SIZE, 1)) return -1;
    if (!virtio_modern_cap_valid(device, VIRTIO_MODERN_DEVICE_MIN_SIZE, 1)) return -1;
    return 0;
}

static uint32_t vring_used_offset(uint32_t num) {
    uint32_t off = num * (uint32_t)sizeof(struct vring_desc);
    off += (uint32_t)sizeof(struct vring_avail) + num * (uint32_t)sizeof(uint16_t) + (uint32_t)sizeof(uint16_t);
    return (off + VIRTIO_PCI_VRING_ALIGN - 1u) & ~(VIRTIO_PCI_VRING_ALIGN - 1u);
}

static int virtio_input_setup_queue(virtio_input_queue_t *q, uint16_t qsz) {
    uint32_t used_off;
    uint32_t used_bytes;
    if (!q) return -1;
    if (qsz == 0 || qsz > VIRTIO_INPUT_QUEUE_SIZE) qsz = VIRTIO_INPUT_QUEUE_SIZE;
    used_off = vring_used_offset(qsz);
    used_bytes = (uint32_t)sizeof(struct vring_used) +
                 (uint32_t)qsz * (uint32_t)sizeof(struct vring_used_elem) +
                 (uint32_t)sizeof(uint16_t);
    if (used_off + used_bytes > VIRTIO_INPUT_RING_BYTES) return -1;
    memset(q->ring, 0, sizeof(q->ring));
    q->desc = (struct vring_desc *)q->ring;
    q->avail = (struct vring_avail *)(q->ring + qsz * sizeof(struct vring_desc));
    q->used = (struct vring_used *)(q->ring + used_off);
    q->size = qsz;
    q->avail_idx = 0;
    q->used_idx = 0;
    return 0;
}

static void virtio_input_program_queue(virtio_input_dev_t *d, virtio_input_queue_t *q, uint16_t q_index) {
    mmio_write16(d->common_base, VIRTIO_PCI_COMMON_Q_SELECT, q_index);
    q->notify_off = mmio_read16(d->common_base, VIRTIO_PCI_COMMON_Q_NOFF);
    mmio_write16(d->common_base, VIRTIO_PCI_COMMON_Q_SIZE, q->size);
    mmio_write32(d->common_base, VIRTIO_PCI_COMMON_Q_DESCLO, (uint32_t)(uintptr_t)q->desc);
    mmio_write32(d->common_base, VIRTIO_PCI_COMMON_Q_DESCHI, (uint32_t)((uint64_t)(uintptr_t)q->desc >> 32));
    mmio_write32(d->common_base, VIRTIO_PCI_COMMON_Q_AVAILLO, (uint32_t)(uintptr_t)q->avail);
    mmio_write32(d->common_base, VIRTIO_PCI_COMMON_Q_AVAILHI, (uint32_t)((uint64_t)(uintptr_t)q->avail >> 32));
    mmio_write32(d->common_base, VIRTIO_PCI_COMMON_Q_USEDLO, (uint32_t)(uintptr_t)q->used);
    mmio_write32(d->common_base, VIRTIO_PCI_COMMON_Q_USEDHI, (uint32_t)((uint64_t)(uintptr_t)q->used >> 32));
    mmio_write16(d->common_base, VIRTIO_PCI_COMMON_Q_ENABLE, 1);
}

static void virtio_input_notify(virtio_input_dev_t *d, virtio_input_queue_t *q) {
    mmio_write16(d->notify_base, (uint32_t)q->notify_off * d->notify_multiplier, 0);
}

static void virtio_input_post_event_buf(virtio_input_dev_t *d, uint16_t id) {
    virtio_input_queue_t *q = &d->eventq;
    q->desc[id].addr = (uint64_t)(uintptr_t)&d->event_buf[id];
    q->desc[id].len = VIRTIO_INPUT_EVENT_BYTES;
    q->desc[id].flags = VRING_DESC_F_WRITE;
    q->desc[id].next = 0;
    q->avail->ring[q->avail_idx % q->size] = id;
    virtio_mb();
    q->avail->idx = (uint16_t)(q->avail_idx + 1u);
    q->avail_idx++;
}

static void virtio_input_post_all_events(virtio_input_dev_t *d) {
    for (uint16_t i = 0; i < d->eventq.size; ++i) {
        virtio_input_post_event_buf(d, i);
    }
}

static void virtio_input_cfg_select(virtio_input_dev_t *d, uint8_t select, uint8_t subsel) {
    mmio_write8(d->device_base, 0, select);
    mmio_write8(d->device_base, 1, subsel);
    (void)mmio_read8(d->device_base, 2);
}

static uint8_t virtio_input_cfg_size(virtio_input_dev_t *d) {
    return mmio_read8(d->device_base, 2);
}

static uint8_t virtio_input_cfg_data8(virtio_input_dev_t *d, uint32_t off) {
    return mmio_read8(d->device_base, (uint32_t)(8u + off));
}

static uint8_t virtio_input_cfg_read(virtio_input_dev_t *d, uint8_t select,
                                     uint8_t subsel, void *out,
                                     uint8_t maximum) {
    uint8_t size;
    uint8_t *bytes = out;

    if (!out || maximum == 0) return 0;
    virtio_input_cfg_select(d, select, subsel);
    size = virtio_input_cfg_size(d);
    if (size > maximum) size = maximum;
    for (uint8_t i = 0; i < size; ++i)
        bytes[i] = virtio_input_cfg_data8(d, i);
    return size;
}

static void virtio_input_read_name(virtio_input_dev_t *d) {
    uint8_t size;
    uint32_t n;
    virtio_input_cfg_select(d, VIRTIO_INPUT_CFG_SELECT_NAME, 0);
    size = virtio_input_cfg_size(d);
    if (size >= sizeof(d->name)) size = sizeof(d->name) - 1u;
    for (n = 0; n < size; ++n) {
        char c = (char)virtio_input_cfg_data8(d, n);
        d->name[n] = c ? c : ' ';
    }
    d->name[n] = 0;
    if (n == 0) {
        d->name[0] = 'v';
        d->name[1] = 'i';
        d->name[2] = 'n';
        d->name[3] = 'p';
        d->name[4] = 'u';
        d->name[5] = 't';
        d->name[6] = 0;
    }
}

static int virtio_input_any_bits(const uint8_t *bits, uint32_t length) {
    for (uint32_t i = 0; i < length; ++i)
        if (bits[i]) return 1;
    return 0;
}

static void virtio_input_probe_caps(virtio_input_dev_t *d) {
    struct {
        uint16_t bustype;
        uint16_t vendor;
        uint16_t product;
        uint16_t version;
    } __attribute__((packed)) ids;

    memset(&ids, 0, sizeof(ids));
    memset(d->prop_bits, 0, sizeof(d->prop_bits));
    memset(d->key_bits, 0, sizeof(d->key_bits));
    memset(d->rel_bits, 0, sizeof(d->rel_bits));
    memset(d->abs_bits, 0, sizeof(d->abs_bits));
    memset(d->abs_info, 0, sizeof(d->abs_info));
    (void)virtio_input_cfg_read(d, VIRTIO_INPUT_CFG_SELECT_DEVIDS, 0,
                                &ids, sizeof(ids));
    d->bustype = ids.bustype;
    d->vendor = ids.vendor;
    d->product = ids.product;
    d->version = ids.version;
    (void)virtio_input_cfg_read(d, VIRTIO_INPUT_CFG_SELECT_PROP_BITS, 0,
                                d->prop_bits, sizeof(d->prop_bits));
    (void)virtio_input_cfg_read(d, VIRTIO_INPUT_CFG_SELECT_EV_BITS,
                                LINUX_EV_KEY, d->key_bits,
                                sizeof(d->key_bits));
    (void)virtio_input_cfg_read(d, VIRTIO_INPUT_CFG_SELECT_EV_BITS,
                                LINUX_EV_REL, d->rel_bits,
                                sizeof(d->rel_bits));
    (void)virtio_input_cfg_read(d, VIRTIO_INPUT_CFG_SELECT_EV_BITS,
                                LINUX_EV_ABS, d->abs_bits,
                                sizeof(d->abs_bits));
    for (uint32_t axis = 0; axis < 64u; ++axis) {
        struct {
            int32_t minimum;
            int32_t maximum;
            int32_t fuzz;
            int32_t flat;
            int32_t resolution;
        } info;
        if ((d->abs_bits[axis >> 3] & (1u << (axis & 7u))) == 0)
            continue;
        memset(&info, 0, sizeof(info));
        (void)virtio_input_cfg_read(d, VIRTIO_INPUT_CFG_SELECT_ABS_INFO,
                                    (uint8_t)axis, &info, sizeof(info));
        d->abs_info[axis].minimum = info.minimum;
        d->abs_info[axis].maximum = info.maximum;
        d->abs_info[axis].fuzz = info.fuzz;
        d->abs_info[axis].flat = info.flat;
        d->abs_info[axis].resolution = info.resolution;
    }
    d->has_key = virtio_input_any_bits(d->key_bits,
                                       sizeof(d->key_bits));
    d->has_rel = virtio_input_any_bits(d->rel_bits,
                                       sizeof(d->rel_bits));
    d->has_abs = virtio_input_any_bits(d->abs_bits,
                                       sizeof(d->abs_bits));
}

static uint8_t linux_key_to_set1(uint16_t code) {
    if (code == LINUX_BTN_LEFT || code == LINUX_BTN_RIGHT || code == LINUX_BTN_MIDDLE ||
        code == LINUX_BTN_TOUCH || code == LINUX_BTN_TOOL_FINGER) return 0;
    if (code < 0x80u) return (uint8_t)code;
    return 0;
}

static int virtio_input_abs_delta_to_pixels(int delta,
                                            const input_absinfo_t *axis,
                                            uint32_t extent,
                                            int64_t *remainder) {
    int64_t range;
    int64_t scaled;
    int64_t pixels;

    if (!axis || !remainder || extent == 0) return delta;
    range = (int64_t)axis->maximum - (int64_t)axis->minimum;
    if (range <= 0) return delta;
    scaled = (int64_t)delta * (int64_t)extent + *remainder;
    pixels = scaled / range;
    *remainder = scaled - pixels * range;
    if (pixels > 0x7fffffffll) return 0x7fffffff;
    if (pixels < -0x7fffffffll) return -0x7fffffff;
    return (int)pixels;
}

static void virtio_input_flush_pointer(virtio_input_dev_t *d) {
    int dx = d->rel_x;
    int dy = -d->rel_y;
    int wheel = d->rel_wheel;

    if (d->has_abs && !d->abs_initialized) {
        d->last_abs_x = d->abs_x;
        d->last_abs_y = d->abs_y;
        d->abs_initialized = 1;
    } else if (d->has_abs &&
               (d->abs_x != d->last_abs_x ||
                d->abs_y != d->last_abs_y)) {
        dx += virtio_input_abs_delta_to_pixels(
            d->abs_x - d->last_abs_x, &d->abs_info[LINUX_ABS_X],
            fb.width, &d->abs_x_remainder);
        dy -= virtio_input_abs_delta_to_pixels(
            d->abs_y - d->last_abs_y, &d->abs_info[LINUX_ABS_Y],
            fb.height, &d->abs_y_remainder);
        d->last_abs_x = d->abs_x;
        d->last_abs_y = d->abs_y;
    }
    if (dx || dy || wheel || d->buttons != keyboard_mouse_buttons()) {
        keyboard_mouse_emit_compat_packet_ex(dx, dy, wheel, d->buttons,
                                             wheel != 0);
    }
    d->rel_x = d->rel_y = d->rel_wheel = 0;
}

static void virtio_input_handle_event(virtio_input_dev_t *d, const struct virtio_input_event *ev) {
    if (!d || !ev) return;

    if (ev->type == LINUX_EV_SYN && ev->code == LINUX_SYN_REPORT) {
        if (d->has_rel || d->has_abs) {
            virtio_input_flush_pointer(d);
            keyboard_emit_linux_input_event(EDGE_INPUT_MOUSE, ev->type,
                                            ev->code, ev->value);
        } else {
            keyboard_emit_linux_input_event(EDGE_INPUT_KEYBOARD, ev->type,
                                            ev->code, ev->value);
        }
        return;
    }
    if (ev->type == LINUX_EV_KEY) {
        if (ev->code == LINUX_BTN_LEFT) {
            if (ev->value) d->buttons |= 0x01u; else d->buttons &= (uint8_t)~0x01u;
            keyboard_emit_linux_input_event(EDGE_INPUT_MOUSE, ev->type, ev->code, ev->value);
        } else if (ev->code == LINUX_BTN_RIGHT) {
            if (ev->value) d->buttons |= 0x02u; else d->buttons &= (uint8_t)~0x02u;
            keyboard_emit_linux_input_event(EDGE_INPUT_MOUSE, ev->type, ev->code, ev->value);
        } else if (ev->code == LINUX_BTN_MIDDLE) {
            if (ev->value) d->buttons |= 0x04u; else d->buttons &= (uint8_t)~0x04u;
            keyboard_emit_linux_input_event(EDGE_INPUT_MOUSE, ev->type, ev->code, ev->value);
        } else if (ev->code == LINUX_BTN_TOUCH || ev->code == LINUX_BTN_TOOL_FINGER) {
            d->pointer_down = ev->value != 0;
            keyboard_emit_linux_input_event(EDGE_INPUT_MOUSE, ev->type, ev->code, ev->value);
        } else {
            uint8_t scan = linux_key_to_set1(ev->code);
            keyboard_emit_linux_input_event(EDGE_INPUT_KEYBOARD, ev->type, ev->code, ev->value);
            if (scan && ev->value != 2) {
                keyboard_emit_scancode_console_only((uint8_t)(ev->value ? scan : (scan | 0x80u)));
            }
        }
        return;
    }
    if (ev->type == LINUX_EV_REL) {
        if (ev->code == LINUX_REL_X) d->rel_x += ev->value;
        else if (ev->code == LINUX_REL_Y) d->rel_y += ev->value;
        else if (ev->code == LINUX_REL_WHEEL) d->rel_wheel += ev->value;
        keyboard_emit_linux_input_event(EDGE_INPUT_MOUSE, ev->type, ev->code, ev->value);
        return;
    }
    if (ev->type == LINUX_EV_ABS) {
        if (ev->code == LINUX_ABS_X) {
            d->abs_x = ev->value;
            d->abs_info[LINUX_ABS_X].value = ev->value;
        } else if (ev->code == LINUX_ABS_Y) {
            d->abs_y = ev->value;
            d->abs_info[LINUX_ABS_Y].value = ev->value;
        }
        keyboard_emit_linux_input_event(EDGE_INPUT_MOUSE, ev->type, ev->code, ev->value);
        return;
    }
    keyboard_emit_linux_input_event((d->has_rel || d->has_abs) ?
                                    EDGE_INPUT_MOUSE : EDGE_INPUT_KEYBOARD,
                                    ev->type, ev->code, ev->value);
}

static int virtio_input_attach(uint8_t bus, uint8_t dev, uint8_t fn) {
    virtio_input_dev_t *d;
    virtio_modern_cap_t common, notify, isr, device;
    uint32_t notify_multiplier = 0;
    uint64_t features;
    uint16_t command;
    uint16_t qsz0, qsz1;

    if (g_vtinput_count >= VIRTIO_INPUT_MAX_DEVICES) return -1;
    memset(&common, 0, sizeof(common));
    memset(&notify, 0, sizeof(notify));
    memset(&isr, 0, sizeof(isr));
    memset(&device, 0, sizeof(device));
    if (virtio_modern_find_caps(bus, dev, fn, &common, &notify, &isr, &device,
                                &notify_multiplier) < 0) {
        printf("[virtio-input] modern device %u:%u.%u missing usable PCI capabilities\n",
               (uint32_t)bus, dev, fn);
        return -1;
    }

    d = &g_vtinput[g_vtinput_count];
    memset(d, 0, sizeof(*d));
    d->repeat_delay_ms = 250u;
    d->repeat_period_ms = 33u;
    if (virtio_modern_cap_addr(bus, dev, fn, &common, &d->common_base) < 0 ||
        virtio_modern_cap_addr(bus, dev, fn, &notify, &d->notify_base) < 0 ||
        virtio_modern_cap_addr(bus, dev, fn, &isr, &d->isr_base) < 0 ||
        virtio_modern_cap_addr(bus, dev, fn, &device, &d->device_base) < 0) {
        printf("[virtio-input] modern device %u:%u.%u has unsupported BAR mapping\n",
               (uint32_t)bus, dev, fn);
        return -1;
    }

    d->bus = bus;
    d->dev = dev;
    d->fn = fn;
    d->notify_multiplier = notify_multiplier;

    command = pci_cfg_read16(bus, dev, fn, 0x04);
    pci_cfg_write16(bus, dev, fn, 0x04, (uint16_t)(command | PCI_COMMAND_MEM | PCI_COMMAND_BUSMASTER));

    mmio_write8(d->common_base, VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_STATUS_RESET);
    mmio_write8(d->common_base, VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_STATUS_ACK);
    mmio_write8(d->common_base, VIRTIO_PCI_COMMON_STATUS,
                VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER);

    mmio_write32(d->common_base, VIRTIO_PCI_COMMON_DFSELECT, 1);
    features = ((uint64_t)mmio_read32(d->common_base, VIRTIO_PCI_COMMON_DF)) << 32;
    mmio_write32(d->common_base, VIRTIO_PCI_COMMON_DFSELECT, 0);
    features |= mmio_read32(d->common_base, VIRTIO_PCI_COMMON_DF);
    if ((features & VIRTIO_F_VERSION_1) == 0) {
        mmio_write8(d->common_base, VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_STATUS_FAILED);
        printf("[virtio-input] modern device missing VERSION_1 feature\n");
        return -1;
    }

    mmio_write32(d->common_base, VIRTIO_PCI_COMMON_GFSELECT, 0);
    mmio_write32(d->common_base, VIRTIO_PCI_COMMON_GF, 0);
    mmio_write32(d->common_base, VIRTIO_PCI_COMMON_GFSELECT, 1);
    mmio_write32(d->common_base, VIRTIO_PCI_COMMON_GF, (uint32_t)(VIRTIO_F_VERSION_1 >> 32));
    mmio_write8(d->common_base, VIRTIO_PCI_COMMON_STATUS,
                VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER |
                VIRTIO_CONFIG_STATUS_FEATURES_OK);
    if ((mmio_read8(d->common_base, VIRTIO_PCI_COMMON_STATUS) &
         VIRTIO_CONFIG_STATUS_FEATURES_OK) == 0) {
        mmio_write8(d->common_base, VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_STATUS_FAILED);
        printf("[virtio-input] feature negotiation rejected\n");
        return -1;
    }

    mmio_write16(d->common_base, VIRTIO_PCI_COMMON_Q_SELECT, VIRTIO_INPUT_EVENTQ);
    qsz0 = mmio_read16(d->common_base, VIRTIO_PCI_COMMON_Q_SIZE);
    mmio_write16(d->common_base, VIRTIO_PCI_COMMON_Q_SELECT, VIRTIO_INPUT_STATUSQ);
    qsz1 = mmio_read16(d->common_base, VIRTIO_PCI_COMMON_Q_SIZE);
    if (virtio_input_setup_queue(&d->eventq, qsz0) < 0 ||
        virtio_input_setup_queue(&d->statusq, qsz1) < 0) {
        mmio_write8(d->common_base, VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_STATUS_FAILED);
        printf("[virtio-input] queue sizes event=%u status=%u do not fit local rings\n", qsz0, qsz1);
        return -1;
    }

    virtio_input_program_queue(d, &d->eventq, VIRTIO_INPUT_EVENTQ);
    virtio_input_program_queue(d, &d->statusq, VIRTIO_INPUT_STATUSQ);
    virtio_input_read_name(d);
    virtio_input_probe_caps(d);
    virtio_input_post_all_events(d);
    virtio_mb();
    mmio_write8(d->common_base, VIRTIO_PCI_COMMON_STATUS,
                VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER |
                VIRTIO_CONFIG_STATUS_FEATURES_OK | VIRTIO_CONFIG_STATUS_DRIVER_OK);
    if ((mmio_read8(d->common_base, VIRTIO_PCI_COMMON_STATUS) &
         VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0) {
        mmio_write8(d->common_base, VIRTIO_PCI_COMMON_STATUS,
                    VIRTIO_CONFIG_STATUS_FAILED);
        printf("[virtio-input] device rejected DRIVER_OK\n");
        return -1;
    }
    /*
     * Publish the initial receive buffers only after DRIVER_OK is visible.
     * A notification sent earlier may be ignored, leaving a fully discovered
     * input device with an event queue that never starts.
     */
    virtio_mb();
    virtio_input_notify(d, &d->eventq);
    d->ready = 1;
    if (virtio_input_publish_device(d) < 0) {
        d->ready = 0;
        mmio_write8(d->common_base, VIRTIO_PCI_COMMON_STATUS,
                    VIRTIO_CONFIG_STATUS_FAILED);
        printf("[virtio-input] failed to publish Linux input device for %u:%u.%u\n",
               (uint32_t)bus, dev, fn);
        return -1;
    }
    g_vtinput_count++;
    printf("[virtio-input] device at %u:%u.%u qsz=%u name=\"%s\" key=%d rel=%d abs=%d\n",
           (uint32_t)bus, dev, fn, d->eventq.size, d->name, d->has_key, d->has_rel, d->has_abs);
    return 0;
}

int virtio_input_init(void) {
    int found = 0;
    memset(g_vtinput, 0, sizeof(g_vtinput));
    g_vtinput_count = 0;
    for (uint16_t bus = 0; bus < 256; ++bus) {
        for (uint8_t dev = 0; dev < 32; ++dev) {
            for (uint8_t fn = 0; fn < 8; ++fn) {
                uint32_t id = pci_cfg_read32((uint8_t)bus, dev, fn, 0x00);
                uint16_t vendor = (uint16_t)(id & 0xFFFFu);
                uint16_t device = (uint16_t)(id >> 16);
                if (vendor == 0xFFFFu) {
                    if (fn == 0) break;
                    continue;
                }
                if (vendor == VIRTIO_PCI_VENDORID && device == VIRTIO_PCI_DEVICEID_MODERN_INPUT) {
                    if (virtio_input_attach((uint8_t)bus, dev, fn) == 0) found++;
                    if (g_vtinput_count >= VIRTIO_INPUT_MAX_DEVICES) break;
                }
            }
        }
    }
    if (!found) {
        printf("[virtio-input] no modern PCI input device found\n");
        return -1;
    }
    return 0;
}

int virtio_input_is_ready(void) {
    return g_vtinput_count > 0;
}

void virtio_input_poll(void) {
    /*
     * Evdev readiness checks and the periodic input poll can run on separate
     * CPUs.  Serialize used-ring consumption without spinning because a timer
     * interrupt may preempt a task that is already draining this queue.
     */
    if (__atomic_exchange_n(&g_poll_active, 1u, __ATOMIC_ACQUIRE))
        return;
    for (int i = 0; i < g_vtinput_count; ++i) {
        virtio_input_dev_t *d = &g_vtinput[i];
        virtio_input_queue_t *q = &d->eventq;
        int consumed = 0;
        int replenished = 0;
        if (!d->ready) continue;
        while (q->used_idx != q->used->idx) {
            struct vring_used_elem *e = &q->used->ring[q->used_idx % q->size];
            uint16_t id = (uint16_t)e->id;
            consumed = 1;
            if (id < q->size && e->len >= VIRTIO_INPUT_EVENT_BYTES) {
                virtio_input_handle_event(d, &d->event_buf[id]);
                virtio_input_post_event_buf(d, id);
                replenished = 1;
            }
            q->used_idx++;
        }
        /* Reading the PCI ISR page acknowledges legacy INTx and exits a VM. */
        if (consumed) (void)mmio_read8(d->isr_base, 0);
        virtio_mb();
        /*
         * Queue notification announces newly available descriptors; it is
         * not a device-poll operation.  Notifying an idle queue turns every
         * evdev readiness check into an MMIO/KVM exit and makes an otherwise
         * idle desktop consume a measurable fraction of a host CPU.
         */
        if (replenished) virtio_input_notify(d, q);
    }
    __atomic_store_n(&g_poll_active, 0u, __ATOMIC_RELEASE);
}
