/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This file contains VirtIO ring and network protocol definitions derived from
 * FreeBSD sys/dev/virtio/virtio_ring.h and sys/dev/virtio/network/virtio_net.h.
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
 * Portions also use BSD-licensed VirtIO PCI/config constants and network queue
 * structure from FreeBSD sys/dev/virtio/pci, sys/dev/virtio/virtio_config.h,
 * sys/dev/virtio/pci/virtio_pci_modern_var.h, and
 * sys/dev/virtio/network/if_vtnetvar.h:
 *
 * Copyright (c) 2011, 2014, 2017, Bryan Venteicher <bryanv@FreeBSD.org>
 * All rights reserved.
 *
 * Modifications for EdgeOS.
 * Copyright (c) EdgeOS Contributors.
 */

#include "drivers/virtio_net.h"
#include "drivers/apic.h"
#include "drivers/pci.h"

#include "arch/x86_64/pic.h"
#include "arch/x86_64/io_ports.h"
#include "arch/x86_64/isr.h"
#include "stdio.h"
#include "string.h"
#include "sys/boottime.h"
#include "sys/mmio.h"
#include "sys/scheduler.h"

#define VIRTIO_PCI_VENDORID 0x1AF4u
#define VIRTIO_PCI_DEVICEID_NET_LEGACY 0x1000u
#define VIRTIO_PCI_DEVICEID_MODERN_NET 0x1041u

#define PCI_COMMAND_MEM 0x0002u
#define PCI_COMMAND_BUSMASTER 0x0004u
#define PCI_STATUS_CAP_LIST 0x0010u
#define PCI_CAP_ID_VENDOR 0x09u

#define VIRTIO_CONFIG_STATUS_RESET     0x00u
#define VIRTIO_CONFIG_STATUS_ACK       0x01u
#define VIRTIO_CONFIG_STATUS_DRIVER    0x02u
#define VIRTIO_CONFIG_STATUS_DRIVER_OK 0x04u
#define VIRTIO_CONFIG_STATUS_FEATURES_OK 0x08u
#define VIRTIO_CONFIG_STATUS_FAILED    0x80u

#define VIRTIO_F_VERSION_1 (1ull << 32)
#define VIRTIO_NET_F_MAC  (1ull << 5)

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
#define VRING_DESC_F_NEXT  1u
#define VRING_DESC_F_WRITE 2u

#define VIRTIO_NET_RX_QUEUE 0u
#define VIRTIO_NET_TX_QUEUE 1u
#define VIRTIO_NET_QUEUE_SIZE 128u
#define VIRTIO_NET_RING_BYTES 16384u
#define VIRTIO_NET_RX_FRAME_BYTES 2048u
#define VIRTIO_NET_TX_FRAME_BYTES 2048u
#define VIRTIO_MSI_NO_VECTOR 0xFFFFu
#define VIRTIO_MODERN_COMMON_MIN_SIZE 56u
#define VIRTIO_MODERN_NOTIFY_MIN_SIZE 2u
#define VIRTIO_MODERN_ISR_MIN_SIZE 1u

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

struct virtio_net_hdr_v1 {
    uint8_t flags;
    uint8_t gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
    uint16_t num_buffers;
} __attribute__((packed));

typedef struct {
    struct virtio_net_hdr_v1 hdr;
    uint8_t frame[VIRTIO_NET_RX_FRAME_BYTES];
} __attribute__((packed, aligned(16))) virtio_net_rx_buf_t;

typedef struct {
    struct virtio_net_hdr_v1 hdr;
    uint8_t frame[VIRTIO_NET_TX_FRAME_BYTES];
} __attribute__((packed, aligned(16))) virtio_net_tx_buf_t;

typedef struct {
    uint8_t ring[VIRTIO_NET_RING_BYTES] __attribute__((aligned(VIRTIO_PCI_VRING_ALIGN)));
    struct vring_desc *desc;
    struct vring_avail *avail;
    struct vring_used *used;
    uint16_t size;
    uint16_t avail_idx;
    uint16_t used_idx;
    uint16_t notify_off;
} virtio_net_queue_t;

typedef struct {
    volatile uint8_t *common_base;
    volatile uint8_t *notify_base;
    volatile uint8_t *isr_base;
    volatile uint8_t *device_base;
    uint32_t notify_multiplier;
    uint8_t bus;
    uint8_t dev;
    uint8_t fn;
    uint8_t irq_line;
    uint8_t irq_vector;
    uint8_t irq_mode;
    void *irq_cookie;
    int present;
    uint8_t mac[6];
    virtio_net_rx_frame_cb_t rx_cb;
    virtio_net_queue_t rxq;
    virtio_net_queue_t txq;
} virtio_net_dev_t;

typedef struct {
    uint8_t bar;
    uint32_t offset;
    uint32_t length;
} virtio_modern_cap_t;

static virtio_net_dev_t g_vtnet;
static virtio_net_rx_buf_t g_vtnet_rx_buf[VIRTIO_NET_QUEUE_SIZE];
static virtio_net_tx_buf_t g_vtnet_tx_buf[VIRTIO_NET_QUEUE_SIZE];
static uint8_t g_vtnet_tx_in_flight[VIRTIO_NET_QUEUE_SIZE];
static uint16_t g_vtnet_tx_next;
static uint16_t g_vtnet_tx_free_count;
static volatile int g_vtnet_tx_lock;
static volatile uint32_t g_vtnet_rx_irq_pending;
static uint32_t g_vtnet_irq_count;
static uint32_t g_vtnet_rx_count;
static uint32_t g_vtnet_tx_count;

static void virtio_net_irq_handler(void *context);

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

static uint8_t virtio_status_get(void) {
    return mmio_read8(g_vtnet.common_base, VIRTIO_PCI_COMMON_STATUS);
}

static void virtio_status_set(uint8_t status) {
    mmio_write8(g_vtnet.common_base, VIRTIO_PCI_COMMON_STATUS, status);
}

static uint64_t virtio_features_read(void) {
    uint32_t lo;
    uint32_t hi;
    mmio_write32(g_vtnet.common_base, VIRTIO_PCI_COMMON_DFSELECT, 0);
    lo = mmio_read32(g_vtnet.common_base, VIRTIO_PCI_COMMON_DF);
    mmio_write32(g_vtnet.common_base, VIRTIO_PCI_COMMON_DFSELECT, 1);
    hi = mmio_read32(g_vtnet.common_base, VIRTIO_PCI_COMMON_DF);
    return (uint64_t)lo | ((uint64_t)hi << 32);
}

static void virtio_features_write(uint64_t features) {
    mmio_write32(g_vtnet.common_base, VIRTIO_PCI_COMMON_GFSELECT, 0);
    mmio_write32(g_vtnet.common_base, VIRTIO_PCI_COMMON_GF, (uint32_t)features);
    mmio_write32(g_vtnet.common_base, VIRTIO_PCI_COMMON_GFSELECT, 1);
    mmio_write32(g_vtnet.common_base, VIRTIO_PCI_COMMON_GF, (uint32_t)(features >> 32));
}

static void virtio_device_config_read_mac(uint8_t mac[6]) {
    uint8_t gen;
    do {
        gen = mmio_read8(g_vtnet.common_base, VIRTIO_PCI_COMMON_CFGGENERATION);
        for (uint32_t i = 0; i < 6; ++i) mac[i] = mmio_read8(g_vtnet.device_base, i);
    } while (gen != mmio_read8(g_vtnet.common_base, VIRTIO_PCI_COMMON_CFGGENERATION));
}

static void virtio_queue_select(uint16_t idx) {
    mmio_write16(g_vtnet.common_base, VIRTIO_PCI_COMMON_Q_SELECT, idx);
}

static uint16_t virtio_queue_size_read(void) {
    return mmio_read16(g_vtnet.common_base, VIRTIO_PCI_COMMON_Q_SIZE);
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
    return qsz >= 2 && qsz <= VIRTIO_NET_QUEUE_SIZE &&
           used_off + used_bytes <= VIRTIO_NET_RING_BYTES;
}

static void virtio_queue_setup(virtio_net_queue_t *q, uint16_t qsz) {
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

static int virtio_queue_program(uint16_t index, virtio_net_queue_t *q, uint16_t qsz) {
    uintptr_t desc;
    uintptr_t avail;
    uintptr_t used;
    uint16_t max_qsz;

    virtio_queue_select(index);
    max_qsz = virtio_queue_size_read();
    if (max_qsz < qsz || !virtio_queue_ring_fits(qsz)) return -1;

    virtio_queue_setup(q, qsz);
    desc = (uintptr_t)q->desc;
    avail = (uintptr_t)q->avail;
    used = (uintptr_t)q->used;
    mmio_write16(g_vtnet.common_base, VIRTIO_PCI_COMMON_Q_SIZE, qsz);
    q->notify_off = mmio_read16(g_vtnet.common_base, VIRTIO_PCI_COMMON_Q_NOFF);
    mmio_write32(g_vtnet.common_base, VIRTIO_PCI_COMMON_Q_DESCLO, (uint32_t)desc);
    mmio_write32(g_vtnet.common_base, VIRTIO_PCI_COMMON_Q_DESCHI, (uint32_t)((uint64_t)desc >> 32));
    mmio_write32(g_vtnet.common_base, VIRTIO_PCI_COMMON_Q_AVAILLO, (uint32_t)avail);
    mmio_write32(g_vtnet.common_base, VIRTIO_PCI_COMMON_Q_AVAILHI, (uint32_t)((uint64_t)avail >> 32));
    mmio_write32(g_vtnet.common_base, VIRTIO_PCI_COMMON_Q_USEDLO, (uint32_t)used);
    mmio_write32(g_vtnet.common_base, VIRTIO_PCI_COMMON_Q_USEDHI, (uint32_t)((uint64_t)used >> 32));
    mmio_write16(g_vtnet.common_base, VIRTIO_PCI_COMMON_Q_ENABLE, 1);
    return 0;
}

static void virtio_queue_notify(const virtio_net_queue_t *q, uint16_t queue_index) {
    uint32_t off = (uint32_t)q->notify_off * g_vtnet.notify_multiplier;
    mmio_write16(g_vtnet.notify_base, off, queue_index);
}

static int virtio_queue_set_msix(uint16_t queue_index,
                                 uint16_t table_index) {
    virtio_queue_select(queue_index);
    mmio_write16(g_vtnet.common_base,
                 VIRTIO_PCI_COMMON_Q_MSIX_VECTOR, table_index);
    return mmio_read16(g_vtnet.common_base,
                       VIRTIO_PCI_COMMON_Q_MSIX_VECTOR) == table_index ?
        0 : -1;
}

static void virtio_ack_isr(void) {
    (void)mmio_read8(g_vtnet.isr_base, 0);
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
                                   virtio_modern_cap_t *device_cfg,
                                   uint32_t *notify_multiplier) {
    uint16_t status = pci_cfg_read16(bus, dev, fn, 0x06);
    uint8_t cap = pci_cfg_read8(bus, dev, fn, 0x34) & 0xFCu;
    int have_common = 0;
    int have_notify = 0;
    int have_isr = 0;
    int have_device = 0;

    if ((status & PCI_STATUS_CAP_LIST) == 0) return -1;
    for (uint32_t guard = 0; cap >= 0x40 && guard < 48; ++guard) {
        uint8_t id = pci_cfg_read8(bus, dev, fn, cap);
        uint8_t next = pci_cfg_read8(bus, dev, fn, (uint8_t)(cap + 1u)) & 0xFCu;
        if (id == PCI_CAP_ID_VENDOR) {
            uint8_t cfg_type = pci_cfg_read8(bus, dev, fn, (uint8_t)(cap + VIRTIO_PCI_CAP_CFG_TYPE));
            virtio_modern_cap_t tmp;
            if (virtio_modern_read_cap(bus, dev, fn, cap, &tmp) == 0) {
                if (cfg_type == VIRTIO_PCI_CAP_COMMON_CFG) {
                    *common = tmp;
                    have_common = 1;
                } else if (cfg_type == VIRTIO_PCI_CAP_NOTIFY_CFG) {
                    *notify = tmp;
                    *notify_multiplier = pci_cfg_read32(bus, dev, fn, (uint8_t)(cap + VIRTIO_PCI_NOTIFY_CAP_MULT));
                    have_notify = 1;
                } else if (cfg_type == VIRTIO_PCI_CAP_ISR_CFG) {
                    *isr = tmp;
                    have_isr = 1;
                } else if (cfg_type == VIRTIO_PCI_CAP_DEVICE_CFG) {
                    *device_cfg = tmp;
                    have_device = 1;
                }
            }
        }
        if (next == 0 || next == cap) break;
        cap = next;
    }

    if (!have_common || !have_notify || !have_isr || !have_device) return -1;
    if (!virtio_modern_cap_valid(common, VIRTIO_MODERN_COMMON_MIN_SIZE, 4)) return -1;
    if (!virtio_modern_cap_valid(notify, VIRTIO_MODERN_NOTIFY_MIN_SIZE, 2)) return -1;
    if (!virtio_modern_cap_valid(isr, VIRTIO_MODERN_ISR_MIN_SIZE, 1)) return -1;
    if (!virtio_modern_cap_valid(device_cfg, 6, 1)) return -1;
    return 0;
}

static int virtio_net_find_modern(void) {
    for (uint16_t bus = 0; bus < 256; ++bus) {
        for (uint8_t dev = 0; dev < 32; ++dev) {
            for (uint8_t fn = 0; fn < 8; ++fn) {
                uint32_t id = pci_cfg_read32((uint8_t)bus, dev, fn, 0x00);
                uint16_t vendor = (uint16_t)(id & 0xFFFFu);
                uint16_t device = (uint16_t)(id >> 16);
                virtio_modern_cap_t common;
                virtio_modern_cap_t notify;
                virtio_modern_cap_t isr;
                virtio_modern_cap_t device_cfg;
                uint32_t notify_multiplier = 0;
                if (vendor == 0xFFFFu) {
                    if (fn == 0) break;
                    continue;
                }
                if (vendor != VIRTIO_PCI_VENDORID ||
                    (device != VIRTIO_PCI_DEVICEID_MODERN_NET &&
                     device != VIRTIO_PCI_DEVICEID_NET_LEGACY)) {
                    continue;
                }
                memset(&common, 0, sizeof(common));
                memset(&notify, 0, sizeof(notify));
                memset(&isr, 0, sizeof(isr));
                memset(&device_cfg, 0, sizeof(device_cfg));
                if (virtio_modern_find_caps((uint8_t)bus, dev, fn, &common, &notify, &isr,
                                            &device_cfg, &notify_multiplier) < 0) {
                    if (device == VIRTIO_PCI_DEVICEID_MODERN_NET) {
                        printf("[virtio-net] modern device %u:%u.%u missing usable PCI capabilities\n",
                               (uint32_t)bus, dev, fn);
                    }
                    continue;
                }
                if (virtio_modern_cap_addr((uint8_t)bus, dev, fn, &common, &g_vtnet.common_base) < 0 ||
                    virtio_modern_cap_addr((uint8_t)bus, dev, fn, &notify, &g_vtnet.notify_base) < 0 ||
                    virtio_modern_cap_addr((uint8_t)bus, dev, fn, &isr, &g_vtnet.isr_base) < 0 ||
                    virtio_modern_cap_addr((uint8_t)bus, dev, fn, &device_cfg, &g_vtnet.device_base) < 0) {
                    printf("[virtio-net] modern device %u:%u.%u has unsupported BAR mapping\n",
                           (uint32_t)bus, dev, fn);
                    continue;
                }
                g_vtnet.bus = (uint8_t)bus;
                g_vtnet.dev = dev;
                g_vtnet.fn = fn;
                g_vtnet.notify_multiplier = notify_multiplier;
                return 0;
            }
        }
    }
    return -1;
}

static void virtio_net_fail(void) {
    virtio_status_set((uint8_t)(virtio_status_get() | VIRTIO_CONFIG_STATUS_FAILED));
}

static void virtio_net_requeue_rx(uint16_t id) {
    virtio_net_queue_t *q = &g_vtnet.rxq;
    memset(&g_vtnet_rx_buf[id].hdr, 0, sizeof(g_vtnet_rx_buf[id].hdr));
    q->desc[id].addr = (uint64_t)(uintptr_t)&g_vtnet_rx_buf[id];
    q->desc[id].len = sizeof(g_vtnet_rx_buf[id]);
    q->desc[id].flags = VRING_DESC_F_WRITE;
    q->desc[id].next = 0;
    q->avail->ring[q->avail_idx % q->size] = id;
    __sync_synchronize();
    q->avail_idx++;
    q->avail->idx = q->avail_idx;
}

static void virtio_net_post_rx_buffers(void) {
    virtio_net_queue_t *q = &g_vtnet.rxq;
    for (uint16_t i = 0; i < q->size; ++i) virtio_net_requeue_rx(i);
    __sync_synchronize();
    virtio_queue_notify(q, VIRTIO_NET_RX_QUEUE);
}

static void virtio_net_setup_interrupts(void) {
    int vector;
    uint32_t allocated_vector;
    uint8_t irq_line = g_vtnet.irq_line;

    g_vtnet.irq_mode = 0;
    g_vtnet.irq_vector = 0;
    g_vtnet.irq_cookie = 0;
    vector = apic_allocate_msi_vector();
    if (vector >= 0) {
        allocated_vector = (uint32_t)vector;
        if (pci_enable_msix_vector(g_vtnet.bus, g_vtnet.dev,
                g_vtnet.fn, 0, (uint8_t)vector) == 0) {
            if (virtio_queue_set_msix(VIRTIO_NET_RX_QUEUE, 0) == 0 &&
                virtio_queue_set_msix(VIRTIO_NET_TX_QUEUE, 0) == 0 &&
                isr_register_context_interrupt_handler(vector,
                    virtio_net_irq_handler, 0,
                    &g_vtnet.irq_cookie) == 0) {
                mmio_write16(g_vtnet.common_base,
                             VIRTIO_PCI_COMMON_MSIX_CONFIG,
                             VIRTIO_MSI_NO_VECTOR);
                g_vtnet.irq_vector = (uint8_t)vector;
                g_vtnet.irq_mode = 3;
                printf("[virtio-net] msix queue vector=%u table=0 irq_line=%u\n",
                       (uint32_t)g_vtnet.irq_vector,
                       (uint32_t)irq_line);
                return;
            }
            (void)virtio_queue_set_msix(VIRTIO_NET_RX_QUEUE,
                                        VIRTIO_MSI_NO_VECTOR);
            (void)virtio_queue_set_msix(VIRTIO_NET_TX_QUEUE,
                                        VIRTIO_MSI_NO_VECTOR);
            (void)pci_disable_msix_vectors(g_vtnet.bus,
                                           g_vtnet.dev, g_vtnet.fn);
        }
        apic_release_msi_vectors(&allocated_vector, 1);
    }

    vector = apic_allocate_msi_vector();
    if (vector >= 0) {
        allocated_vector = (uint32_t)vector;
        if (pci_enable_msi_vector(g_vtnet.bus, g_vtnet.dev,
                g_vtnet.fn, (uint8_t)vector) == 0) {
            if (isr_register_context_interrupt_handler(vector,
                    virtio_net_irq_handler, 0,
                    &g_vtnet.irq_cookie) == 0) {
                g_vtnet.irq_vector = (uint8_t)vector;
                g_vtnet.irq_mode = 2;
                printf("[virtio-net] msi vector=%u irq_line=%u\n",
                       (uint32_t)g_vtnet.irq_vector,
                       (uint32_t)irq_line);
                return;
            }
            (void)pci_disable_msi_vectors(g_vtnet.bus,
                                          g_vtnet.dev, g_vtnet.fn);
        }
        apic_release_msi_vectors(&allocated_vector, 1);
    }

    if (irq_line < 16u &&
        isr_register_context_interrupt_handler(IRQ_BASE + irq_line,
            virtio_net_irq_handler, 0, &g_vtnet.irq_cookie) == 0) {
        pic8259_unmask_irq(irq_line);
        g_vtnet.irq_vector = (uint8_t)(IRQ_BASE + irq_line);
        g_vtnet.irq_mode = 1;
        printf("[virtio-net] intx irq line %u handler installed\n",
               (uint32_t)irq_line);
    } else {
        printf("[virtio-net] no usable interrupt route irq_line=%u, using polling mode\n",
               (uint32_t)irq_line);
    }
}

int virtio_net_init(void) {
    uint16_t cmd;
    uint8_t irq_line;
    uint64_t host_features;
    uint64_t guest_features;

    memset(&g_vtnet, 0, sizeof(g_vtnet));
    memset(g_vtnet_tx_buf, 0, sizeof(g_vtnet_tx_buf));
    memset(g_vtnet_tx_in_flight, 0, sizeof(g_vtnet_tx_in_flight));
    g_vtnet_tx_next = 0;
    g_vtnet_tx_free_count = 0;
    g_vtnet_tx_lock = 0;
    g_vtnet_rx_irq_pending = 0;
    if (virtio_net_find_modern() < 0) return -1;

    cmd = pci_cfg_read16(g_vtnet.bus, g_vtnet.dev, g_vtnet.fn, 0x04);
    cmd |= PCI_COMMAND_MEM | PCI_COMMAND_BUSMASTER;
    pci_cfg_write16(g_vtnet.bus, g_vtnet.dev, g_vtnet.fn, 0x04, cmd);
    irq_line = pci_cfg_read8(g_vtnet.bus, g_vtnet.dev, g_vtnet.fn, 0x3C);
    g_vtnet.irq_line = irq_line;

    virtio_status_set(VIRTIO_CONFIG_STATUS_RESET);
    for (uint32_t spin = 0; spin < 1000000u && virtio_status_get() != VIRTIO_CONFIG_STATUS_RESET; ++spin) {
        __asm__ __volatile__("pause");
    }
    virtio_status_set(VIRTIO_CONFIG_STATUS_ACK);
    virtio_status_set((uint8_t)(VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER));

    host_features = virtio_features_read();
    if ((host_features & VIRTIO_F_VERSION_1) == 0) {
        printf("[virtio-net] modern device missing VERSION_1 feature\n");
        virtio_net_fail();
        return -1;
    }
    guest_features = VIRTIO_F_VERSION_1;
    if (host_features & VIRTIO_NET_F_MAC) guest_features |= VIRTIO_NET_F_MAC;
    virtio_features_write(guest_features);
    virtio_status_set((uint8_t)(VIRTIO_CONFIG_STATUS_ACK |
                                VIRTIO_CONFIG_STATUS_DRIVER |
                                VIRTIO_CONFIG_STATUS_FEATURES_OK));
    if ((virtio_status_get() & VIRTIO_CONFIG_STATUS_FEATURES_OK) == 0) {
        printf("[virtio-net] feature negotiation rejected\n");
        virtio_net_fail();
        return -1;
    }

    if (guest_features & VIRTIO_NET_F_MAC) {
        virtio_device_config_read_mac(g_vtnet.mac);
    } else {
        g_vtnet.mac[0] = 0x52u;
        g_vtnet.mac[1] = 0x54u;
        g_vtnet.mac[2] = 0x00u;
        g_vtnet.mac[3] = 0x12u;
        g_vtnet.mac[4] = 0x34u;
        g_vtnet.mac[5] = 0x56u;
    }

    if (virtio_queue_program(VIRTIO_NET_RX_QUEUE, &g_vtnet.rxq, VIRTIO_NET_QUEUE_SIZE) < 0 ||
        virtio_queue_program(VIRTIO_NET_TX_QUEUE, &g_vtnet.txq, VIRTIO_NET_QUEUE_SIZE) < 0) {
        printf("[virtio-net] unsupported queue layout\n");
        virtio_net_fail();
        return -1;
    }
    g_vtnet_tx_free_count = g_vtnet.txq.size;

    virtio_net_post_rx_buffers();
    virtio_net_setup_interrupts();
    g_vtnet.present = 1;
    virtio_status_set((uint8_t)(VIRTIO_CONFIG_STATUS_ACK |
                                VIRTIO_CONFIG_STATUS_DRIVER |
                                VIRTIO_CONFIG_STATUS_FEATURES_OK |
                                VIRTIO_CONFIG_STATUS_DRIVER_OK));
    printf("[virtio-net] modern PCI network device at %u:%u.%u common=0x%x mac=%x:%x:%x:%x:%x:%x qsz=%u irq=%u mode=%u vector=%u\n",
           g_vtnet.bus, g_vtnet.dev, g_vtnet.fn,
           (uint32_t)(uintptr_t)g_vtnet.common_base,
           g_vtnet.mac[0], g_vtnet.mac[1], g_vtnet.mac[2],
           g_vtnet.mac[3], g_vtnet.mac[4], g_vtnet.mac[5],
           g_vtnet.rxq.size, (uint32_t)irq_line,
           (uint32_t)g_vtnet.irq_mode,
           (uint32_t)g_vtnet.irq_vector);
    return 0;
}

int virtio_net_is_ready(void) {
    return g_vtnet.present ? 1 : 0;
}

void virtio_net_set_rx_frame_callback(virtio_net_rx_frame_cb_t cb) {
    g_vtnet.rx_cb = cb;
}

int virtio_net_get_mac(uint8_t mac_out[6]) {
    if (!g_vtnet.present || !mac_out) return -1;
    memcpy(mac_out, g_vtnet.mac, 6);
    return 0;
}

static uint16_t virtio_net_reap_tx(void) {
    virtio_net_queue_t *q = &g_vtnet.txq;
    uint16_t device_index;
    uint16_t pending;
    uint16_t reaped = 0;

    __sync_synchronize();
    device_index = q->used->idx;
    pending = (uint16_t)(device_index - q->used_idx);
    if (pending > q->size) {
        printf("[virtio-net] TX used-ring overrun driver=%u device=%u pending=%u\n",
               (uint32_t)q->used_idx, (uint32_t)device_index,
               (uint32_t)pending);
        q->used_idx = (uint16_t)(device_index - q->size);
        pending = q->size;
    }
    while (pending--) {
        struct vring_used_elem *used =
            &q->used->ring[q->used_idx % q->size];
        uint32_t descriptor;

        __sync_synchronize();
        descriptor = used->id;
        if (descriptor < q->size &&
            g_vtnet_tx_in_flight[descriptor]) {
            g_vtnet_tx_in_flight[descriptor] = 0;
            if (g_vtnet_tx_free_count < q->size)
                ++g_vtnet_tx_free_count;
            ++g_vtnet_tx_count;
        }
        ++q->used_idx;
        ++reaped;
    }
    return reaped;
}

static int virtio_net_reserve_tx_descriptor(uint16_t *descriptor_out) {
    virtio_net_queue_t *q = &g_vtnet.txq;
    uint64_t deadline;

    if (!descriptor_out) return -1;
    (void)virtio_net_reap_tx();
    if (!g_vtnet_tx_free_count) {
        deadline = boottime_monotonic_us() + 1000000ull;
        while (!g_vtnet_tx_free_count &&
               boottime_monotonic_us() < deadline) {
            if (virtio_net_reap_tx()) break;
            __asm__ __volatile__("pause");
        }
    }
    if (!g_vtnet_tx_free_count) return -1;
    for (uint16_t scanned = 0; scanned < q->size; ++scanned) {
        uint16_t descriptor = g_vtnet_tx_next++ % q->size;
        if (g_vtnet_tx_in_flight[descriptor]) continue;
        g_vtnet_tx_in_flight[descriptor] = 1;
        --g_vtnet_tx_free_count;
        *descriptor_out = descriptor;
        return 0;
    }
    return -1;
}

void virtio_net_poll(void) {
    virtio_net_queue_t *q = &g_vtnet.rxq;
    int requeued = 0;
    if (!g_vtnet.present) return;
    if (!__sync_lock_test_and_set(&g_vtnet_tx_lock, 1)) {
        (void)virtio_net_reap_tx();
        __sync_lock_release(&g_vtnet_tx_lock);
    }
    g_vtnet_rx_irq_pending = 0;
    virtio_ack_isr();
    while (q->used_idx != q->used->idx) {
        struct vring_used_elem *ue = &q->used->ring[q->used_idx % q->size];
        uint16_t id = (uint16_t)ue->id;
        uint32_t len = ue->len;
        __sync_synchronize();
        if (id < q->size && len > sizeof(struct virtio_net_hdr_v1)) {
            uint32_t frame_len = len - (uint32_t)sizeof(struct virtio_net_hdr_v1);
            if (frame_len <= VIRTIO_NET_RX_FRAME_BYTES && g_vtnet.rx_cb) {
                g_vtnet_rx_count++;
                g_vtnet.rx_cb(g_vtnet_rx_buf[id].frame, frame_len);
            }
        }
        q->used_idx++;
        if (id < q->size) {
            virtio_net_requeue_rx(id);
            requeued = 1;
        }
    }
    if (requeued) {
        __sync_synchronize();
        virtio_queue_notify(q, VIRTIO_NET_RX_QUEUE);
    }
}

static void virtio_net_irq_handler(void *context) {
    (void)context;
    if (!g_vtnet.present) return;
    g_vtnet_irq_count++;
    (void)virtio_ack_isr();
    g_vtnet_rx_irq_pending = 1;
    scheduler_request_deferred_work();
    /*
     * Virtio interrupts may arrive while a socket syscall is mutating lwIP.
     * A NO_SYS lwIP core must never be re-entered from the hard IRQ.  The IRQ
     * only acknowledges the device and wakes HLT; scheduler_idle_loop() drains
     * this queue from the same process-context bottom half used by e1000.
     */
}

int
virtio_net_get_pci_location(uint8_t *bus, uint8_t *slot,
                            uint8_t *function)
{
    if (!g_vtnet.present || !bus || !slot || !function)
        return -1;
    *bus = g_vtnet.bus;
    *slot = g_vtnet.dev;
    *function = g_vtnet.fn;
    return 0;
}

int
virtio_net_stop(void)
{
    uint32_t vector;

    if (!g_vtnet.present)
        return 0;
    g_vtnet.present = 0;
    g_vtnet.rx_cb = 0;
    __sync_synchronize();
    virtio_status_set(VIRTIO_CONFIG_STATUS_RESET);
    if (g_vtnet.irq_mode == 3)
        (void)pci_disable_msix_vectors(g_vtnet.bus,
                                       g_vtnet.dev, g_vtnet.fn);
    else if (g_vtnet.irq_mode == 2)
        (void)pci_disable_msi_vectors(g_vtnet.bus,
                                      g_vtnet.dev, g_vtnet.fn);
    if (g_vtnet.irq_cookie &&
        isr_unregister_context_interrupt_handler(
            g_vtnet.irq_cookie) != 0)
        return -1;
    if (g_vtnet.irq_mode == 2 || g_vtnet.irq_mode == 3) {
        vector = g_vtnet.irq_vector;
        apic_release_msi_vectors(&vector, 1);
    }
    g_vtnet.irq_cookie = 0;
    g_vtnet.irq_mode = 0;
    g_vtnet.irq_vector = 0;
    printf("[virtio-net] native PCI transport stopped\n");
    return 0;
}

int
virtio_net_resume(void)
{
    if (g_vtnet.present)
        return 0;
    return virtio_net_init();
}

int virtio_net_send_frame_raw(const void *frame, uint16_t len) {
    virtio_net_queue_t *q = &g_vtnet.txq;
    virtio_net_tx_buf_t *buffer;
    uint16_t descriptor;
    uint16_t wire_len;

    if (!g_vtnet.present || !frame || len == 0 || len > VIRTIO_NET_TX_FRAME_BYTES) return -1;
    if (__sync_lock_test_and_set(&g_vtnet_tx_lock, 1)) return -1;
    if (virtio_net_reserve_tx_descriptor(&descriptor) < 0) {
        __sync_lock_release(&g_vtnet_tx_lock);
        return -1;
    }

    wire_len = len < EDGE_VIRTIO_NET_ETHERNET_MIN_FRAME_SIZE ?
        EDGE_VIRTIO_NET_ETHERNET_MIN_FRAME_SIZE : len;
    buffer = &g_vtnet_tx_buf[descriptor];
    memset(&buffer->hdr, 0, sizeof(buffer->hdr));
    memcpy(buffer->frame, frame, len);
    if (wire_len > len) memset(buffer->frame + len, 0, wire_len - len);

    q->desc[descriptor].addr = (uint64_t)(uintptr_t)buffer;
    q->desc[descriptor].len =
        (uint32_t)sizeof(struct virtio_net_hdr_v1) + wire_len;
    q->desc[descriptor].flags = 0;
    q->desc[descriptor].next = 0;
    q->avail->ring[q->avail_idx % q->size] = descriptor;
    __sync_synchronize();
    q->avail_idx++;
    q->avail->idx = q->avail_idx;
    __sync_synchronize();
    virtio_queue_notify(q, VIRTIO_NET_TX_QUEUE);
    __sync_lock_release(&g_vtnet_tx_lock);
    return 0;
}
