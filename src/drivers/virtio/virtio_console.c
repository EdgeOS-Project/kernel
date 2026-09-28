/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This file contains VirtIO ring, PCI transport, and console definitions
 * derived from FreeBSD sys/dev/virtio/virtio_ring.h,
 * sys/dev/virtio/pci, sys/dev/virtio/virtio_config.h,
 * sys/dev/virtio/pci/virtio_pci_modern_var.h, and
 * sys/dev/virtio/console/virtio_console.h.
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
 * Copyright (C) Red Hat, Inc., 2009, 2010, 2011
 * Copyright (C) Amit Shah <amit.shah@redhat.com>, 2009, 2010, 2011
 *
 * Copyright (c) 2011, 2014, 2017, Bryan Venteicher <bryanv@FreeBSD.org>
 * All rights reserved.
 *
 * Modifications for EdgeOS.
 * Copyright (c) EdgeOS Contributors.
 */

#include "drivers/virtio_console.h"
#include "drivers/pci.h"

#include "arch/x86_64/io_ports.h"
#include "stdio.h"
#include "string.h"
#include "sys/mmio.h"

#include <stdint.h>

#define VIRTIO_PCI_VENDORID 0x1AF4u
#define VIRTIO_PCI_DEVICEID_CONSOLE_LEGACY 0x1003u
#define VIRTIO_PCI_DEVICEID_MODERN_CONSOLE 0x1043u

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

#define VIRTIO_CONSOLE_F_SIZE      (1ull << 0)
#define VIRTIO_CONSOLE_F_MULTIPORT (1ull << 1)

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
#define VIRTIO_PCI_COMMON_STATUS        20u
#define VIRTIO_PCI_COMMON_CFGGENERATION 21u
#define VIRTIO_PCI_COMMON_Q_SELECT      22u
#define VIRTIO_PCI_COMMON_Q_SIZE        24u
#define VIRTIO_PCI_COMMON_Q_ENABLE      28u
#define VIRTIO_PCI_COMMON_Q_NOFF        30u
#define VIRTIO_PCI_COMMON_Q_DESCLO      32u
#define VIRTIO_PCI_COMMON_Q_DESCHI      36u
#define VIRTIO_PCI_COMMON_Q_AVAILLO     40u
#define VIRTIO_PCI_COMMON_Q_AVAILHI     44u
#define VIRTIO_PCI_COMMON_Q_USEDLO      48u
#define VIRTIO_PCI_COMMON_Q_USEDHI      52u

#define VIRTIO_PCI_VRING_ALIGN 4096u
#define VRING_DESC_F_WRITE 2u
#define VIRTIO_CONSOLE_RXQ 0u
#define VIRTIO_CONSOLE_TXQ 1u
#define VIRTIO_CONSOLE_QUEUE_SIZE 32u
#define VIRTIO_CONSOLE_RING_BYTES 8192u
#define VIRTIO_CONSOLE_RX_BUF_BYTES 128u
#define VIRTIO_CONSOLE_TX_BUF_BYTES 256u
#define VIRTIO_CONSOLE_RX_RING_BYTES 4096u
#define VIRTIO_CONSOLE_TX_TIMEOUT 2000000u
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

typedef struct {
    uint8_t bar;
    uint32_t offset;
    uint32_t length;
} virtio_modern_cap_t;

typedef struct {
    uint8_t ring[VIRTIO_CONSOLE_RING_BYTES] __attribute__((aligned(VIRTIO_PCI_VRING_ALIGN)));
    struct vring_desc *desc;
    struct vring_avail *avail;
    struct vring_used *used;
    uint16_t size;
    uint16_t avail_idx;
    uint16_t used_idx;
    uint16_t notify_off;
} virtio_console_queue_t;

typedef struct {
    volatile uint8_t *common_base;
    volatile uint8_t *notify_base;
    volatile uint8_t *isr_base;
    volatile uint8_t *device_base;
    uint32_t notify_multiplier;
    uint8_t bus;
    uint8_t dev;
    uint8_t fn;
    uint16_t cols;
    uint16_t rows;
    int ready;
} virtio_console_dev_t;

static virtio_console_dev_t g_vtcon;
static virtio_console_queue_t g_vtcon_rxq;
static virtio_console_queue_t g_vtcon_txq;
static uint8_t g_vtcon_rx_buf[VIRTIO_CONSOLE_QUEUE_SIZE][VIRTIO_CONSOLE_RX_BUF_BYTES] __attribute__((aligned(16)));
static uint8_t g_vtcon_tx_buf[VIRTIO_CONSOLE_TX_BUF_BYTES] __attribute__((aligned(16)));
static uint8_t g_vtcon_in[VIRTIO_CONSOLE_RX_RING_BYTES];
static volatile uint32_t g_vtcon_in_head;
static volatile uint32_t g_vtcon_in_tail;
static volatile int g_vtcon_tx_busy;

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

static uint64_t virtio_features_read(void) {
    uint64_t f;
    mmio_write32(g_vtcon.common_base, VIRTIO_PCI_COMMON_DFSELECT, 0);
    f = mmio_read32(g_vtcon.common_base, VIRTIO_PCI_COMMON_DF);
    mmio_write32(g_vtcon.common_base, VIRTIO_PCI_COMMON_DFSELECT, 1);
    f |= ((uint64_t)mmio_read32(g_vtcon.common_base, VIRTIO_PCI_COMMON_DF)) << 32;
    return f;
}

static void virtio_features_write(uint64_t features) {
    mmio_write32(g_vtcon.common_base, VIRTIO_PCI_COMMON_GFSELECT, 0);
    mmio_write32(g_vtcon.common_base, VIRTIO_PCI_COMMON_GF, (uint32_t)features);
    mmio_write32(g_vtcon.common_base, VIRTIO_PCI_COMMON_GFSELECT, 1);
    mmio_write32(g_vtcon.common_base, VIRTIO_PCI_COMMON_GF, (uint32_t)(features >> 32));
}

static void virtio_status_set(uint8_t status) {
    mmio_write8(g_vtcon.common_base, VIRTIO_PCI_COMMON_STATUS, status);
}

static uint8_t virtio_status_get(void) {
    return mmio_read8(g_vtcon.common_base, VIRTIO_PCI_COMMON_STATUS);
}

static void virtio_fail(void) {
    virtio_status_set((uint8_t)(virtio_status_get() | VIRTIO_CONFIG_STATUS_FAILED));
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
    return qsz >= 2 && qsz <= VIRTIO_CONSOLE_QUEUE_SIZE &&
           used_off + used_bytes <= VIRTIO_CONSOLE_RING_BYTES;
}

static void virtio_queue_setup(virtio_console_queue_t *q, uint16_t qsz) {
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

static int virtio_queue_program(uint16_t index, virtio_console_queue_t *q, uint16_t want_qsz) {
    uintptr_t desc;
    uintptr_t avail;
    uintptr_t used;
    uint16_t max_qsz;
    uint16_t qsz = want_qsz;

    mmio_write16(g_vtcon.common_base, VIRTIO_PCI_COMMON_Q_SELECT, index);
    max_qsz = mmio_read16(g_vtcon.common_base, VIRTIO_PCI_COMMON_Q_SIZE);
    if (max_qsz == 0) return -1;
    if (qsz > max_qsz) qsz = max_qsz;
    if (!virtio_queue_ring_fits(qsz)) return -1;

    virtio_queue_setup(q, qsz);
    desc = (uintptr_t)q->desc;
    avail = (uintptr_t)q->avail;
    used = (uintptr_t)q->used;
    mmio_write16(g_vtcon.common_base, VIRTIO_PCI_COMMON_Q_SIZE, qsz);
    q->notify_off = mmio_read16(g_vtcon.common_base, VIRTIO_PCI_COMMON_Q_NOFF);
    mmio_write32(g_vtcon.common_base, VIRTIO_PCI_COMMON_Q_DESCLO, (uint32_t)desc);
    mmio_write32(g_vtcon.common_base, VIRTIO_PCI_COMMON_Q_DESCHI, (uint32_t)((uint64_t)desc >> 32));
    mmio_write32(g_vtcon.common_base, VIRTIO_PCI_COMMON_Q_AVAILLO, (uint32_t)avail);
    mmio_write32(g_vtcon.common_base, VIRTIO_PCI_COMMON_Q_AVAILHI, (uint32_t)((uint64_t)avail >> 32));
    mmio_write32(g_vtcon.common_base, VIRTIO_PCI_COMMON_Q_USEDLO, (uint32_t)used);
    mmio_write32(g_vtcon.common_base, VIRTIO_PCI_COMMON_Q_USEDHI, (uint32_t)((uint64_t)used >> 32));
    mmio_write16(g_vtcon.common_base, VIRTIO_PCI_COMMON_Q_ENABLE, 1);
    return 0;
}

static void virtio_queue_notify(const virtio_console_queue_t *q, uint16_t queue_index) {
    uint32_t off = (uint32_t)q->notify_off * g_vtcon.notify_multiplier;
    mmio_write16(g_vtcon.notify_base, off, queue_index);
}

static void virtio_ack_isr(void) {
    if (g_vtcon.isr_base) (void)mmio_read8(g_vtcon.isr_base, 0);
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
        uint8_t next = pci_cfg_read8(bus, dev, fn, (uint8_t)(cap + VIRTIO_PCI_CAP_NEXT)) & 0xFCu;
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

    if (!have_common || !have_notify || !have_isr) return -1;
    if (!virtio_modern_cap_valid(common, VIRTIO_MODERN_COMMON_MIN_SIZE, 4)) return -1;
    if (!virtio_modern_cap_valid(notify, VIRTIO_MODERN_NOTIFY_MIN_SIZE, 2)) return -1;
    if (!virtio_modern_cap_valid(isr, VIRTIO_MODERN_ISR_MIN_SIZE, 1)) return -1;
    if (have_device && !virtio_modern_cap_valid(device_cfg, 4, 1)) return -1;
    return 0;
}

static int virtio_console_find_modern(void) {
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
                    (device != VIRTIO_PCI_DEVICEID_MODERN_CONSOLE &&
                     device != VIRTIO_PCI_DEVICEID_CONSOLE_LEGACY)) {
                    continue;
                }
                memset(&common, 0, sizeof(common));
                memset(&notify, 0, sizeof(notify));
                memset(&isr, 0, sizeof(isr));
                memset(&device_cfg, 0, sizeof(device_cfg));
                if (virtio_modern_find_caps((uint8_t)bus, dev, fn, &common, &notify, &isr,
                                            &device_cfg, &notify_multiplier) < 0) {
                    printf("[virtio-console] PCI device %u:%u.%u missing usable modern caps\n",
                           (uint32_t)bus, (uint32_t)dev, (uint32_t)fn);
                    continue;
                }
                if (virtio_modern_cap_addr((uint8_t)bus, dev, fn, &common, &g_vtcon.common_base) < 0 ||
                    virtio_modern_cap_addr((uint8_t)bus, dev, fn, &notify, &g_vtcon.notify_base) < 0 ||
                    virtio_modern_cap_addr((uint8_t)bus, dev, fn, &isr, &g_vtcon.isr_base) < 0) {
                    printf("[virtio-console] PCI device %u:%u.%u has unsupported BAR mapping\n",
                           (uint32_t)bus, (uint32_t)dev, (uint32_t)fn);
                    continue;
                }
                if (device_cfg.length != 0) {
                    (void)virtio_modern_cap_addr((uint8_t)bus, dev, fn, &device_cfg, &g_vtcon.device_base);
                }
                g_vtcon.bus = (uint8_t)bus;
                g_vtcon.dev = dev;
                g_vtcon.fn = fn;
                g_vtcon.notify_multiplier = notify_multiplier;
                return 0;
            }
        }
    }
    return -1;
}

static void virtio_console_read_size(void) {
    uint8_t before;
    uint8_t after;
    if (!g_vtcon.device_base) return;
    for (int tries = 0; tries < 8; ++tries) {
        before = mmio_read8(g_vtcon.common_base, VIRTIO_PCI_COMMON_CFGGENERATION);
        virtio_mb();
        g_vtcon.cols = mmio_read16(g_vtcon.device_base, 0);
        g_vtcon.rows = mmio_read16(g_vtcon.device_base, 2);
        virtio_mb();
        after = mmio_read8(g_vtcon.common_base, VIRTIO_PCI_COMMON_CFGGENERATION);
        if (before == after) break;
    }
}

static void vtcon_in_push(uint8_t b) {
    uint32_t next = (g_vtcon_in_head + 1u) % VIRTIO_CONSOLE_RX_RING_BYTES;
    if (next == g_vtcon_in_tail) {
        g_vtcon_in_tail = (g_vtcon_in_tail + 1u) % VIRTIO_CONSOLE_RX_RING_BYTES;
    }
    g_vtcon_in[g_vtcon_in_head] = b;
    g_vtcon_in_head = next;
}

static void virtio_console_requeue_rx(uint16_t id) {
    virtio_console_queue_t *q = &g_vtcon_rxq;
    q->desc[id].addr = (uint64_t)(uintptr_t)g_vtcon_rx_buf[id];
    q->desc[id].len = VIRTIO_CONSOLE_RX_BUF_BYTES;
    q->desc[id].flags = VRING_DESC_F_WRITE;
    q->desc[id].next = 0;
    q->avail->ring[q->avail_idx % q->size] = id;
    __sync_synchronize();
    q->avail_idx++;
    q->avail->idx = q->avail_idx;
}

static void virtio_console_post_rx_buffers(void) {
    uint16_t count = g_vtcon_rxq.size;
    if (count > VIRTIO_CONSOLE_QUEUE_SIZE) count = VIRTIO_CONSOLE_QUEUE_SIZE;
    for (uint16_t i = 0; i < count; ++i) virtio_console_requeue_rx(i);
    __sync_synchronize();
    virtio_queue_notify(&g_vtcon_rxq, VIRTIO_CONSOLE_RXQ);
}

int virtio_console_init(void) {
    uint16_t command;
    uint64_t host_features;
    uint64_t guest_features;

    memset(&g_vtcon, 0, sizeof(g_vtcon));
    memset(&g_vtcon_rxq, 0, sizeof(g_vtcon_rxq));
    memset(&g_vtcon_txq, 0, sizeof(g_vtcon_txq));
    g_vtcon_in_head = 0;
    g_vtcon_in_tail = 0;
    g_vtcon_tx_busy = 0;

    if (virtio_console_find_modern() < 0) {
        printf("[virtio-console] no modern PCI console device found\n");
        return -1;
    }

    command = pci_cfg_read16(g_vtcon.bus, g_vtcon.dev, g_vtcon.fn, 0x04);
    command |= PCI_COMMAND_MEM | PCI_COMMAND_BUSMASTER;
    pci_cfg_write16(g_vtcon.bus, g_vtcon.dev, g_vtcon.fn, 0x04, command);

    virtio_status_set(VIRTIO_CONFIG_STATUS_RESET);
    for (uint32_t spin = 0; spin < 1000000u && virtio_status_get() != VIRTIO_CONFIG_STATUS_RESET; ++spin) {
        __asm__ __volatile__("pause");
    }
    virtio_status_set(VIRTIO_CONFIG_STATUS_ACK);
    virtio_status_set((uint8_t)(VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER));

    host_features = virtio_features_read();
    if ((host_features & VIRTIO_F_VERSION_1) == 0) {
        printf("[virtio-console] modern device missing VERSION_1 feature\n");
        virtio_fail();
        return -1;
    }
    /*
     * Do not negotiate MULTIPORT yet.  The base console queues provide one
     * Linux hvc-style port and avoid dynamic port/control events until EdgeOS
     * has fuller tty hotplug and /sys/class/virtio-ports plumbing.
     */
    guest_features = VIRTIO_F_VERSION_1;
    if (host_features & VIRTIO_CONSOLE_F_SIZE) guest_features |= VIRTIO_CONSOLE_F_SIZE;
    virtio_features_write(guest_features);
    virtio_status_set((uint8_t)(VIRTIO_CONFIG_STATUS_ACK |
                                VIRTIO_CONFIG_STATUS_DRIVER |
                                VIRTIO_CONFIG_STATUS_FEATURES_OK));
    if ((virtio_status_get() & VIRTIO_CONFIG_STATUS_FEATURES_OK) == 0) {
        printf("[virtio-console] feature negotiation rejected\n");
        virtio_fail();
        return -1;
    }
    if (guest_features & VIRTIO_CONSOLE_F_SIZE) virtio_console_read_size();

    if (virtio_queue_program(VIRTIO_CONSOLE_RXQ, &g_vtcon_rxq, VIRTIO_CONSOLE_QUEUE_SIZE) < 0 ||
        virtio_queue_program(VIRTIO_CONSOLE_TXQ, &g_vtcon_txq, VIRTIO_CONSOLE_QUEUE_SIZE) < 0) {
        printf("[virtio-console] unsupported queue layout\n");
        virtio_fail();
        return -1;
    }

    virtio_console_post_rx_buffers();
    g_vtcon.ready = 1;
    virtio_status_set((uint8_t)(VIRTIO_CONFIG_STATUS_ACK |
                                VIRTIO_CONFIG_STATUS_DRIVER |
                                VIRTIO_CONFIG_STATUS_FEATURES_OK |
                                VIRTIO_CONFIG_STATUS_DRIVER_OK));
    printf("[virtio-console] ready at %u:%u.%u rxq=%u txq=%u size=%ux%u hvc0\n",
           (uint32_t)g_vtcon.bus, (uint32_t)g_vtcon.dev, (uint32_t)g_vtcon.fn,
           (uint32_t)g_vtcon_rxq.size, (uint32_t)g_vtcon_txq.size,
           (uint32_t)g_vtcon.cols, (uint32_t)g_vtcon.rows);
    return 0;
}

int virtio_console_is_ready(void) {
    return g_vtcon.ready;
}

void virtio_console_poll(void) {
    virtio_console_queue_t *q = &g_vtcon_rxq;
    int requeued = 0;
    if (!g_vtcon.ready) return;
    virtio_ack_isr();
    while (q->used_idx != q->used->idx) {
        struct vring_used_elem *ue = &q->used->ring[q->used_idx % q->size];
        uint16_t id = (uint16_t)ue->id;
        uint32_t len = ue->len;
        __sync_synchronize();
        if (id < q->size && id < VIRTIO_CONSOLE_QUEUE_SIZE) {
            if (len > VIRTIO_CONSOLE_RX_BUF_BYTES) len = VIRTIO_CONSOLE_RX_BUF_BYTES;
            for (uint32_t i = 0; i < len; ++i) vtcon_in_push(g_vtcon_rx_buf[id][i]);
        }
        q->used_idx++;
        if (id < q->size && id < VIRTIO_CONSOLE_QUEUE_SIZE) {
            virtio_console_requeue_rx(id);
            requeued = 1;
        }
    }
    if (requeued) {
        __sync_synchronize();
        virtio_queue_notify(q, VIRTIO_CONSOLE_RXQ);
    }
}

int virtio_console_read(char *out, uint32_t max) {
    uint32_t n = 0;
    if (!g_vtcon.ready || !out || max == 0) return 0;
    virtio_console_poll();
    while (n < max && g_vtcon_in_tail != g_vtcon_in_head) {
        out[n++] = (char)g_vtcon_in[g_vtcon_in_tail];
        g_vtcon_in_tail = (g_vtcon_in_tail + 1u) % VIRTIO_CONSOLE_RX_RING_BYTES;
    }
    return (int)n;
}

int virtio_console_write(const char *buf, uint32_t len) {
    virtio_console_queue_t *q = &g_vtcon_txq;
    uint16_t old_used;
    uint32_t pos = 0;
    int wrote = 0;

    if (!g_vtcon.ready || !buf) return -1;
    while (pos < len) {
        uint32_t chunk = len - pos;
        int completed = 0;
        if (chunk > VIRTIO_CONSOLE_TX_BUF_BYTES) chunk = VIRTIO_CONSOLE_TX_BUF_BYTES;
        if (__sync_lock_test_and_set(&g_vtcon_tx_busy, 1)) break;

        memcpy(g_vtcon_tx_buf, buf + pos, chunk);
        memset(q->desc, 0, sizeof(struct vring_desc) * q->size);
        q->desc[0].addr = (uint64_t)(uintptr_t)g_vtcon_tx_buf;
        q->desc[0].len = chunk;
        q->desc[0].flags = 0;
        q->desc[0].next = 0;

        old_used = q->used->idx;
        q->avail->ring[q->avail_idx % q->size] = 0;
        __sync_synchronize();
        q->avail_idx++;
        q->avail->idx = q->avail_idx;
        __sync_synchronize();
        virtio_queue_notify(q, VIRTIO_CONSOLE_TXQ);

        for (uint32_t spin = 0; spin < VIRTIO_CONSOLE_TX_TIMEOUT; ++spin) {
            __sync_synchronize();
            if (q->used->idx != old_used) {
                q->used_idx = q->used->idx;
                virtio_ack_isr();
                pos += chunk;
                wrote += (int)chunk;
                completed = 1;
                break;
            }
            __asm__ __volatile__("pause");
        }
        __sync_lock_release(&g_vtcon_tx_busy);
        if (!completed) break;
    }
    return wrote;
}
