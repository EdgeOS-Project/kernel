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
 */

#include "drivers/virtio_rng.h"
#include "drivers/pci.h"

#include "arch/x86_64/io_ports.h"
#include "stdio.h"
#include "string.h"
#include "sys/mmio.h"

#include <stdint.h>

#define VIRTIO_PCI_VENDORID 0x1AF4u
#define VIRTIO_PCI_DEVICEID_RNG_LEGACY 0x1005u
#define VIRTIO_PCI_DEVICEID_MODERN_RNG 0x1044u

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

#define VIRTIO_PCI_VRING_ALIGN 4096u
#define VIRTIO_RNG_QUEUE_SIZE 8u
#define VIRTIO_RNG_RING_BYTES 8192u
#define VIRTIO_RNG_BUF_BYTES 256u
#define VIRTIO_RNG_TIMEOUT 1000000u
#define VRING_DESC_F_WRITE 2u
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
    volatile uint8_t *common_base;
    volatile uint8_t *notify_base;
    volatile uint8_t *isr_base;
    uint32_t notify_multiplier;
    uint16_t queue_size;
    uint16_t queue_notify_off;
    uint16_t avail_idx;
    uint16_t used_idx;
    uint8_t bus;
    uint8_t dev;
    uint8_t fn;
    int ready;
} virtio_rng_dev_t;

static virtio_rng_dev_t g_vtrng;
static uint8_t g_vtrng_ring[VIRTIO_RNG_RING_BYTES] __attribute__((aligned(VIRTIO_PCI_VRING_ALIGN)));
static uint8_t g_vtrng_buf[VIRTIO_RNG_BUF_BYTES] __attribute__((aligned(16)));
static volatile int g_vtrng_busy;
static struct vring_desc *g_desc;
static struct vring_avail *g_avail;
static struct vring_used *g_used;

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
                                   uint32_t *notify_multiplier) {
    uint16_t status = pci_cfg_read16(bus, dev, fn, 0x06);
    uint8_t cap = pci_cfg_read8(bus, dev, fn, 0x34) & 0xFCu;
    int have_common = 0;
    int have_notify = 0;
    int have_isr = 0;

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
    return 0;
}

static int virtio_rng_find_modern(void) {
    for (uint16_t bus = 0; bus < 256; ++bus) {
        for (uint8_t dev = 0; dev < 32; ++dev) {
            for (uint8_t fn = 0; fn < 8; ++fn) {
                uint32_t id = pci_cfg_read32((uint8_t)bus, dev, fn, 0x00);
                uint16_t vendor = (uint16_t)(id & 0xFFFFu);
                uint16_t device = (uint16_t)(id >> 16);
                virtio_modern_cap_t common;
                virtio_modern_cap_t notify;
                virtio_modern_cap_t isr;
                uint32_t notify_multiplier = 0;
                if (vendor == 0xFFFFu) {
                    if (fn == 0) break;
                    continue;
                }
                if (vendor != VIRTIO_PCI_VENDORID ||
                    (device != VIRTIO_PCI_DEVICEID_MODERN_RNG &&
                     device != VIRTIO_PCI_DEVICEID_RNG_LEGACY)) {
                    continue;
                }
                memset(&common, 0, sizeof(common));
                memset(&notify, 0, sizeof(notify));
                memset(&isr, 0, sizeof(isr));
                if (virtio_modern_find_caps((uint8_t)bus, dev, fn, &common, &notify, &isr,
                                            &notify_multiplier) < 0) {
                    if (device == VIRTIO_PCI_DEVICEID_MODERN_RNG) {
                        printf("[virtio-rng] modern device %u:%u.%u missing usable PCI capabilities\n",
                               (uint32_t)bus, dev, fn);
                    }
                    continue;
                }
                if (virtio_modern_cap_addr((uint8_t)bus, dev, fn, &common, &g_vtrng.common_base) < 0 ||
                    virtio_modern_cap_addr((uint8_t)bus, dev, fn, &notify, &g_vtrng.notify_base) < 0 ||
                    virtio_modern_cap_addr((uint8_t)bus, dev, fn, &isr, &g_vtrng.isr_base) < 0) {
                    printf("[virtio-rng] modern device %u:%u.%u has unsupported BAR mapping\n",
                           (uint32_t)bus, dev, fn);
                    continue;
                }
                g_vtrng.bus = (uint8_t)bus;
                g_vtrng.dev = dev;
                g_vtrng.fn = fn;
                g_vtrng.notify_multiplier = notify_multiplier;
                return 0;
            }
        }
    }
    return -1;
}

static uint32_t vring_used_offset(uint32_t num) {
    uint32_t off = num * (uint32_t)sizeof(struct vring_desc);
    off += (uint32_t)sizeof(struct vring_avail) + num * (uint32_t)sizeof(uint16_t) + (uint32_t)sizeof(uint16_t);
    return (off + VIRTIO_PCI_VRING_ALIGN - 1u) & ~(VIRTIO_PCI_VRING_ALIGN - 1u);
}

static int virtio_rng_setup_ring(uint16_t qsz) {
    uint32_t used_off;
    uint32_t used_bytes;
    if (qsz == 0 || qsz > VIRTIO_RNG_QUEUE_SIZE) qsz = VIRTIO_RNG_QUEUE_SIZE;
    used_off = vring_used_offset(qsz);
    used_bytes = (uint32_t)sizeof(struct vring_used) +
                 (uint32_t)qsz * (uint32_t)sizeof(struct vring_used_elem) +
                 (uint32_t)sizeof(uint16_t);
    if (used_off + used_bytes > VIRTIO_RNG_RING_BYTES) return -1;

    memset(g_vtrng_ring, 0, sizeof(g_vtrng_ring));
    g_desc = (struct vring_desc *)g_vtrng_ring;
    g_avail = (struct vring_avail *)(g_vtrng_ring + qsz * sizeof(struct vring_desc));
    g_used = (struct vring_used *)(g_vtrng_ring + used_off);
    g_vtrng.queue_size = qsz;
    g_vtrng.avail_idx = 0;
    g_vtrng.used_idx = 0;
    return 0;
}

int virtio_rng_init(void) {
    uint64_t features;
    uint16_t command;
    uint16_t qsz;

    memset(&g_vtrng, 0, sizeof(g_vtrng));
    g_vtrng_busy = 0;
    if (virtio_rng_find_modern() < 0) {
        printf("[virtio-rng] no modern PCI RNG device found\n");
        return -1;
    }

    command = pci_cfg_read16(g_vtrng.bus, g_vtrng.dev, g_vtrng.fn, 0x04);
    command |= PCI_COMMAND_MEM | PCI_COMMAND_BUSMASTER;
    pci_cfg_write16(g_vtrng.bus, g_vtrng.dev, g_vtrng.fn, 0x04, command);

    mmio_write8(g_vtrng.common_base, VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_STATUS_RESET);
    mmio_write8(g_vtrng.common_base, VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_STATUS_ACK);
    mmio_write8(g_vtrng.common_base, VIRTIO_PCI_COMMON_STATUS,
                VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER);

    mmio_write32(g_vtrng.common_base, VIRTIO_PCI_COMMON_DFSELECT, 1);
    features = ((uint64_t)mmio_read32(g_vtrng.common_base, VIRTIO_PCI_COMMON_DF)) << 32;
    mmio_write32(g_vtrng.common_base, VIRTIO_PCI_COMMON_DFSELECT, 0);
    features |= mmio_read32(g_vtrng.common_base, VIRTIO_PCI_COMMON_DF);
    if ((features & VIRTIO_F_VERSION_1) == 0) {
        mmio_write8(g_vtrng.common_base, VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_STATUS_FAILED);
        printf("[virtio-rng] modern device missing VERSION_1 feature\n");
        return -1;
    }

    mmio_write32(g_vtrng.common_base, VIRTIO_PCI_COMMON_GFSELECT, 0);
    mmio_write32(g_vtrng.common_base, VIRTIO_PCI_COMMON_GF, 0);
    mmio_write32(g_vtrng.common_base, VIRTIO_PCI_COMMON_GFSELECT, 1);
    mmio_write32(g_vtrng.common_base, VIRTIO_PCI_COMMON_GF, (uint32_t)(VIRTIO_F_VERSION_1 >> 32));
    mmio_write8(g_vtrng.common_base, VIRTIO_PCI_COMMON_STATUS,
                VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER |
                VIRTIO_CONFIG_STATUS_FEATURES_OK);
    if ((mmio_read8(g_vtrng.common_base, VIRTIO_PCI_COMMON_STATUS) &
         VIRTIO_CONFIG_STATUS_FEATURES_OK) == 0) {
        mmio_write8(g_vtrng.common_base, VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_STATUS_FAILED);
        printf("[virtio-rng] feature negotiation rejected\n");
        return -1;
    }

    mmio_write16(g_vtrng.common_base, VIRTIO_PCI_COMMON_Q_SELECT, 0);
    qsz = mmio_read16(g_vtrng.common_base, VIRTIO_PCI_COMMON_Q_SIZE);
    if (virtio_rng_setup_ring(qsz) < 0) {
        mmio_write8(g_vtrng.common_base, VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_STATUS_FAILED);
        printf("[virtio-rng] queue size %u does not fit local ring\n", qsz);
        return -1;
    }
    mmio_write16(g_vtrng.common_base, VIRTIO_PCI_COMMON_Q_SIZE, g_vtrng.queue_size);
    g_vtrng.queue_notify_off = mmio_read16(g_vtrng.common_base, VIRTIO_PCI_COMMON_Q_NOFF);
    mmio_write32(g_vtrng.common_base, VIRTIO_PCI_COMMON_Q_DESCLO, (uint32_t)(uintptr_t)g_desc);
    mmio_write32(g_vtrng.common_base, VIRTIO_PCI_COMMON_Q_DESCHI, (uint32_t)((uint64_t)(uintptr_t)g_desc >> 32));
    mmio_write32(g_vtrng.common_base, VIRTIO_PCI_COMMON_Q_AVAILLO, (uint32_t)(uintptr_t)g_avail);
    mmio_write32(g_vtrng.common_base, VIRTIO_PCI_COMMON_Q_AVAILHI, (uint32_t)((uint64_t)(uintptr_t)g_avail >> 32));
    mmio_write32(g_vtrng.common_base, VIRTIO_PCI_COMMON_Q_USEDLO, (uint32_t)(uintptr_t)g_used);
    mmio_write32(g_vtrng.common_base, VIRTIO_PCI_COMMON_Q_USEDHI, (uint32_t)((uint64_t)(uintptr_t)g_used >> 32));
    mmio_write16(g_vtrng.common_base, VIRTIO_PCI_COMMON_Q_ENABLE, 1);

    mmio_write8(g_vtrng.common_base, VIRTIO_PCI_COMMON_STATUS,
                VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER |
                VIRTIO_CONFIG_STATUS_FEATURES_OK | VIRTIO_CONFIG_STATUS_DRIVER_OK);
    g_vtrng.ready = 1;
    printf("[virtio-rng] modern PCI RNG device at %u:%u.%u qsz=%u\n",
           g_vtrng.bus, g_vtrng.dev, g_vtrng.fn, g_vtrng.queue_size);
    return 0;
}

int virtio_rng_is_ready(void) {
    return g_vtrng.ready;
}

int virtio_rng_fill(void *buf, uint32_t len) {
    uint8_t *out = (uint8_t *)buf;
    uint32_t done = 0;
    if (!g_vtrng.ready || !out || len == 0) return 0;
    if (g_vtrng_busy) return 0;
    g_vtrng_busy = 1;

    while (done < len) {
        uint32_t want = len - done;
        uint32_t spin = 0;
        uint16_t slot;
        uint16_t before;
        if (want > VIRTIO_RNG_BUF_BYTES) want = VIRTIO_RNG_BUF_BYTES;

        g_desc[0].addr = (uint64_t)(uintptr_t)g_vtrng_buf;
        g_desc[0].len = want;
        g_desc[0].flags = VRING_DESC_F_WRITE;
        g_desc[0].next = 0;
        slot = (uint16_t)(g_vtrng.avail_idx % g_vtrng.queue_size);
        g_avail->ring[slot] = 0;
        virtio_mb();
        before = g_used->idx;
        g_avail->idx = (uint16_t)(g_vtrng.avail_idx + 1u);
        g_vtrng.avail_idx++;
        virtio_mb();
        mmio_write16(g_vtrng.notify_base,
                     (uint32_t)g_vtrng.queue_notify_off * g_vtrng.notify_multiplier,
                     0);
        while (g_used->idx == before && spin++ < VIRTIO_RNG_TIMEOUT) {
            __asm__ __volatile__("pause");
        }
        if (g_used->idx == before) break;
        while (g_vtrng.used_idx != g_used->idx) {
            struct vring_used_elem *e = &g_used->ring[g_vtrng.used_idx % g_vtrng.queue_size];
            uint32_t got = e->len;
            if (got > want) got = want;
            if (got == 0) {
                g_vtrng.used_idx++;
                g_vtrng_busy = 0;
                return (int)done;
            }
            memcpy(out + done, g_vtrng_buf, got);
            done += got;
            g_vtrng.used_idx++;
            break;
        }
        (void)mmio_read8(g_vtrng.isr_base, 0);
        if (want == 0) break;
    }

    g_vtrng_busy = 0;
    return (int)done;
}
