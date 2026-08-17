/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This file contains VirtIO PCI transport and balloon configuration
 * definitions derived from FreeBSD sys/dev/virtio/virtio_config.h,
 * sys/dev/virtio/pci, and sys/dev/virtio/balloon/virtio_balloon.c.
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

#include "drivers/virtio_balloon.h"
#include "drivers/pci.h"

#include "arch/x86_64/io_ports.h"
#include "stdio.h"
#include "string.h"
#include "sys/mmio.h"

#include <stdint.h>

#define VIRTIO_PCI_VENDORID 0x1AF4u
#define VIRTIO_PCI_DEVICEID_BALLOON_LEGACY 0x1002u
#define VIRTIO_PCI_DEVICEID_MODERN_BALLOON 0x1045u

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
#define VIRTIO_PCI_CAP_DEVICE_CFG 4u

#define VIRTIO_PCI_CAP_VNDR       0u
#define VIRTIO_PCI_CAP_LEN        2u
#define VIRTIO_PCI_CAP_CFG_TYPE   3u
#define VIRTIO_PCI_CAP_BAR        4u
#define VIRTIO_PCI_CAP_OFFSET     8u
#define VIRTIO_PCI_CAP_LENGTH     12u

#define VIRTIO_PCI_COMMON_DFSELECT      0u
#define VIRTIO_PCI_COMMON_DF            4u
#define VIRTIO_PCI_COMMON_GFSELECT      8u
#define VIRTIO_PCI_COMMON_GF            12u
#define VIRTIO_PCI_COMMON_STATUS        20u
#define VIRTIO_PCI_COMMON_CFGGENERATION 21u

#define VIRTIO_MODERN_COMMON_MIN_SIZE 56u
#define VIRTIO_BALLOON_CONFIG_MIN_SIZE 8u
#define VIRTIO_BALLOON_PAGE_SIZE 4096u

typedef struct {
    uint8_t bar;
    uint32_t offset;
    uint32_t length;
} virtio_modern_cap_t;

typedef struct {
    volatile uint8_t *common_base;
    volatile uint8_t *device_base;
    uint8_t bus;
    uint8_t dev;
    uint8_t fn;
    uint32_t target_pages;
    uint32_t actual_pages;
    int ready;
} virtio_balloon_dev_t;

static virtio_balloon_dev_t g_vtballoon;

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

static uint32_t mmio_read32(volatile uint8_t *base, uint32_t off) {
    return *(volatile uint32_t *)(base + off);
}

static void mmio_write8(volatile uint8_t *base, uint32_t off, uint8_t v) {
    *(volatile uint8_t *)(base + off) = v;
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
                                   virtio_modern_cap_t *device) {
    uint16_t status = pci_cfg_read16(bus, dev, fn, 0x06);
    uint8_t cap = pci_cfg_read8(bus, dev, fn, 0x34) & 0xFCu;
    int have_common = 0;
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
                } else if (cfg_type == VIRTIO_PCI_CAP_DEVICE_CFG) {
                    *device = tmp;
                    have_device = 1;
                }
            }
        }
        if (next == 0 || next == cap) break;
        cap = next;
    }

    if (!have_common || !have_device) return -1;
    if (!virtio_modern_cap_valid(common, VIRTIO_MODERN_COMMON_MIN_SIZE, 4)) return -1;
    if (!virtio_modern_cap_valid(device, VIRTIO_BALLOON_CONFIG_MIN_SIZE, 4)) return -1;
    return 0;
}

static int virtio_balloon_find_modern(void) {
    for (uint16_t bus = 0; bus < 256; ++bus) {
        for (uint8_t dev = 0; dev < 32; ++dev) {
            for (uint8_t fn = 0; fn < 8; ++fn) {
                uint32_t id = pci_cfg_read32((uint8_t)bus, dev, fn, 0x00);
                uint16_t vendor = (uint16_t)(id & 0xFFFFu);
                uint16_t device_id = (uint16_t)(id >> 16);
                virtio_modern_cap_t common;
                virtio_modern_cap_t device;
                if (vendor == 0xFFFFu) {
                    if (fn == 0) break;
                    continue;
                }
                if (vendor != VIRTIO_PCI_VENDORID ||
                    (device_id != VIRTIO_PCI_DEVICEID_MODERN_BALLOON &&
                     device_id != VIRTIO_PCI_DEVICEID_BALLOON_LEGACY)) {
                    continue;
                }
                memset(&common, 0, sizeof(common));
                memset(&device, 0, sizeof(device));
                if (virtio_modern_find_caps((uint8_t)bus, dev, fn, &common, &device) < 0) {
                    printf("[virtio-balloon] PCI device %u:%u.%u missing usable modern caps\n",
                           (uint32_t)bus, dev, fn);
                    continue;
                }
                if (virtio_modern_cap_addr((uint8_t)bus, dev, fn, &common, &g_vtballoon.common_base) < 0 ||
                    virtio_modern_cap_addr((uint8_t)bus, dev, fn, &device, &g_vtballoon.device_base) < 0) {
                    printf("[virtio-balloon] PCI device %u:%u.%u has unsupported BAR mapping\n",
                           (uint32_t)bus, dev, fn);
                    continue;
                }
                g_vtballoon.bus = (uint8_t)bus;
                g_vtballoon.dev = dev;
                g_vtballoon.fn = fn;
                return 0;
            }
        }
    }
    return -1;
}

static void virtio_balloon_read_config(uint32_t *target_pages, uint32_t *actual_pages) {
    uint8_t before;
    uint8_t after;
    uint32_t target = 0;
    uint32_t actual = 0;

    for (int tries = 0; tries < 8; ++tries) {
        before = mmio_read8(g_vtballoon.common_base, VIRTIO_PCI_COMMON_CFGGENERATION);
        virtio_mb();
        target = mmio_read32(g_vtballoon.device_base, 0);
        actual = mmio_read32(g_vtballoon.device_base, 4);
        virtio_mb();
        after = mmio_read8(g_vtballoon.common_base, VIRTIO_PCI_COMMON_CFGGENERATION);
        if (before == after) break;
    }

    if (target_pages) *target_pages = target;
    if (actual_pages) *actual_pages = actual;
}

int virtio_balloon_init(void) {
    uint64_t features;
    uint16_t command;
    memset(&g_vtballoon, 0, sizeof(g_vtballoon));
    if (virtio_balloon_find_modern() < 0) {
        printf("[virtio-balloon] no modern PCI balloon device found\n");
        return -1;
    }

    command = pci_cfg_read16(g_vtballoon.bus, g_vtballoon.dev, g_vtballoon.fn, 0x04);
    command |= PCI_COMMAND_MEM | PCI_COMMAND_BUSMASTER;
    pci_cfg_write16(g_vtballoon.bus, g_vtballoon.dev, g_vtballoon.fn, 0x04, command);

    mmio_write8(g_vtballoon.common_base, VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_STATUS_RESET);
    mmio_write8(g_vtballoon.common_base, VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_STATUS_ACK);
    mmio_write8(g_vtballoon.common_base, VIRTIO_PCI_COMMON_STATUS,
                VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER);

    mmio_write32(g_vtballoon.common_base, VIRTIO_PCI_COMMON_DFSELECT, 1);
    features = ((uint64_t)mmio_read32(g_vtballoon.common_base, VIRTIO_PCI_COMMON_DF)) << 32;
    mmio_write32(g_vtballoon.common_base, VIRTIO_PCI_COMMON_DFSELECT, 0);
    features |= mmio_read32(g_vtballoon.common_base, VIRTIO_PCI_COMMON_DF);
    if ((features & VIRTIO_F_VERSION_1) == 0) {
        mmio_write8(g_vtballoon.common_base, VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_STATUS_FAILED);
        printf("[virtio-balloon] modern device missing VERSION_1 feature\n");
        return -1;
    }

    mmio_write32(g_vtballoon.common_base, VIRTIO_PCI_COMMON_GFSELECT, 0);
    mmio_write32(g_vtballoon.common_base, VIRTIO_PCI_COMMON_GF, 0);
    mmio_write32(g_vtballoon.common_base, VIRTIO_PCI_COMMON_GFSELECT, 1);
    mmio_write32(g_vtballoon.common_base, VIRTIO_PCI_COMMON_GF, (uint32_t)(VIRTIO_F_VERSION_1 >> 32));
    mmio_write8(g_vtballoon.common_base, VIRTIO_PCI_COMMON_STATUS,
                VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER |
                VIRTIO_CONFIG_STATUS_FEATURES_OK);
    if ((mmio_read8(g_vtballoon.common_base, VIRTIO_PCI_COMMON_STATUS) &
         VIRTIO_CONFIG_STATUS_FEATURES_OK) == 0) {
        mmio_write8(g_vtballoon.common_base, VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_STATUS_FAILED);
        printf("[virtio-balloon] feature negotiation rejected\n");
        return -1;
    }

    /*
     * Linux-compatible behavior note:
     * actual_pages is the number of pages currently held by the balloon, not
     * total guest memory.  EdgeOS does not yet expose a driver-safe page
     * isolation/offline API.  Sending arbitrary PFNs to the inflate queue would
     * hand live kernel or userspace memory to the host and corrupt the guest.
     * Keep the device initialized and publish actual=0 until a real page
     * allocator handoff exists, then add inflate/deflate queue support here.
     */
    mmio_write32(g_vtballoon.device_base, 4, 0);
    virtio_mb();
    virtio_balloon_read_config(&g_vtballoon.target_pages, &g_vtballoon.actual_pages);

    mmio_write8(g_vtballoon.common_base, VIRTIO_PCI_COMMON_STATUS,
                VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER |
                VIRTIO_CONFIG_STATUS_FEATURES_OK | VIRTIO_CONFIG_STATUS_DRIVER_OK);

    g_vtballoon.ready = 1;
    printf("[virtio-balloon] ready at %u:%u.%u target=%u actual=%u\n",
           (uint32_t)g_vtballoon.bus, (uint32_t)g_vtballoon.dev, (uint32_t)g_vtballoon.fn,
           g_vtballoon.target_pages, g_vtballoon.actual_pages);
    if (g_vtballoon.target_pages != 0) {
        printf("[virtio-balloon] host requested %u KiB, inflation deferred until page isolation exists\n",
               g_vtballoon.target_pages * (VIRTIO_BALLOON_PAGE_SIZE / 1024u));
    }
    return 0;
}

int virtio_balloon_is_ready(void) {
    return g_vtballoon.ready;
}

uint32_t virtio_balloon_target_pages(void) {
    return g_vtballoon.target_pages;
}

uint32_t virtio_balloon_actual_pages(void) {
    return g_vtballoon.actual_pages;
}
