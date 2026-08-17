/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file contains VirtIO SCSI protocol definitions derived from
 * FreeBSD sys/dev/virtio/scsi/virtio_scsi.h.
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
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Portions also use BSD-licensed VirtIO ring and PCI/config constants from
 * FreeBSD sys/dev/virtio/virtio_ring.h, sys/dev/virtio/pci, and
 * sys/dev/virtio/virtio_config.h:
 *
 * Copyright Rusty Russell IBM Corporation 2007.
 *
 * Copyright (c) 2011, 2014, 2017, Bryan Venteicher <bryanv@FreeBSD.org>
 * All rights reserved.
 *
 * Modifications for EdgeOS.
 * Copyright (c) EdgeOS Contributors.
 *
 * The EdgeOS integration below is a small polled block-device front-end for
 * target 0/lun 0. It uses SCSI inquiry/capacity/read/write commands through
 * the VirtIO SCSI request queue and intentionally avoids Linux implementation
 * code.
 */

#include "drivers/virtio_scsi.h"
#include "drivers/pci.h"

#include "arch/x86_64/io_ports.h"
#include "stdio.h"
#include "string.h"
#include "sys/mmio.h"

#include <stdint.h>

#define VIRTIO_PCI_VENDORID 0x1AF4u
#define VIRTIO_PCI_DEVICEID_SCSI_LEGACY 0x1004u
#define VIRTIO_PCI_DEVICEID_MODERN_SCSI 0x1048u

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

#define VIRTIO_PCI_COMMON_DFSELECT      0u
#define VIRTIO_PCI_COMMON_DF            4u
#define VIRTIO_PCI_COMMON_GFSELECT      8u
#define VIRTIO_PCI_COMMON_GF            12u
#define VIRTIO_PCI_COMMON_STATUS        20u
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

#define VIRTIO_SCSI_CDB_SIZE   32u
#define VIRTIO_SCSI_SENSE_SIZE 96u
#define VIRTIO_SCSI_S_OK       0u
#define VIRTIO_SCSI_S_SIMPLE   0u

#define VRING_DESC_F_NEXT  1u
#define VRING_DESC_F_WRITE 2u

#define VIRTIO_SCSI_QUEUE_CONTROL 0u
#define VIRTIO_SCSI_QUEUE_EVENT   1u
#define VIRTIO_SCSI_QUEUE_REQUEST 2u
#define VIRTIO_SCSI_QUEUE_SIZE    256u
#define VIRTIO_SCSI_RING_BYTES    32768u
#define VIRTIO_PCI_VRING_ALIGN    4096u
#define VIRTIO_SCSI_MAX_SECTORS   1024u
#define VIRTIO_SCSI_DEFAULT_SECTOR_SIZE 512u
#define VIRTIO_MODERN_COMMON_MIN_SIZE 56u
#define VIRTIO_MODERN_NOTIFY_MIN_SIZE 2u
#define VIRTIO_MODERN_ISR_MIN_SIZE 1u

#define SCSI_STATUS_GOOD 0x00u
#define SCSI_CMD_TEST_UNIT_READY 0x00u
#define SCSI_CMD_INQUIRY 0x12u
#define SCSI_CMD_READ_CAPACITY_10 0x25u
#define SCSI_CMD_READ_10 0x28u
#define SCSI_CMD_WRITE_10 0x2Au
#define SCSI_CMD_SERVICE_ACTION_IN_16 0x9Eu
#define SCSI_SAI_READ_CAPACITY_16 0x10u

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

struct virtio_scsi_cmd_req {
    uint8_t lun[8];
    uint64_t tag;
    uint8_t task_attr;
    uint8_t prio;
    uint8_t crn;
    uint8_t cdb[VIRTIO_SCSI_CDB_SIZE];
} __attribute__((packed));

struct virtio_scsi_cmd_resp {
    uint32_t sense_len;
    uint32_t resid;
    uint16_t status_qualifier;
    uint8_t status;
    uint8_t response;
    uint8_t sense[VIRTIO_SCSI_SENSE_SIZE];
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
    volatile uint8_t *device_base;
    uint32_t notify_multiplier;
    uint16_t queue_notify_off;
    uint8_t bus;
    uint8_t dev;
    uint8_t fn;
    int present;
    uint32_t sector_size;
    uint32_t sector_count;
    uint32_t max_sectors;
    uint16_t queue_size;
    uint16_t avail_idx;
    uint16_t used_idx;
    struct vring_desc *desc;
    struct vring_avail *avail;
    struct vring_used *used;
} virtio_scsi_dev_t;

static virtio_scsi_dev_t g_vtscsi;
static uint8_t g_vtscsi_ring[VIRTIO_SCSI_RING_BYTES] __attribute__((aligned(VIRTIO_PCI_VRING_ALIGN)));
static struct virtio_scsi_cmd_req g_vtscsi_req __attribute__((aligned(16)));
static struct virtio_scsi_cmd_resp g_vtscsi_resp __attribute__((aligned(16)));
static volatile int g_vtscsi_busy;

static uint64_t pci_bar_base(uint8_t bus, uint8_t slot, uint8_t func, uint8_t bar, int *is_io) {
    uint32_t lo;
    uint8_t off;
    if (bar >= 6) return 0;
    off = (uint8_t)(0x10u + bar * 4u);
    lo = pci_cfg_read32(bus, slot, func, off);
    if (lo & 1u) {
        if (is_io) *is_io = 1;
        return lo & ~3u;
    }
    if (is_io) *is_io = 0;
    if ((lo & 0x6u) == 0x4u && bar < 5) {
        uint32_t hi = pci_cfg_read32(bus, slot, func, (uint8_t)(off + 4u));
        return ((uint64_t)hi << 32) | (uint64_t)(lo & ~0xFu);
    }
    return lo & ~0xFu;
}

static uint16_t mmio_read16(volatile uint8_t *base, uint32_t off) {
    return *(volatile uint16_t *)(base + off);
}

static uint32_t mmio_read32(volatile uint8_t *base, uint32_t off) {
    return *(volatile uint32_t *)(base + off);
}

static void mmio_write8(volatile uint8_t *base, uint32_t off, uint8_t val) {
    *(volatile uint8_t *)(base + off) = val;
}

static void mmio_write16(volatile uint8_t *base, uint32_t off, uint16_t val) {
    *(volatile uint16_t *)(base + off) = val;
}

static void mmio_write32(volatile uint8_t *base, uint32_t off, uint32_t val) {
    *(volatile uint32_t *)(base + off) = val;
}

static void mmio_write64(volatile uint8_t *base, uint32_t off, uint64_t val) {
    mmio_write32(base, off, (uint32_t)val);
    mmio_write32(base, off + 4u, (uint32_t)(val >> 32));
}

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t be64(const uint8_t *p) {
    return ((uint64_t)be32(p) << 32) | be32(p + 4);
}

static void put_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t vring_used_offset(uint16_t qsz) {
    uint32_t off = (uint32_t)qsz * sizeof(struct vring_desc) +
                   sizeof(struct vring_avail) +
                   (uint32_t)qsz * sizeof(uint16_t);
    return (off + VIRTIO_PCI_VRING_ALIGN - 1u) & ~(VIRTIO_PCI_VRING_ALIGN - 1u);
}

static int virtio_scsi_ring_fits(uint16_t qsz) {
    uint32_t used_off = vring_used_offset(qsz);
    uint32_t used_bytes = sizeof(struct vring_used) +
                          (uint32_t)qsz * sizeof(struct vring_used_elem) +
                          sizeof(uint16_t);
    return qsz >= 4 && qsz <= VIRTIO_SCSI_QUEUE_SIZE &&
           used_off + used_bytes <= VIRTIO_SCSI_RING_BYTES;
}

static void virtio_scsi_setup_ring(uint16_t qsz) {
    memset(g_vtscsi_ring, 0, sizeof(g_vtscsi_ring));
    g_vtscsi.desc = (struct vring_desc *)g_vtscsi_ring;
    g_vtscsi.avail = (struct vring_avail *)(g_vtscsi_ring + qsz * sizeof(struct vring_desc));
    g_vtscsi.used = (struct vring_used *)(g_vtscsi_ring + vring_used_offset(qsz));
    g_vtscsi.avail_idx = 0;
    g_vtscsi.used_idx = 0;
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
    int have_common = 0, have_notify = 0, have_isr = 0, have_device = 0;

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
    if (!virtio_modern_cap_valid(device_cfg, 32, 4)) return -1;
    return 0;
}

static int virtio_scsi_find_modern(void) {
    for (uint16_t bus = 0; bus < 256; ++bus) {
        for (uint8_t dev = 0; dev < 32; ++dev) {
            for (uint8_t fn = 0; fn < 8; ++fn) {
                uint32_t id = pci_cfg_read32((uint8_t)bus, dev, fn, 0x00);
                uint16_t vendor = (uint16_t)(id & 0xFFFFu);
                uint16_t device = (uint16_t)(id >> 16);
                virtio_modern_cap_t common, notify, isr, device_cfg;
                uint32_t notify_multiplier = 0;
                if (vendor == 0xFFFFu) {
                    if (fn == 0) break;
                    continue;
                }
                if (vendor != VIRTIO_PCI_VENDORID ||
                    (device != VIRTIO_PCI_DEVICEID_MODERN_SCSI &&
                     device != VIRTIO_PCI_DEVICEID_SCSI_LEGACY)) {
                    continue;
                }
                memset(&common, 0, sizeof(common));
                memset(&notify, 0, sizeof(notify));
                memset(&isr, 0, sizeof(isr));
                memset(&device_cfg, 0, sizeof(device_cfg));
                if (virtio_modern_find_caps((uint8_t)bus, dev, fn, &common, &notify, &isr,
                                            &device_cfg, &notify_multiplier) < 0) {
                    continue;
                }
                if (virtio_modern_cap_addr((uint8_t)bus, dev, fn, &common, &g_vtscsi.common_base) < 0 ||
                    virtio_modern_cap_addr((uint8_t)bus, dev, fn, &notify, &g_vtscsi.notify_base) < 0 ||
                    virtio_modern_cap_addr((uint8_t)bus, dev, fn, &isr, &g_vtscsi.isr_base) < 0 ||
                    virtio_modern_cap_addr((uint8_t)bus, dev, fn, &device_cfg, &g_vtscsi.device_base) < 0) {
                    continue;
                }
                g_vtscsi.bus = (uint8_t)bus;
                g_vtscsi.dev = dev;
                g_vtscsi.fn = fn;
                g_vtscsi.notify_multiplier = notify_multiplier;
                return 0;
            }
        }
    }
    return -1;
}

static void virtio_status_set(uint8_t st) {
    mmio_write8(g_vtscsi.common_base, VIRTIO_PCI_COMMON_STATUS, st);
    __sync_synchronize();
}

static uint8_t virtio_status_get(void) {
    return *(volatile uint8_t *)(g_vtscsi.common_base + VIRTIO_PCI_COMMON_STATUS);
}

static void virtio_fail(void) {
    virtio_status_set((uint8_t)(virtio_status_get() | VIRTIO_CONFIG_STATUS_FAILED));
}

static uint64_t virtio_features_read(void) {
    uint64_t f;
    mmio_write32(g_vtscsi.common_base, VIRTIO_PCI_COMMON_DFSELECT, 0);
    f = mmio_read32(g_vtscsi.common_base, VIRTIO_PCI_COMMON_DF);
    mmio_write32(g_vtscsi.common_base, VIRTIO_PCI_COMMON_DFSELECT, 1);
    f |= ((uint64_t)mmio_read32(g_vtscsi.common_base, VIRTIO_PCI_COMMON_DF) << 32);
    return f;
}

static void virtio_features_write(uint64_t f) {
    mmio_write32(g_vtscsi.common_base, VIRTIO_PCI_COMMON_GFSELECT, 0);
    mmio_write32(g_vtscsi.common_base, VIRTIO_PCI_COMMON_GF, (uint32_t)f);
    mmio_write32(g_vtscsi.common_base, VIRTIO_PCI_COMMON_GFSELECT, 1);
    mmio_write32(g_vtscsi.common_base, VIRTIO_PCI_COMMON_GF, (uint32_t)(f >> 32));
}

static void virtio_queue_select(uint16_t q) {
    mmio_write16(g_vtscsi.common_base, VIRTIO_PCI_COMMON_Q_SELECT, q);
    __sync_synchronize();
}

static uint16_t virtio_queue_size_read(void) {
    return mmio_read16(g_vtscsi.common_base, VIRTIO_PCI_COMMON_Q_SIZE);
}

static void virtio_queue_program(uint16_t qsz) {
    uint64_t desc = (uint64_t)(uintptr_t)g_vtscsi.desc;
    uint64_t avail = (uint64_t)(uintptr_t)g_vtscsi.avail;
    uint64_t used = (uint64_t)(uintptr_t)g_vtscsi.used;
    g_vtscsi.queue_notify_off = mmio_read16(g_vtscsi.common_base, VIRTIO_PCI_COMMON_Q_NOFF);
    mmio_write16(g_vtscsi.common_base, VIRTIO_PCI_COMMON_Q_SIZE, qsz);
    mmio_write64(g_vtscsi.common_base, VIRTIO_PCI_COMMON_Q_DESCLO, desc);
    mmio_write64(g_vtscsi.common_base, VIRTIO_PCI_COMMON_Q_AVAILLO, avail);
    mmio_write64(g_vtscsi.common_base, VIRTIO_PCI_COMMON_Q_USEDLO, used);
    mmio_write16(g_vtscsi.common_base, VIRTIO_PCI_COMMON_Q_ENABLE, 1);
}

static void virtio_queue_notify(void) {
    uint32_t off = (uint32_t)g_vtscsi.queue_notify_off * g_vtscsi.notify_multiplier;
    *(volatile uint16_t *)(g_vtscsi.notify_base + off) = VIRTIO_SCSI_QUEUE_REQUEST;
    __sync_synchronize();
}

static void virtio_ack_isr(void) {
    (void)*(volatile uint8_t *)g_vtscsi.isr_base;
}

static void virtio_scsi_set_lun(uint8_t lun[8], uint8_t target, uint16_t target_lun) {
    memset(lun, 0, 8);
    lun[0] = 1;
    lun[1] = target;
    lun[2] = (uint8_t)(0x40u | ((target_lun >> 8) & 0x3Fu));
    lun[3] = (uint8_t)target_lun;
}

static int virtio_scsi_submit(const uint8_t *cdb, uint32_t cdb_len,
                              void *data, uint32_t data_len, int data_in) {
    uint16_t head = 0;
    uint16_t old_used;
    uint16_t desc = 0;

    if (!g_vtscsi.common_base || !cdb || cdb_len == 0 || cdb_len > VIRTIO_SCSI_CDB_SIZE) return -1;
    if (data_len && !data) return -1;
    if (__sync_lock_test_and_set(&g_vtscsi_busy, 1)) return -1;

    memset(&g_vtscsi_req, 0, sizeof(g_vtscsi_req));
    memset(&g_vtscsi_resp, 0, sizeof(g_vtscsi_resp));
    memset(g_vtscsi.desc, 0, sizeof(struct vring_desc) * g_vtscsi.queue_size);

    virtio_scsi_set_lun(g_vtscsi_req.lun, 0, 0);
    g_vtscsi_req.tag = (uint64_t)(uintptr_t)&g_vtscsi_req;
    g_vtscsi_req.task_attr = VIRTIO_SCSI_S_SIMPLE;
    memcpy(g_vtscsi_req.cdb, cdb, cdb_len);

    g_vtscsi.desc[0].addr = (uint64_t)(uintptr_t)&g_vtscsi_req;
    g_vtscsi.desc[0].len = sizeof(g_vtscsi_req);
    g_vtscsi.desc[0].flags = VRING_DESC_F_NEXT;
    desc = 1;

    if (data_len && !data_in) {
        g_vtscsi.desc[0].next = desc;
        g_vtscsi.desc[desc].addr = (uint64_t)(uintptr_t)data;
        g_vtscsi.desc[desc].len = data_len;
        g_vtscsi.desc[desc].flags = VRING_DESC_F_NEXT;
        desc++;
    }

    g_vtscsi.desc[desc - 1].next = desc;
    g_vtscsi.desc[desc].addr = (uint64_t)(uintptr_t)&g_vtscsi_resp;
    g_vtscsi.desc[desc].len = sizeof(g_vtscsi_resp);
    g_vtscsi.desc[desc].flags = VRING_DESC_F_WRITE | (data_len && data_in ? VRING_DESC_F_NEXT : 0);
    desc++;

    if (data_len && data_in) {
        g_vtscsi.desc[desc - 1].next = desc;
        g_vtscsi.desc[desc].addr = (uint64_t)(uintptr_t)data;
        g_vtscsi.desc[desc].len = data_len;
        g_vtscsi.desc[desc].flags = VRING_DESC_F_WRITE;
    }

    old_used = g_vtscsi.used->idx;
    g_vtscsi.avail->ring[g_vtscsi.avail_idx % g_vtscsi.queue_size] = head;
    __sync_synchronize();
    g_vtscsi.avail_idx++;
    g_vtscsi.avail->idx = g_vtscsi.avail_idx;
    __sync_synchronize();
    virtio_queue_notify();

    for (uint32_t spin = 0; spin < 20000000u; ++spin) {
        __sync_synchronize();
        if (g_vtscsi.used->idx != old_used) {
            virtio_ack_isr();
            g_vtscsi.used_idx = g_vtscsi.used->idx;
            __sync_lock_release(&g_vtscsi_busy);
            if (g_vtscsi_resp.response == VIRTIO_SCSI_S_OK &&
                g_vtscsi_resp.status == SCSI_STATUS_GOOD) {
                return 0;
            }
            return -1;
        }
        __asm__ __volatile__("pause");
    }

    printf("[virtio-scsi] request timeout opcode=0x%x\n", cdb[0]);
    __sync_lock_release(&g_vtscsi_busy);
    return -1;
}

static int virtio_scsi_test_unit_ready(void) {
    uint8_t cdb[6];
    memset(cdb, 0, sizeof(cdb));
    cdb[0] = SCSI_CMD_TEST_UNIT_READY;
    return virtio_scsi_submit(cdb, sizeof(cdb), 0, 0, 1);
}

static int virtio_scsi_inquiry(void) {
    uint8_t cdb[6];
    uint8_t data[36];
    memset(cdb, 0, sizeof(cdb));
    memset(data, 0, sizeof(data));
    cdb[0] = SCSI_CMD_INQUIRY;
    cdb[4] = sizeof(data);
    if (virtio_scsi_submit(cdb, sizeof(cdb), data, sizeof(data), 1) < 0) return -1;
    if ((data[0] & 0x1Fu) != 0x00u) {
        printf("[virtio-scsi] target 0 lun 0 is not direct-access device type=0x%x\n", data[0] & 0x1Fu);
        return -1;
    }
    return 0;
}

static int virtio_scsi_read_capacity16(void) {
    uint8_t cdb[16];
    uint8_t data[32];
    uint64_t last_lba;
    uint32_t block_len;
    memset(cdb, 0, sizeof(cdb));
    memset(data, 0, sizeof(data));
    cdb[0] = SCSI_CMD_SERVICE_ACTION_IN_16;
    cdb[1] = SCSI_SAI_READ_CAPACITY_16;
    put_be32(cdb + 10, sizeof(data));
    if (virtio_scsi_submit(cdb, sizeof(cdb), data, sizeof(data), 1) < 0) return -1;
    last_lba = be64(data);
    block_len = be32(data + 8);
    if (last_lba == 0 || block_len == 0 || block_len > 4096u || (block_len & (block_len - 1u)) != 0) return -1;
    if (last_lba + 1ull > 0xFFFFFFFFull) return -1;
    g_vtscsi.sector_size = block_len;
    g_vtscsi.sector_count = (uint32_t)(last_lba + 1ull);
    return 0;
}

static int virtio_scsi_read_capacity10(void) {
    uint8_t cdb[10];
    uint8_t data[8];
    uint32_t last_lba;
    uint32_t block_len;
    memset(cdb, 0, sizeof(cdb));
    memset(data, 0, sizeof(data));
    cdb[0] = SCSI_CMD_READ_CAPACITY_10;
    if (virtio_scsi_submit(cdb, sizeof(cdb), data, sizeof(data), 1) < 0) return -1;
    last_lba = be32(data);
    block_len = be32(data + 4);
    if (last_lba == 0xFFFFFFFFu) return virtio_scsi_read_capacity16();
    if (block_len == 0 || block_len > 4096u || (block_len & (block_len - 1u)) != 0) return -1;
    g_vtscsi.sector_size = block_len;
    g_vtscsi.sector_count = last_lba + 1u;
    return g_vtscsi.sector_count ? 0 : -1;
}

static int virtio_scsi_rw10(uint8_t opcode, uint32_t lba, uint32_t count, void *buf) {
    uint8_t cdb[10];
    uint32_t bytes;
    if (!buf || count == 0 || count > 0xFFFFu) return -1;
    if (lba + count < lba || lba + count > g_vtscsi.sector_count) return -1;
    bytes = count * g_vtscsi.sector_size;
    memset(cdb, 0, sizeof(cdb));
    cdb[0] = opcode;
    put_be32(cdb + 2, lba);
    put_be16(cdb + 7, (uint16_t)count);
    return virtio_scsi_submit(cdb, sizeof(cdb), buf, bytes, opcode == SCSI_CMD_READ_10);
}

int virtio_scsi_init(void) {
    uint16_t command;
    uint64_t features;
    uint16_t qsz;
    uint32_t max_sectors;

    memset(&g_vtscsi, 0, sizeof(g_vtscsi));
    g_vtscsi_busy = 0;
    if (virtio_scsi_find_modern() < 0) return -1;

    command = pci_cfg_read16(g_vtscsi.bus, g_vtscsi.dev, g_vtscsi.fn, 0x04);
    command |= PCI_COMMAND_MEM | PCI_COMMAND_BUSMASTER;
    pci_cfg_write16(g_vtscsi.bus, g_vtscsi.dev, g_vtscsi.fn, 0x04, command);

    virtio_status_set(VIRTIO_CONFIG_STATUS_RESET);
    for (uint32_t spin = 0; spin < 1000000u && virtio_status_get() != VIRTIO_CONFIG_STATUS_RESET; ++spin) {
        __asm__ __volatile__("pause");
    }
    virtio_status_set(VIRTIO_CONFIG_STATUS_ACK);
    virtio_status_set((uint8_t)(VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER));

    features = virtio_features_read();
    if ((features & VIRTIO_F_VERSION_1) == 0) {
        printf("[virtio-scsi] modern device missing VERSION_1 feature\n");
        virtio_fail();
        return -1;
    }
    virtio_features_write(VIRTIO_F_VERSION_1);
    virtio_status_set((uint8_t)(VIRTIO_CONFIG_STATUS_ACK |
                                VIRTIO_CONFIG_STATUS_DRIVER |
                                VIRTIO_CONFIG_STATUS_FEATURES_OK));
    if ((virtio_status_get() & VIRTIO_CONFIG_STATUS_FEATURES_OK) == 0) {
        printf("[virtio-scsi] feature negotiation rejected\n");
        virtio_fail();
        return -1;
    }

    max_sectors = mmio_read32(g_vtscsi.device_base, 8);
    if (max_sectors == 0 || max_sectors > VIRTIO_SCSI_MAX_SECTORS) max_sectors = VIRTIO_SCSI_MAX_SECTORS;
    g_vtscsi.max_sectors = max_sectors;

    virtio_queue_select(VIRTIO_SCSI_QUEUE_REQUEST);
    qsz = virtio_queue_size_read();
    if (!virtio_scsi_ring_fits(qsz)) {
        printf("[virtio-scsi] unsupported request queue size %u\n", qsz);
        virtio_fail();
        return -1;
    }
    virtio_scsi_setup_ring(qsz);
    g_vtscsi.queue_size = qsz;
    virtio_queue_program(qsz);

    virtio_status_set((uint8_t)(VIRTIO_CONFIG_STATUS_ACK |
                                VIRTIO_CONFIG_STATUS_DRIVER |
                                VIRTIO_CONFIG_STATUS_FEATURES_OK |
                                VIRTIO_CONFIG_STATUS_DRIVER_OK));

    /*
     * Keep the initial target scan conservative until EdgeOS has a full CAM
     * layer. QEMU and common VM setups expose the boot disk as target 0/lun 0.
     */
    (void)virtio_scsi_test_unit_ready();
    if (virtio_scsi_inquiry() < 0 || virtio_scsi_read_capacity10() < 0) {
        virtio_fail();
        return -1;
    }
    if (g_vtscsi.sector_size == 0) g_vtscsi.sector_size = VIRTIO_SCSI_DEFAULT_SECTOR_SIZE;
    g_vtscsi.present = 1;
    printf("[virtio-scsi] modern PCI SCSI device at %u:%u.%u sectors=%u sector_size=%u max_sectors=%u\n",
           g_vtscsi.bus, g_vtscsi.dev, g_vtscsi.fn,
           g_vtscsi.sector_count, g_vtscsi.sector_size, g_vtscsi.max_sectors);
    return 0;
}

int virtio_scsi_present(void) {
    return g_vtscsi.present;
}

uint32_t virtio_scsi_sector_size(void) {
    return g_vtscsi.sector_size ? g_vtscsi.sector_size : VIRTIO_SCSI_DEFAULT_SECTOR_SIZE;
}

uint32_t virtio_scsi_sector_count(void) {
    return g_vtscsi.sector_count;
}

int virtio_scsi_read(uint32_t lba, uint32_t sector_count, void *buf) {
    if (sector_count > g_vtscsi.max_sectors) return -1;
    return virtio_scsi_rw10(SCSI_CMD_READ_10, lba, sector_count, buf);
}

int virtio_scsi_write(uint32_t lba, uint32_t sector_count, const void *buf) {
    if (sector_count > g_vtscsi.max_sectors) return -1;
    return virtio_scsi_rw10(SCSI_CMD_WRITE_10, lba, sector_count, (void *)buf);
}
