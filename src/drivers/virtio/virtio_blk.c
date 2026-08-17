/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This file contains VirtIO ring and block protocol definitions derived from
 * FreeBSD sys/dev/virtio/virtio_ring.h and sys/dev/virtio/block/virtio_blk.h.
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
 * Portions also use BSD-licensed VirtIO PCI/config constants from FreeBSD
 * sys/dev/virtio/pci and sys/dev/virtio/virtio_config.h, including the
 * modern PCI capability layout from sys/dev/virtio/pci/virtio_pci_modern_var.h:
 *
 * Copyright (c) 2011, 2014, 2017, Bryan Venteicher <bryanv@FreeBSD.org>
 * All rights reserved.
 *
 * Modifications for EdgeOS.
 * Copyright (c) EdgeOS Contributors.
 */

#include "drivers/virtio_blk.h"
#include "drivers/pci.h"

#include "arch/x86_64/pic.h"
#include "drivers/apic.h"
#include "arch/x86_64/io_ports.h"
#include "arch/x86_64/isr.h"
#include "stdio.h"
#include "string.h"
#include "sys/boottime.h"
#include "sys/mmio.h"
#include "sys/scheduler.h"

#define VIRTIO_PCI_VENDORID 0x1AF4u
#define VIRTIO_PCI_DEVICEID_BLOCK_LEGACY 0x1001u
#define VIRTIO_PCI_DEVICEID_MODERN_BLOCK 0x1042u
#define VIRTIO_PCI_ABI_VERSION 0u

#define PCI_COMMAND_IO 0x0001u
#define PCI_COMMAND_MEM 0x0002u
#define PCI_COMMAND_BUSMASTER 0x0004u
#define PCI_STATUS_CAP_LIST 0x0010u
#define PCI_CAP_ID_VENDOR 0x09u

#define VIRTIO_PCI_HOST_FEATURES  0u
#define VIRTIO_PCI_GUEST_FEATURES 4u
#define VIRTIO_PCI_QUEUE_PFN      8u
#define VIRTIO_PCI_QUEUE_NUM      12u
#define VIRTIO_PCI_QUEUE_SEL      14u
#define VIRTIO_PCI_QUEUE_NOTIFY   16u
#define VIRTIO_PCI_STATUS         18u
#define VIRTIO_PCI_ISR            19u
#define VIRTIO_PCI_CONFIG_OFF     20u
#define VIRTIO_PCI_QUEUE_ADDR_SHIFT 12u
#define VIRTIO_PCI_VRING_ALIGN    4096u

#define VIRTIO_CONFIG_STATUS_RESET     0x00u
#define VIRTIO_CONFIG_STATUS_ACK       0x01u
#define VIRTIO_CONFIG_STATUS_DRIVER    0x02u
#define VIRTIO_CONFIG_STATUS_DRIVER_OK 0x04u
#define VIRTIO_CONFIG_STATUS_FEATURES_OK 0x08u
#define VIRTIO_CONFIG_STATUS_FAILED    0x80u

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
#define VIRTIO_PCI_COMMON_MSIX          16u
#define VIRTIO_PCI_COMMON_NUMQ          18u
#define VIRTIO_PCI_COMMON_STATUS        20u
#define VIRTIO_PCI_COMMON_CFGGENERATION 21u
#define VIRTIO_PCI_COMMON_Q_SELECT      22u
#define VIRTIO_PCI_COMMON_Q_SIZE        24u
#define VIRTIO_PCI_COMMON_Q_MSIX        26u
#define VIRTIO_PCI_COMMON_Q_ENABLE      28u
#define VIRTIO_PCI_COMMON_Q_NOFF        30u
#define VIRTIO_PCI_COMMON_Q_DESCLO      32u
#define VIRTIO_PCI_COMMON_Q_DESCHI      36u
#define VIRTIO_PCI_COMMON_Q_AVAILLO     40u
#define VIRTIO_PCI_COMMON_Q_AVAILHI     44u
#define VIRTIO_PCI_COMMON_Q_USEDLO      48u
#define VIRTIO_PCI_COMMON_Q_USEDHI      52u

#define VIRTIO_BLK_F_RO       0x0020u
#define VIRTIO_BLK_F_BLK_SIZE 0x0040u

#define VIRTIO_BLK_T_IN  0u
#define VIRTIO_BLK_T_OUT 1u
#define VIRTIO_BLK_S_OK  0u

#define VRING_DESC_F_NEXT  1u
#define VRING_DESC_F_WRITE 2u

#define VIRTIO_BLK_QUEUE_SIZE 256u
#define VIRTIO_BLK_MAX_INFLIGHT (VIRTIO_BLK_QUEUE_SIZE / 3u)
#define VIRTIO_BLK_RING_BYTES 16384u
#define VIRTIO_BLK_MAX_SECTORS 1024u
#define VIRTIO_BLK_DEFAULT_SECTOR_SIZE 512u
#define VIRTIO_BLK_POLL_YIELD_INTERVAL 256u
#define VIRTIO_MODERN_COMMON_MIN_SIZE 56u
#define VIRTIO_MODERN_NOTIFY_MIN_SIZE 2u
#define VIRTIO_MODERN_ISR_MIN_SIZE 1u
#define VIRTIO_MSI_NO_VECTOR 0xFFFFu

typedef enum {
    VIRTIO_BLK_TRANSPORT_NONE = 0,
    VIRTIO_BLK_TRANSPORT_LEGACY,
    VIRTIO_BLK_TRANSPORT_MODERN,
} virtio_blk_transport_t;

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

struct virtio_blk_outhdr {
    uint32_t type;
    uint32_t ioprio;
    uint64_t sector;
} __attribute__((packed));

typedef struct {
    virtio_blk_transport_t transport;
    uint32_t io_base;
    volatile uint8_t *common_base;
    volatile uint8_t *notify_base;
    volatile uint8_t *isr_base;
    volatile uint8_t *device_base;
    uint32_t notify_multiplier;
    uint16_t queue_notify_off;
    uint8_t bus;
    uint8_t dev;
    uint8_t fn;
    uint8_t irq_line;
    uint8_t irq_vector;
    uint8_t irq_mode;
    int present;
    int readonly;
    uint32_t sector_size;
    uint32_t sector_count;
    uint16_t queue_size;
    uint16_t avail_idx;
    uint16_t used_idx;
    uint16_t inflight_slots;
    struct vring_desc *desc;
    struct vring_avail *avail;
    struct vring_used *used;
} virtio_blk_dev_t;

typedef struct {
    struct virtio_blk_outhdr hdr;
    uint8_t status;
    volatile uint8_t busy;
    volatile uint8_t done;
    uint8_t pad[14];
} virtio_blk_req_t;

static virtio_blk_dev_t g_vtblk;
static uint8_t g_vtblk_ring[VIRTIO_BLK_RING_BYTES] __attribute__((aligned(VIRTIO_PCI_VRING_ALIGN)));
static virtio_blk_req_t g_vtblk_reqs[VIRTIO_BLK_MAX_INFLIGHT] __attribute__((aligned(16)));
static volatile int g_vtblk_queue_lock;
static volatile int g_vtblk_complete_lock;
#ifndef EDGE_VIRTIO_BLK_TRACE
#define EDGE_VIRTIO_BLK_TRACE 0
#endif
static uint32_t g_vtblk_slow_log_budget = EDGE_VIRTIO_BLK_TRACE ? 64 : 0;
static uint32_t g_vtblk_busy_log_budget = EDGE_VIRTIO_BLK_TRACE ? 32 : 0;
static uint32_t g_vtblk_irq_log_budget = 16;
static uint32_t g_vtblk_dma_alias_log_budget =
    EDGE_VIRTIO_BLK_TRACE ? 16 : 0;
static volatile uint32_t g_vtblk_irq_count;

static void virtio_blk_irq_handler(REGISTERS *reg);

static uint64_t virtio_blk_dma_addr(const void *ptr) {
    uintptr_t va = (uintptr_t)ptr;

    /*
     * Virtio queue/device-visible addresses are guest physical addresses.
     * EdgeOS maps low physical memory both identity-mapped and through the
     * supervisor-only low alias while user CR3s are active.  Block I/O can be
     * submitted from either context, so never hand the alias VA to QEMU.
     */
    if (va >= EDGE_MMIO_LOW_ALIAS_BASE &&
        va < EDGE_MMIO_LOW_ALIAS_BASE + EDGE_MMIO_LOW_ALIAS_SIZE) {
        uint64_t phys = (uint64_t)(va - EDGE_MMIO_LOW_ALIAS_BASE);
        if (g_vtblk_dma_alias_log_budget > 0) {
            printf("[virtio-blk] dma alias va=0x%x phys=0x%x budget=%u\n",
                   (uint32_t)va, (uint32_t)phys,
                   (unsigned)(g_vtblk_dma_alias_log_budget - 1u));
            g_vtblk_dma_alias_log_budget--;
        }
        return phys;
    }
    return (uint64_t)va;
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

static uint32_t virtio_in32(uint32_t off) {
    return inportl((uint16_t)(g_vtblk.io_base + off));
}

static uint16_t virtio_in16(uint32_t off) {
    return inports((uint16_t)(g_vtblk.io_base + off));
}

static uint8_t virtio_in8(uint32_t off) {
    return inportb((uint16_t)(g_vtblk.io_base + off));
}

static void virtio_out32(uint32_t off, uint32_t v) {
    outportl((uint16_t)(g_vtblk.io_base + off), v);
}

static void virtio_out16(uint32_t off, uint16_t v) {
    outports((uint16_t)(g_vtblk.io_base + off), v);
}

static void virtio_out8(uint32_t off, uint8_t v) {
    outportb((uint16_t)(g_vtblk.io_base + off), v);
}

static uint64_t virtio_config_read64(uint32_t off) {
    uint32_t lo = virtio_in32(VIRTIO_PCI_CONFIG_OFF + off);
    uint32_t hi = virtio_in32(VIRTIO_PCI_CONFIG_OFF + off + 4u);
    return (uint64_t)lo | ((uint64_t)hi << 32);
}

static uint32_t virtio_config_read32(uint32_t off) {
    return virtio_in32(VIRTIO_PCI_CONFIG_OFF + off);
}

static uint8_t virtio_status_get(void) {
    if (g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN) {
        return mmio_read8(g_vtblk.common_base, VIRTIO_PCI_COMMON_STATUS);
    }
    return virtio_in8(VIRTIO_PCI_STATUS);
}

static void virtio_status_set(uint8_t status) {
    if (g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN) {
        mmio_write8(g_vtblk.common_base, VIRTIO_PCI_COMMON_STATUS, status);
    } else {
        virtio_out8(VIRTIO_PCI_STATUS, status);
    }
}

static uint64_t virtio_features_read(void) {
    if (g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN) {
        uint32_t lo;
        uint32_t hi;
        mmio_write32(g_vtblk.common_base, VIRTIO_PCI_COMMON_DFSELECT, 0);
        lo = mmio_read32(g_vtblk.common_base, VIRTIO_PCI_COMMON_DF);
        mmio_write32(g_vtblk.common_base, VIRTIO_PCI_COMMON_DFSELECT, 1);
        hi = mmio_read32(g_vtblk.common_base, VIRTIO_PCI_COMMON_DF);
        return (uint64_t)lo | ((uint64_t)hi << 32);
    }
    return virtio_in32(VIRTIO_PCI_HOST_FEATURES);
}

static void virtio_features_write(uint64_t features) {
    if (g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN) {
        mmio_write32(g_vtblk.common_base, VIRTIO_PCI_COMMON_GFSELECT, 0);
        mmio_write32(g_vtblk.common_base, VIRTIO_PCI_COMMON_GF, (uint32_t)features);
        mmio_write32(g_vtblk.common_base, VIRTIO_PCI_COMMON_GFSELECT, 1);
        mmio_write32(g_vtblk.common_base, VIRTIO_PCI_COMMON_GF, (uint32_t)(features >> 32));
    } else {
        virtio_out32(VIRTIO_PCI_GUEST_FEATURES, (uint32_t)features);
    }
}

static uint64_t virtio_device_config_read64(uint32_t off) {
    if (g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN) {
        uint8_t gen;
        uint32_t lo;
        uint32_t hi;
        do {
            gen = mmio_read8(g_vtblk.common_base, VIRTIO_PCI_COMMON_CFGGENERATION);
            lo = mmio_read32(g_vtblk.device_base, off);
            hi = mmio_read32(g_vtblk.device_base, off + 4u);
        } while (gen != mmio_read8(g_vtblk.common_base, VIRTIO_PCI_COMMON_CFGGENERATION));
        return (uint64_t)lo | ((uint64_t)hi << 32);
    }
    return virtio_config_read64(off);
}

static uint32_t virtio_device_config_read32(uint32_t off) {
    if (g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN) {
        return mmio_read32(g_vtblk.device_base, off);
    }
    return virtio_config_read32(off);
}

static void virtio_queue_select(uint16_t idx) {
    if (g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN) {
        mmio_write16(g_vtblk.common_base, VIRTIO_PCI_COMMON_Q_SELECT, idx);
    } else {
        virtio_out16(VIRTIO_PCI_QUEUE_SEL, idx);
    }
}

static uint16_t virtio_queue_size_read(void) {
    if (g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN) {
        return mmio_read16(g_vtblk.common_base, VIRTIO_PCI_COMMON_Q_SIZE);
    }
    return virtio_in16(VIRTIO_PCI_QUEUE_NUM);
}

static void virtio_queue_program(uint16_t qsz) {
    uintptr_t desc = (uintptr_t)virtio_blk_dma_addr(g_vtblk.desc);
    uintptr_t avail = (uintptr_t)virtio_blk_dma_addr(g_vtblk.avail);
    uintptr_t used = (uintptr_t)virtio_blk_dma_addr(g_vtblk.used);

    if (g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN) {
        mmio_write16(g_vtblk.common_base, VIRTIO_PCI_COMMON_Q_SIZE, qsz);
        g_vtblk.queue_notify_off = mmio_read16(g_vtblk.common_base, VIRTIO_PCI_COMMON_Q_NOFF);
        mmio_write32(g_vtblk.common_base, VIRTIO_PCI_COMMON_Q_DESCLO, (uint32_t)desc);
        mmio_write32(g_vtblk.common_base, VIRTIO_PCI_COMMON_Q_DESCHI, (uint32_t)((uint64_t)desc >> 32));
        mmio_write32(g_vtblk.common_base, VIRTIO_PCI_COMMON_Q_AVAILLO, (uint32_t)avail);
        mmio_write32(g_vtblk.common_base, VIRTIO_PCI_COMMON_Q_AVAILHI, (uint32_t)((uint64_t)avail >> 32));
        mmio_write32(g_vtblk.common_base, VIRTIO_PCI_COMMON_Q_USEDLO, (uint32_t)used);
        mmio_write32(g_vtblk.common_base, VIRTIO_PCI_COMMON_Q_USEDHI, (uint32_t)((uint64_t)used >> 32));
        mmio_write16(g_vtblk.common_base, VIRTIO_PCI_COMMON_Q_ENABLE, 1);
    } else {
        virtio_out32(VIRTIO_PCI_QUEUE_PFN, (uint32_t)((uintptr_t)g_vtblk_ring >> VIRTIO_PCI_QUEUE_ADDR_SHIFT));
    }
}

static int virtio_blk_modern_set_config_msix(uint16_t table_index) {
    if (g_vtblk.transport != VIRTIO_BLK_TRANSPORT_MODERN) return -1;
    mmio_write16(g_vtblk.common_base, VIRTIO_PCI_COMMON_MSIX, table_index);
    return mmio_read16(g_vtblk.common_base, VIRTIO_PCI_COMMON_MSIX) == table_index ? 0 : -1;
}

static int virtio_blk_modern_set_queue_msix(uint16_t queue, uint16_t table_index) {
    if (g_vtblk.transport != VIRTIO_BLK_TRANSPORT_MODERN) return -1;
    virtio_queue_select(queue);
    mmio_write16(g_vtblk.common_base, VIRTIO_PCI_COMMON_Q_MSIX, table_index);
    return mmio_read16(g_vtblk.common_base, VIRTIO_PCI_COMMON_Q_MSIX) == table_index ? 0 : -1;
}

static void virtio_queue_notify(void) {
    if (g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN) {
        uint32_t off = (uint32_t)g_vtblk.queue_notify_off * g_vtblk.notify_multiplier;
        mmio_write16(g_vtblk.notify_base, off, 0);
    } else {
        virtio_out16(VIRTIO_PCI_QUEUE_NOTIFY, 0);
    }
}

static void virtio_ack_isr(void) {
    if (g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN) {
        (void)mmio_read8(g_vtblk.isr_base, 0);
    } else {
        (void)virtio_in8(VIRTIO_PCI_ISR);
    }
}

static void virtio_blk_lock(volatile int *lock) {
    while (__sync_lock_test_and_set(lock, 1)) {
        task_t *cur = scheduler_current_task();
        if (cur && !cur->is_idle && cur->pid > 0 && cur->state == TASK_RUNNING) {
            scheduler_yield();
        } else {
            __asm__ __volatile__("pause");
        }
    }
}

static void virtio_blk_unlock(volatile int *lock) {
    __sync_lock_release(lock);
}

static void virtio_blk_drain_used_locked(void) {
    __sync_synchronize();
    while (g_vtblk.used_idx != g_vtblk.used->idx) {
        uint16_t used_pos = (uint16_t)(g_vtblk.used_idx % g_vtblk.queue_size);
        uint32_t id = g_vtblk.used->ring[used_pos].id;
        uint16_t done_slot = (uint16_t)(id / 3u);
        if ((id % 3u) == 0 && done_slot < g_vtblk.inflight_slots) {
            g_vtblk_reqs[done_slot].done = 1;
        } else if (g_vtblk_irq_log_budget > 0) {
            g_vtblk_irq_log_budget--;
            printf("[virtio-blk] unexpected used id=%u used_idx=%u qsz=%u budget=%u\n",
                   id, g_vtblk.used_idx, g_vtblk.queue_size, g_vtblk_irq_log_budget);
        }
        g_vtblk.used_idx++;
    }
}

static void virtio_blk_drain_used_poll(void) {
    uint16_t before;

    virtio_blk_lock(&g_vtblk_complete_lock);
    before = g_vtblk.used_idx;
    virtio_blk_drain_used_locked();
    /*
     * The used ring is ordinary DMA-coherent guest memory.  Reading the PCI
     * ISR on every process-context poll is unnecessary for MSI/MSI-X and is a
     * VM exit under KVM.  A single 4K metadata read used to perform thousands
     * of such exits, turning apk operations into 50-100 ms stalls per block.
     *
     * Legacy INTx is level-triggered, so acknowledge it only when this poll
     * consumed a completion before the interrupt handler did.  MSI and MSI-X
     * have no shared line to deassert; their real handler performs the normal
     * ISR acknowledgement when QEMU delivers the vector.
     */
    if (g_vtblk.irq_mode == 1u && before != g_vtblk.used_idx)
        virtio_ack_isr();
    virtio_blk_unlock(&g_vtblk_complete_lock);
}

static void virtio_blk_irq_handler(REGISTERS *reg) {
    (void)reg;
    if (!g_vtblk.present) return;
    g_vtblk_irq_count++;
    /*
     * Real virtio-blk completion interrupt path.  Do not sleep or call the
     * scheduler from IRQ context; if process context is already draining the
     * used ring, the waiter will catch the completion on its next poll pass.
     */
    if (__sync_lock_test_and_set(&g_vtblk_complete_lock, 1)) {
        virtio_ack_isr();
        return;
    }
    virtio_blk_drain_used_locked();
    virtio_ack_isr();
    virtio_blk_unlock(&g_vtblk_complete_lock);
}

static uint32_t vring_used_offset(uint32_t num) {
    uint32_t off = num * (uint32_t)sizeof(struct vring_desc);
    off += (uint32_t)sizeof(struct vring_avail) + num * (uint32_t)sizeof(uint16_t) + (uint32_t)sizeof(uint16_t);
    return (off + VIRTIO_PCI_VRING_ALIGN - 1u) & ~(VIRTIO_PCI_VRING_ALIGN - 1u);
}

static void virtio_blk_setup_ring(uint16_t qsz) {
    uint32_t used_off;
    memset(g_vtblk_ring, 0, sizeof(g_vtblk_ring));
    g_vtblk.desc = (struct vring_desc *)g_vtblk_ring;
    g_vtblk.avail = (struct vring_avail *)(g_vtblk_ring + qsz * sizeof(struct vring_desc));
    used_off = vring_used_offset(qsz);
    g_vtblk.used = (struct vring_used *)(g_vtblk_ring + used_off);
    g_vtblk.avail_idx = 0;
    g_vtblk.used_idx = 0;
    g_vtblk.inflight_slots = (uint16_t)(qsz / 3u);
    if (g_vtblk.inflight_slots > VIRTIO_BLK_MAX_INFLIGHT) {
        g_vtblk.inflight_slots = VIRTIO_BLK_MAX_INFLIGHT;
    }
    memset(g_vtblk_reqs, 0, sizeof(g_vtblk_reqs));
}

static int virtio_blk_ring_fits(uint16_t qsz) {
    uint32_t used_off = vring_used_offset(qsz);
    uint32_t used_bytes = (uint32_t)sizeof(struct vring_used) +
                          (uint32_t)qsz * (uint32_t)sizeof(struct vring_used_elem) +
                          (uint32_t)sizeof(uint16_t);
    return qsz >= 3 && qsz <= VIRTIO_BLK_QUEUE_SIZE &&
           used_off + used_bytes <= VIRTIO_BLK_RING_BYTES;
}

typedef struct {
    uint8_t bar;
    uint32_t offset;
    uint32_t length;
} virtio_modern_cap_t;

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
    uint64_t phys;
    uintptr_t kva;
    if (!virtio_modern_cap_valid(cap, 1, 1) || !out) return -1;
    base = pci_bar_base(bus, dev, fn, cap->bar, &is_io);
    phys = base + cap->offset;
    if (is_io || base == 0 || phys >= 0x0000800000000000ULL || phys < base) return -1;
    if (!edge_mmio_phys_range_mapped(phys, cap->length)) {
        printf("[virtio-blk] BAR%u phys=0x%llx len=0x%x is outside mapped MMIO apertures\n",
               (uint32_t)cap->bar,
               (unsigned long long)phys,
               cap->length);
        return -1;
    }
    kva = edge_mmio_low_alias(phys);
    *out = (volatile uint8_t *)kva;
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
    if (!virtio_modern_cap_valid(device_cfg, 8, 4)) return -1;
    return 0;
}

static int virtio_blk_find_modern(void) {
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
                    (device != VIRTIO_PCI_DEVICEID_MODERN_BLOCK &&
                     device != VIRTIO_PCI_DEVICEID_BLOCK_LEGACY)) {
                    continue;
                }
                memset(&common, 0, sizeof(common));
                memset(&notify, 0, sizeof(notify));
                memset(&isr, 0, sizeof(isr));
                memset(&device_cfg, 0, sizeof(device_cfg));
                if (virtio_modern_find_caps((uint8_t)bus, dev, fn, &common, &notify, &isr,
                                            &device_cfg, &notify_multiplier) < 0) {
                    if (device == VIRTIO_PCI_DEVICEID_MODERN_BLOCK) {
                        printf("[virtio-blk] modern device %u:%u.%u missing usable PCI capabilities\n",
                               (uint32_t)bus, dev, fn);
                    }
                    continue;
                }
                if (virtio_modern_cap_addr((uint8_t)bus, dev, fn, &common, &g_vtblk.common_base) < 0 ||
                    virtio_modern_cap_addr((uint8_t)bus, dev, fn, &notify, &g_vtblk.notify_base) < 0 ||
                    virtio_modern_cap_addr((uint8_t)bus, dev, fn, &isr, &g_vtblk.isr_base) < 0 ||
                    virtio_modern_cap_addr((uint8_t)bus, dev, fn, &device_cfg, &g_vtblk.device_base) < 0) {
                    printf("[virtio-blk] modern device %u:%u.%u has unsupported BAR mapping\n",
                           (uint32_t)bus, dev, fn);
                    continue;
                }
                g_vtblk.bus = (uint8_t)bus;
                g_vtblk.dev = dev;
                g_vtblk.fn = fn;
                g_vtblk.notify_multiplier = notify_multiplier;
                g_vtblk.transport = VIRTIO_BLK_TRANSPORT_MODERN;
                return 0;
            }
        }
    }
    return -1;
}

static int virtio_blk_find_legacy(void) {
    for (uint16_t bus = 0; bus < 256; ++bus) {
        for (uint8_t dev = 0; dev < 32; ++dev) {
            for (uint8_t fn = 0; fn < 8; ++fn) {
                uint32_t id = pci_cfg_read32((uint8_t)bus, dev, fn, 0x00);
                uint16_t vendor = (uint16_t)(id & 0xFFFFu);
                uint16_t device = (uint16_t)(id >> 16);
                uint8_t rev;
                uint32_t bar0;
                if (vendor == 0xFFFFu) {
                    if (fn == 0) break;
                    continue;
                }
                if (vendor != VIRTIO_PCI_VENDORID || device != VIRTIO_PCI_DEVICEID_BLOCK_LEGACY) continue;
                rev = pci_cfg_read8((uint8_t)bus, dev, fn, 0x08);
                if (rev != VIRTIO_PCI_ABI_VERSION) continue;
                bar0 = pci_cfg_read32((uint8_t)bus, dev, fn, 0x10);
                if ((bar0 & 1u) == 0) continue;
                g_vtblk.bus = (uint8_t)bus;
                g_vtblk.dev = dev;
                g_vtblk.fn = fn;
                g_vtblk.io_base = bar0 & ~3u;
                g_vtblk.transport = VIRTIO_BLK_TRANSPORT_LEGACY;
                return 0;
            }
        }
    }
    return -1;
}

static int virtio_blk_find(void) {
    if (virtio_blk_find_modern() == 0) return 0;
    return virtio_blk_find_legacy();
}

static void virtio_blk_set_status(uint8_t status) {
    virtio_status_set(status);
}

static void virtio_blk_fail(void) {
    virtio_blk_set_status((uint8_t)(virtio_status_get() | VIRTIO_CONFIG_STATUS_FAILED));
}

static int virtio_blk_submit(uint32_t type, uint32_t lba, uint32_t count, void *buf) {
    uint16_t slot = 0;
    uint16_t head;
    uint16_t data;
    uint16_t status;
    uint32_t bytes;
    uint64_t wait_start_us;
    uint64_t start_us;
    uint32_t last_irq;
    uint32_t quiet_polls = 0;

    if (!g_vtblk.present || !buf || count == 0) return -1;
    if (g_vtblk.inflight_slots == 0 || g_vtblk.inflight_slots > VIRTIO_BLK_MAX_INFLIGHT) return -1;

    wait_start_us = boottime_monotonic_us();
    for (;;) {
        int found = 0;
        for (uint16_t i = 0; i < g_vtblk.inflight_slots; ++i) {
            if (!__sync_lock_test_and_set(&g_vtblk_reqs[i].busy, 1)) {
                slot = i;
                found = 1;
                break;
            }
        }
        if (found) break;
        task_t *cur = scheduler_current_task();
        /*
         * Linux block devices queue valid concurrent I/O instead of failing it.
         * All virtqueue slots are busy here, so wait for an in-flight request to
         * retire and then reserve a descriptor chain.
         */
        if (cur && !cur->is_idle && cur->pid > 0 && cur->state == TASK_RUNNING) {
            scheduler_yield();
        } else {
            __asm__ __volatile__("pause");
        }
    }
    if (g_vtblk_busy_log_budget > 0) {
        uint64_t waited = boottime_monotonic_us() - wait_start_us;
        if (waited >= 50000ull) {
            g_vtblk_busy_log_budget--;
            printf("[virtio-blk-queue-wait] type=%u lba=%u count=%u us=%u budget=%u\n",
                   type, lba, count, (unsigned)waited, (unsigned)g_vtblk_busy_log_budget);
        }
    }
    start_us = boottime_monotonic_us();
    bytes = count * g_vtblk.sector_size;
    head = (uint16_t)(slot * 3u);
    data = (uint16_t)(head + 1u);
    status = (uint16_t)(head + 2u);

    g_vtblk_reqs[slot].hdr.type = type;
    g_vtblk_reqs[slot].hdr.ioprio = 0;
    g_vtblk_reqs[slot].hdr.sector = ((uint64_t)lba * (uint64_t)g_vtblk.sector_size) / 512ull;
    g_vtblk_reqs[slot].status = 0xFFu;
    g_vtblk_reqs[slot].done = 0;

    g_vtblk.desc[head].addr = virtio_blk_dma_addr(&g_vtblk_reqs[slot].hdr);
    g_vtblk.desc[head].len = sizeof(g_vtblk_reqs[slot].hdr);
    g_vtblk.desc[head].flags = VRING_DESC_F_NEXT;
    g_vtblk.desc[head].next = data;

    g_vtblk.desc[data].addr = virtio_blk_dma_addr(buf);
    g_vtblk.desc[data].len = bytes;
    g_vtblk.desc[data].flags = VRING_DESC_F_NEXT | (type == VIRTIO_BLK_T_IN ? VRING_DESC_F_WRITE : 0);
    g_vtblk.desc[data].next = status;

    g_vtblk.desc[status].addr = virtio_blk_dma_addr(&g_vtblk_reqs[slot].status);
    g_vtblk.desc[status].len = sizeof(g_vtblk_reqs[slot].status);
    g_vtblk.desc[status].flags = VRING_DESC_F_WRITE;
    g_vtblk.desc[status].next = 0;

    virtio_blk_lock(&g_vtblk_queue_lock);
    g_vtblk.avail->ring[g_vtblk.avail_idx % g_vtblk.queue_size] = head;
    __sync_synchronize();
    g_vtblk.avail_idx++;
    g_vtblk.avail->idx = g_vtblk.avail_idx;
    __sync_synchronize();
    virtio_queue_notify();
    virtio_blk_unlock(&g_vtblk_queue_lock);

    last_irq = g_vtblk_irq_count;
    for (uint32_t spin = 0; spin < 20000000u; ++spin) {
        __sync_synchronize();
        virtio_blk_drain_used_poll();
        if (g_vtblk_reqs[slot].done) {
            uint64_t dt_us = boottime_monotonic_us() - start_us;
            if (dt_us >= 50000ull && g_vtblk_slow_log_budget > 0) {
                g_vtblk_slow_log_budget--;
                printf("[virtio-blk-slow] slot=%u type=%u lba=%u count=%u us=%u status=%u spin=%u irq=%u mode=%u used=%u/%u avail=%u budget=%u\n",
                       slot,
                       type,
                       lba,
                       count,
                       (unsigned)dt_us,
                       g_vtblk_reqs[slot].status,
                       spin,
                       (unsigned)g_vtblk_irq_count,
                       (unsigned)g_vtblk.irq_mode,
                       (unsigned)g_vtblk.used_idx,
                       (unsigned)g_vtblk.used->idx,
                       (unsigned)g_vtblk.avail_idx,
                       (unsigned)g_vtblk_slow_log_budget);
            }
            uint8_t st = g_vtblk_reqs[slot].status;
            g_vtblk_reqs[slot].busy = 0;
            return st == VIRTIO_BLK_S_OK ? 0 : -1;
        }
        if (g_vtblk.irq_mode) {
            /*
             * INTx/MSI delivery is still not a Linux-grade block waitqueue in
             * EdgeOS.  Halting here makes a missed or delayed virtio interrupt
             * fall back to the timer tick, which turns every apk/XFCE metadata
             * read into a 50 ms stall.  Poll the used ring in process context
             * and yield only occasionally so QEMU's I/O thread and other guest
             * tasks still make progress.  Red flag: do not replace this with a
             * fake completion path; the request is complete only when the
             * virtqueue used ring reports it.
             */
            if (g_vtblk_irq_count == last_irq) {
                quiet_polls++;
            } else {
                quiet_polls = 0;
                last_irq = g_vtblk_irq_count;
            }
            if ((spin & 0x3FFFu) == 0x3FFFu) {
                task_t *cur = scheduler_current_task();
                if (cur && !cur->is_idle && cur->pid > 0 && cur->state == TASK_RUNNING) {
                    scheduler_yield();
                }
            } else {
                __asm__ __volatile__("pause");
            }
            if (quiet_polls > 262144u && g_vtblk_irq_log_budget > 0) {
                g_vtblk_irq_log_budget--;
                printf("[virtio-blk] poll wait quiet mode=%u vector=%u irq=%u used=%u/%u budget=%u\n",
                       (unsigned)g_vtblk.irq_mode,
                       (unsigned)g_vtblk.irq_vector,
                       (unsigned)g_vtblk_irq_count,
                       (unsigned)g_vtblk.used_idx,
                       (unsigned)g_vtblk.used->idx,
                       (unsigned)g_vtblk_irq_log_budget);
                quiet_polls = 0;
            }
        } else {
            task_t *cur = scheduler_current_task();
            if ((spin & (VIRTIO_BLK_POLL_YIELD_INTERVAL - 1u)) == 0 &&
                cur && !cur->is_idle && cur->pid > 0 && cur->state == TASK_RUNNING) {
                scheduler_yield();
            } else {
                __asm__ __volatile__("pause");
            }
        }
    }

    printf("[virtio-blk] request timeout type=%u lba=%u count=%u status=%u\n",
           type, lba, count, g_vtblk_reqs[slot].status);
    g_vtblk_reqs[slot].busy = 0;
    return -1;
}

static void virtio_blk_setup_interrupts(void) {
    int vector;
    uint8_t irq_line;

    g_vtblk.irq_mode = 0;
    g_vtblk.irq_vector = 0;
    irq_line = pci_cfg_read8(g_vtblk.bus, g_vtblk.dev, g_vtblk.fn, 0x3C);
    g_vtblk.irq_line = irq_line;

    /*
     * The modern virtio queue_msix_vector register contains an MSI-X table
     * index.  EdgeOS then programs that table entry with the CPU APIC vector.
     * This mirrors the BSD virtio PCI transport split and avoids confusing the
     * guest interrupt vector with the device table slot.
     */
    vector = apic_allocate_msi_vector();
    if (vector >= 0 &&
        g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN &&
        pci_enable_msix_vector(g_vtblk.bus, g_vtblk.dev, g_vtblk.fn, 0, (uint8_t)vector) == 0 &&
        virtio_blk_modern_set_queue_msix(0, 0) == 0) {
        (void)virtio_blk_modern_set_config_msix(VIRTIO_MSI_NO_VECTOR);
        isr_register_interrupt_handler(vector, virtio_blk_irq_handler);
        g_vtblk.irq_vector = (uint8_t)vector;
        g_vtblk.irq_mode = 3;
        printf("[virtio-blk] msix queue vector=%u table=0 irq_line=%u\n",
               (uint32_t)g_vtblk.irq_vector, (uint32_t)irq_line);
        return;
    }

    vector = apic_allocate_msi_vector();
    if (vector >= 0 &&
        pci_enable_msi_vector(g_vtblk.bus, g_vtblk.dev, g_vtblk.fn, (uint8_t)vector) == 0) {
        isr_register_interrupt_handler(vector, virtio_blk_irq_handler);
        g_vtblk.irq_vector = (uint8_t)vector;
        g_vtblk.irq_mode = 2;
        printf("[virtio-blk] msi vector=%u irq_line=%u\n",
               (uint32_t)g_vtblk.irq_vector, (uint32_t)irq_line);
        return;
    }

    if (irq_line < 16u) {
        isr_register_interrupt_handler(IRQ_BASE + irq_line, virtio_blk_irq_handler);
        pic8259_unmask_irq(irq_line);
        g_vtblk.irq_vector = (uint8_t)(IRQ_BASE + irq_line);
        g_vtblk.irq_mode = 1;
        printf("[virtio-blk] intx irq line %u handler installed\n", (uint32_t)irq_line);
    } else {
        printf("[virtio-blk] no usable interrupt route irq_line=%u, polling completions\n",
               (uint32_t)irq_line);
    }
}

int virtio_blk_init(void) {
    uint16_t cmd;
    uint64_t host_features;
    uint64_t guest_features = 0;
    uint16_t qsz;
    uint64_t capacity;
    uint32_t sector_size = VIRTIO_BLK_DEFAULT_SECTOR_SIZE;

    memset(&g_vtblk, 0, sizeof(g_vtblk));
    g_vtblk_queue_lock = 0;
    g_vtblk_complete_lock = 0;
    if (virtio_blk_find() < 0) return -1;

    cmd = pci_cfg_read16(g_vtblk.bus, g_vtblk.dev, g_vtblk.fn, 0x04);
    if (g_vtblk.transport == VIRTIO_BLK_TRANSPORT_LEGACY) cmd |= PCI_COMMAND_IO;
    if (g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN) cmd |= PCI_COMMAND_MEM;
    cmd |= PCI_COMMAND_BUSMASTER;
    pci_cfg_write16(g_vtblk.bus, g_vtblk.dev, g_vtblk.fn, 0x04, cmd);

    virtio_blk_set_status(VIRTIO_CONFIG_STATUS_RESET);
    for (uint32_t spin = 0; spin < 1000000u && virtio_status_get() != VIRTIO_CONFIG_STATUS_RESET; ++spin) {
        __asm__ __volatile__("pause");
    }
    virtio_blk_set_status(VIRTIO_CONFIG_STATUS_ACK);
    virtio_blk_set_status((uint8_t)(VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER));

    host_features = virtio_features_read();
    if (host_features & VIRTIO_BLK_F_BLK_SIZE) guest_features |= VIRTIO_BLK_F_BLK_SIZE;
    if (g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN) {
        if ((host_features & VIRTIO_F_VERSION_1) == 0) {
            printf("[virtio-blk] modern device missing VERSION_1 feature\n");
            virtio_blk_fail();
            return -1;
        }
        guest_features |= VIRTIO_F_VERSION_1;
    }
    virtio_features_write(guest_features);
    if (g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN) {
        virtio_blk_set_status((uint8_t)(VIRTIO_CONFIG_STATUS_ACK |
                                        VIRTIO_CONFIG_STATUS_DRIVER |
                                        VIRTIO_CONFIG_STATUS_FEATURES_OK));
        if ((virtio_status_get() & VIRTIO_CONFIG_STATUS_FEATURES_OK) == 0) {
            printf("[virtio-blk] modern feature negotiation rejected\n");
            virtio_blk_fail();
            return -1;
        }
    }

    virtio_queue_select(0);
    qsz = virtio_queue_size_read();
    if (!virtio_blk_ring_fits(qsz)) {
        printf("[virtio-blk] unsupported queue size %u\n", qsz);
        virtio_blk_fail();
        return -1;
    }
    virtio_blk_setup_ring(qsz);
    virtio_queue_program(qsz);
    virtio_blk_setup_interrupts();

    capacity = virtio_device_config_read64(0);
    if (guest_features & VIRTIO_BLK_F_BLK_SIZE) {
        sector_size = virtio_device_config_read32(20);
        if (sector_size == 0 || sector_size > 4096u || (sector_size & (sector_size - 1u)) != 0) {
            sector_size = VIRTIO_BLK_DEFAULT_SECTOR_SIZE;
        }
    }
    if (capacity == 0 || capacity > 0xFFFFFFFFull) {
        printf("[virtio-blk] invalid capacity=%llu\n", (unsigned long long)capacity);
        virtio_blk_fail();
        return -1;
    }
    g_vtblk.readonly = (host_features & VIRTIO_BLK_F_RO) ? 1 : 0;
    g_vtblk.sector_size = sector_size;
    g_vtblk.sector_count = (uint32_t)((capacity * 512ull) / (uint64_t)sector_size);
    if (g_vtblk.sector_count == 0) {
        virtio_blk_fail();
        return -1;
    }
    g_vtblk.queue_size = qsz;
    g_vtblk.present = 1;
    virtio_blk_set_status((uint8_t)(VIRTIO_CONFIG_STATUS_ACK |
                                    VIRTIO_CONFIG_STATUS_DRIVER |
                                    (g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN ? VIRTIO_CONFIG_STATUS_FEATURES_OK : 0) |
                                    VIRTIO_CONFIG_STATUS_DRIVER_OK));
    printf("[virtio-blk] %s PCI block device at %u:%u.%u %s=0x%x sectors=%u sector_size=%u irq_mode=%u vector=%u%s\n",
           g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN ? "modern" : "legacy",
           g_vtblk.bus, g_vtblk.dev, g_vtblk.fn,
           g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN ? "common" : "io",
           g_vtblk.transport == VIRTIO_BLK_TRANSPORT_MODERN ?
               (uint32_t)(uintptr_t)g_vtblk.common_base : g_vtblk.io_base,
           g_vtblk.sector_count, g_vtblk.sector_size,
           (uint32_t)g_vtblk.irq_mode, (uint32_t)g_vtblk.irq_vector,
           g_vtblk.readonly ? " ro" : "");
    return 0;
}

int virtio_blk_present(void) {
    return g_vtblk.present;
}

uint32_t virtio_blk_sector_size(void) {
    return g_vtblk.sector_size ? g_vtblk.sector_size : VIRTIO_BLK_DEFAULT_SECTOR_SIZE;
}

uint32_t virtio_blk_sector_count(void) {
    return g_vtblk.sector_count;
}

int virtio_blk_read(uint32_t lba, uint32_t sector_count, void *buf) {
    if (sector_count > VIRTIO_BLK_MAX_SECTORS) return -1;
    if (lba + sector_count < lba || lba + sector_count > g_vtblk.sector_count) return -1;
    return virtio_blk_submit(VIRTIO_BLK_T_IN, lba, sector_count, buf);
}

int virtio_blk_write(uint32_t lba, uint32_t sector_count, const void *buf) {
    if (g_vtblk.readonly) return -1;
    if (sector_count > VIRTIO_BLK_MAX_SECTORS) return -1;
    if (lba + sector_count < lba || lba + sector_count > g_vtblk.sector_count) return -1;
    return virtio_blk_submit(VIRTIO_BLK_T_OUT, lba, sector_count, (void *)buf);
}
