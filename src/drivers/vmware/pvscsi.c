/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018 VMware, Inc.
 *
 * This file ports the VMware PVSCSI device command/ring model from
 * FreeBSD sys/dev/vmware/pvscsi.  EdgeOS replaces the FreeBSD CAM, busdma,
 * interrupt, and PCI attachment layers with its block-device interface while
 * preserving the PVSCSI reset, ring setup, request descriptor, completion
 * status, and command submission flow.
 *
 * Modifications for EdgeOS.
 * Copyright (c) EdgeOS Contributors.
 */

#include "drivers/pvscsi.h"

#include "drivers/pci.h"
#include "stdio.h"
#include "string.h"
#include "sys/boottime.h"
#include "sys/mmio.h"
#include "sys/spinlock.h"

#include <stdint.h>

#define PCI_VENDOR_ID_VMWARE        0x15ADu
#define PCI_DEVICE_ID_VMWARE_PVSCSI 0x07C0u

#define PCI_COMMAND_MEM       0x0002u
#define PCI_COMMAND_BUSMASTER 0x0004u

#define PVSCSI_PAGE_SIZE 4096u
#define PVSCSI_PAGE_SHIFT 12u
#define PVSCSI_DEFAULT_NUM_PAGES_REQ_RING 8u
#define PVSCSI_REQ_RING_PAGES PVSCSI_DEFAULT_NUM_PAGES_REQ_RING
#define PVSCSI_CMP_RING_PAGES PVSCSI_DEFAULT_NUM_PAGES_REQ_RING
#define PVSCSI_MSG_RING_PAGES 1u
#define PVSCSI_MAX_QUEUE_DEPTH 256u
#define PVSCSI_SENSE_LENGTH 256u
#define PVSCSI_MAX_TRANSFER_SECTORS 1024u
#define PVSCSI_COMPLETION_TIMEOUT_US 5000000ull
#define PVSCSI_RESET_TIMEOUT_US 1000000ull

#define MASK(v) ((1u << (v)) - 1u)

enum pvscsi_reg_offset {
    PVSCSI_REG_OFFSET_COMMAND = 0x0000u,
    PVSCSI_REG_OFFSET_COMMAND_DATA = 0x0004u,
    PVSCSI_REG_OFFSET_COMMAND_STATUS = 0x0008u,
    PVSCSI_REG_OFFSET_INTR_STATUS = 0x100Cu,
    PVSCSI_REG_OFFSET_INTR_MASK = 0x2010u,
    PVSCSI_REG_OFFSET_KICK_NON_RW_IO = 0x3014u,
    PVSCSI_REG_OFFSET_KICK_RW_IO = 0x4018u,
};

enum pvscsi_commands {
    PVSCSI_CMD_ADAPTER_RESET = 1,
    PVSCSI_CMD_SETUP_RINGS = 3,
    PVSCSI_CMD_RESET_BUS = 4,
    PVSCSI_CMD_RESET_DEVICE = 5,
    PVSCSI_CMD_ABORT_CMD = 6,
    PVSCSI_CMD_SETUP_MSG_RING = 8,
    PVSCSI_CMD_SETUP_REQCALLTHRESHOLD = 10,
    PVSCSI_CMD_GET_MAX_TARGETS = 11,
};

struct pvscsi_cmd_desc_reset_device {
    uint32_t target;
    uint8_t lun[8];
} __attribute__((packed));

struct pvscsi_cmd_desc_abort_cmd {
    uint64_t context;
    uint32_t target;
    uint32_t pad;
} __attribute__((packed));

#define PVSCSI_SETUP_RINGS_MAX_NUM_PAGES 32u
#define PVSCSI_SETUP_MSG_RING_MAX_NUM_PAGES 16u

struct pvscsi_cmd_desc_setup_rings {
    uint32_t req_ring_num_pages;
    uint32_t cmp_ring_num_pages;
    uint64_t rings_state_ppn;
    uint64_t req_ring_ppns[PVSCSI_SETUP_RINGS_MAX_NUM_PAGES];
    uint64_t cmp_ring_ppns[PVSCSI_SETUP_RINGS_MAX_NUM_PAGES];
} __attribute__((packed));

struct pvscsi_cmd_desc_setup_msg_ring {
    uint32_t num_pages;
    uint32_t pad;
    uint64_t ring_ppns[PVSCSI_SETUP_MSG_RING_MAX_NUM_PAGES];
} __attribute__((packed));

struct pvscsi_rings_state {
    uint32_t req_prod_idx;
    uint32_t req_cons_idx;
    uint32_t req_num_entries_log2;
    uint32_t cmp_prod_idx;
    uint32_t cmp_cons_idx;
    uint32_t cmp_num_entries_log2;
    uint32_t req_call_threshold;
    uint8_t pad[100];
    uint32_t msg_prod_idx;
    uint32_t msg_cons_idx;
    uint32_t msg_num_entries_log2;
} __attribute__((packed));

#define PVSCSI_FLAG_CMD_WITH_SG_LIST   (1u << 0)
#define PVSCSI_FLAG_CMD_DIR_NONE       (1u << 2)
#define PVSCSI_FLAG_CMD_DIR_TOHOST     (1u << 3)
#define PVSCSI_FLAG_CMD_DIR_TODEVICE   (1u << 4)

#define PVSCSI_INTR_CMPL_MASK MASK(2)
#define PVSCSI_INTR_MSG_MASK  (MASK(2) << 2)
#define PVSCSI_INTR_ALL_SUPPORTED MASK(4)

struct pvscsi_ring_req_desc {
    uint64_t context;
    uint64_t data_addr;
    uint64_t data_len;
    uint64_t sense_addr;
    uint32_t sense_len;
    uint32_t flags;
    uint8_t cdb[16];
    uint8_t cdb_len;
    uint8_t lun[8];
    uint8_t tag;
    uint8_t bus;
    uint8_t target;
    uint16_t vcpu_hint;
    uint8_t unused[58];
} __attribute__((packed));

struct pvscsi_ring_cmp_desc {
    uint64_t context;
    uint64_t data_len;
    uint32_t sense_len;
    uint16_t host_status;
    uint16_t scsi_status;
    uint32_t pad[2];
} __attribute__((packed));

struct pvscsi_ring_msg_desc {
    uint32_t type;
    uint32_t args[31];
} __attribute__((packed));

struct pvscsi_cmd_desc_setup_req_call {
    uint32_t enable;
} __attribute__((packed));

enum pvscsi_host_status {
    BTSTAT_SUCCESS = 0x00,
    BTSTAT_LINKED_COMMAND_COMPLETED = 0x0A,
    BTSTAT_LINKED_COMMAND_COMPLETED_WITH_FLAG = 0x0B,
    BTSTAT_DATA_UNDERRUN = 0x0C,
};

#define SCSI_STATUS_GOOD 0x00u
#define SCSI_STATUS_CHECK_COND 0x02u

#define SCSI_CMD_TEST_UNIT_READY 0x00u
#define SCSI_CMD_INQUIRY 0x12u
#define SCSI_CMD_READ_CAPACITY_10 0x25u
#define SCSI_CMD_READ_10 0x28u
#define SCSI_CMD_WRITE_10 0x2Au
#define SCSI_CMD_SERVICE_ACTION_IN_16 0x9Eu
#define SCSI_SAI_READ_CAPACITY_16 0x10u

#define MSG_SIMPLE_Q_TAG 0x20u

typedef struct {
    uint8_t bus;
    uint8_t dev;
    uint8_t fn;
    uint8_t present;
    uint8_t rings_ready;
    uint8_t use_msg;
    uint32_t sector_size;
    uint32_t sector_count;
    uint32_t max_targets;
    uint32_t queue_depth;
    volatile uint8_t *mmio;
    spinlock_t lock;
    struct pvscsi_rings_state *rings_state;
    struct pvscsi_ring_req_desc *req_ring;
    struct pvscsi_ring_cmp_desc *cmp_ring;
    struct pvscsi_ring_msg_desc *msg_ring;
    uint8_t *sense;
    uint32_t next_context;
    uint32_t last_host_status;
    uint32_t last_scsi_status;
} pvscsi_softc_t;

static pvscsi_softc_t g_pvscsi;
static uint8_t g_pvscsi_state_page[PVSCSI_PAGE_SIZE] __attribute__((aligned(PVSCSI_PAGE_SIZE)));
static uint8_t g_pvscsi_req_pages[PVSCSI_REQ_RING_PAGES * PVSCSI_PAGE_SIZE] __attribute__((aligned(PVSCSI_PAGE_SIZE)));
static uint8_t g_pvscsi_cmp_pages[PVSCSI_CMP_RING_PAGES * PVSCSI_PAGE_SIZE] __attribute__((aligned(PVSCSI_PAGE_SIZE)));
static uint8_t g_pvscsi_msg_pages[PVSCSI_MSG_RING_PAGES * PVSCSI_PAGE_SIZE] __attribute__((aligned(PVSCSI_PAGE_SIZE)));
static uint8_t g_pvscsi_sense[PVSCSI_SENSE_LENGTH] __attribute__((aligned(16)));

static void pvscsi_mb(void) {
    __asm__ __volatile__("" ::: "memory");
}

static uint32_t pvscsi_reg_read(uint32_t off) {
    return *(volatile uint32_t *)(g_pvscsi.mmio + off);
}

static void pvscsi_reg_write(uint32_t off, uint32_t v) {
    *(volatile uint32_t *)(g_pvscsi.mmio + off) = v;
}

static uint64_t pvscsi_phys(const void *p) {
    return (uint64_t)(uintptr_t)p;
}

static uint64_t pvscsi_ppn(const void *p) {
    return pvscsi_phys(p) >> PVSCSI_PAGE_SHIFT;
}

static uint32_t pvscsi_log2_u32(uint32_t v) {
    uint32_t r = 0;
    while ((1u << r) < v && r < 31) r++;
    return r;
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

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t be64(const uint8_t *p) {
    return ((uint64_t)be32(p) << 32) | be32(p + 4);
}

static uint64_t pci_bar_base(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t bar, int *is_io) {
    uint32_t lo;
    uint8_t off;
    if (bar >= 6) return 0;
    off = (uint8_t)(0x10u + bar * 4u);
    lo = pci_cfg_read32(bus, dev, fn, off);
    if (lo & 1u) {
        if (is_io) *is_io = 1;
        return (uint64_t)(lo & ~3u);
    }
    if (is_io) *is_io = 0;
    if ((lo & 0x6u) == 0x4u && bar < 5) {
        uint32_t hi = pci_cfg_read32(bus, dev, fn, (uint8_t)(off + 4u));
        return ((uint64_t)hi << 32) | (uint64_t)(lo & ~0xFULL);
    }
    return (uint64_t)(lo & ~0xFULL);
}

static int pvscsi_find_pci(uint8_t *bus_out, uint8_t *dev_out, uint8_t *fn_out, uint64_t *mmio_out) {
    for (uint16_t bus = 0; bus < 256; ++bus) {
        for (uint8_t dev = 0; dev < 32; ++dev) {
            for (uint8_t fn = 0; fn < 8; ++fn) {
                uint16_t vendor = pci_cfg_read16((uint8_t)bus, dev, fn, 0x00);
                uint16_t device;
                if (vendor == PCI_VENDOR_INVALID) {
                    if (fn == 0) break;
                    continue;
                }
                device = pci_cfg_read16((uint8_t)bus, dev, fn, 0x02);
                if (vendor != PCI_VENDOR_ID_VMWARE || device != PCI_DEVICE_ID_VMWARE_PVSCSI) continue;
                for (uint8_t bar = 0; bar < 6; ++bar) {
                    int is_io = 0;
                    uint64_t base = pci_bar_base((uint8_t)bus, dev, fn, bar, &is_io);
                    if (!is_io && base) {
                        *bus_out = (uint8_t)bus;
                        *dev_out = dev;
                        *fn_out = fn;
                        *mmio_out = base;
                        return 0;
                    }
                }
            }
        }
    }
    return -1;
}

static void pvscsi_write_cmd(uint32_t cmd, const void *data, uint32_t len) {
    const uint32_t *p = (const uint32_t *)data;
    pvscsi_reg_write(PVSCSI_REG_OFFSET_COMMAND, cmd);
    for (uint32_t i = 0; i < len / sizeof(uint32_t); ++i) {
        pvscsi_reg_write(PVSCSI_REG_OFFSET_COMMAND_DATA, p[i]);
    }
}

static uint32_t pvscsi_get_max_targets(void) {
    uint32_t max_targets;
    pvscsi_write_cmd(PVSCSI_CMD_GET_MAX_TARGETS, 0, 0);
    max_targets = pvscsi_reg_read(PVSCSI_REG_OFFSET_COMMAND_STATUS);
    if (max_targets == 0xFFFFFFFFu || max_targets == 0) max_targets = 16;
    return max_targets;
}

static int pvscsi_hw_supports_msg(void) {
    uint32_t status;
    pvscsi_reg_write(PVSCSI_REG_OFFSET_COMMAND, PVSCSI_CMD_SETUP_MSG_RING);
    status = pvscsi_reg_read(PVSCSI_REG_OFFSET_COMMAND_STATUS);
    return status != 0xFFFFFFFFu;
}

static void pvscsi_intr_disable(void) {
    pvscsi_reg_write(PVSCSI_REG_OFFSET_INTR_MASK, 0);
}

static void pvscsi_intr_ack_all(void) {
    uint32_t val = pvscsi_reg_read(PVSCSI_REG_OFFSET_INTR_STATUS);
    if (val & PVSCSI_INTR_ALL_SUPPORTED) {
        pvscsi_reg_write(PVSCSI_REG_OFFSET_INTR_STATUS, val & PVSCSI_INTR_ALL_SUPPORTED);
    }
}

static void pvscsi_adapter_reset(void) {
    pvscsi_write_cmd(PVSCSI_CMD_ADAPTER_RESET, 0, 0);
    (void)pvscsi_reg_read(PVSCSI_REG_OFFSET_INTR_STATUS);
}

static void pvscsi_bus_reset(void) {
    pvscsi_write_cmd(PVSCSI_CMD_RESET_BUS, 0, 0);
}

static void pvscsi_device_reset(uint32_t target) {
    struct pvscsi_cmd_desc_reset_device cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.target = target;
    pvscsi_write_cmd(PVSCSI_CMD_RESET_DEVICE, &cmd, sizeof(cmd));
}

static void pvscsi_abort_context(uint32_t target, uint64_t context) {
    struct pvscsi_cmd_desc_abort_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.target = target;
    cmd.context = context;
    pvscsi_write_cmd(PVSCSI_CMD_ABORT_CMD, &cmd, sizeof(cmd));
}

static int pvscsi_setup_req_call(uint32_t enable) {
    struct pvscsi_cmd_desc_setup_req_call cmd;
    uint32_t status;
    pvscsi_reg_write(PVSCSI_REG_OFFSET_COMMAND, PVSCSI_CMD_SETUP_REQCALLTHRESHOLD);
    status = pvscsi_reg_read(PVSCSI_REG_OFFSET_COMMAND_STATUS);
    if (status == 0xFFFFFFFFu) return 0;
    cmd.enable = enable;
    pvscsi_write_cmd(PVSCSI_CMD_SETUP_REQCALLTHRESHOLD, &cmd, sizeof(cmd));
    status = pvscsi_reg_read(PVSCSI_REG_OFFSET_COMMAND_STATUS);
    return status == 0;
}

static void pvscsi_setup_rings(void) {
    struct pvscsi_cmd_desc_setup_rings cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.rings_state_ppn = pvscsi_ppn(g_pvscsi_state_page);
    cmd.req_ring_num_pages = PVSCSI_REQ_RING_PAGES;
    cmd.cmp_ring_num_pages = PVSCSI_CMP_RING_PAGES;
    for (uint32_t i = 0; i < PVSCSI_REQ_RING_PAGES; ++i) {
        cmd.req_ring_ppns[i] = pvscsi_ppn(g_pvscsi_req_pages + i * PVSCSI_PAGE_SIZE);
    }
    for (uint32_t i = 0; i < PVSCSI_CMP_RING_PAGES; ++i) {
        cmd.cmp_ring_ppns[i] = pvscsi_ppn(g_pvscsi_cmp_pages + i * PVSCSI_PAGE_SIZE);
    }
    pvscsi_write_cmd(PVSCSI_CMD_SETUP_RINGS, &cmd, sizeof(cmd));
}

static void pvscsi_setup_msg_ring(void) {
    struct pvscsi_cmd_desc_setup_msg_ring cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.num_pages = PVSCSI_MSG_RING_PAGES;
    for (uint32_t i = 0; i < PVSCSI_MSG_RING_PAGES; ++i) {
        cmd.ring_ppns[i] = pvscsi_ppn(g_pvscsi_msg_pages + i * PVSCSI_PAGE_SIZE);
    }
    pvscsi_write_cmd(PVSCSI_CMD_SETUP_MSG_RING, &cmd, sizeof(cmd));
}

static void pvscsi_kick_io(uint8_t cdb0) {
    struct pvscsi_rings_state *s = g_pvscsi.rings_state;
    if (cdb0 == SCSI_CMD_READ_10 || cdb0 == SCSI_CMD_WRITE_10) {
        if ((s->req_prod_idx - s->req_cons_idx) >= s->req_call_threshold) {
            pvscsi_reg_write(PVSCSI_REG_OFFSET_KICK_RW_IO, 0);
        } else {
            pvscsi_reg_write(PVSCSI_REG_OFFSET_KICK_RW_IO, 0);
        }
    } else {
        pvscsi_reg_write(PVSCSI_REG_OFFSET_KICK_NON_RW_IO, 0);
    }
}

static int pvscsi_completion_success(const struct pvscsi_ring_cmp_desc *cmp, uint32_t expect_context) {
    uint32_t host = cmp->host_status;
    uint32_t scsi = cmp->scsi_status;
    g_pvscsi.last_host_status = host;
    g_pvscsi.last_scsi_status = scsi;
    if ((uint32_t)cmp->context != expect_context) return 0;
    if ((host == BTSTAT_SUCCESS ||
         host == BTSTAT_LINKED_COMMAND_COMPLETED ||
         host == BTSTAT_LINKED_COMMAND_COMPLETED_WITH_FLAG ||
         host == BTSTAT_DATA_UNDERRUN) &&
        scsi == SCSI_STATUS_GOOD) {
        return 1;
    }
    return 0;
}

static int pvscsi_poll_completion(uint32_t context) {
    struct pvscsi_rings_state *s = g_pvscsi.rings_state;
    uint32_t mask = MASK(s->cmp_num_entries_log2);
    uint64_t until = boottime_monotonic_us() + PVSCSI_COMPLETION_TIMEOUT_US;

    while (boottime_monotonic_us() < until) {
        pvscsi_intr_ack_all();
        while (s->cmp_cons_idx != s->cmp_prod_idx) {
            struct pvscsi_ring_cmp_desc *cmp = &g_pvscsi.cmp_ring[s->cmp_cons_idx & mask];
            int ok = pvscsi_completion_success(cmp, context);
            pvscsi_mb();
            s->cmp_cons_idx++;
            if (ok) return 0;
            if ((uint32_t)cmp->context == context) return -1;
        }
        __asm__ __volatile__("pause");
    }
    pvscsi_abort_context(0, context);
    pvscsi_device_reset(0);
    pvscsi_bus_reset();
    return -1;
}

static int pvscsi_submit_scsi(const uint8_t *cdb, uint8_t cdb_len, void *buf,
                              uint32_t bytes, int read) {
    struct pvscsi_rings_state *s = g_pvscsi.rings_state;
    uint32_t req_mask = MASK(s->req_num_entries_log2);
    uint32_t context;
    struct pvscsi_ring_req_desc *req;

    if (!g_pvscsi.rings_ready || !cdb || cdb_len == 0 || cdb_len > 16) return -1;
    if (bytes && !buf) return -1;
    if ((s->req_prod_idx - s->cmp_cons_idx) >= g_pvscsi.queue_depth) return -1;

    context = ++g_pvscsi.next_context;
    if (context == 0) context = ++g_pvscsi.next_context;
    req = &g_pvscsi.req_ring[s->req_prod_idx & req_mask];
    memset(req, 0, sizeof(*req));
    req->context = context;
    req->data_addr = bytes ? pvscsi_phys(buf) : 0;
    req->data_len = bytes;
    req->sense_addr = pvscsi_phys(g_pvscsi.sense);
    req->sense_len = PVSCSI_SENSE_LENGTH;
    req->flags = bytes ? (read ? PVSCSI_FLAG_CMD_DIR_TOHOST : PVSCSI_FLAG_CMD_DIR_TODEVICE)
                       : PVSCSI_FLAG_CMD_DIR_NONE;
    memcpy(req->cdb, cdb, cdb_len);
    req->cdb_len = cdb_len;
    req->lun[1] = 0;
    req->tag = MSG_SIMPLE_Q_TAG;
    req->bus = 0;
    req->target = 0;
    req->vcpu_hint = 0;
    memset(g_pvscsi.sense, 0, PVSCSI_SENSE_LENGTH);

    pvscsi_mb();
    s->req_prod_idx++;
    pvscsi_kick_io(cdb[0]);
    return pvscsi_poll_completion(context);
}

static int pvscsi_test_unit_ready(void) {
    uint8_t cdb[6];
    memset(cdb, 0, sizeof(cdb));
    cdb[0] = SCSI_CMD_TEST_UNIT_READY;
    return pvscsi_submit_scsi(cdb, sizeof(cdb), 0, 0, 0);
}

static int pvscsi_inquiry(void) {
    uint8_t cdb[6];
    uint8_t data[96];
    memset(cdb, 0, sizeof(cdb));
    memset(data, 0, sizeof(data));
    cdb[0] = SCSI_CMD_INQUIRY;
    cdb[4] = sizeof(data);
    if (pvscsi_submit_scsi(cdb, sizeof(cdb), data, sizeof(data), 1) < 0) return -1;
    printf("[pvscsi] target0 inquiry vendor=%c%c%c%c%c%c%c%c product=%c%c%c%c%c%c%c%c\n",
           data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
           data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23]);
    return 0;
}

static int pvscsi_read_capacity16(void) {
    uint8_t cdb[16];
    uint8_t data[32];
    uint64_t last_lba;
    uint32_t block_len;
    memset(cdb, 0, sizeof(cdb));
    memset(data, 0, sizeof(data));
    cdb[0] = SCSI_CMD_SERVICE_ACTION_IN_16;
    cdb[1] = SCSI_SAI_READ_CAPACITY_16;
    put_be32(cdb + 10, sizeof(data));
    if (pvscsi_submit_scsi(cdb, sizeof(cdb), data, sizeof(data), 1) < 0) return -1;
    last_lba = be64(data);
    block_len = be32(data + 8);
    if (last_lba == 0 || block_len == 0 || block_len > 4096u || (block_len & (block_len - 1u)) != 0) return -1;
    if (last_lba + 1ull > 0xFFFFFFFFull) return -1;
    g_pvscsi.sector_size = block_len;
    g_pvscsi.sector_count = (uint32_t)(last_lba + 1ull);
    return 0;
}

static int pvscsi_read_capacity10(void) {
    uint8_t cdb[10];
    uint8_t data[8];
    uint32_t last_lba;
    uint32_t block_len;
    memset(cdb, 0, sizeof(cdb));
    memset(data, 0, sizeof(data));
    cdb[0] = SCSI_CMD_READ_CAPACITY_10;
    if (pvscsi_submit_scsi(cdb, sizeof(cdb), data, sizeof(data), 1) < 0) return -1;
    last_lba = be32(data);
    block_len = be32(data + 4);
    if (last_lba == 0xFFFFFFFFu) return pvscsi_read_capacity16();
    if (block_len == 0 || block_len > 4096u || (block_len & (block_len - 1u)) != 0) return -1;
    g_pvscsi.sector_size = block_len;
    g_pvscsi.sector_count = last_lba + 1u;
    return g_pvscsi.sector_count ? 0 : -1;
}

static int pvscsi_rw10(uint8_t opcode, uint32_t lba, uint32_t count, void *buf) {
    uint8_t cdb[10];
    uint32_t bytes;
    if (!g_pvscsi.present || !buf || count == 0 || count > PVSCSI_MAX_TRANSFER_SECTORS) return -1;
    if (lba + count < lba || lba + count > g_pvscsi.sector_count) return -1;
    bytes = count * g_pvscsi.sector_size;
    memset(cdb, 0, sizeof(cdb));
    cdb[0] = opcode;
    put_be32(cdb + 2, lba);
    put_be16(cdb + 7, (uint16_t)count);
    return pvscsi_submit_scsi(cdb, sizeof(cdb), buf, bytes, opcode == SCSI_CMD_READ_10);
}

static int pvscsi_prepare_rings(void) {
    uint32_t req_entries = (PVSCSI_REQ_RING_PAGES * PVSCSI_PAGE_SIZE) /
                           (uint32_t)sizeof(struct pvscsi_ring_req_desc);
    uint32_t cmp_entries = (PVSCSI_CMP_RING_PAGES * PVSCSI_PAGE_SIZE) /
                           (uint32_t)sizeof(struct pvscsi_ring_cmp_desc);
    if (req_entries > PVSCSI_MAX_QUEUE_DEPTH) req_entries = PVSCSI_MAX_QUEUE_DEPTH;
    if (cmp_entries > PVSCSI_MAX_QUEUE_DEPTH) cmp_entries = PVSCSI_MAX_QUEUE_DEPTH;
    if ((req_entries & (req_entries - 1u)) != 0 || (cmp_entries & (cmp_entries - 1u)) != 0) return -1;

    memset(g_pvscsi_state_page, 0, sizeof(g_pvscsi_state_page));
    memset(g_pvscsi_req_pages, 0, sizeof(g_pvscsi_req_pages));
    memset(g_pvscsi_cmp_pages, 0, sizeof(g_pvscsi_cmp_pages));
    memset(g_pvscsi_msg_pages, 0, sizeof(g_pvscsi_msg_pages));
    memset(g_pvscsi_sense, 0, sizeof(g_pvscsi_sense));

    g_pvscsi.rings_state = (struct pvscsi_rings_state *)g_pvscsi_state_page;
    g_pvscsi.req_ring = (struct pvscsi_ring_req_desc *)g_pvscsi_req_pages;
    g_pvscsi.cmp_ring = (struct pvscsi_ring_cmp_desc *)g_pvscsi_cmp_pages;
    g_pvscsi.msg_ring = (struct pvscsi_ring_msg_desc *)g_pvscsi_msg_pages;
    g_pvscsi.sense = g_pvscsi_sense;
    g_pvscsi.queue_depth = req_entries;
    g_pvscsi.rings_state->req_num_entries_log2 = pvscsi_log2_u32(req_entries);
    g_pvscsi.rings_state->cmp_num_entries_log2 = pvscsi_log2_u32(cmp_entries);
    g_pvscsi.rings_state->msg_num_entries_log2 = pvscsi_log2_u32(PVSCSI_PAGE_SIZE / sizeof(struct pvscsi_ring_msg_desc));
    g_pvscsi.rings_state->req_call_threshold = 1;
    return 0;
}

int pvscsi_init(void) {
    uint8_t bus = 0;
    uint8_t dev = 0;
    uint8_t fn = 0;
    uint64_t mmio = 0;
    uint16_t cmd;
    uint64_t reset_until;

    if (g_pvscsi.present) return 0;
    memset(&g_pvscsi, 0, sizeof(g_pvscsi));
    if (pvscsi_find_pci(&bus, &dev, &fn, &mmio) < 0) return -1;
    if (pvscsi_prepare_rings() < 0) return -1;
    spinlock_init(&g_pvscsi.lock);
    g_pvscsi.bus = bus;
    g_pvscsi.dev = dev;
    g_pvscsi.fn = fn;
    g_pvscsi.mmio = (volatile uint8_t *)edge_mmio_low_alias(mmio);

    cmd = pci_cfg_read16(bus, dev, fn, 0x04);
    cmd |= PCI_COMMAND_MEM | PCI_COMMAND_BUSMASTER;
    pci_cfg_write16(bus, dev, fn, 0x04, cmd);

    pvscsi_intr_disable();
    pvscsi_adapter_reset();
    reset_until = boottime_monotonic_us() + PVSCSI_RESET_TIMEOUT_US;
    while (boottime_monotonic_us() < reset_until) {
        __asm__ __volatile__("pause");
        break;
    }

    g_pvscsi.max_targets = pvscsi_get_max_targets();
    g_pvscsi.use_msg = pvscsi_hw_supports_msg() ? 1 : 0;
    pvscsi_setup_rings();
    if (g_pvscsi.use_msg) pvscsi_setup_msg_ring();
    (void)pvscsi_setup_req_call(1);
    g_pvscsi.rings_ready = 1;

    (void)pvscsi_test_unit_ready();
    if (pvscsi_inquiry() < 0 || pvscsi_read_capacity10() < 0) {
        printf("[pvscsi] device present but target0/lun0 did not identify host=0x%x scsi=0x%x\n",
               g_pvscsi.last_host_status, g_pvscsi.last_scsi_status);
        return -1;
    }

    g_pvscsi.present = 1;
    printf("[pvscsi] ready at %u:%u.%u targets=%u queues=%u sectors=%u sector_size=%u msg=%u\n",
           g_pvscsi.bus, g_pvscsi.dev, g_pvscsi.fn, g_pvscsi.max_targets,
           g_pvscsi.queue_depth, g_pvscsi.sector_count, g_pvscsi.sector_size,
           g_pvscsi.use_msg);
    return 0;
}

int pvscsi_present(void) {
    return g_pvscsi.present ? 1 : 0;
}

uint32_t pvscsi_sector_size(void) {
    return g_pvscsi.sector_size ? g_pvscsi.sector_size : 512u;
}

uint32_t pvscsi_sector_count(void) {
    return g_pvscsi.sector_count;
}

int pvscsi_read(uint32_t lba, uint32_t sector_count, void *buf) {
    uint64_t flags;
    int rc;
    flags = spin_lock_irqsave(&g_pvscsi.lock);
    rc = pvscsi_rw10(SCSI_CMD_READ_10, lba, sector_count, buf);
    spin_unlock_irqrestore(&g_pvscsi.lock, flags);
    return rc;
}

int pvscsi_write(uint32_t lba, uint32_t sector_count, const void *buf) {
    uint64_t flags;
    int rc;
    flags = spin_lock_irqsave(&g_pvscsi.lock);
    rc = pvscsi_rw10(SCSI_CMD_WRITE_10, lba, sector_count, (void *)buf);
    spin_unlock_irqrestore(&g_pvscsi.lock, flags);
    return rc;
}
