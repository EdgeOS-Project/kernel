#include "drivers/nvme.h"
#include "drivers/pci.h"

#ifdef CONFIG_BSD_DRIVER_BRIDGE
#include "compat/freebsd/edgeos/x86_64_handoff.h"
#endif
#include "stdio.h"
#include "string.h"
#include "sys/mmio.h"

#define NVME_PCI_CLASS_MASS_STORAGE 0x01u
#define NVME_PCI_SUBCLASS_NVM       0x08u
#define NVME_PCI_VENDOR_QEMU        0x1B36u
#define NVME_PCI_DEVICE_QEMU_NVME   0x0010u
#define NVME_REG_CAP   0x0000u
#define NVME_REG_VS    0x0008u
#define NVME_REG_CC    0x0014u
#define NVME_REG_CSTS  0x001Cu
#define NVME_REG_AQA   0x0024u
#define NVME_REG_ASQ   0x0028u
#define NVME_REG_ACQ   0x0030u

#define NVME_CC_EN        (1u << 0)
#define NVME_CSTS_RDY     (1u << 0)

#define NVME_ADMIN_OP_DELETE_IOSQ 0x00u
#define NVME_ADMIN_OP_CREATE_IOSQ 0x01u
#define NVME_ADMIN_OP_DELETE_IOCQ 0x04u
#define NVME_ADMIN_OP_CREATE_IOCQ 0x05u
#define NVME_ADMIN_OP_IDENTIFY    0x06u

#define NVME_NVM_OP_WRITE 0x01u
#define NVME_NVM_OP_READ  0x02u

#define NVME_IDENTIFY_CNS_NAMESPACE 0x00u
#define NVME_IDENTIFY_CNS_CONTROLLER 0x01u

#define NVME_ADMIN_Q_DEPTH 16u
#define NVME_IO_Q_DEPTH    32u
#define NVME_PAGE_SIZE     4096u
#define NVME_MAX_PRP_LIST  512u

typedef volatile struct {
    uint64_t cap;
    uint32_t vs;
    uint32_t intms;
    uint32_t intmc;
    uint32_t cc;
    uint32_t rsv0;
    uint32_t csts;
    uint32_t nssr;
    uint32_t aqa;
    uint64_t asq;
    uint64_t acq;
} nvme_bar_t;

typedef struct {
    uint32_t cdw0;
    uint32_t nsid;
    uint64_t rsv0;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} nvme_sqe_t;

typedef struct {
    uint32_t dw0;
    uint32_t rsv0;
    uint16_t sq_head;
    uint16_t sq_id;
    uint16_t cid;
    uint16_t status;
} nvme_cqe_t;

typedef struct {
    uint8_t  opcode;
    uint8_t  flags;
    uint16_t cid;
} nvme_cmd_hdr_t;

typedef struct {
    uint64_t nsze;
    uint64_t ncap;
    uint64_t nuse;
    uint8_t  nsfeat;
    uint8_t  nlbaf;
    uint8_t  flbas;
    uint8_t  mc;
    uint8_t  dpc;
    uint8_t  dps;
    uint8_t  nmic;
    uint8_t  rescap;
    uint8_t  fpi;
    uint8_t  dlfeat;
    uint16_t nawun;
    uint16_t nawupf;
    uint16_t nacwu;
    uint16_t nabsn;
    uint16_t nabo;
    uint16_t nabspf;
    uint16_t noiob;
    uint8_t  rsv0[80];
    struct {
        uint16_t ms;
        uint8_t  lbads;
        uint8_t  rp;
    } lbaf[16];
} __attribute__((packed)) nvme_identify_ns_t;

typedef struct {
    uint8_t  rsv0[77];
    uint8_t  mdts;
    uint8_t  rsv1[438];
    uint32_t nn;
    uint8_t  rsv2[3576];
} __attribute__((packed)) nvme_identify_ctrl_t;

typedef struct {
    uint16_t q_depth;
    uint16_t sq_tail;
    uint16_t cq_head;
    uint8_t  cq_phase;
    nvme_sqe_t *sq;
    nvme_cqe_t *cq;
} nvme_queue_t;

typedef struct {
    int present;
    uint8_t bus;
    uint8_t dev;
    uint8_t fn;
    uint8_t dstrd;
    uint32_t sector_size;
    uint32_t sector_count;
    uint32_t max_transfer_sectors;
    uint32_t nsid;
    nvme_bar_t *bar;
    nvme_queue_t adminq;
    nvme_queue_t ioq;
} nvme_ctrl_t;

static nvme_ctrl_t g_nvme;
static nvme_sqe_t g_admin_sq[NVME_ADMIN_Q_DEPTH] __attribute__((aligned(NVME_PAGE_SIZE)));
static nvme_cqe_t g_admin_cq[NVME_ADMIN_Q_DEPTH] __attribute__((aligned(NVME_PAGE_SIZE)));
static nvme_sqe_t g_io_sq[NVME_IO_Q_DEPTH] __attribute__((aligned(NVME_PAGE_SIZE)));
static nvme_cqe_t g_io_cq[NVME_IO_Q_DEPTH] __attribute__((aligned(NVME_PAGE_SIZE)));
static uint64_t g_prp_list[NVME_MAX_PRP_LIST] __attribute__((aligned(NVME_PAGE_SIZE)));
static nvme_identify_ctrl_t g_id_ctrl __attribute__((aligned(NVME_PAGE_SIZE)));
static nvme_identify_ns_t g_id_ns __attribute__((aligned(NVME_PAGE_SIZE)));
static volatile uint32_t g_submit_busy;

static uint64_t nvme_dma_address(const void *pointer) {
    uintptr_t address = (uintptr_t)pointer;
    if (address >= EDGE_MMIO_LOW_ALIAS_BASE &&
        address < EDGE_MMIO_LOW_ALIAS_BASE + EDGE_MMIO_LOW_ALIAS_SIZE) {
        return (uint64_t)(address - EDGE_MMIO_LOW_ALIAS_BASE);
    }
    return (uint64_t)address;
}

static inline uint32_t nvme_mmio_read32(nvme_ctrl_t *c, uint32_t off) {
    return *(volatile uint32_t *)((volatile uint8_t *)c->bar + off);
}

static inline void nvme_mmio_write32(nvme_ctrl_t *c, uint32_t off, uint32_t v) {
    *(volatile uint32_t *)((volatile uint8_t *)c->bar + off) = v;
}

static inline void nvme_mmio_write64(nvme_ctrl_t *c, uint32_t off, uint64_t v) {
    *(volatile uint64_t *)((volatile uint8_t *)c->bar + off) = v;
}

static uint32_t nvme_doorbell_stride(const nvme_ctrl_t *c) {
    return 4u << c->dstrd;
}

static void nvme_ring_sq_tail(nvme_ctrl_t *c, uint16_t qid, uint16_t tail) {
    uint32_t off = 0x1000u + (2u * (uint32_t)qid) * nvme_doorbell_stride(c);
    __sync_synchronize();
    nvme_mmio_write32(c, off, tail);
}

static void nvme_ring_cq_head(nvme_ctrl_t *c, uint16_t qid, uint16_t head) {
    uint32_t off = 0x1000u + (2u * (uint32_t)qid + 1u) * nvme_doorbell_stride(c);
    __sync_synchronize();
    nvme_mmio_write32(c, off, head);
}

static int nvme_wait_ready(nvme_ctrl_t *c, int want_ready) {
    for (uint32_t i = 0; i < 5000000u; ++i) {
        uint32_t csts = nvme_mmio_read32(c, NVME_REG_CSTS);
        if (((csts & NVME_CSTS_RDY) != 0) == (want_ready != 0)) return 0;
        __asm__ __volatile__("pause");
    }
    return -1;
}

static int nvme_setup_prps(void *buf, uint32_t len, uint64_t *prp1_out, uint64_t *prp2_out) {
    uint64_t address;
    uint32_t first;
    uint32_t remain;
    uint32_t nprps;
    if (!buf || !prp1_out || !prp2_out) return -1;
    address = nvme_dma_address(buf);
    first = NVME_PAGE_SIZE -
            (uint32_t)(address & (NVME_PAGE_SIZE - 1u));
    *prp1_out = address;
    *prp2_out = 0;
    if (len <= first) return 0;
    remain = len - first;
    if (remain <= NVME_PAGE_SIZE) {
        *prp2_out = address + first;
        return 0;
    }
    nprps = (remain + NVME_PAGE_SIZE - 1u) / NVME_PAGE_SIZE;
    if (nprps > NVME_MAX_PRP_LIST) return -1;
    for (uint32_t i = 0; i < nprps; ++i) {
        g_prp_list[i] = address + first + (uint64_t)i * NVME_PAGE_SIZE;
    }
    *prp2_out = nvme_dma_address(g_prp_list);
    return 0;
}

static void nvme_wait_relax(uint32_t spins) {
    /*
     * NVMe is currently driven by synchronous polling.  Keep this helper to a
     * CPU pause only: calling into the scheduler from this low-level MMIO wait
     * path can strand early userspace during OpenRC boot, before the process
     * model is tolerant of arbitrary reschedules from block driver internals.
     */
    (void)spins;
    __asm__ __volatile__("pause");
}

static int nvme_submit_acquire(void) {
    for (uint32_t spins = 0; spins < 5000000u; ++spins) {
        if (__sync_bool_compare_and_swap(&g_submit_busy, 0u, 1u)) return 0;
        nvme_wait_relax(spins);
    }
    return -1;
}

static void nvme_submit_release(void) {
    __sync_synchronize();
    g_submit_busy = 0;
}

static int nvme_submit_sync_locked(nvme_ctrl_t *c, nvme_queue_t *q,
                                   uint16_t qid, nvme_sqe_t *sqe) {
    uint16_t cid;
    nvme_cqe_t *cqe;
    uint16_t status;
    int rc = -1;
    if (!c || !q || !sqe || q->q_depth == 0) return -1;
    cid = q->sq_tail;
    ((nvme_cmd_hdr_t *)sqe)->cid = cid;
    memcpy(&q->sq[q->sq_tail], sqe, sizeof(*sqe));
    q->sq_tail++;
    if (q->sq_tail >= q->q_depth) q->sq_tail = 0;
    nvme_ring_sq_tail(c, qid, q->sq_tail);

    for (uint32_t spins = 0; spins < 5000000u; ++spins) {
        cqe = &q->cq[q->cq_head];
        if ((cqe->status & 1u) != q->cq_phase) {
            nvme_wait_relax(spins);
            continue;
        }
        if (cqe->cid != cid) goto out;
        status = (uint16_t)(cqe->status >> 1);
        q->cq_head++;
        if (q->cq_head >= q->q_depth) {
            q->cq_head = 0;
            q->cq_phase ^= 1u;
        }
        nvme_ring_cq_head(c, qid, q->cq_head);
        rc = status == 0 ? 0 : -1;
        goto out;
    }
out:
    return rc;
}

static int nvme_submit_sync(nvme_ctrl_t *c, nvme_queue_t *q, uint16_t qid,
                            nvme_sqe_t *sqe) {
    int result;
    if (nvme_submit_acquire() < 0) return -1;
    result = nvme_submit_sync_locked(c, q, qid, sqe);
    nvme_submit_release();
    return result;
}

static int nvme_identify(nvme_ctrl_t *c, uint32_t nsid, uint8_t cns, void *buf, uint32_t len) {
    nvme_sqe_t sqe;
    uint64_t prp1 = 0, prp2 = 0;
    int result;
    if (nvme_submit_acquire() < 0) return -1;
    if (nvme_setup_prps(buf, len, &prp1, &prp2) < 0) {
        nvme_submit_release();
        return -1;
    }
    memset(&sqe, 0, sizeof(sqe));
    ((nvme_cmd_hdr_t *)&sqe)->opcode = NVME_ADMIN_OP_IDENTIFY;
    sqe.nsid = nsid;
    sqe.prp1 = prp1;
    sqe.prp2 = prp2;
    sqe.cdw10 = (uint32_t)cns;
    result = nvme_submit_sync_locked(c, &c->adminq, 0, &sqe);
    nvme_submit_release();
    return result;
}

static int nvme_create_io_cq(nvme_ctrl_t *c, uint16_t qid, uint16_t q_depth, nvme_cqe_t *cq) {
    nvme_sqe_t sqe;
    memset(&sqe, 0, sizeof(sqe));
    ((nvme_cmd_hdr_t *)&sqe)->opcode = NVME_ADMIN_OP_CREATE_IOCQ;
    sqe.prp1 = nvme_dma_address(cq);
    sqe.cdw10 = (uint32_t)qid | ((uint32_t)(q_depth - 1u) << 16);
    sqe.cdw11 = 1u;
    return nvme_submit_sync(c, &c->adminq, 0, &sqe);
}

static int nvme_create_io_sq(nvme_ctrl_t *c, uint16_t qid, uint16_t q_depth, nvme_sqe_t *sq) {
    nvme_sqe_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    ((nvme_cmd_hdr_t *)&cmd)->opcode = NVME_ADMIN_OP_CREATE_IOSQ;
    cmd.prp1 = nvme_dma_address(sq);
    cmd.cdw10 = (uint32_t)qid | ((uint32_t)(q_depth - 1u) << 16);
    cmd.cdw11 = 1u | ((uint32_t)qid << 16);
    return nvme_submit_sync(c, &c->adminq, 0, &cmd);
}

static int nvme_rw(int write, uint32_t lba, uint32_t sector_count, void *buf) {
    nvme_sqe_t sqe;
    uint64_t byte_len;
    uint64_t prp1 = 0, prp2 = 0;
    int result;
    if (!g_nvme.present || !buf || sector_count == 0 ||
        g_nvme.sector_size == 0 ||
        sector_count > g_nvme.max_transfer_sectors) return -1;
    byte_len = (uint64_t)sector_count * (uint64_t)g_nvme.sector_size;
    if (byte_len > 0xFFFFFFFFu) return -1;
    if (nvme_submit_acquire() < 0) return -1;
    if (nvme_setup_prps(buf, (uint32_t)byte_len, &prp1, &prp2) < 0) {
        nvme_submit_release();
        return -1;
    }
    memset(&sqe, 0, sizeof(sqe));
    ((nvme_cmd_hdr_t *)&sqe)->opcode = write ? NVME_NVM_OP_WRITE : NVME_NVM_OP_READ;
    sqe.nsid = g_nvme.nsid;
    sqe.prp1 = prp1;
    sqe.prp2 = prp2;
    sqe.cdw10 = lba;
    sqe.cdw11 = 0;
    sqe.cdw12 = (sector_count - 1u) & 0xFFFFu;
    result = nvme_submit_sync_locked(&g_nvme, &g_nvme.ioq, 1, &sqe);
    nvme_submit_release();
    return result;
}

int nvme_present(void) {
    return g_nvme.present;
}

uint32_t nvme_sector_size(void) {
    return g_nvme.present ? g_nvme.sector_size : 0;
}

uint32_t nvme_sector_count(void) {
    return g_nvme.present ? g_nvme.sector_count : 0;
}

uint32_t nvme_max_transfer_sectors(void) {
    return g_nvme.present ? g_nvme.max_transfer_sectors : 0;
}

int nvme_read(uint32_t lba, uint32_t sector_count, void *buf) {
    return nvme_rw(0, lba, sector_count, buf);
}

int nvme_write(uint32_t lba, uint32_t sector_count, const void *buf) {
    return nvme_rw(1, lba, sector_count, (void *)buf);
}

int nvme_init(void) {
    uint8_t bus, dev, fn;
    uint8_t found_bus = 0, found_dev = 0, found_fn = 0;
    uint64_t mmio_base = 0;
    uintptr_t mmio_va = 0;
    uint32_t bar0 = 0, bar1 = 0;
    uint16_t cmd;
    uint64_t cap;
    uint32_t cc;
    uint32_t flbas;
    uint32_t lbaf;
    uint8_t lba_index;
    uint8_t lbads;
    uint32_t nsid = 0;
    uint32_t nn = 0;
    int found = 0;

    memset(&g_nvme, 0, sizeof(g_nvme));
    printf("[nvme] probing PCI for NVMe controller\n");

    for (bus = 0; bus < 255 && !found; ++bus) {
        for (dev = 0; dev < 32 && !found; ++dev) {
            for (fn = 0; fn < 8; ++fn) {
                uint16_t ven = pci_cfg_read16(bus, dev, fn, 0x00);
                uint16_t did;
                uint8_t cls;
                uint8_t sub;
                if (ven == 0xFFFFu) {
                    if (fn == 0) break;
                    continue;
                }
                did = pci_cfg_read16(bus, dev, fn, 0x02);
                cls = pci_cfg_read8(bus, dev, fn, 0x0B);
                sub = pci_cfg_read8(bus, dev, fn, 0x0A);
                if (!(cls == NVME_PCI_CLASS_MASS_STORAGE && sub == NVME_PCI_SUBCLASS_NVM) &&
                    !(ven == NVME_PCI_VENDOR_QEMU && did == NVME_PCI_DEVICE_QEMU_NVME)) {
                    continue;
                }
#ifdef CONFIG_BSD_DRIVER_BRIDGE
                if (bsd_bridge_x86_64_native_pci_reserved(bus, dev, fn))
                    continue;
#endif
                found_bus = bus;
                found_dev = dev;
                found_fn = fn;
                found = 1;
                break;
            }
        }
    }

    if (!found) {
        printf("[nvme] no supported controller found on PCI bus\n");
        return -1;
    }

    printf("[nvme] found candidate controller at %u:%u.%u\n",
           (unsigned)found_bus, (unsigned)found_dev, (unsigned)found_fn);

    bar0 = pci_cfg_read32(found_bus, found_dev, found_fn, 0x10);
    bar1 = pci_cfg_read32(found_bus, found_dev, found_fn, 0x14);
    if ((bar0 & 1u) != 0u) {
        printf("[nvme] BAR0 is not MMIO\n");
        return -1;
    }
    if ((bar0 & 0x6u) == 0x4u) mmio_base = ((uint64_t)bar1 << 32) | (uint64_t)(bar0 & ~0xFULL);
    else mmio_base = (uint64_t)(bar0 & ~0xFULL);
    if (mmio_base == 0 || mmio_base >= 0x0000800000000000ULL) {
        printf("[nvme] unsupported MMIO BAR hi=0x%x lo=0x%x\n",
               (uint32_t)(mmio_base >> 32), (uint32_t)mmio_base);
        return -1;
    }

    if (!edge_mmio_phys_range_mapped(mmio_base, 0x4000ULL)) {
        /*
         * Never dereference a BAR unless the architecture page tables cover
         * its complete register aperture.  This accepts both the low linear
         * alias and the supervisor-only high PCI window used by OVMF.
         */
        printf("[nvme] MMIO BAR 0x%llx is outside mapped MMIO apertures; skipping controller\n",
               (unsigned long long)mmio_base);
        return -1;
    }
    mmio_va = edge_mmio_low_alias(mmio_base);

    printf("[nvme] using MMIO BAR 0x%llx kva=0x%llx\n",
           (unsigned long long)mmio_base, (unsigned long long)mmio_va);

    cmd = pci_cfg_read16(found_bus, found_dev, found_fn, 0x04);
    cmd |= 0x0002u;
    cmd |= 0x0004u;
    pci_cfg_write16(found_bus, found_dev, found_fn, 0x04, cmd);

    g_nvme.bus = found_bus;
    g_nvme.dev = found_dev;
    g_nvme.fn = found_fn;
    g_nvme.bar = (nvme_bar_t *)mmio_va;
    cap = g_nvme.bar->cap;
    g_nvme.dstrd = (uint8_t)((cap >> 32) & 0x0Fu);
    printf("[nvme] CAP=0x%llx DSTRD=%u VS=0x%x\n",
           (unsigned long long)cap,
           (unsigned)g_nvme.dstrd,
           (unsigned)g_nvme.bar->vs);

    nvme_mmio_write32(&g_nvme, NVME_REG_CC, 0);
    if (nvme_wait_ready(&g_nvme, 0) < 0) {
        printf("[nvme] controller did not become disabled\n");
        return -1;
    }

    memset(g_admin_sq, 0, sizeof(g_admin_sq));
    memset(g_admin_cq, 0, sizeof(g_admin_cq));
    g_nvme.adminq.q_depth = NVME_ADMIN_Q_DEPTH;
    g_nvme.adminq.sq = g_admin_sq;
    g_nvme.adminq.cq = g_admin_cq;
    g_nvme.adminq.cq_phase = 1;

    nvme_mmio_write32(&g_nvme, NVME_REG_AQA,
                      ((NVME_ADMIN_Q_DEPTH - 1u) << 16) | (NVME_ADMIN_Q_DEPTH - 1u));
    nvme_mmio_write64(&g_nvme, NVME_REG_ASQ,
                      nvme_dma_address(g_admin_sq));
    nvme_mmio_write64(&g_nvme, NVME_REG_ACQ,
                      nvme_dma_address(g_admin_cq));
    cc = (6u << 16) | (4u << 20) | NVME_CC_EN;
    nvme_mmio_write32(&g_nvme, NVME_REG_CC, cc);
    if (nvme_wait_ready(&g_nvme, 1) < 0) {
        printf("[nvme] controller did not become ready\n");
        return -1;
    }
    printf("[nvme] controller ready\n");

    if (nvme_identify(&g_nvme, 0, NVME_IDENTIFY_CNS_CONTROLLER, &g_id_ctrl, sizeof(g_id_ctrl)) < 0) {
        printf("[nvme] identify controller failed\n");
        return -1;
    }
    nn = g_id_ctrl.nn;
    printf("[nvme] controller reports %u namespace(s)\n", (unsigned)nn);
    if (nn == 0) nn = 1;
    if (nn > 16) nn = 16;
    for (uint32_t i = 1; i <= nn; ++i) {
        if (nvme_identify(&g_nvme, i, NVME_IDENTIFY_CNS_NAMESPACE, &g_id_ns, sizeof(g_id_ns)) < 0) {
            printf("[nvme] identify namespace probe %u failed\n", (unsigned)i);
            continue;
        }
        printf("[nvme] namespace %u size=%llu flbas=0x%x\n",
               (unsigned)i,
               (unsigned long long)g_id_ns.nsze,
               (unsigned)g_id_ns.flbas);
        if (g_id_ns.nsze == 0) continue;
        nsid = i;
        break;
    }
    if (nsid == 0) {
        printf("[nvme] no active namespace found\n");
        return -1;
    }

    memset(g_io_sq, 0, sizeof(g_io_sq));
    memset(g_io_cq, 0, sizeof(g_io_cq));
    g_nvme.ioq.q_depth = NVME_IO_Q_DEPTH;
    g_nvme.ioq.sq = g_io_sq;
    g_nvme.ioq.cq = g_io_cq;
    g_nvme.ioq.cq_phase = 1;

    (void)nvme_submit_sync; /* keep compiler quiet if optimized oddly */
    if (nvme_create_io_cq(&g_nvme, 1, NVME_IO_Q_DEPTH, g_io_cq) < 0) {
        printf("[nvme] create I/O completion queue failed\n");
        return -1;
    }
    if (nvme_create_io_sq(&g_nvme, 1, NVME_IO_Q_DEPTH, g_io_sq) < 0) {
        printf("[nvme] create I/O submission queue failed\n");
        return -1;
    }
    printf("[nvme] I/O queues ready\n");

    if (nvme_identify(&g_nvme, nsid, NVME_IDENTIFY_CNS_NAMESPACE, &g_id_ns, sizeof(g_id_ns)) < 0) {
        printf("[nvme] identify namespace %u failed\n", nsid);
        return -1;
    }
    flbas = g_id_ns.flbas;
    lba_index = (uint8_t)(flbas & 0x0Fu);
    if (lba_index >= 16) {
        printf("[nvme] invalid FLBAS index %u\n", (unsigned)lba_index);
        return -1;
    }
    lbaf = (uint32_t)g_id_ns.lbaf[lba_index].ms;
    if (lbaf != 0) {
        printf("[nvme] unsupported metadata size %u for LBA format %u\n",
               (unsigned)lbaf, (unsigned)lba_index);
        return -1;
    }
    lbads = g_id_ns.lbaf[lba_index].lbads;
    if (lbads < 9 || lbads > 12) {
        printf("[nvme] unsupported LBA data size shift %u\n", (unsigned)lbads);
        return -1;
    }

    g_nvme.nsid = nsid;
    g_nvme.sector_size = 1u << lbads;
    if (g_nvme.sector_size == 0) {
        printf("[nvme] computed sector size overflow\n");
        return -1;
    }
    if (g_id_ns.nsze == 0) {
        printf("[nvme] namespace %u has zero size\n", (unsigned)nsid);
        return -1;
    }
    if (g_id_ns.nsze > 0xFFFFFFFFull) g_nvme.sector_count = 0xFFFFFFFFu;
    else g_nvme.sector_count = (uint32_t)g_id_ns.nsze;
    {
        uint64_t prp_limit =
            (uint64_t)NVME_MAX_PRP_LIST * NVME_PAGE_SIZE;
        uint64_t controller_limit = UINT64_MAX;
        uint32_t mpsmin = (uint32_t)((cap >> 48) & 0x0fu);
        if (g_id_ctrl.mdts != 0) {
            uint32_t shift = 12u + mpsmin + g_id_ctrl.mdts;
            controller_limit = shift < 63u ? (1ull << shift) : UINT64_MAX;
        }
        if (controller_limit < prp_limit) prp_limit = controller_limit;
        g_nvme.max_transfer_sectors =
            (uint32_t)(prp_limit / g_nvme.sector_size);
        if (!g_nvme.max_transfer_sectors)
            g_nvme.max_transfer_sectors = 1;
        if (g_nvme.max_transfer_sectors > 65536u)
            g_nvme.max_transfer_sectors = 65536u;
    }
    g_nvme.present = 1;

    printf("[nvme] namespace %u selected: sector_size=%u sectors=%u mdts=%u max_transfer_sectors=%u\n",
           (unsigned)nsid,
           (unsigned)g_nvme.sector_size,
           (unsigned)g_nvme.sector_count,
           (unsigned)g_id_ctrl.mdts,
           (unsigned)g_nvme.max_transfer_sectors);

    printf("[nvme] controller %u:%u.%u nsid=%u lba_size=%u sectors=%u version=%u.%u\n",
           found_bus, found_dev, found_fn,
           g_nvme.nsid, g_nvme.sector_size, g_nvme.sector_count,
           (unsigned)((g_nvme.bar->vs >> 16) & 0xFFFFu),
           (unsigned)((g_nvme.bar->vs >> 8) & 0xFFu));
    return 0;
}
