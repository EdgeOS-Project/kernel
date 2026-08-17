#include "drivers/xhci.h"
#include "drivers/xhci_capability.h"
#include "drivers/xhci_device_policy.h"
#include "drivers/xhci_transfer.h"
#include "drivers/pci.h"
#include "drivers/audio.h"
#include "drivers/usb.h"
#include "dev/uvc.h"
#include "kernel/input_device.h"
#include "stdio.h"
#include "string.h"
#include "sys/boottime.h"
#include "sys/mmio.h"

#define XHCI_USBCMD 0x00u
#define XHCI_USBSTS 0x04u
#define XHCI_PAGESIZE 0x08u
#define XHCI_DNCTRL 0x14u
#define XHCI_CRCR 0x18u
#define XHCI_DCBAAP 0x30u
#define XHCI_CONFIG 0x38u
#define XHCI_PORTSC_BASE 0x400u
#define XHCI_PORTSC_STRIDE 0x10u

#define XHCI_CMD_RUN   (1u << 0)
#define XHCI_CMD_HCRST (1u << 1)
#define XHCI_CMD_INTE  (1u << 2)
#define XHCI_STS_HCH   (1u << 0)
#define XHCI_STS_EINT  (1u << 3)
#define XHCI_STS_CNR   (1u << 11)

#define XHCI_PORTSC_CCS          (1u << 0)
#define XHCI_PORTSC_PED          (1u << 1)
#define XHCI_PORTSC_PR           (1u << 4)
#define XHCI_PORTSC_PP           (1u << 9)
#define XHCI_PORTSC_SPEED_SHIFT  10u
#define XHCI_PORTSC_SPEED_MASK   0xFu
#define XHCI_PORTSC_CSC          (1u << 17)
#define XHCI_PORTSC_PRC          (1u << 21)
#define XHCI_PORTSC_RW1C (XHCI_PORTSC_CSC | (1u << 18) | (1u << 19) | (1u << 20) | XHCI_PORTSC_PRC | (1u << 22) | (1u << 23))

#define XHCI_CAP_DBOFF  0x14u
#define XHCI_CAP_RTSOFF 0x18u
#define XHCI_CAP_HCSPARAMS2 0x08u

#define XHCI_INTR_BASE 0x20u
#define XHCI_IMAN   0x00u
#define XHCI_ERSTSZ 0x08u
#define XHCI_ERSTBA 0x10u
#define XHCI_ERDP   0x18u
#define XHCI_IMAN_IP (1u << 0)
#define XHCI_IMAN_IE (1u << 1)
#define XHCI_PORT_RESCAN_INTERVAL 256u
#define XHCI_TRB_CYCLE 1u
#define XHCI_TRB_TC    (1u << 1)
#define XHCI_TRB_ISP   (1u << 2)
#define XHCI_TRB_IOC   (1u << 5)

#define XHCI_TRB_TYPE_NORMAL            1u
#define XHCI_TRB_TYPE_ISOCH             5u
#define XHCI_TRB_TYPE_LINK              6u
#define XHCI_TRB_TYPE_ENABLE_SLOT       9u
#define XHCI_TRB_TYPE_DISABLE_SLOT     10u
#define XHCI_TRB_TYPE_ADDRESS_DEVICE   11u
#define XHCI_TRB_TYPE_CONFIGURE_EP     12u
#define XHCI_TRB_TYPE_EVALUATE_CONTEXT 13u
#define XHCI_TRB_TYPE_TRANSFER_EVENT   32u
#define XHCI_TRB_TYPE_CMD_COMPLETION   33u
#define XHCI_TRB_TYPE_PORTSC_EVENT     34u

#define XHCI_COMP_SUCCESS 1u
#define XHCI_COMP_SHORT_PACKET 13u
#define XHCI_EP_TYPE_CONTROL 4u
#define XHCI_EP_TYPE_ISOCH_OUT 1u
#define XHCI_EP_TYPE_BULK_OUT 2u
#define XHCI_EP_TYPE_BULK_IN 6u
#define XHCI_EP_TYPE_INTERRUPT_IN 7u
#define XHCI_CONTROLLER_TIMEOUT_US 1250000ull
#define XHCI_LEGACY_HANDOFF_TIMEOUT_US 1000000ull
#define XHCI_PORT_POWER_SETTLE_US 20000ull
#define XHCI_PORT_RESET_TIMEOUT_US 200000ull
#define XHCI_RESET_RECOVERY_US 50000ull
#define XHCI_INITIAL_PORT_DISCOVERY_US 100000ull
#define XHCI_TRANSFER_TIMEOUT_US 1000000ull
#define XHCI_COMMAND_TIMEOUT_US 1000000ull
#define XHCI_ADDRESS_SETTLE_US 2000ull
#define XHCI_MASS_RETRY_US 50000ull
#define XHCI_RING_BOUNDARY 65536u

#define USB_REQ_GET_DESCRIPTOR 6u
#define USB_REQ_SET_CONFIGURATION 9u
#define USB_REQ_SET_INTERFACE 11u
#define USB_REQ_SET_IDLE 10u
#define USB_DT_DEVICE 1u
#define USB_DT_CONFIG 2u
#define USB_DT_HID 0x21u
#define USB_DT_HID_REPORT 0x22u
#define USB_CLASS_AUDIO 1u
#define USB_AUDIO_SUBCLASS_CONTROL 1u
#define USB_AUDIO_SUBCLASS_STREAMING 2u
#define USB_DT_CS_INTERFACE 0x24u
#define USB_AS_GENERAL 1u
#define USB_AS_FORMAT_TYPE 2u
#define USB_AUDIO_FORMAT_TYPE_I 1u
#define USB_CLASS_HID 3u
#define USB_CLASS_MASS_STORAGE 8u
#define USB_CLASS_HUB 9u
#define USB_CLASS_VIDEO 0x0Eu
#define USB_VIDEO_SUBCLASS_CONTROL 1u
#define USB_VIDEO_SUBCLASS_STREAMING 2u
#define USB_CLASS_VENDOR 0xFFu

#define USBNET_DRIVER_NONE 0u
#define USBNET_DRIVER_AX88179 1u
#define USBNET_DRIVER_RTL8153 2u

#define USB_VENDOR_ASIX 0x0b95u
#define USB_PRODUCT_ASIX_AX88179 0x1790u
#define USB_VENDOR_REALTEK 0x0bdau
#define USB_PRODUCT_REALTEK_RTL8053 0x8053u
#define USB_PRODUCT_REALTEK_RTL8153 0x8153u
#define USB_VENDOR_LENOVO 0x17efu
#define USB_PRODUCT_LENOVO_RTL8153 0x7205u
#define USB_PRODUCT_LENOVO_RTL8153_04 0x720cu
#define USB_MSC_SUBCLASS_SCSI 0x06u
#define USB_MSC_PROTO_BULK_ONLY 0x50u
#define USB_MSC_CBW_SIG 0x43425355u
#define USB_MSC_CSW_SIG 0x53425355u
#define USB_MSC_DATA_OUT 0x00u
#define USB_MSC_DATA_IN 0x80u
#define USB_MSC_CDB_MAX 16u
#define USB_MSC_MAX_DMA_BYTES (64u * 1024u)
#define USB_MSC_PROGRESS_BYTES (16ull * 1024ull * 1024ull)

#define SCSI_TEST_UNIT_READY 0x00u
#define SCSI_INQUIRY 0x12u
#define SCSI_READ_CAPACITY_10 0x25u
#define SCSI_READ_10 0x28u
#define SCSI_WRITE_10 0x2Au

#define USB_QEMU_VENDOR_ID 0x0627u

#define XHCI_DEVICE_CONFIGURED 0
#define XHCI_DEVICE_UNSUPPORTED 1

typedef struct __attribute__((packed)) {
    uint32_t signature;
    uint32_t tag;
    uint32_t data_len;
    uint8_t flags;
    uint8_t lun;
    uint8_t cdb_len;
    uint8_t cdb[USB_MSC_CDB_MAX];
} usb_msc_cbw_t;

typedef struct __attribute__((packed)) {
    uint32_t signature;
    uint32_t tag;
    uint32_t residue;
    uint8_t status;
} usb_msc_csw_t;

typedef struct __attribute__((packed)) {
    uint32_t lo;
    uint32_t hi;
    uint32_t status;
    uint32_t control;
} xhci_trb_t;

typedef struct __attribute__((packed)) {
    uint32_t seg_lo;
    uint32_t seg_hi;
    uint32_t seg_size;
    uint32_t rsvd;
} xhci_erst_ent_t;

typedef struct __attribute__((packed)) {
    uint8_t bmRequestType;
    uint8_t bRequest;
    uint16_t wValue;
    uint16_t wIndex;
    uint16_t wLength;
} usb_setup_pkt_t;

typedef struct __attribute__((packed)) {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint16_t bcdUSB;
    uint8_t bDeviceClass;
    uint8_t bDeviceSubClass;
    uint8_t bDeviceProtocol;
    uint8_t bMaxPacketSize0;
    uint16_t idVendor;
    uint16_t idProduct;
    uint16_t bcdDevice;
    uint8_t iManufacturer;
    uint8_t iProduct;
    uint8_t iSerialNumber;
    uint8_t bNumConfigurations;
} usb_dev_desc_t;

typedef struct __attribute__((packed)) {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint16_t wTotalLength;
    uint8_t bNumInterfaces;
    uint8_t bConfigurationValue;
    uint8_t iConfiguration;
    uint8_t bmAttributes;
    uint8_t bMaxPower;
} usb_cfg_desc_t;

typedef struct __attribute__((packed)) {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint8_t bInterfaceNumber;
    uint8_t bAlternateSetting;
    uint8_t bNumEndpoints;
    uint8_t bInterfaceClass;
    uint8_t bInterfaceSubClass;
    uint8_t bInterfaceProtocol;
    uint8_t iInterface;
} usb_if_desc_t;

typedef struct __attribute__((packed)) {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint8_t bEndpointAddress;
    uint8_t bmAttributes;
    uint16_t wMaxPacketSize;
    uint8_t bInterval;
} usb_ep_desc_t;

static int xhci_enumerate_root_port(xhci_controller_t *xc, uint8_t port_id);
static uint32_t g_xhci_msc_tag = 1;
#ifdef CONFIG_USB_AUDIO
static xhci_controller_t *g_uac_xc;
static xhci_slot_state_t *g_uac_slot;
static uint8_t g_uac_pcm_buf[1024];
static uint16_t g_uac_pcm_len;
#endif

static uint32_t xhci_be32_get(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void xhci_be16_put(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void xhci_be32_put(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint16_t xhci_ep_mps(uint16_t raw, uint16_t fallback) {
    uint16_t mps = (uint16_t)(raw & 0x07FFu);
    if (mps == 0) mps = fallback;
    if (mps > 1024u) mps = 1024u;
    return mps;
}

static inline uint8_t mmio_read8(volatile uint8_t *base, uint32_t off) {
    return *(volatile uint8_t *)(base + off);
}

static inline uint32_t mmio_read32(volatile uint8_t *base, uint32_t off) {
    uint32_t value;
    volatile uint32_t *reg = (volatile uint32_t *)(base + off);
    /* xHCI registers require naturally aligned 32-bit transactions.  A plain
     * volatile C load can be narrowed by GCC when the caller only inspects a
     * low status bit, which turns PORTSC reads into unsupported byte accesses.
     */
    __asm__ __volatile__("movl %1, %0"
                         : "=r"(value)
                         : "m"(*reg)
                         : "memory");
    return value;
}

static inline void mmio_write32(volatile uint8_t *base, uint32_t off, uint32_t v) {
    volatile uint32_t *reg = (volatile uint32_t *)(base + off);
    __asm__ __volatile__("movl %1, %0"
                         : "=m"(*reg)
                         : "r"(v)
                         : "memory");
}

static inline uint64_t mmio_read64(volatile uint8_t *base, uint32_t off) {
    uint64_t lo = (uint64_t)mmio_read32(base, off);
    uint64_t hi = (uint64_t)mmio_read32(base, off + 4u);
    return lo | (hi << 32);
}

static inline void mmio_write64(volatile uint8_t *base, uint32_t off, uint64_t v) {
    mmio_write32(base, off, (uint32_t)(v & 0xFFFFFFFFu));
    mmio_write32(base, off + 4u, (uint32_t)(v >> 32));
}

static uint32_t xhci_portsc_neutral(uint32_t status) {
    /*
     * PORTSC mixes read-only status, RW1C change flags, RW1S reset controls,
     * and writable link/power fields.  Echoing a sampled register value can
     * disable an enabled port through PED or restart reset through PR.  Keep
     * only the stable power state and add each command/change bit explicitly.
     */
    return status & XHCI_PORTSC_PP;
}

static void xhci_portsc_clear_changes(xhci_controller_t *xc, uint32_t off,
                                      uint32_t status) {
    uint32_t changes = status & XHCI_PORTSC_RW1C;
    if (!xc || !xc->op || changes == 0) return;
    mmio_write32(xc->op, off,
                 xhci_portsc_neutral(status) | changes);
}

static void xhci_wait_relax(void) {
    uint64_t flags;
    __asm__ __volatile__("pushfq; popq %0" : "=r"(flags));
    if (flags & (1ull << 9))
        __asm__ __volatile__("hlt" ::: "memory");
    else
        __asm__ __volatile__("pause");
}

static int xhci_wait_u32(volatile uint8_t *base, uint32_t off, uint32_t mask,
                         uint32_t want_set, uint64_t timeout_us) {
    uint64_t start_us = boottime_monotonic_us();
    for (;;) {
        uint32_t v = mmio_read32(base, off);
        if (((v & mask) != 0) == (want_set != 0)) return 0;
        if (boottime_monotonic_us() - start_us >= timeout_us) {
            v = mmio_read32(base, off);
            return (((v & mask) != 0) == (want_set != 0)) ? 0 : -1;
        }
        xhci_wait_relax();
    }
}

static void xhci_wait_us(uint64_t duration_us) {
    uint64_t start_us = boottime_monotonic_us();
    while (boottime_monotonic_us() - start_us < duration_us)
        xhci_wait_relax();
}

static uint32_t xhci_ctx_bytes(const xhci_controller_t *xc) {
    return (xc && xc->ctx_sz64) ? 64u : 32u;
}

static uint8_t xhci_port_speed(const xhci_controller_t *xc, uint8_t port_id) {
    uint32_t off;
    uint32_t psc;
    if (!xc || !xc->op || port_id == 0 || port_id > xc->max_ports) return 0;
    off = XHCI_PORTSC_BASE + (uint32_t)(port_id - 1u) * XHCI_PORTSC_STRIDE;
    psc = mmio_read32(xc->op, off);
    return (uint8_t)((psc >> XHCI_PORTSC_SPEED_SHIFT) & XHCI_PORTSC_SPEED_MASK);
}

static int xhci_root_port_connected(const xhci_controller_t *xc) {
    if (!xc || !xc->op) return 0;
    for (uint8_t port = 0; port < xc->max_ports; ++port) {
        uint32_t off = XHCI_PORTSC_BASE +
                       (uint32_t)port * XHCI_PORTSC_STRIDE;
        if (mmio_read32(xc->op, off) & XHCI_PORTSC_CCS) return 1;
    }
    return 0;
}

static void xhci_wait_for_initial_ports(xhci_controller_t *xc) {
    uint64_t start_us;
    if (!xc || !xc->op || xhci_root_port_connected(xc)) return;
    start_us = boottime_monotonic_us();
    while (boottime_monotonic_us() - start_us <
           XHCI_INITIAL_PORT_DISCOVERY_US) {
        xhci_wait_relax();
        if (xhci_root_port_connected(xc)) return;
    }
}

static uint16_t xhci_default_ep0_mps(uint8_t speed_id) {
    if (speed_id >= 4u) return 512u;
    if (speed_id == 3u) return 64u;
    return 8u;
}

static uint8_t xhci_interval_from_binterval(uint8_t speed_id, uint8_t bInterval) {
    uint8_t v;
    uint8_t p;
    if (bInterval == 0) bInterval = 1;
    if (speed_id >= 3u) {
        v = (uint8_t)(bInterval - 1u);
        if (v > 15u) v = 15u;
        return v;
    }
    p = 1u;
    v = 0u;
    while (p < bInterval && v < 15u) {
        p <<= 1;
        v++;
    }
    if (v < 3u) v = 3u;
    return v;
}

static void xhci_ring_init(usb_dma_block_t *ring, uint8_t *enq, uint8_t *ccs) {
    xhci_trb_t *trbs;
    uint32_t n;
    if (!ring || !ring->vaddr || ring->size < sizeof(xhci_trb_t) * 2u) return;
    trbs = (xhci_trb_t *)ring->vaddr;
    n = ring->size / sizeof(xhci_trb_t);
    memset(trbs, 0, ring->size);
    trbs[n - 1u].lo = ring->paddr;
    trbs[n - 1u].hi = 0;
    trbs[n - 1u].status = 0;
    trbs[n - 1u].control = ((uint32_t)XHCI_TRB_TYPE_LINK << 10) | XHCI_TRB_TC | XHCI_TRB_CYCLE;
    if (enq) *enq = 0;
    if (ccs) *ccs = 1;
}

static uint64_t xhci_ring_enqueue(usb_dma_block_t *ring, uint8_t *enq, uint8_t *ccs,
                                  uint32_t lo, uint32_t hi, uint32_t st, uint32_t ctrl) {
    xhci_trb_t *trbs;
    uint32_t n, idx;
    uint64_t phys;
    if (!ring || !ring->vaddr || !enq || !ccs) return 0;
    trbs = (xhci_trb_t *)ring->vaddr;
    n = ring->size / sizeof(xhci_trb_t);
    if (n < 2u) return 0;
    idx = *enq;
    if (idx >= n - 1u) idx = 0;
    phys = (uint64_t)ring->paddr + (uint64_t)idx * sizeof(xhci_trb_t);
    trbs[idx].lo = lo;
    trbs[idx].hi = hi;
    trbs[idx].status = st;
    trbs[idx].control = (ctrl & ~1u) | (uint32_t)(*ccs & 1u);
    idx++;
    if (idx >= n - 1u) {
        trbs[n - 1u].control = ((uint32_t)XHCI_TRB_TYPE_LINK << 10) | XHCI_TRB_TC | (uint32_t)(*ccs & 1u);
        idx = 0;
        *ccs ^= 1u;
    }
    *enq = (uint8_t)idx;
    return phys;
}

static void xhci_ring_doorbell(const xhci_controller_t *xc, uint8_t db, uint32_t val) {
    if (!xc || !xc->db) return;
    /*
     * Command and transfer TRBs live in cacheable coherent DMA memory.  The
     * controller must never observe the MMIO doorbell before all preceding
     * TRB stores are globally visible.  A serial printf used to provide enough
     * accidental serialization to hide this ordering bug during boot HID
     * enumeration.
     */
    __asm__ __volatile__("mfence" ::: "memory");
    mmio_write32(xc->db, (uint32_t)db * 4u, val);
}

static void xhci_legacy_handoff(xhci_controller_t *xc) {
    uint32_t off;
    if (!xc || !xc->mmio || xc->ext_cap_off == 0) return;
    off = xc->ext_cap_off;
    for (int guard = 0; guard < 64 && off >= 0x40u &&
         off <= 0xfffcu; ++guard) {
        uint32_t cap = mmio_read32(xc->mmio, off);
        uint8_t id = (uint8_t)(cap & 0xFFu);
        uint8_t next = (uint8_t)((cap >> 8) & 0xFFu);
        if (id == 1u) {
            uint32_t sem = cap;
            if (sem & (1u << 16)) {
                sem |= (1u << 24);
                mmio_write32(xc->mmio, off, sem);
                if (xhci_wait_u32(xc->mmio, off, 1u << 16, 0,
                                  XHCI_LEGACY_HANDOFF_TIMEOUT_US) < 0)
                    printf("[usb][xhci] firmware ownership handoff timed out\n");
            }
            return;
        }
        if (next == 0) break;
        off += ((uint32_t)next << 2);
    }
}

static int xhci_port_power_and_reset(xhci_controller_t *xc, uint8_t port_index) {
    uint32_t off;
    uint32_t v;
    int failed = 0;
    if (!xc || !xc->op) return -1;
    off = XHCI_PORTSC_BASE + (uint32_t)port_index * XHCI_PORTSC_STRIDE;
    v = mmio_read32(xc->op, off);
    xhci_portsc_clear_changes(xc, off, v);
    v = mmio_read32(xc->op, off);
    mmio_write32(xc->op, off,
                 xhci_portsc_neutral(v) | XHCI_PORTSC_PP);
    v = mmio_read32(xc->op, off);
    if ((v & XHCI_PORTSC_CCS) == 0) return -1;
    xhci_wait_us(XHCI_PORT_POWER_SETTLE_US);
    v = mmio_read32(xc->op, off);
    mmio_write32(xc->op, off,
                 xhci_portsc_neutral(v) | XHCI_PORTSC_PP |
                     XHCI_PORTSC_PR);
    if (xhci_wait_u32(xc->op, off, XHCI_PORTSC_PR, 0,
                      XHCI_PORT_RESET_TIMEOUT_US) < 0) {
        printf("[usb][xhci] port %u reset timed out status=0x%x\n",
               (uint32_t)port_index + 1u, mmio_read32(xc->op, off));
        failed = 1;
    }
    if (xhci_wait_u32(xc->op, off, XHCI_PORTSC_PED, 1,
                      XHCI_PORT_RESET_TIMEOUT_US) < 0) {
        printf("[usb][xhci] port %u did not enable status=0x%x\n",
               (uint32_t)port_index + 1u, mmio_read32(xc->op, off));
        failed = 1;
    }
    v = mmio_read32(xc->op, off);
    xhci_portsc_clear_changes(xc, off, v);
    /*
     * USB reset recovery is observable on xHCI too: the port can report
     * enabled before the device firmware is ready for the first EP0 request.
     * Without this settling window QEMU's boot HID devices intermittently
     * accept Address Device but never produce Transfer Events for the first
     * descriptor read.
     */
    xhci_wait_us(XHCI_RESET_RECOVERY_US);
    v = mmio_read32(xc->op, off);
    return !failed && (v & (XHCI_PORTSC_CCS | XHCI_PORTSC_PED)) ==
                          (XHCI_PORTSC_CCS | XHCI_PORTSC_PED) ? 0 : -1;
}

static int xhci_setup_rings(xhci_controller_t *xc) {
    xhci_erst_ent_t *erst;
    if (!xc) return -1;
    xc->cmd_ring_size = 64;
    xc->evt_ring_size = 256;
    xc->evt_deq = 0;
    xc->evt_ccs = 1;
    xc->cmd_wait_ptr = 0;
    xc->cmd_wait_done = 0;
    xc->xfer_wait_ptr = 0;
    xc->xfer_wait_done = 0;

    if (usb_dma_alloc_zero_boundary(256u * 8u, 64u, xc->page_size,
                                    &xc->dcbaa) < 0) return -1;
    if (usb_dma_alloc_zero_boundary(
            xc->cmd_ring_size * sizeof(xhci_trb_t), 64u,
            XHCI_RING_BOUNDARY, &xc->cmd_ring) < 0) return -1;
    if (usb_dma_alloc_zero_boundary(
            xc->evt_ring_size * sizeof(xhci_trb_t), 64u,
            XHCI_RING_BOUNDARY, &xc->evt_ring) < 0) return -1;
    if (usb_dma_alloc_zero(sizeof(xhci_erst_ent_t), 64u, &xc->erst) < 0) return -1;

    xhci_ring_init(&xc->cmd_ring, &xc->cmd_enq, &xc->cmd_ccs);
    memset(xc->evt_ring.vaddr, 0, xc->evt_ring.size);
    memset(xc->erst.vaddr, 0, xc->erst.size);
    erst = (xhci_erst_ent_t *)xc->erst.vaddr;
    erst[0].seg_lo = xc->evt_ring.paddr;
    erst[0].seg_hi = 0;
    erst[0].seg_size = xc->evt_ring_size;
    return 0;
}

static int xhci_setup_scratchpads(xhci_controller_t *xc) {
    uint64_t *pointers;

    if (!xc || !xc->dcbaa.vaddr)
        return -1;
    if (xc->scratchpad_count == 0)
        return 0;
    if (xc->page_size == 0 ||
        usb_dma_alloc_zero((uint32_t)xc->scratchpad_count * 8u, 64u,
                           &xc->scratchpad_array) < 0) {
        return -1;
    }
    pointers = (uint64_t *)xc->scratchpad_array.vaddr;
    for (uint16_t index = 0; index < xc->scratchpad_count; ++index) {
        usb_dma_block_t page;

        if (usb_dma_alloc_zero(xc->page_size, xc->page_size, &page) < 0) {
            printf("[usb][xhci] scratchpad allocation failed count=%u page=%u dma=%u/%u\n",
                   (uint32_t)xc->scratchpad_count, xc->page_size,
                   usb_dma_bytes_used(), usb_dma_bytes_total());
            return -1;
        }
        pointers[index] = (uint64_t)page.paddr;
    }
    ((uint64_t *)xc->dcbaa.vaddr)[0] =
        (uint64_t)xc->scratchpad_array.paddr;
    return 0;
}

static void xhci_program_runtime(xhci_controller_t *xc) {
    uint32_t intr_off;
    uint64_t erdp;
    if (!xc || !xc->rt) return;
    intr_off = XHCI_INTR_BASE;
    mmio_write32(xc->rt, intr_off + XHCI_ERSTSZ, 1u);
    mmio_write64(xc->rt, intr_off + XHCI_ERSTBA, (uint64_t)xc->erst.paddr);
    erdp = (uint64_t)xc->evt_ring.paddr;
    mmio_write64(xc->rt, intr_off + XHCI_ERDP, erdp | (1ull << 3));
    /*
     * This driver consumes the event ring from synchronous waits and polling
     * paths.  Keep the interrupter disabled until an xHCI interrupt handler is
     * installed; otherwise a shared PCI INTx line can remain asserted and
     * starve the boot CPU while another device services the same IRQ.
     */
    mmio_write32(xc->rt, intr_off + XHCI_IMAN, XHCI_IMAN_IP);
}

static int xhci_cmd_submit_wait(xhci_controller_t *xc, uint32_t lo, uint32_t hi, uint32_t st, uint32_t ctrl, uint8_t *slot_out);
static void xhci_poll_events(xhci_controller_t *xc);

static void xhci_report_transfer_timeout(xhci_controller_t *xc,
                                         uint64_t wait_ptr,
                                         uint8_t slot_id,
                                         uint8_t ep_dci) {
    xhci_slot_state_t *slot = 0;
    uint32_t ep_state = 0xffffffffu;
    uint32_t hw_dequeue = 0;
    uint32_t port_status = 0;

    if (!xc) return;
    if (slot_id > 0 && slot_id <= XHCI_MAX_TRACKED_SLOTS) {
        uint32_t ctx_bytes = xhci_ctx_bytes(xc);
        slot = &xc->slots[slot_id];
        if (slot->device_ctx.vaddr && ep_dci > 0 && ep_dci <= 31u) {
            uint32_t *ep_ctx = (uint32_t *)(
                (uint8_t *)slot->device_ctx.vaddr +
                (uint32_t)ep_dci * ctx_bytes);
            ep_state = ep_ctx[0] & 0x7u;
            hw_dequeue = ep_ctx[2] & ~0x0fu;
        }
        if (xc->op && slot->port_id > 0 && slot->port_id <= xc->max_ports) {
            port_status = mmio_read32(
                xc->op, XHCI_PORTSC_BASE +
                (uint32_t)(slot->port_id - 1u) * XHCI_PORTSC_STRIDE);
        }
    }
    printf("[usb][xhci] transfer timeout bdf=%u:%u.%u slot=%u ep=%u trb=0x%x status=0x%x port=0x%x epstate=%u dequeue=0x%x enq=%u ccs=%u\n",
           (uint32_t)xc->bus, (uint32_t)xc->dev, (uint32_t)xc->fn,
           (uint32_t)slot_id, (uint32_t)ep_dci, (uint32_t)wait_ptr,
           mmio_read32(xc->op, XHCI_USBSTS), port_status, ep_state,
           hw_dequeue, slot ? (uint32_t)slot->ep0_enq : 0u,
           slot ? (uint32_t)slot->ep0_ccs : 0u);
}

static int xhci_wait_transfer(xhci_controller_t *xc, uint64_t wait_ptr, uint64_t alt_ptr1,
                              uint64_t alt_ptr2, uint8_t slot_id, uint8_t ep_dci,
                              uint32_t doorbell_value, uint8_t *cc_out) {
    if (!xc || wait_ptr == 0) return -1;
    xc->xfer_wait_ptr = wait_ptr;
    xc->xfer_wait_alt_ptr1 = alt_ptr1;
    xc->xfer_wait_alt_ptr2 = alt_ptr2;
    xc->xfer_wait_done = 0;
    xc->xfer_wait_cc = 0;
    xc->xfer_wait_slot = slot_id;
    xc->xfer_wait_ep = ep_dci;
    /*
     * Publish the waiter before notifying the controller. A fast controller
     * can complete a small transfer immediately, and the asynchronous event
     * poller must never observe that completion before the matching waiter
     * exists.
     */
    xhci_ring_doorbell(xc, slot_id, doorbell_value);
    uint64_t start_us = boottime_monotonic_us();
    do {
        xhci_poll_events(xc);
        if (xc->xfer_wait_done) break;
        xhci_wait_relax();
    } while (boottime_monotonic_us() - start_us <
             XHCI_TRANSFER_TIMEOUT_US);
    xc->xfer_wait_ptr = 0;
    xc->xfer_wait_alt_ptr1 = 0;
    xc->xfer_wait_alt_ptr2 = 0;
    if (!xc->xfer_wait_done) {
        xhci_report_transfer_timeout(xc, wait_ptr, slot_id, ep_dci);
        return -1;
    }
    if (cc_out) *cc_out = xc->xfer_wait_cc;
    if (xc->xfer_wait_cc == XHCI_COMP_SUCCESS ||
        xc->xfer_wait_cc == XHCI_COMP_SHORT_PACKET)
        return 0;
    printf("[usb][xhci] transfer failed bdf=%u:%u.%u slot=%u ep=%u cc=%u\n",
           (uint32_t)xc->bus, (uint32_t)xc->dev, (uint32_t)xc->fn,
           (uint32_t)slot_id, (uint32_t)ep_dci,
           (uint32_t)xc->xfer_wait_cc);
    return -1;
}

static xhci_slot_state_t *xhci_slot_get(xhci_controller_t *xc, uint8_t slot_id) {
    if (!xc || slot_id == 0 || slot_id > XHCI_MAX_TRACKED_SLOTS) return 0;
    return &xc->slots[slot_id];
}

static void xhci_slot_reset_preserving_dma(xhci_slot_state_t *slot) {
    usb_dma_block_t input_ctx;
    usb_dma_block_t device_ctx;
    usb_dma_block_t ep0_ring;
    usb_dma_block_t ctrl_buf;

    if (!slot)
        return;
    input_ctx = slot->input_ctx;
    device_ctx = slot->device_ctx;
    ep0_ring = slot->ep0_ring;
    ctrl_buf = slot->ctrl_buf;
    memset(slot, 0, sizeof(*slot));
    slot->input_ctx = input_ctx;
    slot->device_ctx = device_ctx;
    slot->ep0_ring = ep0_ring;
    slot->ctrl_buf = ctrl_buf;
}

static void xhci_build_address_input_ctx(xhci_controller_t *xc, xhci_slot_state_t *slot) {
    uint32_t ctx_bytes;
    uint32_t *input_ctrl;
    uint32_t *slot_ctx;
    uint32_t *ep0_ctx;
    uint64_t ep_ring;
    if (!xc || !slot || !slot->input_ctx.vaddr || !slot->device_ctx.vaddr) return;
    ctx_bytes = xhci_ctx_bytes(xc);
    memset(slot->input_ctx.vaddr, 0, slot->input_ctx.size);
    memset(slot->device_ctx.vaddr, 0, slot->device_ctx.size);
    input_ctrl = (uint32_t *)slot->input_ctx.vaddr;
    slot_ctx = (uint32_t *)((uint8_t *)slot->input_ctx.vaddr + ctx_bytes);
    ep0_ctx = (uint32_t *)((uint8_t *)slot->input_ctx.vaddr + 2u * ctx_bytes);
    input_ctrl[1] = (1u << 0) | (1u << 1);
    slot_ctx[0] = ((uint32_t)(slot->speed_id & 0xFu) << 20) | (1u << 27);
    slot_ctx[1] = ((uint32_t)slot->port_id << 16);
    ep_ring = (uint64_t)slot->ep0_ring.paddr;
    /* Endpoint Context layout:
     * DW1: MaxPacketSize[31:16], EPType[5:3], CErr[2:1]
     * DW2/3: TR Dequeue Pointer (DCS in bit0 of DW2)
     * DW4: Average TRB Length
     */
    ep0_ctx[1] = ((uint32_t)slot->max_packet0 << 16) | (3u << 1) | ((uint32_t)XHCI_EP_TYPE_CONTROL << 3);
    ep0_ctx[2] = (uint32_t)(ep_ring & ~0xFULL) | 1u;
    ep0_ctx[3] = (uint32_t)(ep_ring >> 32);
    ep0_ctx[4] = 8u;
}

static void xhci_build_ep0_evaluate_input_ctx(xhci_controller_t *xc,
                                               xhci_slot_state_t *slot,
                                               uint16_t max_packet_size) {
    uint32_t ctx_bytes;
    uint32_t *input_ctrl;
    uint32_t *input_ep0;
    const uint32_t *output_ep0;

    if (!xc || !slot || !slot->input_ctx.vaddr ||
        !slot->device_ctx.vaddr || !max_packet_size)
        return;
    ctx_bytes = xhci_ctx_bytes(xc);
    memset(slot->input_ctx.vaddr, 0, slot->input_ctx.size);
    input_ctrl = (uint32_t *)slot->input_ctx.vaddr;
    input_ep0 = (uint32_t *)(
        (uint8_t *)slot->input_ctx.vaddr + 2u * ctx_bytes);
    output_ep0 = (const uint32_t *)(
        (const uint8_t *)slot->device_ctx.vaddr + ctx_bytes);
    input_ctrl[1] = 1u << 1;
    memcpy(input_ep0, output_ep0, ctx_bytes);
    input_ep0[1] = (input_ep0[1] & 0x0000ffffu) |
                   ((uint32_t)max_packet_size << 16);
}

static void xhci_build_config_input_ctx(xhci_controller_t *xc, xhci_slot_state_t *slot, int add_ep0_flag) {
    uint32_t ctx_bytes;
    uint32_t *input_ctrl;
    uint32_t *slot_ctx;
    uint32_t *ep0_ctx;
    uint32_t *hid_ep_ctx;
    uint32_t *out_slot_ctx;
    uint32_t *out_ep0_ctx;
    uint64_t intr_ring;
    uint8_t dci;
    uint32_t ctx_entries;
    uint8_t interval;
    if (!xc || !slot || !slot->input_ctx.vaddr || !slot->device_ctx.vaddr) return;
    ctx_bytes = xhci_ctx_bytes(xc);
    dci = slot->hid_ep_dci;
    if (dci == 0u) return;
    memset(slot->input_ctx.vaddr, 0, slot->input_ctx.size);
    input_ctrl = (uint32_t *)slot->input_ctx.vaddr;
    slot_ctx = (uint32_t *)((uint8_t *)slot->input_ctx.vaddr + ctx_bytes);
    ep0_ctx = (uint32_t *)((uint8_t *)slot->input_ctx.vaddr + 2u * ctx_bytes);
    hid_ep_ctx = (uint32_t *)((uint8_t *)slot->input_ctx.vaddr + ((uint32_t)1u + dci) * ctx_bytes);
    /*
     * Output device contexts do not contain the Input Control Context.  The
     * slot context is at index 0 and EP0 is at index 1.  Input contexts add the
     * control context before those entries, so reusing input-context offsets
     * here feeds Configure Endpoint stale zeroed data and can corrupt the
     * controller's view of EP0 while adding the HID interrupt pipe.
     */
    out_slot_ctx = (uint32_t *)slot->device_ctx.vaddr;
    out_ep0_ctx = (uint32_t *)((uint8_t *)slot->device_ctx.vaddr + ctx_bytes);
    memcpy(slot_ctx, out_slot_ctx, ctx_bytes);
    memcpy(ep0_ctx, out_ep0_ctx, ctx_bytes);
    /* Configure Endpoint: include slot + target endpoint; EP0 add-flag is controller-specific. */
    input_ctrl[1] = (1u << 0) | (1u << dci);
    if (add_ep0_flag) input_ctrl[1] |= (1u << 1);
    ctx_entries = (slot_ctx[0] >> 27) & 0x1Fu;
    if (ctx_entries < dci) ctx_entries = dci;
    slot_ctx[0] &= ~(0x1Fu << 27);
    slot_ctx[0] |= (ctx_entries & 0x1Fu) << 27;
    intr_ring = (uint64_t)slot->intr_ring.paddr;
    interval = xhci_interval_from_binterval(slot->speed_id, slot->hid_interval);
    hid_ep_ctx[0] = ((uint32_t)interval << 16);
    /*
     * Use the controller retry budget for interrupt endpoints as well.  This
     * matches the conservative xHCI setup used by mature BSD/Linux-style USB
     * stacks and avoids a single transient HID poll miss permanently halting
     * the boot keyboard or mouse endpoint.
     */
    hid_ep_ctx[1] = ((uint32_t)slot->hid_max_packet << 16) |
                    (3u << 1) |
                    ((uint32_t)XHCI_EP_TYPE_INTERRUPT_IN << 3);
    hid_ep_ctx[2] = (uint32_t)(intr_ring & ~0xFULL) | 1u;
    hid_ep_ctx[3] = (uint32_t)(intr_ring >> 32);
    hid_ep_ctx[4] = ((uint32_t)slot->hid_max_packet << 16) | (uint32_t)slot->hid_max_packet;
}

static void xhci_build_mass_config_input_ctx(xhci_controller_t *xc, xhci_slot_state_t *slot, int add_ep0_flag) {
    uint32_t ctx_bytes;
    uint32_t *input_ctrl;
    uint32_t *slot_ctx;
    uint32_t *ep0_ctx;
    uint32_t *in_ep_ctx;
    uint32_t *out_ep_ctx;
    uint32_t *out_slot_ctx;
    uint32_t *out_ep0_ctx;
    uint8_t in_dci;
    uint8_t out_dci;
    uint8_t max_dci;
    uint64_t in_ring;
    uint64_t out_ring;
    if (!xc || !slot || !slot->input_ctx.vaddr || !slot->device_ctx.vaddr) return;
    in_dci = slot->mass_bulk_in_dci;
    out_dci = slot->mass_bulk_out_dci;
    if (in_dci == 0u || out_dci == 0u) return;
    max_dci = (in_dci > out_dci) ? in_dci : out_dci;
    ctx_bytes = xhci_ctx_bytes(xc);
    memset(slot->input_ctx.vaddr, 0, slot->input_ctx.size);
    input_ctrl = (uint32_t *)slot->input_ctx.vaddr;
    slot_ctx = (uint32_t *)((uint8_t *)slot->input_ctx.vaddr + ctx_bytes);
    ep0_ctx = (uint32_t *)((uint8_t *)slot->input_ctx.vaddr + 2u * ctx_bytes);
    out_ep_ctx = (uint32_t *)((uint8_t *)slot->input_ctx.vaddr + ((uint32_t)1u + out_dci) * ctx_bytes);
    in_ep_ctx = (uint32_t *)((uint8_t *)slot->input_ctx.vaddr + ((uint32_t)1u + in_dci) * ctx_bytes);
    out_slot_ctx = (uint32_t *)slot->device_ctx.vaddr;
    out_ep0_ctx = (uint32_t *)((uint8_t *)slot->device_ctx.vaddr + ctx_bytes);
    memcpy(slot_ctx, out_slot_ctx, ctx_bytes);
    memcpy(ep0_ctx, out_ep0_ctx, ctx_bytes);
    input_ctrl[1] = (1u << 0) | (1u << out_dci) | (1u << in_dci);
    if (add_ep0_flag) input_ctrl[1] |= (1u << 1);
    slot_ctx[0] &= ~(0x1Fu << 27);
    slot_ctx[0] |= ((uint32_t)max_dci & 0x1Fu) << 27;

    out_ring = (uint64_t)slot->mass_out_ring.paddr;
    out_ep_ctx[1] = ((uint32_t)slot->mass_bulk_out_mps << 16) |
                    (3u << 1) |
                    ((uint32_t)XHCI_EP_TYPE_BULK_OUT << 3);
    out_ep_ctx[2] = (uint32_t)(out_ring & ~0xFULL) | 1u;
    out_ep_ctx[3] = (uint32_t)(out_ring >> 32);
    out_ep_ctx[4] = ((uint32_t)slot->mass_bulk_out_mps << 16) | (uint32_t)slot->mass_bulk_out_mps;

    in_ring = (uint64_t)slot->mass_in_ring.paddr;
    in_ep_ctx[1] = ((uint32_t)slot->mass_bulk_in_mps << 16) |
                   (3u << 1) |
                   ((uint32_t)XHCI_EP_TYPE_BULK_IN << 3);
    in_ep_ctx[2] = (uint32_t)(in_ring & ~0xFULL) | 1u;
    in_ep_ctx[3] = (uint32_t)(in_ring >> 32);
    in_ep_ctx[4] = ((uint32_t)slot->mass_bulk_in_mps << 16) | (uint32_t)slot->mass_bulk_in_mps;
}

static void xhci_build_usbnet_config_input_ctx(xhci_controller_t *xc, xhci_slot_state_t *slot, int add_ep0_flag) {
    uint32_t ctx_bytes;
    uint8_t in_dci = slot->usbnet_bulk_in_dci;
    uint8_t out_dci = slot->usbnet_bulk_out_dci;
    uint8_t max_dci = (in_dci > out_dci) ? in_dci : out_dci;
    uint32_t *input_ctrl;
    uint32_t *slot_ctx;
    uint32_t *ep0_ctx;
    uint32_t *in_ep_ctx;
    uint32_t *out_ep_ctx;
    uint32_t *out_slot_ctx;
    uint32_t *out_ep0_ctx;
    uint64_t in_ring = (uint64_t)slot->usbnet_in_ring.paddr;
    uint64_t out_ring = (uint64_t)slot->usbnet_out_ring.paddr;
    if (!xc || !slot || !slot->input_ctx.vaddr || !slot->device_ctx.vaddr) return;
    if (in_dci == 0 || out_dci == 0 || in_dci >= 32u || out_dci >= 32u) return;
    ctx_bytes = xhci_ctx_bytes(xc);
    memset(slot->input_ctx.vaddr, 0, slot->input_ctx.size);
    input_ctrl = (uint32_t *)slot->input_ctx.vaddr;
    slot_ctx = (uint32_t *)((uint8_t *)slot->input_ctx.vaddr + ctx_bytes);
    ep0_ctx = (uint32_t *)((uint8_t *)slot->input_ctx.vaddr + 2u * ctx_bytes);
    out_ep_ctx = (uint32_t *)((uint8_t *)slot->input_ctx.vaddr + ((uint32_t)1u + out_dci) * ctx_bytes);
    in_ep_ctx = (uint32_t *)((uint8_t *)slot->input_ctx.vaddr + ((uint32_t)1u + in_dci) * ctx_bytes);
    out_slot_ctx = (uint32_t *)slot->device_ctx.vaddr;
    out_ep0_ctx = (uint32_t *)((uint8_t *)slot->device_ctx.vaddr + ctx_bytes);
    memcpy(slot_ctx, out_slot_ctx, ctx_bytes);
    memcpy(ep0_ctx, out_ep0_ctx, ctx_bytes);
    input_ctrl[0] = add_ep0_flag ? (1u << 1) : 0u;
    input_ctrl[1] = (1u << 0) | (1u << out_dci) | (1u << in_dci);
    if (add_ep0_flag) input_ctrl[1] |= (1u << 1);
    slot_ctx[0] &= ~(0x1Fu << 27);
    slot_ctx[0] |= ((uint32_t)max_dci & 0x1Fu) << 27;

    out_ep_ctx[1] = ((uint32_t)slot->usbnet_bulk_out_mps << 16) |
                    (3u << 1) |
                    ((uint32_t)XHCI_EP_TYPE_BULK_OUT << 3);
    out_ep_ctx[2] = (uint32_t)(out_ring & ~0xFULL) | 1u;
    out_ep_ctx[3] = (uint32_t)(out_ring >> 32);
    out_ep_ctx[4] = ((uint32_t)slot->usbnet_bulk_out_mps << 16) | (uint32_t)slot->usbnet_bulk_out_mps;

    in_ep_ctx[1] = ((uint32_t)slot->usbnet_bulk_in_mps << 16) |
                   (3u << 1) |
                   ((uint32_t)XHCI_EP_TYPE_BULK_IN << 3);
    in_ep_ctx[2] = (uint32_t)(in_ring & ~0xFULL) | 1u;
    in_ep_ctx[3] = (uint32_t)(in_ring >> 32);
    in_ep_ctx[4] = ((uint32_t)slot->usbnet_bulk_in_mps << 16) | (uint32_t)slot->usbnet_bulk_in_mps;
}

#ifdef CONFIG_USB_AUDIO
static void xhci_build_uac_config_input_ctx(xhci_controller_t *xc, xhci_slot_state_t *slot, int add_ep0_flag) {
    uint32_t ctx_bytes;
    uint32_t *input_ctrl;
    uint32_t *slot_ctx;
    uint32_t *ep0_ctx;
    uint32_t *ep_ctx;
    uint32_t *out_slot_ctx;
    uint32_t *out_ep0_ctx;
    uint64_t ring;
    uint8_t dci;
    uint8_t interval;
    uint16_t payload;

    if (!xc || !slot || !slot->input_ctx.vaddr || !slot->device_ctx.vaddr) return;
    dci = slot->uac_ep_dci;
    if (dci == 0u) return;
    ctx_bytes = xhci_ctx_bytes(xc);
    memset(slot->input_ctx.vaddr, 0, slot->input_ctx.size);
    input_ctrl = (uint32_t *)slot->input_ctx.vaddr;
    slot_ctx = (uint32_t *)((uint8_t *)slot->input_ctx.vaddr + ctx_bytes);
    ep0_ctx = (uint32_t *)((uint8_t *)slot->input_ctx.vaddr + 2u * ctx_bytes);
    ep_ctx = (uint32_t *)((uint8_t *)slot->input_ctx.vaddr + ((uint32_t)1u + dci) * ctx_bytes);
    out_slot_ctx = (uint32_t *)slot->device_ctx.vaddr;
    out_ep0_ctx = (uint32_t *)((uint8_t *)slot->device_ctx.vaddr + ctx_bytes);
    memcpy(slot_ctx, out_slot_ctx, ctx_bytes);
    memcpy(ep0_ctx, out_ep0_ctx, ctx_bytes);

    input_ctrl[1] = (1u << 0) | (1u << dci);
    if (add_ep0_flag) input_ctrl[1] |= (1u << 1);
    slot_ctx[0] &= ~(0x1Fu << 27);
    slot_ctx[0] |= ((uint32_t)dci & 0x1Fu) << 27;

    ring = (uint64_t)slot->uac_ring.paddr;
    interval = xhci_interval_from_binterval(slot->speed_id, slot->uac_interval);
    payload = slot->uac_packet_bytes ? slot->uac_packet_bytes : slot->uac_max_packet;
    if (payload == 0) payload = 192u;
    if (payload > slot->uac_max_packet && slot->uac_max_packet != 0) payload = slot->uac_max_packet;
    ep_ctx[0] = ((uint32_t)interval << 16);
    ep_ctx[1] = ((uint32_t)slot->uac_max_packet << 16) |
                (3u << 1) |
                ((uint32_t)XHCI_EP_TYPE_ISOCH_OUT << 3);
    ep_ctx[2] = (uint32_t)(ring & ~0xFULL) | 1u;
    ep_ctx[3] = (uint32_t)(ring >> 32);
    ep_ctx[4] = ((uint32_t)payload << 16) | (uint32_t)payload;
}
#endif

static int xhci_control_transfer(xhci_controller_t *xc, xhci_slot_state_t *slot,
                                 uint8_t bmRequestType, uint8_t bRequest,
                                 uint16_t wValue, uint16_t wIndex,
                                 void *buf, uint16_t len) {
    usb_setup_pkt_t setup;
    uint64_t setup_ptr, data_ptr = 0, status_ptr;
    int dir_in = (bmRequestType & 0x80u) ? 1 : 0;
    uint8_t cc = 0;
    if (!xc || !slot || !slot->online) return -1;
    setup.bmRequestType = bmRequestType;
    setup.bRequest = bRequest;
    setup.wValue = wValue;
    setup.wIndex = wIndex;
    setup.wLength = len;

    if (len > 0 && buf && !dir_in) {
        memcpy(slot->ctrl_buf.vaddr, buf, len);
    }

    setup_ptr = xhci_ring_enqueue(&slot->ep0_ring, &slot->ep0_enq, &slot->ep0_ccs,
                                  *(uint32_t *)&setup, *(((uint32_t *)&setup) + 1),
                                  8u, xhci_control_setup_flags(dir_in, len));
    if (setup_ptr == 0) return -1;

    if (len > 0) {
        data_ptr = xhci_ring_enqueue(&slot->ep0_ring, &slot->ep0_enq, &slot->ep0_ccs,
                                     slot->ctrl_buf.paddr, 0,
                                     (uint32_t)len,
                                     xhci_control_data_flags(dir_in));
        if (data_ptr == 0) return -1;
    }

    status_ptr = xhci_ring_enqueue(&slot->ep0_ring, &slot->ep0_enq, &slot->ep0_ccs,
                                   0, 0, 0,
                                   xhci_control_status_flags(dir_in));
    if (status_ptr == 0) return -1;
    if (xhci_wait_transfer(xc, status_ptr, setup_ptr, data_ptr,
                           slot->slot_id, 1u, 1u, &cc) < 0) return -1;

    if (len > 0 && buf && dir_in) {
        memcpy(buf, slot->ctrl_buf.vaddr, len);
    }
    return 0;
}

static int xhci_hid_rearm_interrupt(xhci_controller_t *xc, xhci_slot_state_t *slot) {
    uint64_t trb;
    if (!xc || !slot || !slot->hid_ready || !slot->intr_buf.vaddr) return -1;
    trb = xhci_ring_enqueue(&slot->intr_ring, &slot->intr_enq, &slot->intr_ccs,
                            slot->intr_buf.paddr, 0,
                            slot->hid_max_packet,
                            ((uint32_t)XHCI_TRB_TYPE_NORMAL << 10) | XHCI_TRB_IOC | XHCI_TRB_ISP);
    if (trb == 0) return -1;
    slot->intr_pending_trb = trb;
    xhci_ring_doorbell(xc, slot->slot_id, (uint32_t)slot->hid_ep_dci);
    return 0;
}

static int xhci_bulk_transfer(xhci_controller_t *xc, xhci_slot_state_t *slot,
                              uint8_t ep_dci, usb_dma_block_t *ring, uint8_t *enq, uint8_t *ccs,
                              uint32_t data_paddr, uint32_t len) {
    uint64_t trb;
    uint8_t cc = 0;
    if (!xc || !slot || !slot->online || !ring || !enq || !ccs) return -1;
    trb = xhci_ring_enqueue(ring, enq, ccs, data_paddr, 0, len,
                            ((uint32_t)XHCI_TRB_TYPE_NORMAL << 10) |
                            XHCI_TRB_IOC | XHCI_TRB_ISP);
    if (trb == 0) return -1;
    if (xhci_wait_transfer(xc, trb, 0, 0, slot->slot_id, ep_dci,
                           ep_dci, &cc) < 0) {
        printf("[usb-storage] bulk transfer failed slot=%u dci=%u len=%u cc=%u\n",
               (uint32_t)slot->slot_id, (uint32_t)ep_dci, len, (uint32_t)cc);
        return -1;
    }
    return 0;
}

#ifdef CONFIG_USB_AUDIO
static int xhci_isoch_out_transfer(xhci_controller_t *xc, xhci_slot_state_t *slot,
                                   const void *data, uint32_t len) {
    uint64_t trb;
    uint8_t cc = 0;
    uint32_t control;
    if (!xc || !slot || !slot->online || !slot->uac_ready || !slot->uac_ring.vaddr || !slot->uac_data.vaddr) return -1;
    if (len == 0) return 0;
    if (len > slot->uac_data.size || len > slot->uac_max_packet) return -1;
    memcpy(slot->uac_data.vaddr, data, len);
    /*
     * Isoch TRBs are required for UAC playback endpoints.  SIA asks the host
     * controller to schedule the packet as soon as possible, which is the
     * correct conservative policy for EdgeOS' current synchronous PCM front-end.
     */
    control = ((uint32_t)XHCI_TRB_TYPE_ISOCH << 10) | XHCI_TRB_IOC | XHCI_TRB_ISP | (1u << 31);
    trb = xhci_ring_enqueue(&slot->uac_ring, &slot->uac_enq, &slot->uac_ccs,
                            slot->uac_data.paddr, 0, len, control);
    if (trb == 0) return -1;
    if (xhci_wait_transfer(xc, trb, 0, 0, slot->slot_id,
                           slot->uac_ep_dci, slot->uac_ep_dci, &cc) < 0) {
        printf("[usb-audio] isoch OUT failed slot=%u dci=%u len=%u cc=%u\n",
               (uint32_t)slot->slot_id, (uint32_t)slot->uac_ep_dci, len, (uint32_t)cc);
        return -1;
    }
    return 0;
}

static int xhci_uac_write_pcm_backend(const char *buf, uint32_t len) {
    uint32_t off = 0;
    uint32_t packet;
    if (!g_uac_xc || !g_uac_slot || !g_uac_slot->uac_ready) return -1;
    if (!buf && len) return -1;
    packet = g_uac_slot->uac_packet_bytes ? g_uac_slot->uac_packet_bytes : g_uac_slot->uac_max_packet;
    if (packet == 0 || packet > g_uac_slot->uac_data.size || packet > sizeof(g_uac_pcm_buf)) return -1;
    while (off < len) {
        uint32_t room = packet - g_uac_pcm_len;
        uint32_t n = len - off;
        if (n > room) n = room;
        memcpy(g_uac_pcm_buf + g_uac_pcm_len, buf + off, n);
        g_uac_pcm_len = (uint16_t)(g_uac_pcm_len + n);
        off += n;
        /*
         * Linux userspace may feed a PCM device in frame-sized writes.  USB
         * Audio Class endpoints, however, are scheduled as periodic isochronous
         * packets.  Accumulate normal write(2)/snd_pcm_writei() fragments until
         * a complete packet is available, then submit exactly the negotiated
         * packet size.  Short packets can be interpreted by some UAC devices as
         * underruns and QEMU reports them as transfer errors.
         */
        if (g_uac_pcm_len < packet) continue;
        if (xhci_isoch_out_transfer(g_uac_xc, g_uac_slot, g_uac_pcm_buf, packet) < 0) {
            g_uac_pcm_len = 0;
            return off ? (int)off : -1;
        }
        g_uac_pcm_len = 0;
    }
    return (int)off;
}
#endif

static int xhci_mass_scsi(xhci_controller_t *xc, xhci_slot_state_t *slot,
                          const uint8_t *cdb, uint8_t cdb_len,
                          void *data, uint32_t data_len, uint8_t flags) {
    usb_msc_cbw_t *cbw;
    usb_msc_csw_t *csw;
    uint32_t tag;
    int data_in = (flags & USB_MSC_DATA_IN) ? 1 : 0;
    if (!xc || !slot || !slot->mass_ready || !cdb || cdb_len == 0 || cdb_len > USB_MSC_CDB_MAX) return -1;
    if (data_len > USB_MSC_MAX_DMA_BYTES || data_len > slot->mass_data.size) return -1;
    if (data_len != 0 && !data) return -1;
    cbw = (usb_msc_cbw_t *)slot->mass_cbw.vaddr;
    csw = (usb_msc_csw_t *)slot->mass_csw.vaddr;
    if (!cbw || !csw || !slot->mass_data.vaddr) return -1;

    tag = g_xhci_msc_tag++;
    if (g_xhci_msc_tag == 0) g_xhci_msc_tag = 1;
    memset(cbw, 0, sizeof(*cbw));
    memset(csw, 0, sizeof(*csw));
    cbw->signature = USB_MSC_CBW_SIG;
    cbw->tag = tag;
    cbw->data_len = data_len;
    cbw->flags = flags;
    cbw->lun = 0;
    cbw->cdb_len = cdb_len;
    memcpy(cbw->cdb, cdb, cdb_len);
    if (data_len && !data_in) memcpy(slot->mass_data.vaddr, data, data_len);

    if (xhci_bulk_transfer(xc, slot, slot->mass_bulk_out_dci, &slot->mass_out_ring,
                           &slot->mass_out_enq, &slot->mass_out_ccs,
                           slot->mass_cbw.paddr, sizeof(*cbw)) < 0) return -1;
    if (data_len) {
        if (data_in) {
            if (xhci_bulk_transfer(xc, slot, slot->mass_bulk_in_dci, &slot->mass_in_ring,
                                   &slot->mass_in_enq, &slot->mass_in_ccs,
                                   slot->mass_data.paddr, data_len) < 0) return -1;
        } else {
            if (xhci_bulk_transfer(xc, slot, slot->mass_bulk_out_dci, &slot->mass_out_ring,
                                   &slot->mass_out_enq, &slot->mass_out_ccs,
                                   slot->mass_data.paddr, data_len) < 0) return -1;
        }
    }
    if (xhci_bulk_transfer(xc, slot, slot->mass_bulk_in_dci, &slot->mass_in_ring,
                           &slot->mass_in_enq, &slot->mass_in_ccs,
                           slot->mass_csw.paddr, sizeof(*csw)) < 0) return -1;
    if (csw->signature != USB_MSC_CSW_SIG || csw->tag != tag || csw->status != 0) {
        printf("[usb-storage] CSW failed slot=%u sig=0x%x tag=%u/%u residue=%u status=%u\n",
               (uint32_t)slot->slot_id, csw->signature, csw->tag, tag,
               csw->residue, (uint32_t)csw->status);
        return -1;
    }
    if (data_len && data_in) memcpy(data, slot->mass_data.vaddr, data_len);
    return 0;
}

static const char *xhci_usb_class_driver_state(uint8_t cls, uint8_t subcls, uint8_t proto, const char **name_out) {
    switch (cls) {
    case USB_CLASS_HID:
        *name_out = "USB HID";
        return "supported";
    case USB_CLASS_HUB:
        *name_out = "USB hub";
        return "partial";
    case USB_CLASS_AUDIO:
        *name_out = "USB Audio Class";
#ifdef CONFIG_USB_AUDIO
        if (subcls == USB_AUDIO_SUBCLASS_CONTROL || subcls == USB_AUDIO_SUBCLASS_STREAMING) return "supported";
        return "partial";
#else
        return "missing";
#endif
    case USB_CLASS_MASS_STORAGE:
        *name_out = "USB Mass Storage";
#ifdef CONFIG_USB_STORAGE
        if (subcls == USB_MSC_SUBCLASS_SCSI && proto == USB_MSC_PROTO_BULK_ONLY) return "supported";
        return "partial";
#else
        return "missing";
#endif
    case USB_CLASS_VIDEO:
        *name_out = "USB Video Class";
#ifdef CONFIG_USB_UVC
        if (subcls == USB_VIDEO_SUBCLASS_CONTROL || subcls == USB_VIDEO_SUBCLASS_STREAMING) return "partial";
#endif
        return "missing";
    case USB_CLASS_VENDOR:
        *name_out = "USB vendor-specific device";
        return "partial";
    default:
        *name_out = "USB interface";
        return "missing";
    }
}

static void xhci_log_interface_coverage(uint8_t slot_id, const usb_if_desc_t *id) {
    const char *name;
    const char *state;
    if (!id) return;
    state = xhci_usb_class_driver_state(id->bInterfaceClass, id->bInterfaceSubClass, id->bInterfaceProtocol, &name);
    printf("[usb][drv] xhci slot=%u iface=%u class=%u/%u/%u %s: %s\n",
           (uint32_t)slot_id, (uint32_t)id->bInterfaceNumber,
           (uint32_t)id->bInterfaceClass, (uint32_t)id->bInterfaceSubClass,
           (uint32_t)id->bInterfaceProtocol, state, name);
}

static int xhci_identify_device(xhci_controller_t *xc,
                                xhci_slot_state_t *slot,
                                uint32_t *candidates_out) {
    usb_dev_desc_t descriptor;
    uint8_t descriptor_prefix[8];
    uint8_t configuration_header[9];
    uint8_t configuration[512];
    uint16_t total;
    uint16_t offset;
    uint16_t ep0_packet_size;

    if (!xc || !slot || !candidates_out) return -1;
    memset(descriptor_prefix, 0, sizeof(descriptor_prefix));
    if (xhci_control_transfer(
            xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR,
            (uint16_t)(USB_DT_DEVICE << 8), 0,
            descriptor_prefix, sizeof(descriptor_prefix)) < 0) {
        printf("[usb][xhci] slot=%u initial device prefix failed\n",
               (uint32_t)slot->slot_id);
        return -1;
    }
    ep0_packet_size = xhci_device_ep0_packet_size(
        slot->speed_id, descriptor_prefix[7]);
    if (!ep0_packet_size) {
        printf("[usb][xhci] slot=%u invalid ep0 packet size=%u speed=%u\n",
               (uint32_t)slot->slot_id, (uint32_t)descriptor_prefix[7],
               (uint32_t)slot->speed_id);
        return -1;
    }
    if (ep0_packet_size != slot->max_packet0) {
        xhci_build_ep0_evaluate_input_ctx(xc, slot, ep0_packet_size);
        if (xhci_cmd_submit_wait(
                xc, slot->input_ctx.paddr, 0, 0,
                ((uint32_t)XHCI_TRB_TYPE_EVALUATE_CONTEXT << 10) |
                    ((uint32_t)slot->slot_id << 24), 0) < 0) {
            printf("[usb][xhci] slot=%u ep0 packet update failed old=%u new=%u\n",
                   (uint32_t)slot->slot_id,
                   (uint32_t)slot->max_packet0,
                   (uint32_t)ep0_packet_size);
            return -1;
        }
        printf("[usb][xhci] slot=%u ep0 packet size %u -> %u\n",
               (uint32_t)slot->slot_id, (uint32_t)slot->max_packet0,
               (uint32_t)ep0_packet_size);
        slot->max_packet0 = ep0_packet_size;
    }
    memset(&descriptor, 0, sizeof(descriptor));
    if (xhci_control_transfer(
            xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR,
            (uint16_t)(USB_DT_DEVICE << 8), 0,
            &descriptor, sizeof(descriptor)) < 0) {
        printf("[usb][xhci] slot=%u initial device descriptor failed\n",
               (uint32_t)slot->slot_id);
        return -1;
    }
    slot->vendor_id = descriptor.idVendor;
    slot->product_id = descriptor.idProduct;
    slot->bcd_device = descriptor.bcdDevice;
    slot->device_class = descriptor.bDeviceClass;
    slot->device_subclass = descriptor.bDeviceSubClass;
    slot->device_protocol = descriptor.bDeviceProtocol;

    memset(configuration_header, 0, sizeof(configuration_header));
    if (xhci_control_transfer(
            xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR,
            (uint16_t)(USB_DT_CONFIG << 8), 0,
            configuration_header, sizeof(configuration_header)) < 0) {
        printf("[usb][xhci] slot=%u initial configuration header failed\n",
               (uint32_t)slot->slot_id);
        return -1;
    }
    total = (uint16_t)configuration_header[2] |
            ((uint16_t)configuration_header[3] << 8);
    if (total < sizeof(configuration_header))
        total = sizeof(configuration_header);
    if (total > sizeof(configuration))
        total = sizeof(configuration);
    memset(configuration, 0, sizeof(configuration));
    if (xhci_control_transfer(
            xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR,
            (uint16_t)(USB_DT_CONFIG << 8), 0,
            configuration, total) < 0) {
        printf("[usb][xhci] slot=%u initial configuration descriptor failed\n",
               (uint32_t)slot->slot_id);
        return -1;
    }

    offset = 0;
    while (offset + 2u <= total) {
        uint8_t length = configuration[offset];
        uint8_t type = configuration[offset + 1u];

        if (length < 2u || offset + length > total) break;
        if (type == USB_DT_CONFIG && length >= sizeof(usb_cfg_desc_t))
            slot->config_value =
                ((const usb_cfg_desc_t *)(configuration + offset))
                    ->bConfigurationValue;
        if (type == 4u && length >= sizeof(usb_if_desc_t))
            xhci_log_interface_coverage(
                slot->slot_id,
                (const usb_if_desc_t *)(configuration + offset));
        offset = (uint16_t)(offset + length);
    }

    *candidates_out = xhci_device_driver_candidates(
        descriptor.bDeviceClass, descriptor.bDeviceSubClass,
        descriptor.bDeviceProtocol, configuration, total);
    printf("[usb][xhci] slot=%u identified vid=%04x pid=%04x candidates=0x%x\n",
           (uint32_t)slot->slot_id, (uint32_t)slot->vendor_id,
           (uint32_t)slot->product_id, *candidates_out);
    return 0;
}

static int xhci_parse_hid_config(xhci_slot_state_t *slot, const uint8_t *cfg, uint16_t len, uint8_t *cfgval_out) {
    uint16_t off = 0;
    int in_hid_if = 0;
    uint8_t ifnum = 0;
    uint16_t report_descriptor_length = 0;
    if (!slot || !cfg || len < sizeof(usb_cfg_desc_t)) return -1;
    if (cfgval_out) *cfgval_out = ((const usb_cfg_desc_t *)cfg)->bConfigurationValue;
    slot->hid_ready = 0;
    slot->hid_report_mode = 0;
    slot->hid_report_descriptor_length = 0;
    while (off + 2 <= len) {
        uint8_t dlen = cfg[off];
        uint8_t dtype = cfg[off + 1];
        if (dlen < 2 || off + dlen > len) break;
        if (dtype == 4 && dlen >= sizeof(usb_if_desc_t)) {
            const usb_if_desc_t *id = (const usb_if_desc_t *)(cfg + off);
            xhci_log_interface_coverage(slot->slot_id, id);
            ifnum = id->bInterfaceNumber;
            in_hid_if = id->bInterfaceClass == USB_CLASS_HID;
            report_descriptor_length = 0;
            if (in_hid_if) {
                slot->interface_class = id->bInterfaceClass;
                slot->interface_subclass = id->bInterfaceSubClass;
                slot->interface_protocol = id->bInterfaceProtocol;
                slot->interface_number = id->bInterfaceNumber;
                slot->hid_protocol = id->bInterfaceProtocol;
            }
        } else if (dtype == USB_DT_HID && dlen >= 9u && in_hid_if) {
            report_descriptor_length =
                (uint16_t)cfg[off + 7u] |
                ((uint16_t)cfg[off + 8u] << 8);
        } else if (dtype == 5 && dlen >= sizeof(usb_ep_desc_t) && in_hid_if) {
            const usb_ep_desc_t *ep = (const usb_ep_desc_t *)(cfg + off);
            if ((ep->bEndpointAddress & 0x80u) && ((ep->bmAttributes & 0x03u) == 0x03u)) {
                uint8_t epn = ep->bEndpointAddress & 0x0Fu;
                slot->hid_iface = ifnum;
                slot->hid_ep_addr = ep->bEndpointAddress;
                slot->hid_ep_dci = (uint8_t)(epn * 2u + 1u);
                slot->hid_interval = ep->bInterval ? ep->bInterval : 10u;
                slot->hid_max_packet = (uint16_t)(ep->wMaxPacketSize & 0x07FFu);
                if (slot->hid_max_packet == 0) slot->hid_max_packet = 8;
                if (slot->hid_max_packet > 64) slot->hid_max_packet = 64;
                slot->hid_report_descriptor_length =
                    report_descriptor_length;
                return 0;
            }
        }
        off += dlen;
    }
    return -1;
}

static int xhci_parse_mass_config(xhci_slot_state_t *slot, const uint8_t *cfg, uint16_t len, uint8_t *cfgval_out) {
    uint16_t off = 0;
    int in_mass_if = 0;
    uint8_t ifnum = 0;
    uint8_t in_addr = 0;
    uint8_t out_addr = 0;
    uint16_t in_mps = 0;
    uint16_t out_mps = 0;
    if (!slot || !cfg || len < sizeof(usb_cfg_desc_t)) return -1;
    if (cfgval_out) *cfgval_out = ((const usb_cfg_desc_t *)cfg)->bConfigurationValue;
    slot->mass_ready = 0;
    while (off + 2 <= len) {
        uint8_t dlen = cfg[off];
        uint8_t dtype = cfg[off + 1];
        if (dlen < 2 || off + dlen > len) break;
        if (dtype == 4 && dlen >= sizeof(usb_if_desc_t)) {
            const usb_if_desc_t *id = (const usb_if_desc_t *)(cfg + off);
            xhci_log_interface_coverage(slot->slot_id, id);
            ifnum = id->bInterfaceNumber;
            in_mass_if = (id->bInterfaceClass == USB_CLASS_MASS_STORAGE &&
                          id->bInterfaceSubClass == USB_MSC_SUBCLASS_SCSI &&
                          id->bInterfaceProtocol == USB_MSC_PROTO_BULK_ONLY);
            if (in_mass_if) {
                slot->interface_class = id->bInterfaceClass;
                slot->interface_subclass = id->bInterfaceSubClass;
                slot->interface_protocol = id->bInterfaceProtocol;
                slot->interface_number = id->bInterfaceNumber;
                in_addr = 0;
                out_addr = 0;
                in_mps = 0;
                out_mps = 0;
            }
        } else if (dtype == 5 && dlen >= sizeof(usb_ep_desc_t) && in_mass_if) {
            const usb_ep_desc_t *ep = (const usb_ep_desc_t *)(cfg + off);
            if ((ep->bmAttributes & 0x03u) == 0x02u) {
                uint16_t mps = xhci_ep_mps(ep->wMaxPacketSize, 64u);
                if (ep->bEndpointAddress & 0x80u) {
                    in_addr = ep->bEndpointAddress;
                    in_mps = mps;
                } else {
                    out_addr = ep->bEndpointAddress;
                    out_mps = mps;
                }
            }
            if (in_addr && out_addr) {
                uint8_t in_epn = (uint8_t)(in_addr & 0x0Fu);
                uint8_t out_epn = (uint8_t)(out_addr & 0x0Fu);
                slot->mass_iface = ifnum;
                slot->mass_bulk_in_addr = in_addr;
                slot->mass_bulk_out_addr = out_addr;
                slot->mass_bulk_in_dci = (uint8_t)(in_epn * 2u + 1u);
                slot->mass_bulk_out_dci = (uint8_t)(out_epn * 2u);
                slot->mass_bulk_in_mps = in_mps;
                slot->mass_bulk_out_mps = out_mps;
                return 0;
            }
        }
        off += dlen;
    }
    return -1;
}

static uint8_t xhci_usbnet_match(uint16_t vid, uint16_t pid) {
    if (vid == USB_VENDOR_ASIX && pid == USB_PRODUCT_ASIX_AX88179) return USBNET_DRIVER_AX88179;
    if (vid == USB_VENDOR_REALTEK &&
        (pid == USB_PRODUCT_REALTEK_RTL8153 || pid == USB_PRODUCT_REALTEK_RTL8053)) {
        return USBNET_DRIVER_RTL8153;
    }
    if (vid == USB_VENDOR_LENOVO &&
        (pid == USB_PRODUCT_LENOVO_RTL8153 || pid == USB_PRODUCT_LENOVO_RTL8153_04)) {
        return USBNET_DRIVER_RTL8153;
    }
    return USBNET_DRIVER_NONE;
}

static const char *xhci_usbnet_driver_name(uint8_t driver) {
    if (driver == USBNET_DRIVER_AX88179) return "ASIX AX88179";
    if (driver == USBNET_DRIVER_RTL8153) return "Realtek RTL8153";
    return "unknown";
}

static int xhci_parse_usbnet_config(xhci_slot_state_t *slot, const uint8_t *cfg, uint16_t len, uint8_t *cfgval_out) {
    uint16_t off = 0;
    int in_net_if = 0;
    uint8_t ifnum = 0;
    uint8_t in_addr = 0;
    uint8_t out_addr = 0;
    uint16_t in_mps = 0;
    uint16_t out_mps = 0;
    if (!slot || !cfg || len < sizeof(usb_cfg_desc_t)) return -1;
    if (cfgval_out) *cfgval_out = ((const usb_cfg_desc_t *)cfg)->bConfigurationValue;
    slot->usbnet_ready = 0;
    while (off + 2 <= len) {
        uint8_t dlen = cfg[off];
        uint8_t dtype = cfg[off + 1];
        if (dlen < 2 || off + dlen > len) break;
        if (dtype == 4 && dlen >= sizeof(usb_if_desc_t)) {
            const usb_if_desc_t *id = (const usb_if_desc_t *)(cfg + off);
            xhci_log_interface_coverage(slot->slot_id, id);
            ifnum = id->bInterfaceNumber;
            in_net_if = (id->bInterfaceClass == USB_CLASS_VENDOR ||
                         id->bInterfaceClass == 0x02u ||
                         id->bInterfaceClass == 0x0au);
            if (in_net_if) {
                slot->interface_class = id->bInterfaceClass;
                slot->interface_subclass = id->bInterfaceSubClass;
                slot->interface_protocol = id->bInterfaceProtocol;
                slot->interface_number = id->bInterfaceNumber;
                in_addr = 0;
                out_addr = 0;
                in_mps = 0;
                out_mps = 0;
            }
        } else if (dtype == 5 && dlen >= sizeof(usb_ep_desc_t) && in_net_if) {
            const usb_ep_desc_t *ep = (const usb_ep_desc_t *)(cfg + off);
            if ((ep->bmAttributes & 0x03u) == 0x02u) {
                uint16_t mps = xhci_ep_mps(ep->wMaxPacketSize, 512u);
                if (ep->bEndpointAddress & 0x80u) {
                    in_addr = ep->bEndpointAddress;
                    in_mps = mps;
                } else {
                    out_addr = ep->bEndpointAddress;
                    out_mps = mps;
                }
            }
            if (in_addr && out_addr) {
                uint8_t in_epn = (uint8_t)(in_addr & 0x0Fu);
                uint8_t out_epn = (uint8_t)(out_addr & 0x0Fu);
                slot->usbnet_iface = ifnum;
                slot->usbnet_bulk_in_addr = in_addr;
                slot->usbnet_bulk_out_addr = out_addr;
                slot->usbnet_bulk_in_dci = (uint8_t)(in_epn * 2u + 1u);
                slot->usbnet_bulk_out_dci = (uint8_t)(out_epn * 2u);
                slot->usbnet_bulk_in_mps = in_mps;
                slot->usbnet_bulk_out_mps = out_mps;
                return 0;
            }
        }
        off += dlen;
    }
    return -1;
}

static int xhci_configure_usbnet(xhci_controller_t *xc, xhci_slot_state_t *slot) {
    usb_dev_desc_t dd;
    uint8_t cfg_hdr[9];
    uint8_t cfg_buf[512];
    uint16_t total;
    uint8_t cfgval = 1;
    uint8_t driver;
    uint64_t *dcbaa;
    if (!xc || !slot) return -1;
    memset(&dd, 0, sizeof(dd));
    if (xhci_control_transfer(xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR,
                              (uint16_t)(USB_DT_DEVICE << 8), 0, &dd, sizeof(dd)) < 0) {
        return -1;
    }
    driver = xhci_usbnet_match(dd.idVendor, dd.idProduct);
    if (driver == USBNET_DRIVER_NONE) return XHCI_DEVICE_UNSUPPORTED;
    slot->vendor_id = dd.idVendor;
    slot->product_id = dd.idProduct;
    slot->bcd_device = dd.bcdDevice;
    slot->device_class = dd.bDeviceClass;
    slot->device_subclass = dd.bDeviceSubClass;
    slot->device_protocol = dd.bDeviceProtocol;
    slot->usbnet_driver = driver;

    memset(cfg_hdr, 0, sizeof(cfg_hdr));
    if (xhci_control_transfer(xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR,
                              (uint16_t)(USB_DT_CONFIG << 8), 0, cfg_hdr, sizeof(cfg_hdr)) < 0) {
        return -1;
    }
    total = (uint16_t)cfg_hdr[2] | ((uint16_t)cfg_hdr[3] << 8);
    if (total < sizeof(cfg_hdr)) total = sizeof(cfg_hdr);
    if (total > sizeof(cfg_buf)) total = sizeof(cfg_buf);
    memset(cfg_buf, 0, sizeof(cfg_buf));
    if (xhci_control_transfer(xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR,
                              (uint16_t)(USB_DT_CONFIG << 8), 0, cfg_buf, total) < 0) return -1;
    if (xhci_parse_usbnet_config(slot, cfg_buf, total, &cfgval) < 0) return -1;
    if (xhci_control_transfer(xc, slot, 0x00u, USB_REQ_SET_CONFIGURATION, cfgval, 0, 0, 0) < 0) {
        printf("[usb-net] slot=%u SET_CONFIGURATION(%u) failed\n",
               (uint32_t)slot->slot_id, (uint32_t)cfgval);
        return -1;
    }
    slot->config_value = cfgval;

    if (!slot->usbnet_in_ring.vaddr &&
        usb_dma_alloc_zero_boundary(64u * sizeof(xhci_trb_t), 64u,
                                    XHCI_RING_BOUNDARY,
                                    &slot->usbnet_in_ring) < 0) return -1;
    if (!slot->usbnet_out_ring.vaddr &&
        usb_dma_alloc_zero_boundary(64u * sizeof(xhci_trb_t), 64u,
                                    XHCI_RING_BOUNDARY,
                                    &slot->usbnet_out_ring) < 0) return -1;
    if (!slot->usbnet_rx_buf.vaddr &&
        usb_dma_alloc_zero_boundary(2048u, 64u, XHCI_RING_BOUNDARY,
                                    &slot->usbnet_rx_buf) < 0) return -1;
    if (!slot->usbnet_tx_buf.vaddr &&
        usb_dma_alloc_zero_boundary(2048u, 64u, XHCI_RING_BOUNDARY,
                                    &slot->usbnet_tx_buf) < 0) return -1;
    xhci_ring_init(&slot->usbnet_in_ring, &slot->usbnet_in_enq, &slot->usbnet_in_ccs);
    xhci_ring_init(&slot->usbnet_out_ring, &slot->usbnet_out_enq, &slot->usbnet_out_ccs);
    xhci_build_usbnet_config_input_ctx(xc, slot, 0);
    dcbaa = (uint64_t *)xc->dcbaa.vaddr;
    dcbaa[slot->slot_id] = (uint64_t)slot->device_ctx.paddr;
    if (xhci_cmd_submit_wait(xc, slot->input_ctx.paddr, 0, 0,
                             ((uint32_t)XHCI_TRB_TYPE_CONFIGURE_EP << 10) | ((uint32_t)slot->slot_id << 24), 0) < 0) {
        xhci_build_usbnet_config_input_ctx(xc, slot, 1);
        if (xhci_cmd_submit_wait(xc, slot->input_ctx.paddr, 0, 0,
                                 ((uint32_t)XHCI_TRB_TYPE_CONFIGURE_EP << 10) | ((uint32_t)slot->slot_id << 24), 0) < 0) {
            printf("[usb-net] slot=%u Configure Endpoint failed\n", (uint32_t)slot->slot_id);
            return -1;
        }
    }
    slot->usbnet_ready = 1;
    printf("[usb-net] %s endpoint-ready slot=%u iface=%u in=0x%02x out=0x%02x mps=%u/%u vid=%04x pid=%04x\n",
           xhci_usbnet_driver_name(driver), (uint32_t)slot->slot_id, (uint32_t)slot->usbnet_iface,
           (uint32_t)slot->usbnet_bulk_in_addr, (uint32_t)slot->usbnet_bulk_out_addr,
           (uint32_t)slot->usbnet_bulk_in_mps, (uint32_t)slot->usbnet_bulk_out_mps,
           (uint32_t)slot->vendor_id, (uint32_t)slot->product_id);
    printf("[usb-net] %s TX/RX data path not implemented; not registering network interface\n",
           xhci_usbnet_driver_name(driver));
    slot->usbnet_ready = 0;
    return XHCI_DEVICE_UNSUPPORTED;
}

#ifdef CONFIG_USB_AUDIO
static uint32_t xhci_uac_rate24(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}

static int xhci_parse_uac_config(xhci_slot_state_t *slot, const uint8_t *cfg, uint16_t len, uint8_t *cfgval_out) {
    uint16_t off = 0;
    int in_stream_if = 0;
    int have_format = 0;
    uint8_t ifnum = 0;
    uint8_t alt = 0;
    uint8_t channels = 2;
    uint8_t subframe = 2;
    uint32_t rate = 48000u;
    uint8_t best_iface = 0;
    uint8_t best_alt = 0;
    uint8_t best_ep = 0;
    uint8_t best_interval = 1;
    uint16_t best_mps = 0;
    uint8_t best_channels = 2;
    uint8_t best_subframe = 2;
    uint32_t best_rate = 48000u;

    if (!slot || !cfg || len < sizeof(usb_cfg_desc_t)) return -1;
    if (cfgval_out) *cfgval_out = ((const usb_cfg_desc_t *)cfg)->bConfigurationValue;
    slot->uac_ready = 0;

    while (off + 2 <= len) {
        uint8_t dlen = cfg[off];
        uint8_t dtype = cfg[off + 1];
        if (dlen < 2 || off + dlen > len) break;
        if (dtype == 4 && dlen >= sizeof(usb_if_desc_t)) {
            const usb_if_desc_t *id = (const usb_if_desc_t *)(cfg + off);
            xhci_log_interface_coverage(slot->slot_id, id);
            ifnum = id->bInterfaceNumber;
            alt = id->bAlternateSetting;
            in_stream_if = (id->bInterfaceClass == USB_CLASS_AUDIO &&
                            id->bInterfaceSubClass == USB_AUDIO_SUBCLASS_STREAMING &&
                            id->bNumEndpoints != 0);
            have_format = 0;
            channels = 2;
            subframe = 2;
            rate = 48000u;
        } else if (dtype == USB_DT_CS_INTERFACE && dlen >= 8u && in_stream_if) {
            uint8_t subtype = cfg[off + 2];
            if (subtype == USB_AS_FORMAT_TYPE && cfg[off + 3] == USB_AUDIO_FORMAT_TYPE_I) {
                uint8_t nr_freq;
                channels = cfg[off + 4] ? cfg[off + 4] : 2u;
                subframe = cfg[off + 5] ? cfg[off + 5] : 2u;
                nr_freq = cfg[off + 7];
                if (nr_freq == 0 && dlen >= 14u) {
                    uint32_t min_rate = xhci_uac_rate24(cfg + off + 8);
                    uint32_t max_rate = xhci_uac_rate24(cfg + off + 11);
                    if (min_rate <= 48000u && max_rate >= 48000u) rate = 48000u;
                    else rate = min_rate ? min_rate : 48000u;
                } else if (nr_freq != 0 && dlen >= (uint8_t)(8u + nr_freq * 3u)) {
                    uint32_t first = xhci_uac_rate24(cfg + off + 8);
                    rate = first ? first : 48000u;
                    for (uint8_t i = 0; i < nr_freq; ++i) {
                        uint32_t r = xhci_uac_rate24(cfg + off + 8u + (uint16_t)i * 3u);
                        if (r == 48000u) {
                            rate = 48000u;
                            break;
                        }
                    }
                }
                have_format = 1;
            }
        } else if (dtype == 5 && dlen >= sizeof(usb_ep_desc_t) && in_stream_if) {
            const usb_ep_desc_t *ep = (const usb_ep_desc_t *)(cfg + off);
            if ((ep->bEndpointAddress & 0x80u) == 0 && ((ep->bmAttributes & 0x03u) == 0x01u)) {
                uint16_t mps = xhci_ep_mps(ep->wMaxPacketSize, 192u);
                if (have_format && channels >= 1u && channels <= 8u && subframe >= 1u && subframe <= 4u && mps != 0) {
                    best_iface = ifnum;
                    best_alt = alt;
                    best_ep = ep->bEndpointAddress;
                    best_interval = ep->bInterval ? ep->bInterval : 1u;
                    best_mps = mps;
                    best_channels = channels;
                    best_subframe = subframe;
                    best_rate = rate ? rate : 48000u;
                    break;
                }
            }
        }
        off += dlen;
    }

    if (best_ep == 0 || best_alt == 0) return -1;
    slot->interface_class = USB_CLASS_AUDIO;
    slot->interface_subclass = USB_AUDIO_SUBCLASS_STREAMING;
    slot->interface_protocol = 0;
    slot->interface_number = best_iface;
    slot->uac_iface = best_iface;
    slot->uac_alt = best_alt;
    slot->uac_ep_addr = best_ep;
    slot->uac_ep_dci = (uint8_t)((best_ep & 0x0Fu) * 2u);
    slot->uac_interval = best_interval;
    slot->uac_max_packet = best_mps;
    slot->uac_channels = best_channels;
    slot->uac_subframe_size = best_subframe;
    slot->uac_rate = best_rate;
    slot->uac_packet_bytes = (uint16_t)(((best_rate / 1000u) ? (best_rate / 1000u) : 48u) *
                                        (uint32_t)best_channels * (uint32_t)best_subframe);
    if (slot->uac_packet_bytes == 0 || slot->uac_packet_bytes > best_mps) slot->uac_packet_bytes = best_mps;
    return 0;
}
#endif

static int xhci_apply_qemu_boot_hid_fallback(xhci_slot_state_t *slot,
                                             const usb_dev_desc_t *dd,
                                             const uint8_t *cfg_hdr,
                                             uint16_t total) {
    if (!slot || !dd || !cfg_hdr || total != 34u) return -1;
    if (dd->idVendor != USB_QEMU_VENDOR_ID) return -1;

    /*
     * QEMU's simple boot HID devices use one boot-protocol interface and one
     * interrupt IN endpoint.  Some versions/controllers can complete the
     * 9-byte config header read but then never complete the exact full-length
     * descriptor request for the mouse.  Linux handles many devices through
     * small hardware quirks; keep this constrained to QEMU's vendor ID and the
     * classic 34-byte boot HID config layout so real hardware still follows
     * descriptor parsing.
     */
    slot->hid_iface = 0;
    slot->hid_ep_addr = 0x81u;
    slot->hid_ep_dci = 3u;
    slot->hid_interval = 7u;
    slot->hid_max_packet = 8u;
    slot->hid_protocol = (slot->slot_id == 1u) ? 1u : 2u;
    slot->interface_class = USB_CLASS_HID;
    slot->interface_subclass = 1u;
    slot->interface_protocol = slot->hid_protocol;
    slot->interface_number = 0;
    if (cfg_hdr[5] == 0) return -1;
    return 0;
}

#ifdef CONFIG_USB_STORAGE
static int xhci_mass_test_unit_ready(xhci_controller_t *xc, xhci_slot_state_t *slot) {
    uint8_t cdb[6];
    memset(cdb, 0, sizeof(cdb));
    cdb[0] = SCSI_TEST_UNIT_READY;
    return xhci_mass_scsi(xc, slot, cdb, sizeof(cdb), 0, 0, USB_MSC_DATA_OUT);
}

static int xhci_mass_inquiry(xhci_controller_t *xc, xhci_slot_state_t *slot) {
    uint8_t cdb[6];
    uint8_t data[36];
    memset(cdb, 0, sizeof(cdb));
    memset(data, 0, sizeof(data));
    cdb[0] = SCSI_INQUIRY;
    cdb[4] = sizeof(data);
    if (xhci_mass_scsi(xc, slot, cdb, sizeof(cdb), data, sizeof(data), USB_MSC_DATA_IN) < 0) return -1;
    printf("[usb-storage] inquiry slot=%u vendor='%c%c%c%c%c%c%c%c' product='%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c'\n",
           (uint32_t)slot->slot_id,
           data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
           data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
           data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31]);
    return 0;
}

static int xhci_mass_read_capacity(xhci_controller_t *xc, xhci_slot_state_t *slot) {
    uint8_t cdb[10];
    uint8_t data[8];
    uint32_t last_lba;
    uint32_t block_len;
    memset(cdb, 0, sizeof(cdb));
    memset(data, 0, sizeof(data));
    cdb[0] = SCSI_READ_CAPACITY_10;
    if (xhci_mass_scsi(xc, slot, cdb, sizeof(cdb), data, sizeof(data), USB_MSC_DATA_IN) < 0) return -1;
    last_lba = xhci_be32_get(data);
    block_len = xhci_be32_get(data + 4);
    if (block_len == 0 || block_len > 4096u) return -1;
    slot->mass_sector_size = block_len;
    slot->mass_sector_count = last_lba + 1u;
    if (slot->mass_sector_count == 0) return -1;
    return 0;
}

static int xhci_configure_mass_storage(xhci_controller_t *xc, xhci_slot_state_t *slot) {
    usb_dev_desc_t dd;
    uint8_t cfg_hdr[9];
    uint8_t cfg_buf[256];
    uint16_t total;
    uint8_t cfgval = 1;
    uint64_t *dcbaa;
    if (!xc || !slot) return -1;
    memset(&dd, 0, sizeof(dd));
    if (xhci_control_transfer(xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR, (uint16_t)(USB_DT_DEVICE << 8), 0, &dd, sizeof(dd)) < 0) {
        return -1;
    }
    slot->vendor_id = dd.idVendor;
    slot->product_id = dd.idProduct;
    slot->bcd_device = dd.bcdDevice;
    slot->device_class = dd.bDeviceClass;
    slot->device_subclass = dd.bDeviceSubClass;
    slot->device_protocol = dd.bDeviceProtocol;

    memset(cfg_hdr, 0, sizeof(cfg_hdr));
    if (xhci_control_transfer(xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR, (uint16_t)(USB_DT_CONFIG << 8), 0, cfg_hdr, sizeof(cfg_hdr)) < 0) {
        return -1;
    }
    total = (uint16_t)cfg_hdr[2] | ((uint16_t)cfg_hdr[3] << 8);
    if (total < sizeof(cfg_hdr)) total = sizeof(cfg_hdr);
    if (total > sizeof(cfg_buf)) total = sizeof(cfg_buf);
    memset(cfg_buf, 0, sizeof(cfg_buf));
    if (xhci_control_transfer(xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR, (uint16_t)(USB_DT_CONFIG << 8), 0, cfg_buf, total) < 0) return -1;
    if (xhci_parse_mass_config(slot, cfg_buf, total, &cfgval) < 0) return -1;

    if (xhci_control_transfer(xc, slot, 0x00u, USB_REQ_SET_CONFIGURATION, cfgval, 0, 0, 0) < 0) {
        printf("[usb-storage] slot=%u SET_CONFIGURATION(%u) failed\n",
               (uint32_t)slot->slot_id, (uint32_t)cfgval);
        return -1;
    }
    slot->config_value = cfgval;

    if (!slot->mass_in_ring.vaddr &&
        usb_dma_alloc_zero_boundary(64u * sizeof(xhci_trb_t), 64u,
                                    XHCI_RING_BOUNDARY,
                                    &slot->mass_in_ring) < 0) return -1;
    if (!slot->mass_out_ring.vaddr &&
        usb_dma_alloc_zero_boundary(64u * sizeof(xhci_trb_t), 64u,
                                    XHCI_RING_BOUNDARY,
                                    &slot->mass_out_ring) < 0) return -1;
    if (!slot->mass_cbw.vaddr &&
        usb_dma_alloc_zero_boundary(64u, 64u, XHCI_RING_BOUNDARY,
                                    &slot->mass_cbw) < 0) return -1;
    if (!slot->mass_csw.vaddr &&
        usb_dma_alloc_zero_boundary(64u, 64u, XHCI_RING_BOUNDARY,
                                    &slot->mass_csw) < 0) return -1;
    if (!slot->mass_data.vaddr &&
        usb_dma_alloc_zero_boundary(USB_MSC_MAX_DMA_BYTES, 64u,
                                    XHCI_RING_BOUNDARY,
                                    &slot->mass_data) < 0) return -1;
    xhci_ring_init(&slot->mass_in_ring, &slot->mass_in_enq, &slot->mass_in_ccs);
    xhci_ring_init(&slot->mass_out_ring, &slot->mass_out_enq, &slot->mass_out_ccs);
    xhci_build_mass_config_input_ctx(xc, slot, 0);
    dcbaa = (uint64_t *)xc->dcbaa.vaddr;
    dcbaa[slot->slot_id] = (uint64_t)slot->device_ctx.paddr;
    if (xhci_cmd_submit_wait(xc, slot->input_ctx.paddr, 0, 0,
                             ((uint32_t)XHCI_TRB_TYPE_CONFIGURE_EP << 10) | ((uint32_t)slot->slot_id << 24), 0) < 0) {
        xhci_build_mass_config_input_ctx(xc, slot, 1);
        if (xhci_cmd_submit_wait(xc, slot->input_ctx.paddr, 0, 0,
                                 ((uint32_t)XHCI_TRB_TYPE_CONFIGURE_EP << 10) | ((uint32_t)slot->slot_id << 24), 0) < 0) {
            printf("[usb-storage] slot=%u Configure Endpoint failed\n", (uint32_t)slot->slot_id);
            return -1;
        }
    }

    slot->mass_ready = 1;
    for (uint32_t retry = 0; retry < 8u; ++retry) {
        if (xhci_mass_test_unit_ready(xc, slot) == 0) break;
        xhci_wait_us(XHCI_MASS_RETRY_US);
    }
    (void)xhci_mass_inquiry(xc, slot);
    if (xhci_mass_read_capacity(xc, slot) < 0) {
        slot->mass_ready = 0;
        return -1;
    }
    printf("[usb-storage] configured slot=%u iface=%u in=0x%02x out=0x%02x sectors=%u sector_size=%u\n",
           (uint32_t)slot->slot_id, (uint32_t)slot->mass_iface,
           (uint32_t)slot->mass_bulk_in_addr, (uint32_t)slot->mass_bulk_out_addr,
           slot->mass_sector_count, slot->mass_sector_size);
    return 0;
}
#endif

#ifdef CONFIG_USB_AUDIO
static int xhci_configure_uac_audio(xhci_controller_t *xc, xhci_slot_state_t *slot) {
    usb_dev_desc_t dd;
    uint8_t cfg_hdr[9];
    uint8_t cfg_buf[512];
    uint16_t total;
    uint8_t cfgval = 1;
    uint64_t *dcbaa;
    struct audio_backend backend;

    if (!xc || !slot) return -1;
    memset(&dd, 0, sizeof(dd));
    if (xhci_control_transfer(xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR, (uint16_t)(USB_DT_DEVICE << 8), 0, &dd, sizeof(dd)) < 0) {
        return -1;
    }
    slot->vendor_id = dd.idVendor;
    slot->product_id = dd.idProduct;
    slot->bcd_device = dd.bcdDevice;
    slot->device_class = dd.bDeviceClass;
    slot->device_subclass = dd.bDeviceSubClass;
    slot->device_protocol = dd.bDeviceProtocol;

    memset(cfg_hdr, 0, sizeof(cfg_hdr));
    if (xhci_control_transfer(xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR, (uint16_t)(USB_DT_CONFIG << 8), 0, cfg_hdr, sizeof(cfg_hdr)) < 0) {
        return -1;
    }
    total = (uint16_t)cfg_hdr[2] | ((uint16_t)cfg_hdr[3] << 8);
    if (total < sizeof(cfg_hdr)) total = sizeof(cfg_hdr);
    if (total > sizeof(cfg_buf)) total = sizeof(cfg_buf);
    memset(cfg_buf, 0, sizeof(cfg_buf));
    if (xhci_control_transfer(xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR, (uint16_t)(USB_DT_CONFIG << 8), 0, cfg_buf, total) < 0) return -1;
    if (xhci_parse_uac_config(slot, cfg_buf, total, &cfgval) < 0) return -1;

    if (xhci_control_transfer(xc, slot, 0x00u, USB_REQ_SET_CONFIGURATION, cfgval, 0, 0, 0) < 0) {
        printf("[usb-audio] slot=%u SET_CONFIGURATION(%u) failed\n",
               (uint32_t)slot->slot_id, (uint32_t)cfgval);
        return -1;
    }
    slot->config_value = cfgval;

    if (xhci_control_transfer(xc, slot, 0x01u, USB_REQ_SET_INTERFACE,
                              slot->uac_alt, slot->uac_iface, 0, 0) < 0) {
        printf("[usb-audio] slot=%u SET_INTERFACE iface=%u alt=%u failed\n",
               (uint32_t)slot->slot_id, (uint32_t)slot->uac_iface, (uint32_t)slot->uac_alt);
        return -1;
    }

    if (!slot->uac_ring.vaddr &&
        usb_dma_alloc_zero_boundary(128u * sizeof(xhci_trb_t), 64u,
                                    XHCI_RING_BOUNDARY,
                                    &slot->uac_ring) < 0) return -1;
    if (!slot->uac_data.vaddr &&
        usb_dma_alloc_zero_boundary(
            slot->uac_max_packet ? slot->uac_max_packet : 1024u, 64u,
            XHCI_RING_BOUNDARY, &slot->uac_data) < 0) return -1;
    xhci_ring_init(&slot->uac_ring, &slot->uac_enq, &slot->uac_ccs);
    xhci_build_uac_config_input_ctx(xc, slot, 0);
    dcbaa = (uint64_t *)xc->dcbaa.vaddr;
    dcbaa[slot->slot_id] = (uint64_t)slot->device_ctx.paddr;

    printf("[usb-audio] cfgep slot=%u iface=%u alt=%u ep=0x%02x dci=%u mps=%u pkt=%u rate=%u ch=%u subframe=%u\n",
           (uint32_t)slot->slot_id, (uint32_t)slot->uac_iface, (uint32_t)slot->uac_alt,
           (uint32_t)slot->uac_ep_addr, (uint32_t)slot->uac_ep_dci,
           (uint32_t)slot->uac_max_packet, (uint32_t)slot->uac_packet_bytes,
           slot->uac_rate, (uint32_t)slot->uac_channels, (uint32_t)slot->uac_subframe_size);

    if (xhci_cmd_submit_wait(xc, slot->input_ctx.paddr, 0, 0,
                             ((uint32_t)XHCI_TRB_TYPE_CONFIGURE_EP << 10) | ((uint32_t)slot->slot_id << 24), 0) < 0) {
        xhci_build_uac_config_input_ctx(xc, slot, 1);
        if (xhci_cmd_submit_wait(xc, slot->input_ctx.paddr, 0, 0,
                                 ((uint32_t)XHCI_TRB_TYPE_CONFIGURE_EP << 10) | ((uint32_t)slot->slot_id << 24), 0) < 0) {
            printf("[usb-audio] slot=%u Configure Endpoint failed\n", (uint32_t)slot->slot_id);
            return -1;
        }
    }

    slot->uac_ready = 1;
    g_uac_xc = xc;
    g_uac_slot = slot;
    g_uac_pcm_len = 0;
    memset(&backend, 0, sizeof(backend));
    backend.name = "USB Audio Class";
    backend.kind = AUDIO_BACKEND_UAC;
    backend.write_pcm = xhci_uac_write_pcm_backend;
    if (audio_register_backend(&backend) < 0 && !audio_available()) return -1;
    printf("[usb-audio] configured slot=%u iface=%u alt=%u endpoint=0x%02x rate=%u format=s%ule-%uch\n",
           (uint32_t)slot->slot_id, (uint32_t)slot->uac_iface, (uint32_t)slot->uac_alt,
           (uint32_t)slot->uac_ep_addr, slot->uac_rate,
           (uint32_t)(slot->uac_subframe_size * 8u), (uint32_t)slot->uac_channels);
    return 0;
}
#endif

#ifdef CONFIG_USB_UVC
static int xhci_config_has_uvc(uint8_t slot_id, const uint8_t *cfg, uint16_t len, uint8_t *cfgval_out) {
    uint16_t off = 0;
    int have_control = 0;
    int have_stream = 0;
    if (!cfg || len < sizeof(usb_cfg_desc_t)) return 0;
    if (cfgval_out) *cfgval_out = ((const usb_cfg_desc_t *)cfg)->bConfigurationValue;
    while (off + 2u <= len) {
        uint8_t dlen = cfg[off];
        uint8_t dtype = cfg[off + 1u];
        if (dlen < 2u || off + dlen > len) break;
        if (dtype == 4u && dlen >= sizeof(usb_if_desc_t)) {
            const usb_if_desc_t *id = (const usb_if_desc_t *)(cfg + off);
            xhci_log_interface_coverage(slot_id, id);
            if (id->bInterfaceClass == USB_CLASS_VIDEO && id->bInterfaceSubClass == USB_VIDEO_SUBCLASS_CONTROL) {
                have_control = 1;
            } else if (id->bInterfaceClass == USB_CLASS_VIDEO && id->bInterfaceSubClass == USB_VIDEO_SUBCLASS_STREAMING) {
                have_stream = 1;
            }
        }
        off += dlen;
    }
    return have_control && have_stream;
}

static int xhci_configure_uvc_video(xhci_controller_t *xc, xhci_slot_state_t *slot) {
    usb_dev_desc_t dd;
    uint8_t cfg_hdr[9];
    uint8_t cfg_buf[1024];
    uint16_t total;
    uint8_t cfgval = 1;
    if (!xc || !slot) return -1;
    memset(&dd, 0, sizeof(dd));
    if (xhci_control_transfer(xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR,
                              (uint16_t)(USB_DT_DEVICE << 8), 0, &dd, sizeof(dd)) < 0) {
        return -1;
    }
    slot->vendor_id = dd.idVendor;
    slot->product_id = dd.idProduct;
    slot->bcd_device = dd.bcdDevice;
    slot->device_class = dd.bDeviceClass;
    slot->device_subclass = dd.bDeviceSubClass;
    slot->device_protocol = dd.bDeviceProtocol;

    memset(cfg_hdr, 0, sizeof(cfg_hdr));
    if (xhci_control_transfer(xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR,
                              (uint16_t)(USB_DT_CONFIG << 8), 0, cfg_hdr, sizeof(cfg_hdr)) < 0) {
        return -1;
    }
    total = (uint16_t)cfg_hdr[2] | ((uint16_t)cfg_hdr[3] << 8);
    if (total < sizeof(cfg_hdr)) total = sizeof(cfg_hdr);
    if (total > sizeof(cfg_buf)) total = sizeof(cfg_buf);
    memset(cfg_buf, 0, sizeof(cfg_buf));
    if (xhci_control_transfer(xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR,
                              (uint16_t)(USB_DT_CONFIG << 8), 0, cfg_buf, total) < 0) {
        return -1;
    }
    if (!xhci_config_has_uvc(slot->slot_id, cfg_buf, total, &cfgval)) return -1;
    if (xhci_control_transfer(xc, slot, 0x00u, USB_REQ_SET_CONFIGURATION,
                              cfgval, 0, 0, 0) < 0) {
        printf("[uvc] slot=%u SET_CONFIGURATION(%u) failed\n",
               (uint32_t)slot->slot_id, (uint32_t)cfgval);
        return -1;
    }
    slot->config_value = cfgval;
    if (uvc_register_from_usb_config("xhci", slot->slot_id, dd.idVendor,
                                     dd.idProduct, cfg_buf, total) < 0) {
        return -1;
    }
    slot->interface_class = USB_CLASS_VIDEO;
    slot->interface_subclass = USB_VIDEO_SUBCLASS_STREAMING;
    slot->interface_protocol = 0;
    return 0;
}
#endif

static int xhci_configure_hid(xhci_controller_t *xc, xhci_slot_state_t *slot) {
    usb_dev_desc_t dd;
    uint8_t cfg_hdr[9];
    uint8_t cfg_buf[256];
    uint16_t total;
    uint8_t report_descriptor[512];
    uint16_t report_descriptor_length = 0;
    uint8_t cfgval = 1;
    uint64_t *dcbaa;
    if (!xc || !slot) return -1;
    memset(&dd, 0, sizeof(dd));
    if (xhci_control_transfer(xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR, (uint16_t)(USB_DT_DEVICE << 8), 0, &dd, sizeof(dd)) < 0) {
        printf("[usb][xhci] slot=%u GET_DESCRIPTOR(device) failed\n", (uint32_t)slot->slot_id);
        return -1;
    }
    slot->vendor_id = dd.idVendor;
    slot->product_id = dd.idProduct;
    slot->bcd_device = dd.bcdDevice;
    slot->device_class = dd.bDeviceClass;
    slot->device_subclass = dd.bDeviceSubClass;
    slot->device_protocol = dd.bDeviceProtocol;
    memset(cfg_hdr, 0, sizeof(cfg_hdr));
    if (xhci_control_transfer(xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR, (uint16_t)(USB_DT_CONFIG << 8), 0, cfg_hdr, sizeof(cfg_hdr)) < 0) {
        printf("[usb][xhci] slot=%u GET_DESCRIPTOR(config hdr) failed\n", (uint32_t)slot->slot_id);
        return -1;
    }
    total = (uint16_t)cfg_hdr[2] | ((uint16_t)cfg_hdr[3] << 8);
    if (total < sizeof(cfg_hdr)) total = sizeof(cfg_hdr);
    if (total > sizeof(cfg_buf)) total = sizeof(cfg_buf);
    memset(cfg_buf, 0, sizeof(cfg_buf));
    if (xhci_control_transfer(xc, slot, 0x80u, USB_REQ_GET_DESCRIPTOR, (uint16_t)(USB_DT_CONFIG << 8), 0, cfg_buf, total) < 0) {
        printf("[usb][xhci] slot=%u GET_DESCRIPTOR(config %u) failed\n",
               (uint32_t)slot->slot_id, (uint32_t)total);
        if (xhci_apply_qemu_boot_hid_fallback(slot, &dd, cfg_hdr, total) < 0) return -1;
        cfgval = cfg_hdr[5];
        printf("[usb][xhci] slot=%u using QEMU boot HID fallback proto=%u\n",
               (uint32_t)slot->slot_id, (uint32_t)slot->hid_protocol);
    } else if (xhci_parse_hid_config(slot, cfg_buf, total, &cfgval) < 0) {
        printf("[usb][xhci] slot=%u no HID interrupt interface found\n",
               (uint32_t)slot->slot_id);
        return -1;
    }

    /*
     * Keep EP0-only USB setup before adding the interrupt endpoint to the host
     * controller context.  The old order issued Configure Endpoint first, then
     * tried SET_CONFIGURATION/SET_PROTOCOL on EP0.  QEMU xHCI and real
     * controllers are allowed to re-evaluate endpoint context state during
     * Configure Endpoint; sending more control transfers immediately after
     * that can leave the boot HID device wedged with no Transfer Event.  This
     * mirrors the mature USB-stack ordering used by production kernels:
     * select the device configuration over EP0, send HID boot-protocol setup,
     * then expose the interrupt pipe to the xHCI scheduler.
     */
    if (xhci_control_transfer(xc, slot, 0x00u, USB_REQ_SET_CONFIGURATION, cfgval, 0, 0, 0) < 0) {
        printf("[usb][xhci] slot=%u SET_CONFIGURATION(%u) failed\n",
               (uint32_t)slot->slot_id, (uint32_t)cfgval);
        return -1;
    }
    slot->config_value = cfgval;
    if (slot->interface_subclass == 1u &&
        (slot->interface_protocol == 1u ||
         slot->interface_protocol == 2u)) {
        (void)xhci_control_transfer(
            xc, slot, 0x21u, 0x0Bu, 0u, slot->hid_iface, 0, 0);
    } else {
        report_descriptor_length = slot->hid_report_descriptor_length;
        if (report_descriptor_length == 0u ||
            report_descriptor_length > sizeof(report_descriptor)) {
            printf("[usb][xhci] slot=%u unsupported HID report descriptor length=%u\n",
                   (uint32_t)slot->slot_id,
                   (uint32_t)report_descriptor_length);
            return -1;
        }
        memset(report_descriptor, 0, sizeof(report_descriptor));
        if (xhci_control_transfer(
                xc, slot, 0x81u, USB_REQ_GET_DESCRIPTOR,
                (uint16_t)(USB_DT_HID_REPORT << 8), slot->hid_iface,
                report_descriptor, report_descriptor_length) < 0 ||
            xhci_hid_pointer_layout_parse(
                report_descriptor, report_descriptor_length,
                &slot->hid_pointer_layout) < 0) {
            printf("[usb][xhci] slot=%u unsupported HID report layout\n",
                   (uint32_t)slot->slot_id);
            return -1;
        }
        slot->hid_report_mode = 1;
        slot->hid_protocol = 2u;
        printf("[usb][xhci] slot=%u HID report mouse id=%u x=%u/%u y=%u/%u wheel=%u/%u\n",
               (uint32_t)slot->slot_id,
               (uint32_t)slot->hid_pointer_layout.report_id,
               (uint32_t)slot->hid_pointer_layout.x_offset,
               (uint32_t)slot->hid_pointer_layout.x_size,
               (uint32_t)slot->hid_pointer_layout.y_offset,
               (uint32_t)slot->hid_pointer_layout.y_size,
               (uint32_t)slot->hid_pointer_layout.wheel_offset,
               (uint32_t)slot->hid_pointer_layout.wheel_size);
    }
    (void)xhci_control_transfer(xc, slot, 0x21u, USB_REQ_SET_IDLE, 0u, slot->hid_iface, 0, 0);

    if (!slot->intr_ring.vaddr &&
        usb_dma_alloc_zero_boundary(32u * sizeof(xhci_trb_t), 64u,
                                    XHCI_RING_BOUNDARY,
                                    &slot->intr_ring) < 0) return -1;
    if (!slot->intr_buf.vaddr &&
        usb_dma_alloc_zero_boundary(slot->hid_max_packet, 64u,
                                    XHCI_RING_BOUNDARY,
                                    &slot->intr_buf) < 0) return -1;
    xhci_ring_init(&slot->intr_ring, &slot->intr_enq, &slot->intr_ccs);
    xhci_build_config_input_ctx(xc, slot, 0);
    dcbaa = (uint64_t *)xc->dcbaa.vaddr;
    dcbaa[slot->slot_id] = (uint64_t)slot->device_ctx.paddr;
    printf("[usb][xhci] cfgep slot=%u dci=%u interval=%u mps=%u ring=0x%x mode=%u\n",
           (uint32_t)slot->slot_id, (uint32_t)slot->hid_ep_dci, (uint32_t)slot->hid_interval,
           (uint32_t)slot->hid_max_packet, slot->intr_ring.paddr, 0u);

    if (xhci_cmd_submit_wait(xc, slot->input_ctx.paddr, 0, 0,
                             ((uint32_t)XHCI_TRB_TYPE_CONFIGURE_EP << 10) | ((uint32_t)slot->slot_id << 24), 0) < 0) {
        xhci_build_config_input_ctx(xc, slot, 1);
        printf("[usb][xhci] cfgep slot=%u dci=%u interval=%u mps=%u ring=0x%x mode=%u\n",
               (uint32_t)slot->slot_id, (uint32_t)slot->hid_ep_dci, (uint32_t)slot->hid_interval,
               (uint32_t)slot->hid_max_packet, slot->intr_ring.paddr, 1u);
        if (xhci_cmd_submit_wait(xc, slot->input_ctx.paddr, 0, 0,
                                 ((uint32_t)XHCI_TRB_TYPE_CONFIGURE_EP << 10) | ((uint32_t)slot->slot_id << 24), 0) < 0) {
            printf("[usb][xhci] slot=%u Configure Endpoint failed\n", (uint32_t)slot->slot_id);
            return -1;
        }
    }
    slot->hid_ready = 1;
    printf("[usb][xhci] HID device configured slot=%u iface=%u proto=%u ep=0x%02x mps=%u interval=%u\n",
           (uint32_t)slot->slot_id, (uint32_t)slot->hid_iface, (uint32_t)slot->hid_protocol,
           (uint32_t)slot->hid_ep_addr, (uint32_t)slot->hid_max_packet, (uint32_t)slot->hid_interval);
    if (xhci_hid_rearm_interrupt(xc, slot) == 0) {
        static const char *const physical_paths[EDGE_INPUT_DEVICE_MAX] = {
            "usb-xhci/input0", "usb-xhci/input1"
        };
        uint32_t event_index = slot->hid_protocol == 1u ?
                               EDGE_INPUT_KEYBOARD : EDGE_INPUT_POINTER;
        input_device_description_t *description =
            &xc->input_description[event_index];
        if (slot->hid_protocol == 1u) {
            input_device_describe_keyboard(
                description, "USB HID Keyboard", physical_paths[event_index],
                "usbhid", 0x03u, slot->vendor_id, slot->product_id,
                slot->bcd_device);
        } else {
            input_device_describe_pointer(
                description, "USB HID Mouse", physical_paths[event_index],
                "usbhid", 0x03u, slot->vendor_id, slot->product_id,
                slot->bcd_device, 0);
        }
        if (input_device_register(event_index, description, slot) < 0) {
            printf("[usb][xhci] input event%u already owned by another backend\n",
                   event_index);
        }
        printf("[usb][xhci] interrupt endpoint active slot=%u dci=%u\n",
               (uint32_t)slot->slot_id, (uint32_t)slot->hid_ep_dci);
    } else {
        slot->hid_ready = 0;
        printf("[usb][xhci] slot=%u failed to arm HID interrupt endpoint\n",
               (uint32_t)slot->slot_id);
        return -1;
    }
    return 0;
}

static int xhci_configure_device(xhci_controller_t *xc, xhci_slot_state_t *slot) {
    uint32_t candidates;
    int attempted = 0;
    int failed = 0;

    if (!xc || !slot) return -1;
    if (xhci_identify_device(xc, slot, &candidates) < 0) return -1;
#if defined(CONFIG_USB_ETH_ASIX) || defined(CONFIG_USB_ETH_RTL8153)
    if (candidates & XHCI_DEVICE_DRIVER_NETWORK) {
        int result;

        attempted = 1;
        result = xhci_configure_usbnet(xc, slot);
        if (result == XHCI_DEVICE_CONFIGURED) return result;
        if (result < 0) failed = 1;
    }
#endif
#ifdef CONFIG_USB_STORAGE
    if (candidates & XHCI_DEVICE_DRIVER_STORAGE) {
        attempted = 1;
        if (xhci_configure_mass_storage(xc, slot) == 0)
            return XHCI_DEVICE_CONFIGURED;
        failed = 1;
    }
#endif
#ifdef CONFIG_USB_AUDIO
    if (candidates & XHCI_DEVICE_DRIVER_AUDIO) {
        attempted = 1;
        if (xhci_configure_uac_audio(xc, slot) == 0)
            return XHCI_DEVICE_CONFIGURED;
        failed = 1;
    }
#endif
#ifdef CONFIG_USB_UVC
    if (candidates & XHCI_DEVICE_DRIVER_VIDEO) {
        attempted = 1;
        if (xhci_configure_uvc_video(xc, slot) == 0)
            return XHCI_DEVICE_CONFIGURED;
        failed = 1;
    }
#endif
    if (candidates & (XHCI_DEVICE_DRIVER_HID_BOOT |
                      XHCI_DEVICE_DRIVER_HID_REPORT)) {
        attempted = 1;
        if (xhci_configure_hid(xc, slot) == 0)
            return XHCI_DEVICE_CONFIGURED;
        failed = 1;
    }
    return attempted && failed ? -1 : XHCI_DEVICE_UNSUPPORTED;
}

static int xhci_disable_slot(xhci_controller_t *xc, uint8_t slot_id) {
    if (!xc || slot_id == 0) return -1;
    return xhci_cmd_submit_wait(xc, 0, 0, 0,
                                ((uint32_t)XHCI_TRB_TYPE_DISABLE_SLOT << 10) | ((uint32_t)slot_id << 24), 0);
}

static void xhci_mark_port_disconnected(xhci_controller_t *xc, uint8_t port_id) {
    uint8_t slot_id;
    xhci_slot_state_t *slot;
    if (!xc || port_id == 0 || port_id > xc->max_ports) return;
    slot_id = xc->port_to_slot[port_id];
    if (slot_id == 0) return;
    slot = xhci_slot_get(xc, slot_id);
    if (slot) {
        if (slot->hid_ready) {
            uint32_t event_index = slot->hid_protocol == 1u ?
                                   EDGE_INPUT_KEYBOARD : EDGE_INPUT_POINTER;
            (void)input_device_unregister(event_index, slot);
            slot->hid_ready = 0;
        }
#ifdef CONFIG_USB_AUDIO
        if (slot->uac_ready) {
            slot->uac_ready = 0;
            if (g_uac_slot == slot) {
                g_uac_slot = 0;
                g_uac_xc = 0;
                g_uac_pcm_len = 0;
                audio_unregister_backend(AUDIO_BACKEND_UAC);
            }
        }
#endif
        slot->online = 0;
    }
    (void)xhci_disable_slot(xc, slot_id);
    xc->port_to_slot[port_id] = 0;
    xc->port_retry_after_us[port_id] = 0;
    xc->port_failure_count[port_id] = 0;
    printf("[usb][xhci] device disconnected port=%u slot=%u\n", (uint32_t)port_id, (uint32_t)slot_id);
}

static void xhci_schedule_port_retry(xhci_controller_t *xc,
                                     uint8_t port_id) {
    uint8_t failures;
    uint64_t delay_us;

    if (!xc || port_id == 0 || port_id > xc->max_ports) return;
    failures = xc->port_failure_count[port_id];
    if (failures < 255u) ++failures;
    xc->port_failure_count[port_id] = failures;
    if (!xhci_device_retry_permitted(failures)) {
        xc->port_retry_after_us[port_id] = UINT64_MAX;
        printf("[usb][xhci] port=%u automatic retries exhausted; waiting for reconnect\n",
               (uint32_t)port_id);
        return;
    }
    delay_us = xhci_device_retry_delay_us(failures);
    xc->port_retry_after_us[port_id] =
        boottime_monotonic_us() + delay_us;
    printf("[usb][xhci] port=%u retry=%u delay_ms=%u\n",
           (uint32_t)port_id, (uint32_t)failures,
           (uint32_t)(delay_us / 1000u));
}

static int xhci_enumerate_root_port(xhci_controller_t *xc, uint8_t port_id) {
    uint32_t psc;
    uint8_t speed;
    uint8_t slot_id = 0;
    xhci_slot_state_t *slot;
    uint64_t *dcbaa;
    uint32_t ctx_bytes;
    int ret = -1;
    uint64_t now_us;
    if (!xc || !xc->op || port_id == 0 || port_id > xc->max_ports) return -1;
    now_us = boottime_monotonic_us();
    if (xc->port_retry_after_us[port_id] != 0 &&
        now_us < xc->port_retry_after_us[port_id]) return 0;
    if (xc->enum_busy) return 0;
    xc->enum_busy = 1;
    psc = mmio_read32(xc->op, XHCI_PORTSC_BASE + (uint32_t)(port_id - 1u) * XHCI_PORTSC_STRIDE);
    if ((psc & XHCI_PORTSC_CCS) == 0) {
        ret = 0;
        goto out;
    }
    if (xc->port_to_slot[port_id] != 0) {
        slot = xhci_slot_get(xc, xc->port_to_slot[port_id]);
        if (slot && slot->online) {
            ret = 0;
            goto out;
        }
    }
    /*
     * Reset newly-connected ports, but do not bounce an already-enabled port.
     * The init path has already powered and reset every connected root port
     * after the scheduler is running.  Resetting again immediately before
     * Enable Slot can race QEMU and some real controllers back to default
     * device state while the software ring is already preparing EP0 traffic.
     */
    if ((psc & XHCI_PORTSC_PED) == 0) {
        if (xhci_port_power_and_reset(xc, (uint8_t)(port_id - 1u)) < 0) {
            xhci_schedule_port_retry(xc, port_id);
            ret = 0;
            goto out;
        }
        psc = mmio_read32(xc->op, XHCI_PORTSC_BASE + (uint32_t)(port_id - 1u) * XHCI_PORTSC_STRIDE);
    }
    if ((psc & XHCI_PORTSC_CCS) == 0) {
        ret = 0;
        goto out;
    }
    if (xhci_cmd_submit_wait(xc, 0, 0, 0, (uint32_t)XHCI_TRB_TYPE_ENABLE_SLOT << 10, &slot_id) < 0) goto out;
    slot = xhci_slot_get(xc, slot_id);
    if (!slot) goto out;
    /*
     * Disable Slot permits the controller to reuse a slot identifier.  Keep
     * the fixed-size address-device DMA objects owned by that software slot;
     * dropping their references on every failed enumeration exhausts the
     * bounded DMA arena while a slow or faulty device is retried.
     */
    xhci_slot_reset_preserving_dma(slot);
    speed = xhci_port_speed(xc, port_id);
    slot->used = 1;
    slot->online = 1;
    slot->slot_id = slot_id;
    slot->port_id = port_id;
    slot->speed_id = speed;
    slot->max_packet0 = xhci_default_ep0_mps(speed);
    xc->port_to_slot[port_id] = slot_id;
    ctx_bytes = xhci_ctx_bytes(xc);
    if (!slot->input_ctx.vaddr &&
        usb_dma_alloc_zero_boundary(ctx_bytes * 33u, 64u, xc->page_size,
                                    &slot->input_ctx) < 0)
        goto fail;
    if (!slot->device_ctx.vaddr &&
        usb_dma_alloc_zero_boundary(ctx_bytes * 32u, 64u, xc->page_size,
                                    &slot->device_ctx) < 0)
        goto fail;
    if (!slot->ep0_ring.vaddr &&
        usb_dma_alloc_zero_boundary(32u * sizeof(xhci_trb_t), 64u,
                                    XHCI_RING_BOUNDARY,
                                    &slot->ep0_ring) < 0)
        goto fail;
    if (!slot->ctrl_buf.vaddr &&
        usb_dma_alloc_zero_boundary(1024u, 64u, XHCI_RING_BOUNDARY,
                                    &slot->ctrl_buf) < 0)
        goto fail;
    xhci_ring_init(&slot->ep0_ring, &slot->ep0_enq, &slot->ep0_ccs);
    xhci_build_address_input_ctx(xc, slot);
    dcbaa = (uint64_t *)xc->dcbaa.vaddr;
    dcbaa[slot_id] = (uint64_t)slot->device_ctx.paddr;
    if (xhci_cmd_submit_wait(xc, slot->input_ctx.paddr, 0, 0,
                             ((uint32_t)XHCI_TRB_TYPE_ADDRESS_DEVICE << 10) | ((uint32_t)slot_id << 24), 0) < 0) {
        goto fail;
    }
    xhci_wait_us(XHCI_ADDRESS_SETTLE_US);
    printf("[usb][xhci] device connected on port %u slot=%u speed=%u\n",
           (uint32_t)port_id, (uint32_t)slot_id, (uint32_t)speed);
    {
        int configuration = xhci_configure_device(xc, slot);

        if (configuration < 0) {
            printf("[usb][xhci] slot=%u device setup failed, retry scheduled\n",
                   (uint32_t)slot_id);
            goto fail;
        }
        if (configuration == XHCI_DEVICE_UNSUPPORTED) {
            printf("[usb][xhci] slot=%u enumerated without a matching built-in driver\n",
                   (uint32_t)slot_id);
        }
    }
    xc->port_retry_after_us[port_id] = 0;
    xc->port_failure_count[port_id] = 0;
    ret = 0;
    goto out;
fail:
    slot->online = 0;
    xc->port_to_slot[port_id] = 0;
    (void)xhci_disable_slot(xc, slot_id);
    /*
     * A failed EP0 transaction leaves the device-side default/configured state
     * ambiguous.  Production USB stacks recover this at the port/device level,
     * not by reusing the same half-initialized slot.  Reset the root port once
     * the controller is running so the next enumeration pass starts from a
     * clean device state and fresh xHCI slot context.
     */
    if (xc->running)
        (void)xhci_port_power_and_reset(xc,
                                        (uint8_t)(port_id - 1u));
    xhci_schedule_port_retry(xc, port_id);
    ret = -1;
out:
    if (ret < 0 && xc->port_retry_after_us[port_id] == 0)
        xhci_schedule_port_retry(xc, port_id);
    xc->enum_busy = 0;
    return ret;
}

static void xhci_enumerate_root_ports(xhci_controller_t *xc) {
    if (!xc || !xc->op) return;
    for (uint8_t pass = 0; pass < 4u; ++pass) {
        for (uint8_t p = 1; p <= xc->max_ports; ++p) {
            (void)xhci_enumerate_root_port(xc, p);
        }
    }
}

static void xhci_handle_transfer_event(xhci_controller_t *xc, xhci_trb_t *t) {
    uint8_t cc = (uint8_t)(t->status >> 24);
    uint8_t ep = (uint8_t)((t->control >> 16) & 0x1Fu);
    uint8_t slot_id = (uint8_t)(t->control >> 24);
    uint32_t rem = (t->status & 0x00FFFFFFu);
    uint64_t ptr = (uint64_t)t->lo | ((uint64_t)t->hi << 32);
    xhci_slot_state_t *slot = xhci_slot_get(xc, slot_id);
    if (xc->xfer_wait_ptr != 0 &&
        slot_id == xc->xfer_wait_slot &&
        ep == xc->xfer_wait_ep &&
        (ptr == xc->xfer_wait_ptr ||
         ptr == xc->xfer_wait_alt_ptr1 ||
         (xc->xfer_wait_alt_ptr2 != 0 && ptr == xc->xfer_wait_alt_ptr2)) &&
        xhci_control_event_is_terminal(ptr, xc->xfer_wait_ptr,
                                       xc->xfer_wait_alt_ptr1,
                                       xc->xfer_wait_alt_ptr2, cc)) {
        xc->xfer_wait_done = 1;
        xc->xfer_wait_cc = cc;
        xc->xfer_wait_slot = slot_id;
        xc->xfer_wait_ep = ep;
        return;
    }
    if (!slot || !slot->hid_ready || ep != slot->hid_ep_dci) return;
    /*
     * HID interrupt IN reports are commonly shorter than wMaxPacketSize
     * (for example QEMU boot mouse reports 4 bytes on an 8-byte endpoint).
     * xHCI reports that as Short Packet, not Success.  Linux treats this as a
     * completed transfer with a valid byte count; dropping it makes USB
     * keyboard/mouse devices enumerate but never deliver input to evdev/Xorg.
     *
     * Do not require the Transfer Event TRB Pointer to byte-match the last
     * queued interrupt TRB before accepting the report.  Some xHCI
     * implementations report equivalent ring positions differently around
     * wrapped or linked rings.  The slot id and endpoint DCI already constrain
     * this path to the boot HID interrupt endpoint, while control/bulk
     * transfers are handled above by the explicit wait path.
     */
    if (cc == XHCI_COMP_SUCCESS || cc == XHCI_COMP_SHORT_PACKET) {
        uint16_t n = slot->hid_max_packet;
        if (rem <= n) n = (uint16_t)(n - rem);
        if (slot->hid_report_mode) {
            int dx;
            int dy;
            int wheel;
            int wheel_present;
            uint8_t buttons;
            int decoded = xhci_hid_pointer_report_decode(
                &slot->hid_pointer_layout,
                (const uint8_t *)slot->intr_buf.vaddr, n,
                &dx, &dy, &wheel, &buttons, &wheel_present);
            if (decoded > 0)
                usb_hid_mouse_report(
                    dx, dy, wheel, buttons, wheel_present);
        } else if (slot->hid_protocol == 1) {
            usb_hid_process_boot_keyboard_report(
                (const uint8_t *)slot->intr_buf.vaddr, n);
        } else {
            usb_hid_process_boot_report(
                (const uint8_t *)slot->intr_buf.vaddr, n);
        }
    }
    (void)xhci_hid_rearm_interrupt(xc, slot);
}

static int xhci_consume_events(xhci_controller_t *xc) {
    volatile xhci_trb_t *evt;
    uint32_t budget = 128;
    int consumed = 0;
    if (!xc || !xc->rt || !xc->evt_ring.vaddr || xc->evt_ring_size == 0) return 0;
    evt = (volatile xhci_trb_t *)xc->evt_ring.vaddr;
    while (budget--) {
        volatile xhci_trb_t *source = &evt[xc->evt_deq];
        xhci_trb_t event;
        uint32_t ctrl = source->control;
        uint32_t type = (ctrl >> 10) & 0x3Fu;
        uint32_t c = ctrl & 1u;
        if (c != (uint32_t)(xc->evt_ccs & 1u)) break;
        __asm__ __volatile__("" ::: "memory");
        event.lo = source->lo;
        event.hi = source->hi;
        event.status = source->status;
        event.control = ctrl;
        consumed = 1;
        if (type == XHCI_TRB_TYPE_PORTSC_EVENT) {
            uint8_t port = (uint8_t)((event.lo >> 24) & 0xFFu);
            if (port > 0 && xc->op) {
                uint32_t off = XHCI_PORTSC_BASE + (uint32_t)(port - 1u) * XHCI_PORTSC_STRIDE;
                uint32_t psc = mmio_read32(xc->op, off);
                xc->port_change_pending = 1;
                xhci_portsc_clear_changes(xc, off, psc);
            }
        } else if (type == XHCI_TRB_TYPE_CMD_COMPLETION) {
            uint8_t cc = (uint8_t)(event.status >> 24);
            uint8_t slot_id = (uint8_t)(ctrl >> 24);
            uint64_t ptr = (uint64_t)event.lo | ((uint64_t)event.hi << 32);
            if (xc->cmd_wait_ptr != 0 && ptr == xc->cmd_wait_ptr) {
                xc->cmd_wait_done = 1;
                xc->cmd_wait_cc = cc;
                xc->cmd_wait_slot = slot_id;
            }
        } else if (type == XHCI_TRB_TYPE_TRANSFER_EVENT) {
            xhci_handle_transfer_event(xc, &event);
        }
        xc->evt_deq++;
        if (xc->evt_deq >= xc->evt_ring_size) {
            xc->evt_deq = 0;
            xc->evt_ccs ^= 1u;
        }
    }
    if (consumed) {
        uint64_t erdp = (uint64_t)xc->evt_ring.paddr + (uint64_t)xc->evt_deq * sizeof(xhci_trb_t);
        mmio_write64(xc->rt, XHCI_INTR_BASE + XHCI_ERDP, erdp | (1ull << 3));
    }
    return consumed;
}

static void xhci_poll_events(xhci_controller_t *xc) {
    uint32_t st;
    if (!xc || !xc->op) return;
    if (!xhci_consume_events(xc)) return;
    st = mmio_read32(xc->op, XHCI_USBSTS);
    if (st & XHCI_STS_EINT) mmio_write32(xc->op, XHCI_USBSTS, XHCI_STS_EINT);
}

static int xhci_cmd_submit_wait(xhci_controller_t *xc, uint32_t lo, uint32_t hi, uint32_t st, uint32_t ctrl, uint8_t *slot_out) {
    uint64_t ptr;
    if (!xc || !xc->running) {
        printf("[usb][xhci] command rejected ctrl=0x%x running=%u\n",
               ctrl, xc ? (uint32_t)xc->running : 0u);
        return -1;
    }
    ptr = xhci_ring_enqueue(&xc->cmd_ring, &xc->cmd_enq, &xc->cmd_ccs, lo, hi, st, ctrl);
    if (ptr == 0) {
        printf("[usb][xhci] command ring enqueue failed ctrl=0x%x ring=0x%x size=%u enq=%u\n",
               ctrl, xc->cmd_ring.paddr, xc->cmd_ring.size,
               (uint32_t)xc->cmd_enq);
        return -1;
    }
    xc->cmd_wait_ptr = ptr;
    xc->cmd_wait_done = 0;
    xc->cmd_wait_cc = 0;
    xc->cmd_wait_slot = 0;
    xhci_ring_doorbell(xc, 0, 0);
    uint64_t start_us = boottime_monotonic_us();
    do {
        xhci_poll_events(xc);
        if (xc->cmd_wait_done) break;
        xhci_wait_relax();
    } while (boottime_monotonic_us() - start_us < XHCI_COMMAND_TIMEOUT_US);
    xc->cmd_wait_ptr = 0;
    if (!xc->cmd_wait_done) {
        printf("[usb][xhci] command timeout ctrl=0x%x\n", ctrl);
        return -1;
    }
    if (xc->cmd_wait_cc != XHCI_COMP_SUCCESS) {
        printf("[usb][xhci] command failed cc=%u ctrl=0x%x\n",
               (uint32_t)xc->cmd_wait_cc, ctrl);
        return -1;
    }
    if (slot_out) *slot_out = xc->cmd_wait_slot;
    return 0;
}

int xhci_init_controller(xhci_controller_t *xc,
                         uint8_t bus, uint8_t dev, uint8_t fn,
                         uint16_t vendor, uint16_t device,
                         uint32_t bar0, uint32_t bar1, uint8_t irq_line) {
    uint64_t mmio_base = 0;
    uintptr_t mmio_va;
    uint16_t cmd;
    uint32_t hcs1, hcs2, hcc1;
    uint32_t dboff, rtsoff;
    uint32_t usbcmd, usbsts, page_size_mask;
    if (!xc) return -1;
    memset(xc, 0, sizeof(*xc));
    xc->bus = bus;
    xc->dev = dev;
    xc->fn = fn;
    xc->vendor = vendor;
    xc->device = device;
    xc->irq_line = irq_line;
    if ((bar0 & 1u) != 0) return -1;
    if ((bar0 & 0x6u) == 0x4u) mmio_base = (((uint64_t)bar1) << 32) | (uint64_t)(bar0 & ~0xFULL);
    else mmio_base = (uint64_t)(bar0 & ~0xFULL);
    if (mmio_base == 0 || mmio_base >= 0x0000800000000000ULL) {
        printf("[usb][xhci] invalid MMIO BAR 0x%llx\n", (unsigned long long)mmio_base);
        return -1;
    }
    if (!edge_mmio_phys_range_mapped(mmio_base, 0x10000ULL)) {
        printf("[usb][xhci] MMIO BAR 0x%llx is outside mapped MMIO apertures\n",
               (unsigned long long)mmio_base);
        return -1;
    }
    mmio_va = edge_mmio_low_alias(mmio_base);
    cmd = pci_cfg_read16(bus, dev, fn, 0x04);
    cmd |= 0x0002u;
    cmd |= 0x0004u;
    pci_cfg_write16(bus, dev, fn, 0x04, cmd);
    xc->mmio_base = mmio_base;
    xc->mmio = (volatile uint8_t *)mmio_va;
    xc->cap_len = mmio_read8(xc->mmio, 0x00);
    hcs1 = mmio_read32(xc->mmio, 0x04);
    hcs2 = mmio_read32(xc->mmio, XHCI_CAP_HCSPARAMS2);
    hcc1 = mmio_read32(xc->mmio, 0x10);
    dboff = mmio_read32(xc->mmio, XHCI_CAP_DBOFF) & ~0x3u;
    rtsoff = mmio_read32(xc->mmio, XHCI_CAP_RTSOFF) & ~0x1Fu;
    xc->max_ports = (uint8_t)((hcs1 >> 24) & 0xFFu);
    xc->max_slots = (uint8_t)(hcs1 & 0xFFu);
    xc->ext_cap_off = xhci_extended_capability_offset(hcc1);
    xc->ctx_sz64 = (uint8_t)((hcc1 >> 2) & 1u);
    xc->scratchpad_count = xhci_hcs2_scratchpad_count(hcs2);
    xc->op = xc->mmio + xc->cap_len;
    xc->rt = xc->mmio + rtsoff;
    xc->db = xc->mmio + dboff;
    xhci_legacy_handoff(xc);
    usbcmd = mmio_read32(xc->op, XHCI_USBCMD);
    usbcmd &= ~XHCI_CMD_RUN;
    mmio_write32(xc->op, XHCI_USBCMD, usbcmd);
    if (xhci_wait_u32(xc->op, XHCI_USBSTS, XHCI_STS_HCH, 1,
                      XHCI_CONTROLLER_TIMEOUT_US) < 0) {
        printf("[usb][xhci] controller failed to halt status=0x%x\n",
               mmio_read32(xc->op, XHCI_USBSTS));
        return -1;
    }
    usbcmd = mmio_read32(xc->op, XHCI_USBCMD);
    usbcmd |= XHCI_CMD_HCRST;
    mmio_write32(xc->op, XHCI_USBCMD, usbcmd);
    if (xhci_wait_u32(xc->op, XHCI_USBCMD, XHCI_CMD_HCRST, 0,
                      XHCI_CONTROLLER_TIMEOUT_US) < 0) {
        printf("[usb][xhci] controller reset timed out command=0x%x\n",
               mmio_read32(xc->op, XHCI_USBCMD));
        return -1;
    }
    if (xhci_wait_u32(xc->op, XHCI_USBSTS, XHCI_STS_HCH, 1,
                      XHCI_CONTROLLER_TIMEOUT_US) < 0 ||
        xhci_wait_u32(xc->op, XHCI_USBSTS, XHCI_STS_CNR, 0,
                      XHCI_CONTROLLER_TIMEOUT_US) < 0) {
        printf("[usb][xhci] controller not ready after reset status=0x%x\n",
               mmio_read32(xc->op, XHCI_USBSTS));
        return -1;
    }
    page_size_mask = mmio_read32(xc->op, XHCI_PAGESIZE) & 0xffffu;
    if (xhci_select_page_size(page_size_mask, &xc->page_size) < 0) {
        printf("[usb][xhci] controller has no supported page size mask=0x%x\n",
               page_size_mask);
        return -1;
    }
    if (xhci_setup_rings(xc) < 0 ||
        xhci_setup_scratchpads(xc) < 0) {
        printf("[usb][xhci] controller DMA setup failed scratchpads=%u page=%u dma=%u/%u\n",
               (uint32_t)xc->scratchpad_count, xc->page_size,
               usb_dma_bytes_used(), usb_dma_bytes_total());
        return -1;
    }
    usbsts = mmio_read32(xc->op, XHCI_USBSTS);
    mmio_write32(xc->op, XHCI_USBSTS, usbsts);
    mmio_write32(xc->op, XHCI_DNCTRL, 0);
    mmio_write32(xc->op, XHCI_CONFIG,
                 (uint32_t)(xc->max_slots < XHCI_MAX_TRACKED_SLOTS ?
                     xc->max_slots : XHCI_MAX_TRACKED_SLOTS));
    mmio_write64(xc->op, XHCI_DCBAAP, (uint64_t)xc->dcbaa.paddr);
    mmio_write64(xc->op, XHCI_DCBAAP, (uint64_t)xc->dcbaa.paddr);
    mmio_write64(xc->op, XHCI_CRCR, ((uint64_t)xc->cmd_ring.paddr & ~0x3FULL) | 1u);
    xhci_program_runtime(xc);
    usbcmd = mmio_read32(xc->op, XHCI_USBCMD);
    usbcmd = (usbcmd & ~XHCI_CMD_INTE) | XHCI_CMD_RUN;
    mmio_write32(xc->op, XHCI_USBCMD, usbcmd);
    if (xhci_wait_u32(xc->op, XHCI_USBSTS, XHCI_STS_HCH, 0,
                      XHCI_CONTROLLER_TIMEOUT_US) < 0) {
        printf("[usb][xhci] controller failed to run status=0x%x\n",
               mmio_read32(xc->op, XHCI_USBSTS));
        return -1;
    }
    xc->running = 1;
    /*
     * Start the scheduler before resetting root ports.  xHCI port-reset
     * completion and subsequent EP0 Transfer Events are controller runtime
     * work; issuing reset while halted is not portable and leaves some
     * controllers with connected devices that do not answer descriptors.
     * A host-controller reset also permits attached devices to reappear
     * asynchronously.  Give the root hub one bounded discovery interval so
     * built-in boot input is present for the initial enumeration pass.
     */
    xhci_wait_for_initial_ports(xc);
    for (uint8_t p = 0; p < xc->max_ports; ++p)
        (void)xhci_port_power_and_reset(xc, p);
    printf("[usb][xhci] controller initialized %u:%u.%u ports=%u slots=%u scratchpads=%u page=%u mmio=0x%x\n",
           (uint32_t)bus, (uint32_t)dev, (uint32_t)fn,
           (uint32_t)xc->max_ports, (uint32_t)xc->max_slots,
           (uint32_t)xc->scratchpad_count, xc->page_size,
           (uint32_t)xc->mmio_base);
    xhci_enumerate_root_ports(xc);
    /*
     * QEMU and real controllers may publish root-hub connection state only
     * after the host controller has completed its start sequence.  The
     * process-context poller can run as infrequently as once per scheduler
     * idle tick on a busy system, so delaying the first rescan by a complete
     * periodic interval can leave boot keyboards and mice undiscovered for
     * minutes.  Request one immediate deferred rescan; later scans retain the
     * normal interval and port-status events still request early work.
     */
    xc->port_poll_countdown = 0;
    /*
     * Publish the controller to the asynchronous USB poll path only after
     * initial root-port enumeration completes.  Otherwise the timer/poll path
     * can race xhci_init_controller(), enumerate a port while reset recovery is
     * still in progress, and leave the second HID device stuck behind EP0
     * timeouts or command timeouts.
     */
    xc->used = 1;
    return 0;
}

int xhci_storage_present(const xhci_controller_t *xc, uint8_t slot_id) {
    const xhci_slot_state_t *slot;
    if (!xc || slot_id == 0 || slot_id > XHCI_MAX_TRACKED_SLOTS) return 0;
    slot = &xc->slots[slot_id];
    return slot->online && slot->mass_ready && slot->mass_sector_size != 0 && slot->mass_sector_count != 0;
}

uint32_t xhci_storage_sector_size(const xhci_controller_t *xc, uint8_t slot_id) {
    if (!xhci_storage_present(xc, slot_id)) return 0;
    return xc->slots[slot_id].mass_sector_size;
}

uint32_t xhci_storage_sector_count(const xhci_controller_t *xc, uint8_t slot_id) {
    if (!xhci_storage_present(xc, slot_id)) return 0;
    return xc->slots[slot_id].mass_sector_count;
}

static int xhci_storage_rw(xhci_controller_t *xc, uint8_t slot_id, uint32_t lba, uint32_t count, void *buf, int write) {
#ifdef CONFIG_USB_STORAGE
    xhci_slot_state_t *slot;
    uint8_t *p = (uint8_t *)buf;
    uint32_t original_count = count;
    uint64_t started_us;
    if (!xc || !buf || count == 0) return (count == 0) ? 0 : -1;
    slot = xhci_slot_get(xc, slot_id);
    if (!slot || !slot->online || !slot->mass_ready || slot->mass_sector_size == 0) return -1;
    if (lba >= slot->mass_sector_count || count > slot->mass_sector_count - lba) return -1;
    started_us = boottime_monotonic_us();
    while (count) {
        uint8_t cdb[10];
        uint32_t max_chunk = slot->mass_data.size / slot->mass_sector_size;
        uint32_t chunk = count;
        uint32_t bytes;
        if (max_chunk == 0) return -1;
        if (chunk > max_chunk) chunk = max_chunk;
        if (chunk > 0xFFFFu) chunk = 0xFFFFu;
        bytes = chunk * slot->mass_sector_size;
        memset(cdb, 0, sizeof(cdb));
        cdb[0] = write ? SCSI_WRITE_10 : SCSI_READ_10;
        xhci_be32_put(cdb + 2, lba);
        xhci_be16_put(cdb + 7, (uint16_t)chunk);
        if (xhci_mass_scsi(xc, slot, cdb, sizeof(cdb), p, bytes,
                           write ? USB_MSC_DATA_OUT : USB_MSC_DATA_IN) < 0) return -1;
        lba += chunk;
        count -= chunk;
        p += bytes;
    }
    if (!write) {
        uint64_t elapsed_us = boottime_monotonic_us() - started_us;

        slot->mass_read_bytes +=
            (uint64_t)original_count * slot->mass_sector_size;
        slot->mass_read_elapsed_us += elapsed_us;
        ++slot->mass_read_commands;
        if (!slot->mass_next_report_bytes)
            slot->mass_next_report_bytes = USB_MSC_PROGRESS_BYTES;
        if (slot->mass_read_bytes >= slot->mass_next_report_bytes) {
            uint64_t kib_per_second = slot->mass_read_elapsed_us ?
                (slot->mass_read_bytes * 1000000ull) /
                    slot->mass_read_elapsed_us / 1024ull : 0;

            printf("[usb-storage] slot=%u read=%llu KiB commands=%u rate=%llu KiB/s\n",
                   (uint32_t)slot->slot_id,
                   (unsigned long long)(slot->mass_read_bytes / 1024ull),
                   slot->mass_read_commands,
                   (unsigned long long)kib_per_second);
            slot->mass_next_report_bytes =
                ((slot->mass_read_bytes / USB_MSC_PROGRESS_BYTES) + 1ull) *
                USB_MSC_PROGRESS_BYTES;
        }
    }
    return 0;
#else
    (void)xc; (void)slot_id; (void)lba; (void)count; (void)buf; (void)write;
    return -1;
#endif
}

int xhci_storage_read(xhci_controller_t *xc, uint8_t slot_id, uint32_t lba, uint32_t count, void *out) {
    return xhci_storage_rw(xc, slot_id, lba, count, out, 0);
}

int xhci_storage_write(xhci_controller_t *xc, uint8_t slot_id, uint32_t lba, uint32_t count, const void *in) {
    return xhci_storage_rw(xc, slot_id, lba, count, (void *)in, 1);
}

void xhci_poll_controller(xhci_controller_t *xc) {
    if (!xc || !xc->used || !xc->running || !xc->op) return;
    xhci_poll_events(xc);
    if (!xc->port_change_pending && xc->port_poll_countdown > 0) {
        xc->port_poll_countdown--;
        return;
    }
    xc->port_change_pending = 0;
    xc->port_poll_countdown = XHCI_PORT_RESCAN_INTERVAL;
    for (uint8_t p = 0; p < xc->max_ports; ++p) {
        uint32_t off = XHCI_PORTSC_BASE + (uint32_t)p * XHCI_PORTSC_STRIDE;
        uint32_t v = mmio_read32(xc->op, off);
        uint32_t ch = v & XHCI_PORTSC_RW1C;
        uint8_t port_id = (uint8_t)(p + 1u);
        if ((v & XHCI_PORTSC_CCS) == 0) {
            if (xc->port_to_slot[port_id] != 0)
                xhci_mark_port_disconnected(xc, port_id);
            else {
                xc->port_retry_after_us[port_id] = 0;
                xc->port_failure_count[port_id] = 0;
            }
        } else if (xc->port_to_slot[port_id] == 0) {
            (void)xhci_enumerate_root_port(xc, port_id);
        }
        if (ch) xhci_portsc_clear_changes(xc, off, v);
    }
}

void xhci_poll_controller_events(xhci_controller_t *xc) {
    if (!xc || !xc->used || !xc->running || !xc->op) return;
    xhci_poll_events(xc);
}

void xhci_debug_dump(const xhci_controller_t *xc) {
    if (!xc || !xc->used || !xc->op) return;
    printf("[usb][xhci] %u:%u.%u ports=%u slots=%u run=%d\n",
           (uint32_t)xc->bus, (uint32_t)xc->dev, (uint32_t)xc->fn,
           (uint32_t)xc->max_ports, (uint32_t)xc->max_slots, xc->running);
}
