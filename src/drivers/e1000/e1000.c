#include "drivers/e1000.h"
#include "drivers/pci.h"
#ifdef CONFIG_NET_REALTEK_R8169
#include "drivers/r8169.h"
#endif
#ifdef CONFIG_VIRTIO_NET
#include "drivers/virtio_net.h"
#endif

#include "arch/x86_64/pic.h"
#include "arch/x86_64/isr.h"
#include "stdio.h"
#include "string.h"
#include "sys/boottime.h"
#include "sys/mmio.h"
#include "sys/scheduler.h"
#include "sys/spinlock.h"

#include <stdint.h>

#define E1000_VENDOR_INTEL 0x8086u
#define E1000_DEV_82540EM  0x100Eu
#define E1000_DEV_82545EM  0x100Fu
#define E1000_DEV_82574L   0x10D3u
#define E1000_DEV_I217_LM  0x153Au
#define E1000_DEV_I219_LM    0x156Fu
#define E1000_DEV_I219_V     0x1570u
#define E1000_DEV_I219_LM2   0x15B7u
#define E1000_DEV_I219_V2    0x15B8u
#define E1000_DEV_I219_LM3   0x15B9u
#define E1000_DEV_I219_LM4   0x15D7u
#define E1000_DEV_I219_V4    0x15D8u
#define E1000_DEV_I219_LM5   0x15E3u
#define E1000_DEV_I219_V5    0x15D6u
#define E1000_DEV_I219_LM6   0x15BDu
#define E1000_DEV_I219_V6    0x15BEu
#define E1000_DEV_I219_LM7   0x15BBu
#define E1000_DEV_I219_V7    0x15BCu
#define E1000_DEV_I219_LM8   0x15DFu
#define E1000_DEV_I219_V8    0x15E0u
#define E1000_DEV_I219_LM9   0x15E1u
#define E1000_DEV_I219_V9    0x15E2u
#define E1000_DEV_I219_LM10  0x0D4Eu
#define E1000_DEV_I219_V10   0x0D4Fu
#define E1000_DEV_I219_LM11  0x0D4Cu
#define E1000_DEV_I219_V11   0x0D4Du
#define E1000_DEV_I219_LM12  0x0D53u
#define E1000_DEV_I219_V12   0x0D55u
#define E1000_DEV_I219_LM13  0x15FBu
#define E1000_DEV_I219_V13   0x15FCu
#define E1000_DEV_I219_LM14  0x15F9u
#define E1000_DEV_I219_V14   0x15FAu
#define E1000_DEV_I219_LM15  0x15F4u
#define E1000_DEV_I219_V15   0x15F5u
#define E1000_DEV_I219_LM16  0x1A1Eu
#define E1000_DEV_I219_V16   0x1A1Fu
#define E1000_DEV_I219_LM17  0x1A1Cu
#define E1000_DEV_I219_V17   0x1A1Du
#define E1000_DEV_I219_LM18  0x550Au
#define E1000_DEV_I219_V18   0x550Bu
#define E1000_DEV_I219_LM19  0x550Cu
#define E1000_DEV_I219_V19   0x550Du
#define E1000_DEV_I219_LM20  0x550Eu
#define E1000_DEV_I219_V20   0x550Fu
#define E1000_DEV_I219_LM21  0x5510u
#define E1000_DEV_I219_V21   0x5511u
#define E1000_DEV_I219_LM22  0x0DC7u
#define E1000_DEV_I219_V22   0x0DC8u
#define E1000_DEV_I219_LM23  0x0DC5u
#define E1000_DEV_I219_V23   0x0DC6u
#define E1000_DEV_I219_LM24  0x57A0u
#define E1000_DEV_I219_V24   0x57A1u
#define E1000_DEV_I219_LM25  0x57B3u
#define E1000_DEV_I219_V25   0x57B4u
#define E1000_DEV_I219_LM26  0x57B5u
#define E1000_DEV_I219_V26   0x57B6u
#define E1000_DEV_I219_LM27  0x57B7u
#define E1000_DEV_I219_V27   0x57B8u
#define E1000_DEV_I225_LM  0x15F2u
#define E1000_DEV_I225_V   0x15F3u
#define E1000_DEV_I225_I   0x15F8u
#define E1000_DEV_I225_LMVP 0x5502u
#define E1000_DEV_I226_LM  0x125Bu
#define E1000_DEV_I226_V   0x125Cu
#define E1000_DEV_I226_IT  0x125Du
#define E1000_REG_CTRL    0x0000
#define E1000_REG_STATUS  0x0008
#define E1000_REG_EECD    0x0010
#define E1000_REG_ICR     0x00C0
#define E1000_REG_IMS     0x00D0
#define E1000_REG_IMC     0x00D8
#define E1000_REG_RCTL    0x0100
#define E1000_REG_TCTL    0x0400
#define E1000_REG_TIPG    0x0410
#define E1000_REG_RDBAL   0x2800
#define E1000_REG_RDBAH   0x2804
#define E1000_REG_RDLEN   0x2808
#define E1000_REG_RDH     0x2810
#define E1000_REG_RDT     0x2818
#define E1000_REG_TDBAL   0x3800
#define E1000_REG_TDBAH   0x3804
#define E1000_REG_TDLEN   0x3808
#define E1000_REG_TDH     0x3810
#define E1000_REG_TDT     0x3818
#define E1000_REG_RAL     0x5400
#define E1000_REG_RAH     0x5404

#define E1000_CTRL_RST        (1u << 26)
#define E1000_CTRL_ASDE       (1u << 5)
#define E1000_CTRL_SLU        (1u << 6)
#define E1000_RCTL_EN         (1u << 1)
#define E1000_RCTL_UPE        (1u << 3)
#define E1000_RCTL_MPE        (1u << 4)
#define E1000_RCTL_BAM        (1u << 15)
#define E1000_RCTL_SECRC      (1u << 26)
#define E1000_TCTL_EN         (1u << 1)
#define E1000_TCTL_PSP        (1u << 3)
#define E1000_RAH_AV          (1u << 31)
#define E1000_TX_CMD_EOP      (1u << 0)
#define E1000_TX_CMD_IFCS     (1u << 1)
#define E1000_TX_CMD_RS       (1u << 3)
#define E1000_TX_STATUS_DD    (1u << 0)
#define E1000_RX_STATUS_DD    (1u << 0)
#define E1000_RX_STATUS_EOP   (1u << 1)

#define E1000_ICR_TXDW        (1u << 0)
#define E1000_ICR_LSC         (1u << 2)
#define E1000_ICR_RXDMT0      (1u << 4)
#define E1000_ICR_RXO         (1u << 6)
#define E1000_ICR_RXT0        (1u << 7)
#define E1000_IMS_RX_MASK     (E1000_ICR_RXDMT0 | E1000_ICR_RXO | E1000_ICR_RXT0)

#define E1000_RX_DESC_COUNT 64
#define E1000_TX_DESC_COUNT 16
#define E1000_RX_BUF_SIZE 2048
#define E1000_TX_BUF_SIZE 2048
#define E1000_RX_QUEUE_MAX 16

#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_IP4 0x0800

typedef struct __attribute__((packed)) {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype_be;
} eth_hdr_t;

typedef struct __attribute__((packed)) {
    uint16_t htype_be;
    uint16_t ptype_be;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper_be;
    uint8_t sha[6];
    uint32_t spa_be;
    uint8_t tha[6];
    uint32_t tpa_be;
} arp_pkt_t;

typedef struct __attribute__((packed)) {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_len_be;
    uint16_t id_be;
    uint16_t frag_be;
    uint8_t ttl;
    uint8_t proto;
    uint16_t csum_be;
    uint32_t src_be;
    uint32_t dst_be;
} ipv4_hdr_t;

typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t code;
    uint16_t csum_be;
    uint16_t id_be;
    uint16_t seq_be;
} icmp_echo_t;

typedef struct __attribute__((packed)) {
    uint64_t addr;
    uint16_t length;
    uint16_t csum;
    uint8_t status;
    uint8_t errors;
    uint16_t special;
} e1000_rx_desc_t;

typedef struct __attribute__((packed)) {
    uint64_t addr;
    uint16_t length;
    uint8_t cso;
    uint8_t cmd;
    uint8_t status;
    uint8_t css;
    uint16_t special;
} e1000_tx_desc_t;

typedef struct {
    uint32_t len;
    uint32_t src_ip_be;
    uint8_t data[1600];
} rx_ip_pkt_t;

static volatile uint8_t *g_mmio;
static int g_ready;
static uint8_t g_mac[6];
static e1000_rx_frame_cb_t g_rx_frame_cb;
static uint32_t g_host_ip_be = 0x0F02000Au;   /* 10.0.2.15 in BE */
static uint32_t g_gateway_ip_be = 0x0202000Au;/* 10.0.2.2 in BE */
static int g_arp_valid;
static uint32_t g_arp_ip_be;
static uint8_t g_arp_mac[6];

static e1000_rx_desc_t g_rx_desc[E1000_RX_DESC_COUNT] __attribute__((aligned(16)));
static e1000_tx_desc_t g_tx_desc[E1000_TX_DESC_COUNT] __attribute__((aligned(16)));
static uint8_t g_rx_buf[E1000_RX_DESC_COUNT][E1000_RX_BUF_SIZE] __attribute__((aligned(16)));
static uint8_t g_tx_buf[E1000_TX_DESC_COUNT][E1000_TX_BUF_SIZE] __attribute__((aligned(16)));
static spinlock_t g_rx_lock;
static spinlock_t g_tx_lock;
static uint32_t g_rx_cur;
static uint32_t g_tx_cur;
static uint32_t g_dbg_tx_sent;
static uint32_t g_dbg_tx_timeout;
static uint32_t g_dbg_rx_seen;
static uint8_t g_irq_line = 0xFFu;
static uint8_t g_pci_bus;
static uint8_t g_pci_slot;
static uint8_t g_pci_function;
static uint32_t g_irq_count;
static uint32_t g_poll_count;
static volatile uint32_t g_rx_irq_pending;

static rx_ip_pkt_t g_rx_ip_queue[E1000_RX_QUEUE_MAX];
static uint32_t g_rx_ip_count;

typedef enum {
    NATIVE_NET_BACKEND_NONE = 0,
    NATIVE_NET_BACKEND_E1000,
    NATIVE_NET_BACKEND_R8169,
    NATIVE_NET_BACKEND_VIRTIO,
} native_net_backend_t;

static native_net_backend_t g_suspended_backend;

static uint16_t bswap16(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }
static uint32_t bswap32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) |
           ((v & 0x0000FF00u) << 8) |
           ((v & 0x00FF0000u) >> 8) |
           ((v & 0xFF000000u) >> 24);
}

static uint16_t csum16(const void *data, uint32_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t acc = 0;
    for (uint32_t i = 0; i + 1 < len; i += 2) acc += ((uint32_t)p[i] << 8) | p[i + 1];
    if (len & 1u) acc += (uint32_t)p[len - 1] << 8;
    while (acc >> 16) acc = (acc & 0xFFFFu) + (acc >> 16);
    return (uint16_t)~acc;
}

static int e1000_supported_device_id(uint16_t did) {
    switch (did) {
    case E1000_DEV_82540EM:
    case E1000_DEV_82545EM:
    case E1000_DEV_82574L:
    case E1000_DEV_I217_LM:
        return 1;
#ifdef CONFIG_NET_INTEL_E1000E
    /*
     * Device IDs are BSD-derived from FreeBSD sys/dev/e1000.  These PCH
     * controllers retain the Intel ring register ABI used below; platform PHY
     * and power-management quirks are intentionally conservative until EdgeOS
     * has a full PHY/NVM layer.
     */
    case E1000_DEV_I219_LM:
    case E1000_DEV_I219_V:
    case E1000_DEV_I219_LM2:
    case E1000_DEV_I219_V2:
    case E1000_DEV_I219_LM3:
    case E1000_DEV_I219_LM4:
    case E1000_DEV_I219_V4:
    case E1000_DEV_I219_LM5:
    case E1000_DEV_I219_V5:
    case E1000_DEV_I219_LM6:
    case E1000_DEV_I219_V6:
    case E1000_DEV_I219_LM7:
    case E1000_DEV_I219_V7:
    case E1000_DEV_I219_LM8:
    case E1000_DEV_I219_V8:
    case E1000_DEV_I219_LM9:
    case E1000_DEV_I219_V9:
    case E1000_DEV_I219_LM10:
    case E1000_DEV_I219_V10:
    case E1000_DEV_I219_LM11:
    case E1000_DEV_I219_V11:
    case E1000_DEV_I219_LM12:
    case E1000_DEV_I219_V12:
    case E1000_DEV_I219_LM13:
    case E1000_DEV_I219_V13:
    case E1000_DEV_I219_LM14:
    case E1000_DEV_I219_V14:
    case E1000_DEV_I219_LM15:
    case E1000_DEV_I219_V15:
    case E1000_DEV_I219_LM16:
    case E1000_DEV_I219_V16:
    case E1000_DEV_I219_LM17:
    case E1000_DEV_I219_V17:
    case E1000_DEV_I219_LM18:
    case E1000_DEV_I219_V18:
    case E1000_DEV_I219_LM19:
    case E1000_DEV_I219_V19:
    case E1000_DEV_I219_LM20:
    case E1000_DEV_I219_V20:
    case E1000_DEV_I219_LM21:
    case E1000_DEV_I219_V21:
    case E1000_DEV_I219_LM22:
    case E1000_DEV_I219_V22:
    case E1000_DEV_I219_LM23:
    case E1000_DEV_I219_V23:
    case E1000_DEV_I219_LM24:
    case E1000_DEV_I219_V24:
    case E1000_DEV_I219_LM25:
    case E1000_DEV_I219_V25:
    case E1000_DEV_I219_LM26:
    case E1000_DEV_I219_V26:
    case E1000_DEV_I219_LM27:
    case E1000_DEV_I219_V27:
        return 1;
#endif
    default:
        return 0;
    }
}

static uint32_t e1000_rd(uint32_t reg) { return *(volatile uint32_t *)(g_mmio + reg); }
static void e1000_wr(uint32_t reg, uint32_t val) { *(volatile uint32_t *)(g_mmio + reg) = val; }

static int e1000_send_frame(const void *frame, uint16_t len) {
    volatile e1000_tx_desc_t *d;
    volatile e1000_tx_desc_t *sent;
    uint32_t next;
    uint32_t tdh;
    uint32_t tdt;
    uint16_t wire_len;
    uint64_t flags;
    int rc = -1;
    if (!g_ready || len == 0 || len > E1000_TX_BUF_SIZE) return -1;
    flags = spin_lock_irqsave(&g_tx_lock);
    d = &g_tx_desc[g_tx_cur];
    if ((d->status & E1000_TX_STATUS_DD) == 0) goto out;
    wire_len = len < 60 ? 60 : len;
    memcpy(g_tx_buf[g_tx_cur], frame, len);
    if (wire_len > len) memset(g_tx_buf[g_tx_cur] + len, 0, wire_len - len);
    d->length = wire_len;
    d->cso = 0;
    d->cmd = E1000_TX_CMD_EOP | E1000_TX_CMD_IFCS | E1000_TX_CMD_RS;
    d->status = 0;
    d->css = 0;
    d->special = 0;
    next = (g_tx_cur + 1u) % E1000_TX_DESC_COUNT;
    __sync_synchronize();
    e1000_wr(E1000_REG_TDT, next);
    sent = d;
    g_tx_cur = next;
    for (volatile uint32_t t = 0; t < 200000u; ++t) {
        if (sent->status & E1000_TX_STATUS_DD) break;
    }
    if ((sent->status & E1000_TX_STATUS_DD) == 0) {
        tdh = e1000_rd(E1000_REG_TDH);
        tdt = e1000_rd(E1000_REG_TDT);
        /* Some QEMU/e1000 paths advance TDH reliably even when DD writeback
         * is late or lost. Treat an advanced head as completion so the TX
         * ring cannot wedge under SSH traffic. */
        if (tdh == next || (tdh == tdt && tdt == next)) {
            ((e1000_tx_desc_t *)sent)->status = E1000_TX_STATUS_DD;
            g_dbg_tx_sent++;
            rc = 0;
            goto out;
        }
        if (g_dbg_tx_timeout < 4) {
            printf("[net] e1000: tx timeout tdt=%u tdh=%u status=0x%x\n",
                   tdt,
                   tdh,
                   (uint32_t)e1000_rd(E1000_REG_STATUS));
        }
        g_dbg_tx_timeout++;
        goto out;
    }
    (void)wire_len;
    g_dbg_tx_sent++;
    rc = 0;
out:
    spin_unlock_irqrestore(&g_tx_lock, flags);
    return rc;
}

static void queue_ipv4_packet(const uint8_t *pkt, uint32_t len, uint32_t src_be) {
    if (!pkt || len == 0 || len > sizeof(g_rx_ip_queue[0].data)) return;
    if (g_rx_ip_count >= E1000_RX_QUEUE_MAX) return;
    g_rx_ip_queue[g_rx_ip_count].len = len;
    g_rx_ip_queue[g_rx_ip_count].src_ip_be = src_be;
    memcpy(g_rx_ip_queue[g_rx_ip_count].data, pkt, len);
    g_rx_ip_count++;
}

static void e1000_handle_rx_frame(const uint8_t *frm, uint32_t len) {
    const eth_hdr_t *eh;
    if (len < sizeof(eth_hdr_t)) return;
    eh = (const eth_hdr_t *)frm;
    g_dbg_rx_seen++;
    if (g_rx_frame_cb) g_rx_frame_cb(frm, len);
    if (bswap16(eh->ethertype_be) == ETH_TYPE_ARP) {
        const arp_pkt_t *arp;
        if (len < sizeof(eth_hdr_t) + sizeof(arp_pkt_t)) return;
        arp = (const arp_pkt_t *)(frm + sizeof(eth_hdr_t));
        if (bswap16(arp->oper_be) == 2 && arp->spa_be == g_gateway_ip_be) {
            g_arp_valid = 1;
            g_arp_ip_be = arp->spa_be;
            memcpy(g_arp_mac, arp->sha, 6);
        }
        return;
    }
    if (bswap16(eh->ethertype_be) == ETH_TYPE_IP4) {
        const ipv4_hdr_t *ip;
        uint32_t iplen;
        if (len < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t)) return;
        ip = (const ipv4_hdr_t *)(frm + sizeof(eth_hdr_t));
        if ((ip->ver_ihl >> 4) != 4) return;
        iplen = (uint32_t)bswap16(ip->total_len_be);
        if (iplen < sizeof(ipv4_hdr_t)) return;
        if (sizeof(eth_hdr_t) + iplen > len) return;
        if (ip->dst_be != g_host_ip_be) return;
        if (ip->proto != 1) return;
        queue_ipv4_packet((const uint8_t *)ip, iplen, ip->src_be);
    }
}

int e1000_send_frame_raw(const void *frame, uint16_t len) {
#ifdef CONFIG_NET_REALTEK_R8169
    if (!g_ready && r8169_is_ready()) return r8169_send_frame_raw(frame, len);
#endif
#ifdef CONFIG_VIRTIO_NET
    if (!g_ready && virtio_net_is_ready()) return virtio_net_send_frame_raw(frame, len);
#endif
    return e1000_send_frame(frame, len);
}

void e1000_set_rx_frame_callback(e1000_rx_frame_cb_t cb) {
    g_rx_frame_cb = cb;
#ifdef CONFIG_NET_REALTEK_R8169
    if (r8169_is_ready()) r8169_set_rx_frame_callback(cb);
#endif
#ifdef CONFIG_VIRTIO_NET
    if (virtio_net_is_ready()) virtio_net_set_rx_frame_callback(cb);
#endif
}

static void e1000_poll_rx(const char *src) {
    uint64_t flags;
    flags = spin_lock_irqsave(&g_rx_lock);
    while (g_ready) {
        e1000_rx_desc_t *d = &g_rx_desc[g_rx_cur];
        if ((d->status & E1000_RX_STATUS_DD) == 0) break;
        (void)src;
        if (d->length > 0 && d->length <= E1000_RX_BUF_SIZE) {
            e1000_handle_rx_frame(g_rx_buf[g_rx_cur], d->length);
        }
        d->status = 0;
        e1000_wr(E1000_REG_RDT, g_rx_cur);
        g_rx_cur = (g_rx_cur + 1u) % E1000_RX_DESC_COUNT;
    }
    spin_unlock_irqrestore(&g_rx_lock, flags);
}

static void e1000_irq_handler(REGISTERS *reg) {
    uint32_t icr;
    (void)reg;
    if (!g_ready) return;
    g_irq_count++;
    icr = e1000_rd(E1000_REG_ICR); /* acknowledge causes by reading ICR */
    if (icr & E1000_IMS_RX_MASK) {
        g_rx_irq_pending = 1;
        scheduler_request_deferred_work();
    }
    /*
     * lwIP is compiled in NO_SYS mode and is therefore single-context.  The
     * interrupt is only a deferred-work notification: scheduler_idle_loop()
     * drains the RX ring and enters lwIP from process context.  Never call the
     * frame callback here because it mutates PCB and socket wait-queue state.
     */
}

static void e1000_send_arp_request(uint32_t target_ip_be) {
    uint8_t frame[64];
    eth_hdr_t *eh = (eth_hdr_t *)frame;
    arp_pkt_t *arp = (arp_pkt_t *)(frame + sizeof(eth_hdr_t));
    memset(frame, 0, sizeof(frame));
    memset(eh->dst, 0xFF, 6);
    memcpy(eh->src, g_mac, 6);
    eh->ethertype_be = bswap16(ETH_TYPE_ARP);
    arp->htype_be = bswap16(1);
    arp->ptype_be = bswap16(ETH_TYPE_IP4);
    arp->hlen = 6;
    arp->plen = 4;
    arp->oper_be = bswap16(1);
    memcpy(arp->sha, g_mac, 6);
    arp->spa_be = g_host_ip_be;
    memset(arp->tha, 0, 6);
    arp->tpa_be = target_ip_be;
    (void)e1000_send_frame(frame, sizeof(frame));
}

static int e1000_resolve_gateway_mac(void) {
    if (g_arp_valid && g_arp_ip_be == g_gateway_ip_be) return 0;
    e1000_send_arp_request(g_gateway_ip_be);
    {
        uint64_t until = boottime_monotonic_us() + 500000ull;
        while (boottime_monotonic_us() < until) {
            g_poll_count++;
            e1000_poll_rx("poll");
            if (g_arp_valid && g_arp_ip_be == g_gateway_ip_be) return 0;
        }
    }
    return -1;
}

void e1000_init(void) {
    uint8_t bus = 0, dev = 0, fn = 0;
    uint8_t found_bus = 0, found_dev = 0, found_fn = 0;
    uint16_t ven = 0xFFFF, did = 0xFFFF;
    uint64_t mmio_base = 0;
    uint16_t cmd;
    uint8_t irq_line;
    int found = 0;

    g_ready = 0;
    for (bus = 0; bus < 255 && !found; ++bus) {
        for (dev = 0; dev < 32 && !found; ++dev) {
            for (fn = 0; fn < 8; ++fn) {
                ven = pci_cfg_read16(bus, dev, fn, 0x00);
                if (ven == 0xFFFFu) {
                    if (fn == 0) break;
                    continue;
                }
                did = pci_cfg_read16(bus, dev, fn, 0x02);
                if (ven == E1000_VENDOR_INTEL && e1000_supported_device_id(did)) {
                    found_bus = bus;
                    found_dev = dev;
                    found_fn = fn;
                    found = 1;
                    break;
                }
            }
        }
    }

    if (!found) {
        printf("[net] e1000: not found\n");
#ifdef CONFIG_NET_REALTEK_R8169
        if (r8169_init() == 0) {
            r8169_set_rx_frame_callback(g_rx_frame_cb);
            printf("[net] r8169: using fallback NIC backend\n");
            return;
        }
#endif
#ifdef CONFIG_VIRTIO_NET
        if (virtio_net_init() == 0) {
            virtio_net_set_rx_frame_callback(g_rx_frame_cb);
            printf("[net] virtio-net: using fallback NIC backend\n");
        }
#endif
        return;
    }

    for (uint8_t off = 0x10; off <= 0x24; off += 4) {
        uint32_t bar = pci_cfg_read32(found_bus, found_dev, found_fn, off);
        if ((bar & 1u) != 0u) continue; /* I/O BAR */
        if ((bar & ~0xFu) == 0u) continue;
        if (((bar >> 1) & 0x3u) == 0x2u && off <= 0x20) {
            uint32_t bar_hi = pci_cfg_read32(found_bus, found_dev, found_fn, (uint8_t)(off + 4));
            mmio_base = ((uint64_t)bar_hi << 32) | (uint64_t)(bar & ~0xFu);
            break;
        }
        mmio_base = (uint64_t)(bar & ~0xFu);
        break;
    }
    if (mmio_base == 0) {
        printf("[net] e1000: no MMIO BAR found\n");
        return;
    }
    /*
     * BARs are bus physical addresses.  Keep all NIC register access through
     * the kernel MMIO alias so the driver continues to work when paging or
     * firmware layout changes make physical addresses non-identity-mapped.
     */
    g_mmio = (volatile uint8_t *)edge_mmio_low_alias(mmio_base);
    g_pci_bus = found_bus;
    g_pci_slot = found_dev;
    g_pci_function = found_fn;
    spinlock_init(&g_rx_lock);
    spinlock_init(&g_tx_lock);
    cmd = pci_cfg_read16(found_bus, found_dev, found_fn, 0x04);
    cmd |= 0x0006u;
    pci_cfg_write32(found_bus, found_dev, found_fn, 0x04,
                    (pci_cfg_read32(found_bus, found_dev, found_fn, 0x04) & 0xFFFF0000u) | cmd);

    irq_line = pci_cfg_read8(found_bus, found_dev, found_fn, 0x3C);
    g_irq_line = irq_line;

    e1000_wr(E1000_REG_IMC, 0xFFFFFFFFu);
    e1000_rd(E1000_REG_ICR);
    e1000_wr(E1000_REG_CTRL, e1000_rd(E1000_REG_CTRL) | E1000_CTRL_RST);
    for (volatile uint32_t i = 0; i < 100000; ++i) {}
    e1000_wr(E1000_REG_CTRL, e1000_rd(E1000_REG_CTRL) | E1000_CTRL_SLU | E1000_CTRL_ASDE);

    {
        uint32_t ral = e1000_rd(E1000_REG_RAL);
        uint32_t rah = e1000_rd(E1000_REG_RAH);
        g_mac[0] = (uint8_t)(ral & 0xFFu);
        g_mac[1] = (uint8_t)((ral >> 8) & 0xFFu);
        g_mac[2] = (uint8_t)((ral >> 16) & 0xFFu);
        g_mac[3] = (uint8_t)((ral >> 24) & 0xFFu);
        g_mac[4] = (uint8_t)(rah & 0xFFu);
        g_mac[5] = (uint8_t)((rah >> 8) & 0xFFu);
    }
    {
        uint32_t ral = (uint32_t)g_mac[0] |
                       ((uint32_t)g_mac[1] << 8) |
                       ((uint32_t)g_mac[2] << 16) |
                       ((uint32_t)g_mac[3] << 24);
        uint32_t rah = (uint32_t)g_mac[4] |
                       ((uint32_t)g_mac[5] << 8) |
                       E1000_RAH_AV;
        e1000_wr(E1000_REG_RAL, ral);
        e1000_wr(E1000_REG_RAH, rah);
    }

    memset(g_rx_desc, 0, sizeof(g_rx_desc));
    memset(g_tx_desc, 0, sizeof(g_tx_desc));
    for (uint32_t i = 0; i < E1000_RX_DESC_COUNT; ++i) g_rx_desc[i].addr = (uint64_t)(uintptr_t)&g_rx_buf[i][0];
    for (uint32_t i = 0; i < E1000_TX_DESC_COUNT; ++i) {
        g_tx_desc[i].addr = (uint64_t)(uintptr_t)&g_tx_buf[i][0];
        g_tx_desc[i].status = E1000_TX_STATUS_DD;
    }
    g_rx_cur = 0;
    g_tx_cur = 0;
    g_rx_ip_count = 0;
    g_arp_valid = 0;
    g_rx_irq_pending = 0;

    e1000_wr(E1000_REG_RDBAL, (uint32_t)(uintptr_t)&g_rx_desc[0]);
    e1000_wr(E1000_REG_RDBAH, 0);
    e1000_wr(E1000_REG_RDLEN, sizeof(g_rx_desc));
    e1000_wr(E1000_REG_RDH, 0);
    e1000_wr(E1000_REG_RDT, E1000_RX_DESC_COUNT - 1);

    e1000_wr(E1000_REG_TDBAL, (uint32_t)(uintptr_t)&g_tx_desc[0]);
    e1000_wr(E1000_REG_TDBAH, 0);
    e1000_wr(E1000_REG_TDLEN, sizeof(g_tx_desc));
    e1000_wr(E1000_REG_TDH, 0);
    e1000_wr(E1000_REG_TDT, 0);

    e1000_wr(E1000_REG_RCTL, E1000_RCTL_EN | E1000_RCTL_UPE | E1000_RCTL_MPE | E1000_RCTL_BAM | E1000_RCTL_SECRC);
    e1000_wr(E1000_REG_TCTL, E1000_TCTL_EN | E1000_TCTL_PSP | (0x10u << 4) | (0x40u << 12));
    e1000_wr(E1000_REG_TIPG, 0x0060200Au);
    e1000_rd(E1000_REG_ICR); /* clear any pending causes before polling */
    e1000_wr(E1000_REG_IMC, 0xFFFFFFFFu);

    g_ready = 1;
    if (irq_line < 16u && !isr_interrupt_has_handler(IRQ_BASE + irq_line)) {
        /*
         * The hard IRQ only acknowledges the device and wakes a halted CPU.
         * RX and lwIP run later from the scheduler idle bottom half, preserving
         * NO_SYS single-context rules while allowing socket waiters to sleep.
         */
        isr_register_interrupt_handler(IRQ_BASE + irq_line, e1000_irq_handler);
        pic8259_unmask_irq(irq_line);
        e1000_wr(E1000_REG_IMS, E1000_IMS_RX_MASK);
        printf("[net] e1000: irq line %u registered, RX deferred to process context\n",
               (uint32_t)irq_line);
    } else if (irq_line < 16u) {
        e1000_wr(E1000_REG_IMC, 0xFFFFFFFFu);
        e1000_rd(E1000_REG_ICR);
        printf("[net] e1000: irq line %u already in use, using polling mode\n", (uint32_t)irq_line);
    } else {
        e1000_wr(E1000_REG_IMC, 0xFFFFFFFFu);
        e1000_rd(E1000_REG_ICR);
        printf("[net] e1000: pci irq line invalid (%u), IRQ RX path disabled\n", (uint32_t)irq_line);
    }

    printf("[net] e1000: ready bus=%u dev=%u fn=%u mac=%x:%x:%x:%x:%x:%x irq=%u status=0x%x ims=0x%x rdh=%u rdt=%u\n",
           (uint32_t)found_bus, (uint32_t)found_dev, (uint32_t)found_fn,
           g_mac[0], g_mac[1], g_mac[2], g_mac[3], g_mac[4], g_mac[5],
           (uint32_t)irq_line,
           e1000_rd(E1000_REG_STATUS),
           e1000_rd(E1000_REG_IMS),
           e1000_rd(E1000_REG_RDH),
           e1000_rd(E1000_REG_RDT));
}

int e1000_is_ready(void) {
#ifdef CONFIG_NET_REALTEK_R8169
    if (r8169_is_ready()) return 1;
#endif
#ifdef CONFIG_VIRTIO_NET
    return (g_ready || virtio_net_is_ready()) ? 1 : 0;
#else
    return g_ready ? 1 : 0;
#endif
}

int e1000_get_mac(uint8_t mac_out[6]) {
#ifdef CONFIG_NET_REALTEK_R8169
    if (!g_ready && r8169_is_ready()) return r8169_get_mac(mac_out);
#endif
#ifdef CONFIG_VIRTIO_NET
    if (!g_ready && virtio_net_is_ready()) return virtio_net_get_mac(mac_out);
#endif
    if (!g_ready || !mac_out) return -1;
    memcpy(mac_out, g_mac, 6);
    return 0;
}

void e1000_poll(void) {
    g_poll_count++;
#ifdef CONFIG_NET_REALTEK_R8169
    if (!g_ready && r8169_is_ready()) {
        r8169_poll();
        return;
    }
#endif
#ifdef CONFIG_VIRTIO_NET
    if (!g_ready && virtio_net_is_ready()) {
        virtio_net_poll();
        return;
    }
#endif
    g_rx_irq_pending = 0;
    e1000_poll_rx("poll");
}

int
e1000_get_pci_location(uint8_t *bus, uint8_t *slot,
                       uint8_t *function)
{
    if (!bus || !slot || !function)
        return -1;
    if (g_ready) {
        *bus = g_pci_bus;
        *slot = g_pci_slot;
        *function = g_pci_function;
        return 0;
    }
#ifdef CONFIG_NET_REALTEK_R8169
    if (r8169_is_ready())
        return r8169_get_pci_location(bus, slot, function);
#endif
#ifdef CONFIG_VIRTIO_NET
    if (virtio_net_is_ready())
        return virtio_net_get_pci_location(bus, slot, function);
#endif
    return -1;
}

int
e1000_stop(void)
{
    if (g_suspended_backend != NATIVE_NET_BACKEND_NONE)
        return -1;
    if (g_ready) {
        e1000_wr(E1000_REG_IMC, 0xffffffffu);
        (void)e1000_rd(E1000_REG_ICR);
        e1000_wr(E1000_REG_RCTL,
                 e1000_rd(E1000_REG_RCTL) & ~E1000_RCTL_EN);
        e1000_wr(E1000_REG_TCTL,
                 e1000_rd(E1000_REG_TCTL) & ~E1000_TCTL_EN);
        g_rx_frame_cb = 0;
        g_ready = 0;
        g_suspended_backend = NATIVE_NET_BACKEND_E1000;
        printf("[net] e1000: native PCI transport stopped\n");
        return 0;
    }
#ifdef CONFIG_NET_REALTEK_R8169
    if (r8169_is_ready()) {
        g_suspended_backend = NATIVE_NET_BACKEND_R8169;
        if (r8169_stop() == 0)
            return 0;
        return -1;
    }
#endif
#ifdef CONFIG_VIRTIO_NET
    if (virtio_net_is_ready()) {
        g_suspended_backend = NATIVE_NET_BACKEND_VIRTIO;
        if (virtio_net_stop() == 0)
            return 0;
        return -1;
    }
#endif
    return -1;
}

int
e1000_resume(void)
{
    native_net_backend_t backend = g_suspended_backend;
    int error = -1;

    if (backend == NATIVE_NET_BACKEND_NONE)
        return e1000_is_ready() ? 0 : -1;
    if (backend == NATIVE_NET_BACKEND_E1000) {
        e1000_init();
        error = g_ready ? 0 : -1;
    }
#ifdef CONFIG_NET_REALTEK_R8169
    else if (backend == NATIVE_NET_BACKEND_R8169)
        error = r8169_resume();
#endif
#ifdef CONFIG_VIRTIO_NET
    else if (backend == NATIVE_NET_BACKEND_VIRTIO)
        error = virtio_net_resume();
#endif
    if (error == 0)
        g_suspended_backend = NATIVE_NET_BACKEND_NONE;
    return error;
}

int e1000_send_icmp_echo(uint32_t dst_ip_be, const uint8_t *icmp_payload, uint16_t icmp_len) {
    uint8_t frm[1514];
    eth_hdr_t *eh;
    ipv4_hdr_t *ip;
    uint16_t ip_len;
    uint16_t frm_len;
    uint8_t *icmp;
    if (!g_ready || !icmp_payload || icmp_len < sizeof(icmp_echo_t)) return -1;
    if (icmp_len > 1400) return -1;
    if (e1000_resolve_gateway_mac() < 0) return -1;

    eh = (eth_hdr_t *)frm;
    memcpy(eh->dst, g_arp_mac, 6);
    memcpy(eh->src, g_mac, 6);
    eh->ethertype_be = bswap16(ETH_TYPE_IP4);

    ip = (ipv4_hdr_t *)(frm + sizeof(eth_hdr_t));
    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl = 0x45;
    ip->ttl = 64;
    ip->proto = 1;
    ip_len = (uint16_t)(sizeof(ipv4_hdr_t) + icmp_len);
    ip->total_len_be = bswap16(ip_len);
    ip->src_be = g_host_ip_be;
    ip->dst_be = dst_ip_be;
    ip->csum_be = csum16(ip, sizeof(ipv4_hdr_t));

    icmp = (uint8_t *)(ip + 1);
    memcpy(icmp, icmp_payload, icmp_len);
    ((icmp_echo_t *)icmp)->csum_be = 0;
    ((icmp_echo_t *)icmp)->csum_be = csum16(icmp, icmp_len);

    frm_len = (uint16_t)(sizeof(eth_hdr_t) + ip_len);
    if (frm_len < 60) {
        memset(frm + frm_len, 0, 60 - frm_len);
        frm_len = 60;
    }
    return e1000_send_frame(frm, frm_len);
}

int e1000_recv_icmp_reply_for_id(uint16_t id_be, uint8_t *ip_packet_out, uint32_t *ip_packet_len, uint32_t *src_ip_be) {
    g_poll_count++;
    e1000_poll_rx("poll");
    for (uint32_t i = 0; i < g_rx_ip_count; ++i) {
        const ipv4_hdr_t *ip = (const ipv4_hdr_t *)g_rx_ip_queue[i].data;
        uint32_t ihl = (uint32_t)(ip->ver_ihl & 0x0Fu) * 4u;
        if (g_rx_ip_queue[i].len < ihl + sizeof(icmp_echo_t)) continue;
        if (ip->proto != 1) continue;
        const icmp_echo_t *ic = (const icmp_echo_t *)(g_rx_ip_queue[i].data + ihl);
        if (ic->type != 0) continue;
        if (ic->id_be != id_be) continue;
        if (ip_packet_out && ip_packet_len && *ip_packet_len >= g_rx_ip_queue[i].len) {
            memcpy(ip_packet_out, g_rx_ip_queue[i].data, g_rx_ip_queue[i].len);
            *ip_packet_len = g_rx_ip_queue[i].len;
            if (src_ip_be) *src_ip_be = g_rx_ip_queue[i].src_ip_be;
        } else if (ip_packet_len) {
            *ip_packet_len = g_rx_ip_queue[i].len;
            return -1;
        }

        for (uint32_t j = i + 1; j < g_rx_ip_count; ++j) g_rx_ip_queue[j - 1] = g_rx_ip_queue[j];
        g_rx_ip_count--;
        return 1;
    }
    return 0;
}
