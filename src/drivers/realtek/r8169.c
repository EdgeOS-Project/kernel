/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * Realtek RTL8111/RTL8168/RTL8125 Ethernet driver.
 *
 * This is an EdgeOS implementation of the 8169-family descriptor path.  The
 * active source tree must not contain advertising-clause BSD driver text; keep
 * future changes based on vendor register documentation or permissively
 * licensed non-advertising-clause sources only.
 */

#include "drivers/r8169.h"

#include "drivers/pci.h"
#include "stdio.h"
#include "string.h"
#include "sys/boottime.h"
#include "sys/mmio.h"
#include "sys/spinlock.h"

#include <stdint.h>

#define RTL_VENDOR_REALTEK 0x10ECu
#define RTL_DEVICE_8168   0x8168u
#define RTL_DEVICE_8125   0x8125u

#define RL_IDR0             0x0000u
#define RL_COMMAND          0x0037u
#define RL_GTXSTART         0x0038u
#define RL_IMR              0x003Cu
#define RL_ISR              0x003Eu
#define RL_TXCFG            0x0040u
#define RL_RXCFG            0x0044u
#define RL_CFG1             0x0052u
#define RL_GMEDIASTAT       0x006Cu
#define RL_MAXRXPKTLEN      0x00DAu
#define RL_TXSTART          0x00D9u
#define RL_CPLUS_CMD        0x00E0u
#define RL_RXLIST_ADDR_LO   0x00E4u
#define RL_RXLIST_ADDR_HI   0x00E8u
#define RL_EARLY_TX_THRESH  0x00ECu

#define RL_CMD_TX_ENB       0x04u
#define RL_CMD_RX_ENB       0x08u
#define RL_CMD_RESET        0x10u

#define RL_ISR_RX_OK        0x0001u
#define RL_ISR_RX_ERR       0x0002u
#define RL_ISR_TX_OK        0x0004u
#define RL_ISR_TX_ERR       0x0008u
#define RL_ISR_RX_OVERRUN   0x0010u
#define RL_ISR_LINKCHG      0x0020u
#define RL_ISR_TIMEOUT      0x4000u
#define RL_ISR_SYSTEM_ERR   0x8000u

#define RL_TXCFG_MAXDMA     0x00000700u
#define RL_TXDMA_1024BYTES  0x00000600u
#define RL_TXCFG_IFG        0x03000000u

#define RL_RXCFG_RX_INDIV   0x00000002u
#define RL_RXCFG_RX_MULTI   0x00000004u
#define RL_RXCFG_RX_BROAD   0x00000008u
#define RL_RXCFG_MAXDMA     0x00000700u
#define RL_RXDMA_UNLIMITED  0x00000700u
#define RL_RXFIFO_NOTHRESH  0x0000E000u

#define RL_CPLUSCMD_TXENB   0x0001u
#define RL_CPLUSCMD_RXENB   0x0002u
#define RL_CPLUSCMD_PCI_MRW 0x0008u

#define RL_TXSTART_START    0x40u

#define RL_TDESC_CMD_FRAGLEN 0x0000FFFFu
#define RL_TDESC_CMD_EOF     0x10000000u
#define RL_TDESC_CMD_SOF     0x20000000u
#define RL_TDESC_CMD_EOR     0x40000000u
#define RL_TDESC_CMD_OWN     0x80000000u
#define RL_TDESC_STAT_OWN    0x80000000u
#define RL_TDESC_STAT_TXERR  0x00800000u

#define RL_RDESC_CMD_EOR     0x40000000u
#define RL_RDESC_CMD_OWN     0x80000000u
#define RL_RDESC_CMD_BUFLEN  0x00001FFFu
#define RL_RDESC_STAT_OWN    0x80000000u
#define RL_RDESC_STAT_SOF    0x20000000u
#define RL_RDESC_STAT_EOF    0x10000000u
#define RL_RDESC_STAT_RXERR  0x00100000u
#define RL_RDESC_STAT_FRAGLEN 0x00001FFFu
#define RL_RDESC_STAT_GFRAGLEN 0x00003FFFu

#define R8169_RX_DESC_COUNT 64
#define R8169_TX_DESC_COUNT 32
#define R8169_RX_BUF_SIZE 2048
#define R8169_TX_BUF_SIZE 2048

typedef struct __attribute__((packed)) {
    uint32_t cmdstat;
    uint32_t vlanctl;
    uint32_t bufaddr_lo;
    uint32_t bufaddr_hi;
} r8169_desc_t;

static volatile uint8_t *g_mmio;
static int g_ready;
static uint8_t g_mac[6];
static r8169_rx_frame_cb_t g_rx_frame_cb;
static spinlock_t g_rx_lock;
static spinlock_t g_tx_lock;
static r8169_desc_t g_rx_desc[R8169_RX_DESC_COUNT] __attribute__((aligned(256)));
static r8169_desc_t g_tx_desc[R8169_TX_DESC_COUNT] __attribute__((aligned(256)));
static uint8_t g_rx_buf[R8169_RX_DESC_COUNT][R8169_RX_BUF_SIZE] __attribute__((aligned(16)));
static uint8_t g_tx_buf[R8169_TX_DESC_COUNT][R8169_TX_BUF_SIZE] __attribute__((aligned(16)));
static uint32_t g_rx_cur;
static uint32_t g_tx_cur;
static uint16_t g_device_id;
static uint8_t g_pci_bus;
static uint8_t g_pci_slot;
static uint8_t g_pci_function;
static uint32_t g_rx_errors;
static uint32_t g_tx_errors;

static uint8_t rl_rd8(uint32_t reg) { return *(volatile uint8_t *)(g_mmio + reg); }
static uint16_t rl_rd16(uint32_t reg) { return *(volatile uint16_t *)(g_mmio + reg); }
static uint32_t rl_rd32(uint32_t reg) { return *(volatile uint32_t *)(g_mmio + reg); }
static void rl_wr8(uint32_t reg, uint8_t val) { *(volatile uint8_t *)(g_mmio + reg) = val; }
static void rl_wr16(uint32_t reg, uint16_t val) { *(volatile uint16_t *)(g_mmio + reg) = val; }
static void rl_wr32(uint32_t reg, uint32_t val) { *(volatile uint32_t *)(g_mmio + reg) = val; }

static int r8169_supported_device(uint16_t ven, uint16_t did) {
    return ven == RTL_VENDOR_REALTEK && (did == RTL_DEVICE_8168 || did == RTL_DEVICE_8125);
}

static void r8169_program_mac_filter(void) {
    /*
     * Linux userspace expects normal Ethernet semantics here: own unicast,
     * broadcast, and multicast needed by IPv6 ND/MLD.  Promiscuous mode is
     * deliberately left off until SIOCSIFFLAGS/IFF_PROMISC is wired through.
     */
    rl_wr32(RL_RXCFG,
            RL_RXCFG_RX_INDIV |
            RL_RXCFG_RX_MULTI |
            RL_RXCFG_RX_BROAD |
            RL_RXDMA_UNLIMITED |
            RL_RXFIFO_NOTHRESH);
}

static int r8169_find_pci(uint8_t *bus_out, uint8_t *dev_out, uint8_t *fn_out,
                          uint16_t *did_out, uint64_t *mmio_out) {
    for (uint8_t bus = 0; bus < 255; ++bus) {
        for (uint8_t dev = 0; dev < 32; ++dev) {
            for (uint8_t fn = 0; fn < 8; ++fn) {
                uint16_t ven = pci_cfg_read16(bus, dev, fn, 0x00);
                uint16_t did;
                if (ven == PCI_VENDOR_INVALID) {
                    if (fn == 0) break;
                    continue;
                }
                did = pci_cfg_read16(bus, dev, fn, 0x02);
                if (!r8169_supported_device(ven, did)) continue;

                for (uint8_t off = 0x10; off <= 0x24; off += 4) {
                    uint32_t bar = pci_cfg_read32(bus, dev, fn, off);
                    uint64_t base;
                    if ((bar & 1u) || (bar & ~0xFu) == 0) continue;
                    if (((bar >> 1) & 0x3u) == 0x2u && off <= 0x20) {
                        uint32_t hi = pci_cfg_read32(bus, dev, fn, (uint8_t)(off + 4));
                        base = ((uint64_t)hi << 32) | (uint64_t)(bar & ~0xFu);
                    } else {
                        base = (uint64_t)(bar & ~0xFu);
                    }
                    *bus_out = bus;
                    *dev_out = dev;
                    *fn_out = fn;
                    *did_out = did;
                    *mmio_out = base;
                    return 0;
                }
            }
        }
    }
    return -1;
}

static void r8169_rearm_rx(uint32_t idx) {
    uint32_t cmd = R8169_RX_BUF_SIZE & RL_RDESC_CMD_BUFLEN;
    if (idx == R8169_RX_DESC_COUNT - 1) cmd |= RL_RDESC_CMD_EOR;
    g_rx_desc[idx].vlanctl = 0;
    g_rx_desc[idx].bufaddr_lo = (uint32_t)(uintptr_t)&g_rx_buf[idx][0];
    g_rx_desc[idx].bufaddr_hi = 0;
    __sync_synchronize();
    g_rx_desc[idx].cmdstat = cmd | RL_RDESC_CMD_OWN;
}

static int r8169_send_frame(const void *frame, uint16_t len) {
    volatile r8169_desc_t *d;
    uint32_t cmd;
    uint16_t wire_len;
    uint64_t flags;
    int rc = -1;
    if (!g_ready || !frame || len == 0 || len > R8169_TX_BUF_SIZE) return -1;
    flags = spin_lock_irqsave(&g_tx_lock);
    d = &g_tx_desc[g_tx_cur];
    if (d->cmdstat & RL_TDESC_STAT_OWN) goto out;
    wire_len = len < 60 ? 60 : len;
    memcpy(g_tx_buf[g_tx_cur], frame, len);
    if (wire_len > len) memset(g_tx_buf[g_tx_cur] + len, 0, wire_len - len);
    d->vlanctl = 0;
    d->bufaddr_lo = (uint32_t)(uintptr_t)&g_tx_buf[g_tx_cur][0];
    d->bufaddr_hi = 0;
    cmd = (wire_len & RL_TDESC_CMD_FRAGLEN) | RL_TDESC_CMD_SOF | RL_TDESC_CMD_EOF | RL_TDESC_CMD_OWN;
    if (g_tx_cur == R8169_TX_DESC_COUNT - 1) cmd |= RL_TDESC_CMD_EOR;
    __sync_synchronize();
    d->cmdstat = cmd;
    rl_wr8(g_device_id == RTL_DEVICE_8125 ? RL_GTXSTART : RL_TXSTART, RL_TXSTART_START);

    for (volatile uint32_t t = 0; t < 200000u; ++t) {
        if ((d->cmdstat & RL_TDESC_STAT_OWN) == 0) {
            rc = (d->cmdstat & RL_TDESC_STAT_TXERR) ? -1 : 0;
            break;
        }
    }
    if (rc < 0) g_tx_errors++;
    g_tx_cur = (g_tx_cur + 1u) % R8169_TX_DESC_COUNT;
out:
    spin_unlock_irqrestore(&g_tx_lock, flags);
    return rc;
}

static void r8169_poll_rx_locked(void) {
    while (g_ready) {
        r8169_desc_t *d = &g_rx_desc[g_rx_cur];
        uint32_t stat = d->cmdstat;
        uint32_t len;
        if (stat & RL_RDESC_STAT_OWN) break;
        len = stat & (g_device_id == RTL_DEVICE_8125 ? RL_RDESC_STAT_GFRAGLEN : RL_RDESC_STAT_FRAGLEN);
        if ((stat & (RL_RDESC_STAT_SOF | RL_RDESC_STAT_EOF)) == (RL_RDESC_STAT_SOF | RL_RDESC_STAT_EOF) &&
            (stat & RL_RDESC_STAT_RXERR) == 0 &&
            len >= 14 && len <= R8169_RX_BUF_SIZE) {
            if (g_rx_frame_cb) g_rx_frame_cb(g_rx_buf[g_rx_cur], len);
        } else {
            g_rx_errors++;
        }
        r8169_rearm_rx(g_rx_cur);
        g_rx_cur = (g_rx_cur + 1u) % R8169_RX_DESC_COUNT;
    }
}

int r8169_init(void) {
    uint8_t bus = 0, dev = 0, fn = 0;
    uint64_t mmio = 0;
    uint16_t cmd;
    uint32_t txcfg;
    if (g_ready) return 0;
    if (r8169_find_pci(&bus, &dev, &fn, &g_device_id, &mmio) < 0) {
        printf("[net] r8169: not found\n");
        return -1;
    }
    g_mmio = (volatile uint8_t *)edge_mmio_low_alias(mmio);
    g_pci_bus = bus;
    g_pci_slot = dev;
    g_pci_function = fn;
    spinlock_init(&g_rx_lock);
    spinlock_init(&g_tx_lock);

    cmd = pci_cfg_read16(bus, dev, fn, 0x04);
    cmd |= 0x0006u;
    pci_cfg_write16(bus, dev, fn, 0x04, cmd);

    rl_wr16(RL_IMR, 0);
    rl_wr16(RL_ISR, 0xFFFFu);
    rl_wr8(RL_COMMAND, RL_CMD_RESET);
    {
        uint64_t until = boottime_monotonic_us() + 500000ull;
        while ((rl_rd8(RL_COMMAND) & RL_CMD_RESET) && boottime_monotonic_us() < until) {}
    }
    if (rl_rd8(RL_COMMAND) & RL_CMD_RESET) {
        printf("[net] r8169: reset timeout\n");
        return -1;
    }

    for (uint32_t i = 0; i < 6; ++i) g_mac[i] = rl_rd8(RL_IDR0 + i);
    memset(g_rx_desc, 0, sizeof(g_rx_desc));
    memset(g_tx_desc, 0, sizeof(g_tx_desc));
    for (uint32_t i = 0; i < R8169_RX_DESC_COUNT; ++i) r8169_rearm_rx(i);
    for (uint32_t i = 0; i < R8169_TX_DESC_COUNT; ++i) {
        g_tx_desc[i].bufaddr_lo = (uint32_t)(uintptr_t)&g_tx_buf[i][0];
        g_tx_desc[i].bufaddr_hi = 0;
        g_tx_desc[i].cmdstat = (i == R8169_TX_DESC_COUNT - 1) ? RL_TDESC_CMD_EOR : 0;
    }
    g_rx_cur = 0;
    g_tx_cur = 0;
    g_rx_errors = 0;
    g_tx_errors = 0;

    rl_wr32(RL_RXLIST_ADDR_LO, (uint32_t)(uintptr_t)&g_rx_desc[0]);
    rl_wr32(RL_RXLIST_ADDR_HI, 0);
    rl_wr32(0x20u, (uint32_t)(uintptr_t)&g_tx_desc[0]);
    rl_wr32(0x24u, 0);
    rl_wr16(RL_MAXRXPKTLEN, (uint16_t)(R8169_RX_BUF_SIZE / 8u));
    rl_wr8(RL_EARLY_TX_THRESH, 0x3Fu);
    rl_wr16(RL_CPLUS_CMD, RL_CPLUSCMD_TXENB | RL_CPLUSCMD_RXENB | RL_CPLUSCMD_PCI_MRW);
    txcfg = rl_rd32(RL_TXCFG);
    txcfg &= ~RL_TXCFG_MAXDMA;
    txcfg |= RL_TXDMA_1024BYTES | RL_TXCFG_IFG;
    rl_wr32(RL_TXCFG, txcfg);
    r8169_program_mac_filter();
    rl_wr8(RL_COMMAND, RL_CMD_TX_ENB | RL_CMD_RX_ENB);
    rl_wr16(RL_ISR, 0xFFFFu);
    rl_wr16(RL_IMR, 0);

    g_ready = 1;
    printf("[net] r8169: ready bus=%u dev=%u fn=%u did=0x%x mac=%x:%x:%x:%x:%x:%x link=0x%x\n",
           (uint32_t)bus, (uint32_t)dev, (uint32_t)fn, (uint32_t)g_device_id,
           g_mac[0], g_mac[1], g_mac[2], g_mac[3], g_mac[4], g_mac[5],
           (uint32_t)rl_rd8(RL_GMEDIASTAT));
    return 0;
}

int r8169_is_ready(void) {
    return g_ready ? 1 : 0;
}

void r8169_poll(void) {
    uint64_t flags;
    if (!g_ready) return;
    rl_wr16(RL_ISR, RL_ISR_RX_OK | RL_ISR_RX_ERR | RL_ISR_RX_OVERRUN |
                    RL_ISR_TX_OK | RL_ISR_TX_ERR | RL_ISR_LINKCHG |
                    RL_ISR_TIMEOUT | RL_ISR_SYSTEM_ERR);
    flags = spin_lock_irqsave(&g_rx_lock);
    r8169_poll_rx_locked();
    spin_unlock_irqrestore(&g_rx_lock, flags);
}

int r8169_get_mac(uint8_t mac_out[6]) {
    if (!g_ready || !mac_out) return -1;
    memcpy(mac_out, g_mac, 6);
    return 0;
}

int r8169_send_frame_raw(const void *frame, uint16_t len) {
    return r8169_send_frame(frame, len);
}

void r8169_set_rx_frame_callback(r8169_rx_frame_cb_t cb) {
    g_rx_frame_cb = cb;
}

int
r8169_get_pci_location(uint8_t *bus, uint8_t *slot,
                       uint8_t *function)
{
    if (!g_ready || !bus || !slot || !function)
        return -1;
    *bus = g_pci_bus;
    *slot = g_pci_slot;
    *function = g_pci_function;
    return 0;
}

int
r8169_stop(void)
{
    if (!g_ready)
        return 0;
    rl_wr16(RL_IMR, 0);
    rl_wr8(RL_COMMAND, 0);
    rl_wr16(RL_ISR, 0xffffu);
    g_rx_frame_cb = 0;
    g_ready = 0;
    printf("[net] r8169: native PCI transport stopped\n");
    return 0;
}

int
r8169_resume(void)
{
    if (g_ready)
        return 0;
    return r8169_init();
}
