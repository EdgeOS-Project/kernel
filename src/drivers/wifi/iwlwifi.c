/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Intel iwlwifi-family PCI probe and hardware quiesce support.
 *
 * Copyright (c) EdgeOS Contributors.
 *
 * Register offsets, device IDs, and firmware naming are BSD-derived from
 * FreeBSD/OpenBSD iwm(4)/iwx(4).  This file is original EdgeOS glue code and
 * intentionally does not expose a working wlan interface until firmware loading
 * and an 802.11 data/control plane are available.
 */

#include "drivers/iwlwifi.h"

#include "drivers/pci.h"
#include "stdio.h"
#include "sys/mmio.h"

#include <stdint.h>

#define IWL_VENDOR_INTEL 0x8086u

#define IWL_CSR_HW_IF_CONFIG_REG 0x000u
#define IWL_CSR_INT             0x008u
#define IWL_CSR_INT_MASK        0x00Cu
#define IWL_CSR_FH_INT_STATUS   0x010u
#define IWL_CSR_RESET           0x020u
#define IWL_CSR_GP_CNTRL        0x024u
#define IWL_CSR_HW_REV          0x028u
#define IWL_CSR_GP_CNTRL_MAC_ACCESS_REQ 0x00000008u
#define IWL_CSR_RESET_STOP_MASTER       0x00000200u
#define IWL_CSR_RESET_L1A_DISABLED      0x80000000u

typedef struct {
    uint16_t device;
    const char *name;
    const char *fw;
    const char *pnvm;
} iwl_id_t;

static const iwl_id_t g_iwl_ids[] = {
    { 0x08B1u, "Intel Wireless 7265", "iwlwifi-7265D-29.ucode", 0 },
    { 0x08B2u, "Intel Wireless 7265", "iwlwifi-7265D-29.ucode", 0 },
    { 0x24F3u, "Intel Wireless 8265", "iwlwifi-8265-36.ucode", 0 },
    { 0x24FDu, "Intel Wireless 8265", "iwlwifi-8265-36.ucode", 0 },
    { 0x2723u, "Intel Wi-Fi 6 AX200", "iwlwifi-cc-a0-77.ucode", 0 },
    { 0x2725u, "Intel Wi-Fi 6 AX210", "iwlwifi-ty-a0-gf-a0-77.ucode", "iwlwifi-ty-a0-gf-a0.pnvm" },
    { 0x02F0u, "Intel Wi-Fi 6 AX201", "iwlwifi-Qu-b0-hr-b0-77.ucode", 0 },
    { 0xA0F0u, "Intel Wi-Fi 6 AX201", "iwlwifi-Qu-b0-hr-b0-77.ucode", 0 },
    { 0x34F0u, "Intel Wi-Fi 6 AX201", "iwlwifi-Qu-b0-hr-b0-77.ucode", 0 },
    { 0x06F0u, "Intel Wi-Fi 6 AX201", "iwlwifi-Qu-b0-hr-b0-77.ucode", 0 },
    { 0x43F0u, "Intel Wi-Fi 6 AX201", "iwlwifi-Qu-b0-hr-b0-77.ucode", 0 },
    { 0x3DF0u, "Intel Wi-Fi 6 AX201", "iwlwifi-Qu-b0-hr-b0-77.ucode", 0 },
    { 0x4DF0u, "Intel Wi-Fi 6 AX201", "iwlwifi-Qu-b0-hr-b0-77.ucode", 0 },
    { 0x2726u, "Intel Wi-Fi 6 AX211", "iwlwifi-so-a0-gf-a0-77.ucode", "iwlwifi-so-a0-gf-a0.pnvm" },
    { 0x51F0u, "Intel Wi-Fi 6 AX211", "iwlwifi-so-a0-gf-a0-77.ucode", "iwlwifi-so-a0-gf-a0.pnvm" },
    { 0x51F1u, "Intel Wi-Fi 6 AX211", "iwlwifi-so-a0-gf4-a0-77.ucode", "iwlwifi-so-a0-gf4-a0.pnvm" },
    { 0x7A70u, "Intel Wi-Fi 6 AX211", "iwlwifi-so-a0-gf-a0-77.ucode", "iwlwifi-so-a0-gf-a0.pnvm" },
    { 0x7AF0u, "Intel Wi-Fi 6 AX211", "iwlwifi-so-a0-gf-a0-77.ucode", "iwlwifi-so-a0-gf-a0.pnvm" },
    { 0x7F70u, "Intel Wi-Fi 6 AX211", "iwlwifi-so-a0-gf-a0-77.ucode", "iwlwifi-so-a0-gf-a0.pnvm" },
    { 0x54F0u, "Intel Wi-Fi 6 AX211", "iwlwifi-so-a0-gf-a0-77.ucode", "iwlwifi-so-a0-gf-a0.pnvm" },
};

static int g_probe_count;

static const iwl_id_t *iwl_lookup(uint16_t device) {
    for (uint32_t i = 0; i < sizeof(g_iwl_ids) / sizeof(g_iwl_ids[0]); ++i) {
        if (g_iwl_ids[i].device == device) return &g_iwl_ids[i];
    }
    return 0;
}

static uint32_t iwl_rd32(volatile uint8_t *mmio, uint32_t reg) {
    return *(volatile uint32_t *)(mmio + reg);
}

static void iwl_wr32(volatile uint8_t *mmio, uint32_t reg, uint32_t val) {
    *(volatile uint32_t *)(mmio + reg) = val;
}

static uint64_t iwl_find_mmio_bar(uint8_t bus, uint8_t slot, uint8_t func) {
    for (uint8_t off = 0x10; off <= 0x24; off += 4) {
        uint32_t bar = pci_cfg_read32(bus, slot, func, off);
        if ((bar & 1u) || (bar & ~0xFu) == 0) continue;
        if (((bar >> 1) & 0x3u) == 0x2u && off <= 0x20) {
            uint32_t hi = pci_cfg_read32(bus, slot, func, (uint8_t)(off + 4));
            return ((uint64_t)hi << 32) | (uint64_t)(bar & ~0xFu);
        }
        return (uint64_t)(bar & ~0xFu);
    }
    return 0;
}

void iwlwifi_init(void) {
    g_probe_count = 0;
    for (uint8_t bus = 0; bus < 255; ++bus) {
        for (uint8_t slot = 0; slot < 32; ++slot) {
            for (uint8_t func = 0; func < 8; ++func) {
                uint16_t ven = pci_cfg_read16(bus, slot, func, 0x00);
                uint16_t did;
                const iwl_id_t *id;
                uint64_t bar;
                volatile uint8_t *mmio;
                uint16_t cmd;
                uint32_t hw_rev;
                uint32_t hw_if;
                uint32_t gp;

                if (ven == PCI_VENDOR_INVALID) {
                    if (func == 0) break;
                    continue;
                }
                if (ven != IWL_VENDOR_INTEL) continue;
                did = pci_cfg_read16(bus, slot, func, 0x02);
                id = iwl_lookup(did);
                if (!id) continue;
                bar = iwl_find_mmio_bar(bus, slot, func);
                if (!bar) {
                    printf("[wifi] iwlwifi: %s %u:%u.%u has no MMIO BAR\n",
                           id->name, (uint32_t)bus, (uint32_t)slot, (uint32_t)func);
                    continue;
                }

                cmd = pci_cfg_read16(bus, slot, func, 0x04);
                pci_cfg_write16(bus, slot, func, 0x04, (uint16_t)(cmd | 0x0006u));
                mmio = (volatile uint8_t *)edge_mmio_low_alias(bar);

                iwl_wr32(mmio, IWL_CSR_INT_MASK, 0);
                iwl_wr32(mmio, IWL_CSR_INT, 0xFFFFFFFFu);
                iwl_wr32(mmio, IWL_CSR_FH_INT_STATUS, 0xFFFFFFFFu);
                gp = iwl_rd32(mmio, IWL_CSR_GP_CNTRL);
                iwl_wr32(mmio, IWL_CSR_GP_CNTRL, gp | IWL_CSR_GP_CNTRL_MAC_ACCESS_REQ);
                hw_rev = iwl_rd32(mmio, IWL_CSR_HW_REV);
                hw_if = iwl_rd32(mmio, IWL_CSR_HW_IF_CONFIG_REG);
                /*
                 * Keep the device quiesced until firmware loading and the
                 * 802.11 stack exist.  This avoids a fake wlan0 while still
                 * proving PCI/MMIO ownership and preventing interrupt storms.
                 */
                iwl_wr32(mmio, IWL_CSR_RESET,
                         iwl_rd32(mmio, IWL_CSR_RESET) |
                         IWL_CSR_RESET_STOP_MASTER |
                         IWL_CSR_RESET_L1A_DISABLED);
                printf("[wifi] iwlwifi: partial probe %s bus=%u dev=%u fn=%u did=0x%x hw_rev=0x%x hw_if=0x%x fw=%s%s%s\n",
                       id->name, (uint32_t)bus, (uint32_t)slot, (uint32_t)func,
                       (uint32_t)did, hw_rev, hw_if, id->fw,
                       id->pnvm ? " pnvm=" : "", id->pnvm ? id->pnvm : "");
                g_probe_count++;
            }
        }
    }
    if (g_probe_count == 0) printf("[wifi] iwlwifi: no supported Intel Wi-Fi PCI device found\n");
}

int iwlwifi_probe_count(void) {
    return g_probe_count;
}
