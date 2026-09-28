/*-
 * Copyright (c) 2000 Whistle Communications, Inc.
 * All rights reserved.
 *
 * Subject to the following obligations and disclaimer of warranty, use and
 * redistribution of this software, in source or object code forms, with or
 * without modifications are expressly permitted by Whistle Communications;
 * provided, however, that:
 * 1. Any and all reproductions of the source or object code must include the
 *    copyright notice above and the following disclaimer of warranties; and
 * 2. No rights are granted, in any manner or form, to use Whistle
 *    Communications, Inc. trademarks, including the mark "WHISTLE
 *    COMMUNICATIONS" on advertising, endorsements, or otherwise except as
 *    such appears in the above copyright notice or in the software.
 *
 * THIS SOFTWARE IS BEING PROVIDED BY WHISTLE COMMUNICATIONS "AS IS", AND
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, WHISTLE COMMUNICATIONS MAKES NO
 * REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, REGARDING THIS SOFTWARE,
 * INCLUDING WITHOUT LIMITATION, ANY AND ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.
 * WHISTLE COMMUNICATIONS DOES NOT WARRANT, GUARANTEE, OR MAKE ANY
 * REPRESENTATIONS REGARDING THE USE OF, OR THE RESULTS OF THE USE OF THIS
 * SOFTWARE IN TERMS OF ITS CORRECTNESS, ACCURACY, RELIABILITY OR OTHERWISE.
 * IN NO EVENT SHALL WHISTLE COMMUNICATIONS BE LIABLE FOR ANY DAMAGES
 * RESULTING FROM OR ARISING OUT OF ANY USE OF THIS SOFTWARE, INCLUDING
 * WITHOUT LIMITATION, ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * PUNITIVE, OR CONSEQUENTIAL DAMAGES, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES, LOSS OF DATA OR PROFITS, HOWEVER CAUSED AND UNDER ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF WHISTLE COMMUNICATIONS IS ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * Modifications for EdgeOS.
 * Copyright (c) EdgeOS Contributors.
 *
 * This file is BSD-derived from FreeBSD's sys/dev/ichsmb driver.  The EdgeOS
 * integration keeps the public register definitions and device IDs, but uses a
 * compact polled controller path instead of FreeBSD's device_t/smbus bus layer.
 */

#include "drivers/smbus.h"
#include "drivers/pci.h"
#include "arch/x86_64/io_ports.h"
#include "stdio.h"
#include "string.h"
#include "sys/spinlock.h"

#include <stdint.h>

#define ICH_SMB_BASE                    0x20u
#define ICH_HOSTC                       0x40u
#define ICH_HOSTC_I2C_EN                0x04u
#define ICH_HOSTC_SMB_SMI_EN            0x02u
#define ICH_HOSTC_HST_EN                0x01u

#define ICH_HST_STA                     0x00u
#define ICH_HST_STA_BYTE_DONE_STS       0x80u
#define ICH_HST_STA_INUSE_STS           0x40u
#define ICH_HST_STA_SMBALERT_STS        0x20u
#define ICH_HST_STA_FAILED              0x10u
#define ICH_HST_STA_BUS_ERR             0x08u
#define ICH_HST_STA_DEV_ERR             0x04u
#define ICH_HST_STA_INTR                0x02u
#define ICH_HST_STA_HOST_BUSY           0x01u
#define ICH_HST_STA_ERRORS              (ICH_HST_STA_FAILED | ICH_HST_STA_BUS_ERR | ICH_HST_STA_DEV_ERR)
#define ICH_HST_CNT                     0x02u
#define ICH_HST_CNT_START               0x40u
#define ICH_HST_CNT_SMB_CMD_QUICK       0x00u
#define ICH_HST_CNT_SMB_CMD_BYTE        0x04u
#define ICH_HST_CNT_SMB_CMD_BYTE_DATA   0x08u
#define ICH_HST_CNT_SMB_CMD_WORD_DATA   0x0cu
#define ICH_HST_CNT_KILL                0x02u
#define ICH_HST_CMD                     0x03u
#define ICH_XMIT_SLVA                   0x04u
#define ICH_XMIT_SLVA_READ              0x01u
#define ICH_XMIT_SLVA_WRITE             0x00u
#define ICH_D0                          0x05u
#define ICH_D1                          0x06u
#define ICH_AUX_CNT                     0x0du
#define ICH_AUX_CNT_E32B                0x02u

#define ICHSMB_FEATURE_BLOCK_BUFFER     0x01u
#define ICHSMB_MAX_CONTROLLERS          4u
#define ICHSMB_WAIT_LOOPS               2000000u

#define PCI_CLASS_SERIAL_BUS            0x0cu
#define PCI_SUBCLASS_SMBUS              0x05u
#define PCI_VENDOR_INTEL                0x8086u

struct ichsmb_id {
    uint16_t device;
    uint32_t features;
    const char *name;
};

struct ichsmb_controller {
    uint8_t used;
    uint8_t bus;
    uint8_t slot;
    uint8_t func;
    uint16_t vendor;
    uint16_t device;
    uint16_t io_base;
    uint8_t hostc;
    uint32_t features;
    const char *name;
    spinlock_t lock;
};

static const struct ichsmb_id g_ichsmb_ids[] = {
    { 0x2413u, 0, "Intel 82801AA ICH SMBus" },
    { 0x2423u, 0, "Intel 82801AB ICH0 SMBus" },
    { 0x2443u, 0, "Intel 82801BA ICH2 SMBus" },
    { 0x2483u, 0, "Intel 82801CA ICH3 SMBus" },
    { 0x24c3u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel 82801DC ICH4 SMBus" },
    { 0x24d3u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel 82801EB ICH5 SMBus" },
    { 0x266au, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel 82801FB ICH6 SMBus" },
    { 0x27dau, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel 82801GB ICH7 SMBus" },
    { 0x283eu, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel 82801H ICH8 SMBus" },
    { 0x2930u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel 82801I ICH9 SMBus" },
    { 0x3a30u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel 82801JI ICH10 SMBus" },
    { 0x3a60u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel 82801JD ICH10 SMBus" },
    { 0x3b30u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel PCH SMBus" },
    { 0x1c22u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Cougar Point SMBus" },
    { 0x1e22u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Panther Point SMBus" },
    { 0x8c22u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Lynx Point SMBus" },
    { 0x9c22u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Lynx Point-LP SMBus" },
    { 0xa123u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Sunrise Point-H SMBus" },
    { 0x9d23u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Sunrise Point-LP SMBus" },
    { 0xa2a3u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Kaby Lake SMBus" },
    { 0xa323u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Cannon Lake SMBus" },
    { 0x02a3u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Comet Lake SMBus" },
    { 0x06a3u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Comet Lake SMBus" },
    { 0xa0a3u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Tiger Lake SMBus" },
    { 0x43a3u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Tiger Lake SMBus" },
    { 0x7aa3u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Alder Lake SMBus" },
    { 0x51a3u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Alder Lake SMBus" },
    { 0x54a3u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Alder Lake SMBus" },
    { 0x7a23u, 0, "Intel Raptor Lake SMBus" },
    { 0x7e22u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Meteor Lake SMBus" },
    { 0x7f23u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Meteor Lake SMBus" },
    { 0xae22u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Meteor Lake SMBus" },
    { 0xe422u, ICHSMB_FEATURE_BLOCK_BUFFER, "Intel Panther Lake SMBus" },
};

static struct ichsmb_controller g_ichsmb[ICHSMB_MAX_CONTROLLERS];
static uint32_t g_ichsmb_count;

static const struct ichsmb_id *ichsmb_match_id(uint16_t device) {
    for (uint32_t i = 0; i < sizeof(g_ichsmb_ids) / sizeof(g_ichsmb_ids[0]); ++i) {
        if (g_ichsmb_ids[i].device == device) return &g_ichsmb_ids[i];
    }
    return 0;
}

static uint8_t smbio_read8(const struct ichsmb_controller *c, uint8_t reg) {
    return inportb((uint16_t)(c->io_base + reg));
}

static void smbio_write8(const struct ichsmb_controller *c, uint8_t reg, uint8_t value) {
    outportb((uint16_t)(c->io_base + reg), value);
}

static int ichsmb_status_to_error(uint8_t status) {
    if (status & ICH_HST_STA_BUS_ERR) return EDGE_SMBUS_EBUSY;
    if (status & ICH_HST_STA_DEV_ERR) return EDGE_SMBUS_ENOACK;
    if (status & ICH_HST_STA_FAILED) return EDGE_SMBUS_EIO;
    return EDGE_SMBUS_OK;
}

static int ichsmb_wait_idle(struct ichsmb_controller *c) {
    for (uint32_t i = 0; i < ICHSMB_WAIT_LOOPS; ++i) {
        uint8_t st = smbio_read8(c, ICH_HST_STA);
        if ((st & ICH_HST_STA_HOST_BUSY) == 0) return EDGE_SMBUS_OK;
        __asm__ __volatile__("pause");
    }
    return EDGE_SMBUS_TIMEOUT;
}

static int ichsmb_start_transaction(struct ichsmb_controller *c, uint8_t command) {
    int ret;

    ret = ichsmb_wait_idle(c);
    if (ret < 0) return ret;

    smbio_write8(c, ICH_HST_STA, 0xffu);
    if (c->features & ICHSMB_FEATURE_BLOCK_BUFFER) {
        smbio_write8(c, ICH_AUX_CNT, (uint8_t)(smbio_read8(c, ICH_AUX_CNT) & ~ICH_AUX_CNT_E32B));
    }
    smbio_write8(c, ICH_HST_CNT, (uint8_t)(ICH_HST_CNT_START | command));

    for (uint32_t i = 0; i < ICHSMB_WAIT_LOOPS; ++i) {
        uint8_t st = smbio_read8(c, ICH_HST_STA);
        if (st & ICH_HST_STA_ERRORS) {
            smbio_write8(c, ICH_HST_STA, st);
            return ichsmb_status_to_error(st);
        }
        if (st & ICH_HST_STA_INTR) {
            smbio_write8(c, ICH_HST_STA, st);
            return EDGE_SMBUS_OK;
        }
        /*
         * Some controllers briefly report an idle status byte before the
         * interrupt bit is observable on the LPC/SMBus I/O window.  Keep
         * polling until a completion/error bit appears or the real timeout
         * expires; otherwise a valid slow transaction can be reported as a
         * timeout while the device is still progressing.
         */
        __asm__ __volatile__("pause");
    }

    smbio_write8(c, ICH_HST_CNT, ICH_HST_CNT_KILL);
    return EDGE_SMBUS_TIMEOUT;
}

static int ichsmb_transfer(uint8_t controller, uint8_t slave_7bit, uint8_t command,
                           uint8_t op, uint8_t read, uint16_t *word, uint8_t *byte) {
    struct ichsmb_controller *c;
    uint64_t flags;
    int ret;

    if (controller >= g_ichsmb_count || !word) return EDGE_SMBUS_ENODEV;
    if (slave_7bit > 0x7fu) return EDGE_SMBUS_EINVAL;
    c = &g_ichsmb[controller];
    if (!c->used) return EDGE_SMBUS_ENODEV;

    flags = spin_lock_irqsave(&c->lock);
    smbio_write8(c, ICH_XMIT_SLVA, (uint8_t)((slave_7bit << 1) | (read ? ICH_XMIT_SLVA_READ : ICH_XMIT_SLVA_WRITE)));
    if (op != ICH_HST_CNT_SMB_CMD_QUICK) smbio_write8(c, ICH_HST_CMD, command);
    if (!read) {
        smbio_write8(c, ICH_D0, (uint8_t)(*word & 0xffu));
        if (op == ICH_HST_CNT_SMB_CMD_WORD_DATA) smbio_write8(c, ICH_D1, (uint8_t)(*word >> 8));
    }
    ret = ichsmb_start_transaction(c, op);
    if (ret == EDGE_SMBUS_OK && read) {
        if (op == ICH_HST_CNT_SMB_CMD_WORD_DATA) {
            *word = (uint16_t)smbio_read8(c, ICH_D0) |
                    ((uint16_t)smbio_read8(c, ICH_D1) << 8);
        } else if (byte) {
            *byte = smbio_read8(c, ICH_D0);
            *word = *byte;
        }
    }
    spin_unlock_irqrestore(&c->lock, flags);
    return ret;
}

static int ichsmb_probe_function(uint8_t bus, uint8_t slot, uint8_t func) {
    const struct ichsmb_id *id;
    struct ichsmb_controller *c;
    uint16_t vendor = pci_cfg_read16(bus, slot, func, 0x00);
    uint16_t device;
    uint8_t class_code;
    uint8_t subclass;
    uint32_t bar;
    uint16_t io_base;
    uint8_t hostc;

    if (vendor != PCI_VENDOR_INTEL) return 0;
    device = pci_cfg_read16(bus, slot, func, 0x02);
    id = ichsmb_match_id(device);
    if (!id) return 0;
    class_code = pci_cfg_read8(bus, slot, func, 0x0b);
    subclass = pci_cfg_read8(bus, slot, func, 0x0a);
    if (class_code != PCI_CLASS_SERIAL_BUS || subclass != PCI_SUBCLASS_SMBUS) return 0;
    if (g_ichsmb_count >= ICHSMB_MAX_CONTROLLERS) {
        printf("[smbus] dropping %02x:%02x.%u %04x:%04x: controller table full\n",
               bus, slot, func, vendor, device);
        return 0;
    }

    bar = pci_cfg_read32(bus, slot, func, ICH_SMB_BASE);
    if ((bar & 1u) == 0) {
        printf("[smbus] %02x:%02x.%u %04x:%04x has non-I/O SMBus BAR 0x%x\n",
               bus, slot, func, vendor, device, bar);
        return 0;
    }
    io_base = (uint16_t)(bar & ~0x1fu);
    if (!io_base) {
        printf("[smbus] %02x:%02x.%u %04x:%04x has null SMBus I/O base\n",
               bus, slot, func, vendor, device);
        return 0;
    }

    hostc = pci_cfg_read8(bus, slot, func, ICH_HOSTC);
    if ((hostc & ICH_HOSTC_HST_EN) == 0) {
        pci_cfg_write8(bus, slot, func, ICH_HOSTC, (uint8_t)((hostc | ICH_HOSTC_HST_EN) & ~ICH_HOSTC_SMB_SMI_EN));
        hostc = pci_cfg_read8(bus, slot, func, ICH_HOSTC);
    }
    if ((hostc & ICH_HOSTC_HST_EN) == 0) {
        printf("[smbus] %02x:%02x.%u %s failed to enable host controller hostc=0x%x\n",
               bus, slot, func, id->name, hostc);
        return 0;
    }

    c = &g_ichsmb[g_ichsmb_count++];
    memset(c, 0, sizeof(*c));
    c->used = 1;
    c->bus = bus;
    c->slot = slot;
    c->func = func;
    c->vendor = vendor;
    c->device = device;
    c->io_base = io_base;
    c->hostc = hostc;
    c->features = id->features;
    c->name = id->name;
    spinlock_init(&c->lock);
    smbio_write8(c, ICH_HST_CNT, 0);
    smbio_write8(c, ICH_HST_STA, 0xffu);
    printf("[smbus] %s ready at %02x:%02x.%u io=0x%x hostc=0x%x features=0x%x\n",
           c->name, bus, slot, func, c->io_base, c->hostc, c->features);
    return 1;
}

void smbus_init(void) {
    g_ichsmb_count = 0;
    memset(g_ichsmb, 0, sizeof(g_ichsmb));

    for (uint32_t bus = 0; bus < 256u; ++bus) {
        for (uint32_t slot = 0; slot < 32u; ++slot) {
            uint16_t vendor0 = pci_cfg_read16((uint8_t)bus, (uint8_t)slot, 0, 0x00);
            uint8_t header_type;
            uint32_t max_func;

            if (vendor0 == PCI_VENDOR_INVALID) continue;
            header_type = pci_cfg_read8((uint8_t)bus, (uint8_t)slot, 0, 0x0e);
            max_func = (header_type & 0x80u) ? 8u : 1u;
            for (uint32_t func = 0; func < max_func; ++func) {
                if (pci_cfg_read16((uint8_t)bus, (uint8_t)slot, (uint8_t)func, 0x00) == PCI_VENDOR_INVALID) continue;
                ichsmb_probe_function((uint8_t)bus, (uint8_t)slot, (uint8_t)func);
            }
        }
    }

    if (g_ichsmb_count == 0) printf("[smbus] no Intel ICH/PCH SMBus controller found\n");
    else printf("[smbus] initialized %u controller(s)\n", g_ichsmb_count);
}

int smbus_controller_count(void) {
    return (int)g_ichsmb_count;
}

int smbus_is_ready(void) {
    return g_ichsmb_count != 0;
}

int smbus_pci_function_ready(uint8_t bus, uint8_t slot, uint8_t func) {
    for (uint32_t i = 0; i < g_ichsmb_count; ++i) {
        if (g_ichsmb[i].used &&
            g_ichsmb[i].bus == bus &&
            g_ichsmb[i].slot == slot &&
            g_ichsmb[i].func == func) {
            return 1;
        }
    }
    return 0;
}

int smbus_pci_device_supported(uint16_t vendor, uint16_t device) {
    return vendor == PCI_VENDOR_INTEL && ichsmb_match_id(device) != 0;
}

int smbus_read_byte(uint8_t controller, uint8_t slave_7bit, uint8_t command, uint8_t *out) {
    uint16_t word = 0;
    uint8_t byte = 0;
    int ret;

    if (!out) return EDGE_SMBUS_EINVAL;
    ret = ichsmb_transfer(controller, slave_7bit, command, ICH_HST_CNT_SMB_CMD_BYTE_DATA, 1, &word, &byte);
    if (ret == EDGE_SMBUS_OK) *out = byte;
    return ret;
}

int smbus_read_word(uint8_t controller, uint8_t slave_7bit, uint8_t command, uint16_t *out) {
    uint16_t word = 0;
    int ret;

    if (!out) return EDGE_SMBUS_EINVAL;
    ret = ichsmb_transfer(controller, slave_7bit, command, ICH_HST_CNT_SMB_CMD_WORD_DATA, 1, &word, 0);
    if (ret == EDGE_SMBUS_OK) *out = word;
    return ret;
}

int smbus_write_byte(uint8_t controller, uint8_t slave_7bit, uint8_t command, uint8_t value) {
    uint16_t word = value;
    return ichsmb_transfer(controller, slave_7bit, command, ICH_HST_CNT_SMB_CMD_BYTE_DATA, 0, &word, 0);
}

int smbus_write_word(uint8_t controller, uint8_t slave_7bit, uint8_t command, uint16_t value) {
    uint16_t word = value;
    return ichsmb_transfer(controller, slave_7bit, command, ICH_HST_CNT_SMB_CMD_WORD_DATA, 0, &word, 0);
}
