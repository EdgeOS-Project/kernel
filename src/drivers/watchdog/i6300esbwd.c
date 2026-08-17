/*
 * Copyright (c) 2025 The FreeBSD Foundation
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Modifications for EdgeOS.
 * Copyright (c) EdgeOS Contributors.
 *
 * Portions of this file are BSD-derived from FreeBSD's sys/dev/ichwd and
 * sys/dev/amdsbwd watchdog drivers.  The EdgeOS port keeps the hardware
 * programming models but replaces FreeBSD device_t/resource/eventhandler glue
 * with EdgeOS PCI, port I/O, MMIO, and Linux-compatible /dev/watchdog
 * integration.
 */

/*
 * Reference: Intel 6300ESB Controller Hub Datasheet Section 16.
 *
 * Linux ABI red flags:
 * - Do not expose /dev/watchdog when no real timer hardware was initialized.
 * - Do not claim WDIOF_MAGICCLOSE until close(2) can disable an armed timer
 *   after userspace writes the magic 'V' byte.  A write alone is keepalive.
 * - Do not return success for unsupported pretimeout/temperature features.
 */

#include "drivers/watchdog.h"
#include "drivers/pci.h"
#include "arch/x86_64/io_ports.h"
#include "stdio.h"
#include "sys/boottime.h"
#include "sys/mmio.h"
#include "sys/spinlock.h"

#ifdef CONFIG_BSD_DRIVER_BRIDGE
#include "compat/freebsd/edgeos/watchdog.h"
#include "compat/freebsd/edgeos/x86_64_handoff.h"
#endif

#include <stdint.h>

#define EDGE_ENODEV 19
#define EDGE_EINVAL 22
#define EDGE_EPERM 1
#define EDGE_EIO 5
#define EDGE_EBUSY 16

#define PCI_VENDOR_INTEL 0x8086u
#define PCI_VENDOR_AMD 0x1022u
#define PCI_VENDOR_HYGON 0x1d94u
#define DEVICEID_6300ESB_2 0x25abu

#define PCI_COMMAND_REG 0x04u
#define PCI_COMMAND_MEMORY 0x0002u

#define WDT_CONFIG_REG 0x60u
#define WDT_LOCK_REG 0x68u

#define WDT_PRELOAD_1_REG 0x00u
#define WDT_PRELOAD_2_REG 0x04u
#define WDT_RELOAD_REG 0x0cu

#define WDT_INT_TYPE_BITS 0x3u
#define WDT_INT_TYPE_DISABLED_VAL 0x3u

#define WDT_TOUT_CNF_WT_MODE (0x0u << 2)
#define WDT_ENABLE 0x02u
#define WDT_LOCK 0x01u

#define WDT_PRELOAD_BIT 20u
#define WDT_PRELOAD_BITS ((1u << WDT_PRELOAD_BIT) - 1u)

#define WDT_TIMEOUT (0x01u << 9)
#define WDT_RELOAD (0x01u << 8)
#define WDT_UNLOCK_SEQ_1_VAL 0x80u
#define WDT_UNLOCK_SEQ_2_VAL 0x86u

#define I6300ESB_DEFAULT_TIMEOUT_SEC 60
#define I6300ESB_MAX_TIMEOUT_SEC ((int)(WDT_PRELOAD_BITS / 1000u))

#define ICH_GEN_STA 0xd4u
#define ICH_GEN_STA_NO_REBOOT 0x02u
#define ICH_PMBASE 0x40u
#define ICH_PMBASE_MASK 0x7f80u
#define ICH_RCBA 0xf0u
#define ICH_GCS_OFFSET 0x3410u
#define ICH_GCS_NO_REBOOT 0x20u
#define SMI_BASE 0x30u
#define SMI_EN 0x00u
#define TCO_BASE 0x60u
#define TCO_RLD 0x00u
#define TCO_TMR1 0x01u
#define TCO1_STS 0x04u
#define TCO2_STS 0x06u
#define TCO1_CNT 0x08u
#define TCO_TMR2 0x12u
#define SMI_TCO_EN 0x2000u
#define TCO_TIMEOUT 0x0008u
#define TCO_BOOT_STS 0x0004u
#define TCO_SECOND_TO_STS 0x0002u
#define TCO_TMR_HALT 0x0800u
#define TCO_NMI2SMI_EN 0x0200u
#define TCO_CNT_PRESERVE TCO_NMI2SMI_EN
#define TCO_RLD_TMR_MIN 4u
#define TCO_RLD1_TMR_MAX 0x3fu
#define TCO_RLD2_TMR_MAX 0x03ffu
#define ICHWD_TCO_TICK_NS 600000000ull
#define INTEL_TCO_DEFAULT_TIMEOUT_SEC 60

#define AMDSB_PMIO_INDEX 0xcd6u
#define AMDSB_PM_RESET_STATUS1 0x45u
#define AMDSB_WD_RST_STS 0x02u
#define AMDSB_PM_WDT_CTRL 0x69u
#define AMDSB_WDT_DISABLE 0x01u
#define AMDSB_WDT_RES_MASK (0x02u | 0x04u)
#define AMDSB_WDT_RES_1S 0x06u
#define AMDSB_PM_WDT_BASE_MSB 0x6fu
#define AMDSB8_PM_WDT_EN 0x48u
#define AMDSB8_WDT_DEC_EN 0x01u
#define AMDSB8_WDT_DISABLE 0x02u
#define AMDSB8_PM_WDT_CTRL 0x4cu
#define AMDSB8_WDT_1HZ 0x03u
#define AMDSB8_WDT_RES_MASK 0x03u
#define AMDFCH41_PM_DECODE_EN0 0x00u
#define AMDFCH41_WDT_EN 0x80u
#define AMDFCH41_PM_DECODE_EN3 0x03u
#define AMDFCH41_WDT_RES_MASK 0x03u
#define AMDFCH41_WDT_RES_1S 0x03u
#define AMDFCH41_WDT_EN_MASK 0x0cu
#define AMDFCH41_WDT_ENABLE 0x00u
#define AMDFCH41_PM_ISA_CTRL 0x04u
#define AMDFCH41_MMIO_EN 0x02u
#define AMDFCH41_WDT_FIXED_ADDR 0xfeb00000u
#define AMDFCH41_MMIO_ADDR 0xfed80000u
#define AMDFCH41_MMIO_WDT_OFF 0x0b00u
#define AMDSB_WD_CTRL 0x00u
#define AMDSB_WD_RUN 0x01u
#define AMDSB_WD_FIRED 0x02u
#define AMDSB_WD_DISABLE 0x08u
#define AMDSB_WD_RELOAD 0x80u
#define AMDSB_WD_COUNT 0x04u
#define AMD_TCO_DEFAULT_TIMEOUT_SEC 60
#define AMD_TCO_MAX_TIMEOUT_SEC 65535

#define AMDSB_SMBUS_DEVICE 0x4385u
#define AMDFCH_SMBUS_DEVICE 0x780bu
#define AMDCZ_SMBUS_DEVICE 0x790bu
#define AMDSB8_REVID 0x40u
#define AMDFCH41_REVID 0x41u
#define AMDCZ49_REVID 0x49u

struct watchdog_ops {
    int (*enable)(void);
    int (*disable)(void);
    int (*keepalive)(void);
    int (*set_timeout)(int seconds);
    int (*get_timeout)(void);
    int (*get_timeleft)(void);
    int (*is_running)(void);
    int (*write)(const char *buf, uint32_t len);
};

struct watchdog_provider {
    const char *identity;
    const struct watchdog_ops *ops;
    uint8_t bus;
    uint8_t slot;
    uint8_t func;
};

static struct watchdog_provider g_watchdog;

struct i6300esb_watchdog {
    uint8_t present;
    uint8_t running;
    uint8_t locked;
    uint8_t bus;
    uint8_t slot;
    uint8_t func;
    uint16_t device;
    uint64_t mmio_phys;
    volatile uint8_t *mmio;
    int timeout_sec;
    uint64_t last_ping_us;
    spinlock_t lock;
};

static struct i6300esb_watchdog g_i6300;

struct intel_tco_watchdog {
    uint8_t present;
    uint8_t running;
    uint8_t tco_version;
    uint8_t bus;
    uint8_t slot;
    uint8_t func;
    uint16_t device;
    uint16_t pmbase;
    uint16_t smi_base;
    uint16_t tco_base;
    int timeout_sec;
    uint64_t last_ping_us;
    spinlock_t lock;
};

static struct intel_tco_watchdog g_itco;

struct amd_tco_watchdog {
    uint8_t present;
    uint8_t running;
    uint8_t bus;
    uint8_t slot;
    uint8_t func;
    uint16_t device;
    uint8_t revision;
    uint64_t mmio_phys;
    volatile uint8_t *mmio;
    int timeout_sec;
    uint64_t last_ping_us;
    spinlock_t lock;
};

static struct amd_tco_watchdog g_amdwd;

struct intel_tco_id {
    uint16_t device;
    uint8_t tco_version;
    const char *name;
};

static const struct intel_tco_id intel_tco_ids[] = {
    { 0x2410, 1, "Intel 82801AA TCO watchdog" },
    { 0x2420, 1, "Intel 82801AB TCO watchdog" },
    { 0x2440, 1, "Intel 82801BA TCO watchdog" },
    { 0x244c, 1, "Intel 82801BAM TCO watchdog" },
    { 0x2480, 1, "Intel 82801CA TCO watchdog" },
    { 0x248c, 1, "Intel 82801CAM TCO watchdog" },
    { 0x24c0, 1, "Intel 82801DB TCO watchdog" },
    { 0x24cc, 1, "Intel 82801DBM TCO watchdog" },
    { 0x2450, 1, "Intel 82801E TCO watchdog" },
    { 0x24dc, 1, "Intel 82801EB TCO watchdog" },
    { 0x24d0, 1, "Intel 82801EB/ER TCO watchdog" },
    { 0x25a1, 1, "Intel 6300ESB TCO watchdog" },
    { 0x2640, 2, "Intel ICH6 TCO watchdog" },
    { 0x2641, 2, "Intel ICH6M TCO watchdog" },
    { 0x2642, 2, "Intel ICH6W TCO watchdog" },
    { 0x2670, 2, "Intel 63XXESB TCO watchdog" },
    { 0x27b8, 2, "Intel ICH7 TCO watchdog" },
    { 0x27b0, 2, "Intel ICH7DH TCO watchdog" },
    { 0x27b9, 2, "Intel ICH7M TCO watchdog" },
    { 0x27bc, 2, "Intel NM10 TCO watchdog" },
    { 0x27bd, 2, "Intel ICH7M-DH TCO watchdog" },
    { 0x2810, 2, "Intel ICH8 TCO watchdog" },
    { 0x2812, 2, "Intel ICH8DH TCO watchdog" },
    { 0x2814, 2, "Intel ICH8DO TCO watchdog" },
    { 0x2815, 2, "Intel ICH8M TCO watchdog" },
    { 0x2811, 2, "Intel ICH8M-E TCO watchdog" },
    { 0x2918, 2, "Intel ICH9 TCO watchdog" },
    { 0x2912, 2, "Intel ICH9DH TCO watchdog" },
    { 0x2914, 2, "Intel ICH9DO TCO watchdog" },
    { 0x2919, 2, "Intel ICH9M TCO watchdog" },
    { 0x2917, 2, "Intel ICH9M-E TCO watchdog" },
    { 0x2916, 2, "Intel ICH9R TCO watchdog" },
    { 0x3a18, 2, "Intel ICH10 TCO watchdog" },
    { 0x3a1a, 2, "Intel ICH10D TCO watchdog" },
    { 0x3a14, 2, "Intel ICH10DO TCO watchdog" },
    { 0x3a16, 2, "Intel ICH10R TCO watchdog" },
    { 0x3b00, 2, "Intel PCH TCO watchdog" },
    { 0x3b01, 2, "Intel PCHM TCO watchdog" },
    { 0x3b02, 2, "Intel P55 TCO watchdog" },
    { 0x3b03, 2, "Intel PM55 TCO watchdog" },
    { 0x3b06, 2, "Intel H55 TCO watchdog" },
    { 0x3b07, 2, "Intel QM57 TCO watchdog" },
    { 0x3b08, 2, "Intel H57 TCO watchdog" },
    { 0x3b09, 2, "Intel HM55 TCO watchdog" },
    { 0x3b0a, 2, "Intel Q57 TCO watchdog" },
    { 0x3b0b, 2, "Intel HM57 TCO watchdog" },
    { 0x3b0d, 2, "Intel PCHMSFF TCO watchdog" },
    { 0x3b0f, 2, "Intel QS57 TCO watchdog" },
    { 0x3b12, 2, "Intel 3400 TCO watchdog" },
    { 0x3b14, 2, "Intel 3420 TCO watchdog" },
    { 0x3b16, 2, "Intel 3450 TCO watchdog" },
    { 0x0000, 0, 0 }
};

static const struct intel_tco_id *intel_tco_lookup(uint16_t device) {
    for (const struct intel_tco_id *id = intel_tco_ids; id->name; ++id) {
        if (id->device == device) return id;
    }
    if (device >= 0x1c40u && device <= 0x1c5fu) {
        static const struct intel_tco_id cpt = { 0, 2, "Intel Cougar Point TCO watchdog" };
        return &cpt;
    }
    if (device == 0x1d40u || device == 0x1d41u) {
        static const struct intel_tco_id patsburg = { 0, 2, "Intel Patsburg TCO watchdog" };
        return &patsburg;
    }
    if (device >= 0x1e40u && device <= 0x1e5fu) {
        static const struct intel_tco_id ppt = { 0, 2, "Intel Panther Point TCO watchdog" };
        return &ppt;
    }
    if (device >= 0x8c40u && device <= 0x8c5fu) {
        static const struct intel_tco_id lpt = { 0, 2, "Intel Lynx Point TCO watchdog" };
        return &lpt;
    }
    if (device == 0x8cc1u || device == 0x8cc2u || device == 0x8cc3u ||
        device == 0x8cc4u || device == 0x8cc6u) {
        static const struct intel_tco_id wcpt = { 0, 2, "Intel Wildcat Point TCO watchdog" };
        return &wcpt;
    }
    if (device >= 0x8d40u && device <= 0x8d5fu) {
        static const struct intel_tco_id wbg = { 0, 2, "Intel Wellsburg TCO watchdog" };
        return &wbg;
    }
    if ((device >= 0x9c40u && device <= 0x9c47u) ||
        device == 0x9cc1u || device == 0x9cc2u || device == 0x9cc3u ||
        device == 0x9cc5u || device == 0x9cc6u || device == 0x9cc7u ||
        device == 0x9cc9u) {
        static const struct intel_tco_id lp = { 0, 2, "Intel LP PCH TCO watchdog" };
        return &lp;
    }
    return 0;
}

static void wdt_mmio_write16(uint32_t reg, uint16_t val) {
    *(volatile uint16_t *)(g_i6300.mmio + reg) = val;
}

static void wdt_mmio_write32(uint32_t reg, uint32_t val) {
    *(volatile uint32_t *)(g_i6300.mmio + reg) = val;
}

static uint8_t wdt_lock_read(void) {
    return pci_cfg_read8(g_i6300.bus, g_i6300.slot, g_i6300.func, WDT_LOCK_REG);
}

static void wdt_lock_write(uint8_t val) {
    pci_cfg_write8(g_i6300.bus, g_i6300.slot, g_i6300.func, WDT_LOCK_REG, val);
}

static void wdt_unlock_registers(void) {
    wdt_mmio_write16(WDT_RELOAD_REG, WDT_UNLOCK_SEQ_1_VAL);
    wdt_mmio_write16(WDT_RELOAD_REG, WDT_UNLOCK_SEQ_2_VAL);
}

static void wdt_reload_locked(void) {
    wdt_unlock_registers();
    wdt_mmio_write16(WDT_RELOAD_REG, WDT_RELOAD);
    g_i6300.last_ping_us = boottime_monotonic_us();
}

static int i6300_program_timeout_locked(int seconds) {
    uint32_t preload;
    uint8_t lock_reg;

    if (!g_i6300.present) return -EDGE_ENODEV;
    if (seconds <= 0 || seconds > I6300ESB_MAX_TIMEOUT_SEC) return -EDGE_EINVAL;

    preload = (uint32_t)seconds * 1000u;
    /*
     * The 6300ESB watchdog uses two preload stages.  FreeBSD programs both
     * stages identically; EdgeOS follows that proven sequence so Linux
     * userspace's one timeout value maps to the full hardware countdown.
     */
    wdt_unlock_registers();
    wdt_mmio_write32(WDT_PRELOAD_1_REG, preload);
    wdt_unlock_registers();
    wdt_mmio_write32(WDT_PRELOAD_2_REG, preload);
    wdt_reload_locked();

    if (!g_i6300.locked) {
        lock_reg = wdt_lock_read();
        wdt_lock_write((uint8_t)(lock_reg | WDT_ENABLE));
        g_i6300.locked = (wdt_lock_read() & WDT_LOCK) ? 1u : 0u;
    }
    g_i6300.timeout_sec = seconds;
    g_i6300.running = 1;
    return 0;
}

static int i6300_disable_locked(void) {
    uint8_t lock_reg;

    if (!g_i6300.present) return -EDGE_ENODEV;
    /*
     * Intel's lock bit makes the enable bit permanent until platform reset.
     * Returning EPERM is the honest Linux-visible result; silently pretending
     * to disable a locked watchdog would risk an unexpected guest reset.
     */
    if (g_i6300.locked) return -EDGE_EPERM;

    wdt_reload_locked();
    lock_reg = wdt_lock_read();
    wdt_lock_write((uint8_t)(lock_reg & (uint8_t)~WDT_ENABLE));
    g_i6300.running = 0;
    return 0;
}

static int i6300_is_running(void) {
    return g_i6300.present && g_i6300.running;
}

static int i6300_set_timeout(int seconds) {
    int rc;
    uint64_t flags;
    if (!g_i6300.present) return -EDGE_ENODEV;
    flags = spin_lock_irqsave(&g_i6300.lock);
    rc = i6300_program_timeout_locked(seconds);
    spin_unlock_irqrestore(&g_i6300.lock, flags);
    return rc;
}

static int i6300_enable(void) {
    int rc;
    uint64_t flags;
    if (!g_i6300.present) return -EDGE_ENODEV;
    flags = spin_lock_irqsave(&g_i6300.lock);
    rc = i6300_program_timeout_locked(g_i6300.timeout_sec > 0 ? g_i6300.timeout_sec :
                                    I6300ESB_DEFAULT_TIMEOUT_SEC);
    spin_unlock_irqrestore(&g_i6300.lock, flags);
    return rc;
}

static int i6300_disable(void) {
    int rc;
    uint64_t flags;
    if (!g_i6300.present) return -EDGE_ENODEV;
    flags = spin_lock_irqsave(&g_i6300.lock);
    rc = i6300_disable_locked();
    spin_unlock_irqrestore(&g_i6300.lock, flags);
    return rc;
}

static int i6300_keepalive(void) {
    int rc = 0;
    uint64_t flags;
    if (!g_i6300.present) return -EDGE_ENODEV;
    flags = spin_lock_irqsave(&g_i6300.lock);
    if (g_i6300.running) {
        wdt_reload_locked();
    } else {
        /*
         * Linux watchdog writes are normally keepalives after open.  EdgeOS
         * does not yet have per-device open hooks, so the first write arms the
         * timer with the configured timeout rather than being ignored.
         */
        rc = i6300_program_timeout_locked(g_i6300.timeout_sec > 0 ? g_i6300.timeout_sec :
                                        I6300ESB_DEFAULT_TIMEOUT_SEC);
    }
    spin_unlock_irqrestore(&g_i6300.lock, flags);
    return rc;
}

static int i6300_get_timeout(void) {
    if (!g_i6300.present) return -EDGE_ENODEV;
    return g_i6300.timeout_sec > 0 ? g_i6300.timeout_sec : I6300ESB_DEFAULT_TIMEOUT_SEC;
}

static int i6300_get_timeleft(void) {
    uint64_t now;
    uint64_t elapsed_sec;
    int timeout;

    if (!g_i6300.present) return -EDGE_ENODEV;
    if (!g_i6300.running) return 0;
    timeout = i6300_get_timeout();
    now = boottime_monotonic_us();
    elapsed_sec = (now > g_i6300.last_ping_us) ? ((now - g_i6300.last_ping_us) / 1000000ull) : 0;
    if (elapsed_sec >= (uint64_t)timeout) return 0;
    return timeout - (int)elapsed_sec;
}

static int i6300_write(const char *buf, uint32_t len) {
    (void)buf;
    if (!g_i6300.present) return -EDGE_ENODEV;
    if (len == 0) return 0;
    {
        int rc = i6300_keepalive();
        if (rc < 0) return rc;
    }
    return (int)len;
}

static const struct watchdog_ops i6300_ops = {
    i6300_enable, i6300_disable, i6300_keepalive, i6300_set_timeout,
    i6300_get_timeout, i6300_get_timeleft, i6300_is_running, i6300_write
};

static int watchdog_register_provider(const char *identity, const struct watchdog_ops *ops,
                                      uint8_t bus, uint8_t slot, uint8_t func) {
    if (g_watchdog.ops) return -EDGE_EBUSY;
    g_watchdog.identity = identity;
    g_watchdog.ops = ops;
    g_watchdog.bus = bus;
    g_watchdog.slot = slot;
    g_watchdog.func = func;
    return 0;
}

static int i6300_probe_one(uint8_t bus, uint8_t slot, uint8_t func, uint16_t device) {
    uint16_t cfg;
    uint16_t command;
    uint8_t lock_reg;
    uint32_t bar0;

    bar0 = pci_read_bar(bus, slot, func, 0);
    if ((bar0 & 0x1u) != 0 || (bar0 & ~0x0fu) == 0) {
        printf("[watchdog] i6300ESB BAR0 invalid bar=0x%x\n", bar0);
        return -EDGE_ENODEV;
    }

    g_i6300.present = 1;
    g_i6300.bus = bus;
    g_i6300.slot = slot;
    g_i6300.func = func;
    g_i6300.device = device;
    g_i6300.mmio_phys = (uint64_t)(bar0 & ~0x0fu);
    g_i6300.mmio = (volatile uint8_t *)edge_mmio_low_alias(g_i6300.mmio_phys);
    g_i6300.timeout_sec = I6300ESB_DEFAULT_TIMEOUT_SEC;
    spinlock_init(&g_i6300.lock);

    command = pci_cfg_read16(g_i6300.bus, g_i6300.slot, g_i6300.func, PCI_COMMAND_REG);
    pci_cfg_write16(g_i6300.bus, g_i6300.slot, g_i6300.func, PCI_COMMAND_REG,
                    (uint16_t)(command | PCI_COMMAND_MEMORY));

    cfg = pci_cfg_read16(g_i6300.bus, g_i6300.slot, g_i6300.func, WDT_CONFIG_REG);
    cfg = (uint16_t)((cfg & (uint16_t)~WDT_INT_TYPE_BITS) | WDT_INT_TYPE_DISABLED_VAL);
    pci_cfg_write16(g_i6300.bus, g_i6300.slot, g_i6300.func, WDT_CONFIG_REG, cfg);

    lock_reg = wdt_lock_read();
    g_i6300.locked = (lock_reg & WDT_LOCK) ? 1u : 0u;
    if (!g_i6300.locked) {
        wdt_lock_write(WDT_TOUT_CNF_WT_MODE);
        (void)i6300_disable_locked();
    } else {
        g_i6300.running = (lock_reg & WDT_ENABLE) ? 1u : 0u;
        wdt_reload_locked();
    }

    wdt_unlock_registers();
    wdt_mmio_write16(WDT_RELOAD_REG, WDT_RELOAD | WDT_TIMEOUT);
    g_i6300.last_ping_us = boottime_monotonic_us();

    printf("[watchdog] i6300ESB ready at %02x:%02x.%u mmio=0x%llx locked=%u running=%u timeout=%ds max=%ds\n",
           (uint32_t)g_i6300.bus, (uint32_t)g_i6300.slot, (uint32_t)g_i6300.func,
           (unsigned long long)g_i6300.mmio_phys,
           (uint32_t)g_i6300.locked, (uint32_t)g_i6300.running,
           g_i6300.timeout_sec, I6300ESB_MAX_TIMEOUT_SEC);
    return watchdog_register_provider("Intel 6300ESB Watchdog Timer", &i6300_ops, bus, slot, func);
}

static uint8_t pmio_read8(uint8_t reg) {
    outportb(AMDSB_PMIO_INDEX, reg);
    return inportb((uint16_t)(AMDSB_PMIO_INDEX + 1u));
}

static void pmio_write8(uint8_t reg, uint8_t val) {
    outportb(AMDSB_PMIO_INDEX, reg);
    outportb((uint16_t)(AMDSB_PMIO_INDEX + 1u), val);
}

static uint8_t amd_mmio_read8(uint32_t reg) {
    return *(volatile uint8_t *)(g_amdwd.mmio + reg);
}

static uint32_t amd_mmio_read32(uint32_t reg) {
    return *(volatile uint32_t *)(g_amdwd.mmio + reg);
}

static void amd_mmio_write32(uint32_t reg, uint32_t val) {
    *(volatile uint32_t *)(g_amdwd.mmio + reg) = val;
}

static uint8_t itco_in8(uint16_t off) {
    return inportb((uint16_t)(g_itco.tco_base + off));
}

static uint16_t itco_in16(uint16_t off) {
    return inports((uint16_t)(g_itco.tco_base + off));
}

static void itco_out8(uint16_t off, uint8_t val) {
    outportb((uint16_t)(g_itco.tco_base + off), val);
}

static void itco_out16(uint16_t off, uint16_t val) {
    outports((uint16_t)(g_itco.tco_base + off), val);
}

static uint32_t itco_smi_in32(uint16_t off) {
    return inportl((uint16_t)(g_itco.smi_base + off));
}

static void itco_smi_out32(uint16_t off, uint32_t val) {
    outportl((uint16_t)(g_itco.smi_base + off), val);
}

static void itco_sts_reset(void) {
    itco_out16(TCO1_STS, TCO_TIMEOUT);
    itco_out16(TCO2_STS, TCO_SECOND_TO_STS);
    if (g_itco.tco_version < 4) itco_out16(TCO2_STS, TCO_BOOT_STS);
}

static void itco_timer_enable_locked(void) {
    uint16_t cnt = (uint16_t)(itco_in16(TCO1_CNT) & TCO_CNT_PRESERVE);
    itco_out16(TCO1_CNT, (uint16_t)(cnt & (uint16_t)~TCO_TMR_HALT));
    g_itco.running = 1;
}

static void itco_timer_disable_locked(void) {
    uint16_t cnt = (uint16_t)(itco_in16(TCO1_CNT) & TCO_CNT_PRESERVE);
    itco_out16(TCO1_CNT, (uint16_t)(cnt | TCO_TMR_HALT));
    g_itco.running = 0;
}

static void itco_reload_locked(void) {
    if (g_itco.tco_version == 1) itco_out8(TCO_RLD, 1);
    else itco_out16(TCO_RLD, 1);
    g_itco.last_ping_us = boottime_monotonic_us();
}

static unsigned int itco_seconds_to_ticks(int seconds) {
    uint64_t ns = (uint64_t)seconds * 1000000000ull;
    uint64_t ticks = (ns + ICHWD_TCO_TICK_NS - 1ull) / ICHWD_TCO_TICK_NS;
    if (ticks < TCO_RLD_TMR_MIN) ticks = TCO_RLD_TMR_MIN;
    if (ticks > TCO_RLD2_TMR_MAX) ticks = TCO_RLD2_TMR_MAX;
    return (unsigned int)ticks;
}

static int itco_program_timeout_locked(int seconds) {
    unsigned int ticks;
    if (!g_itco.present) return -EDGE_ENODEV;
    if (seconds <= 0) return -EDGE_EINVAL;
    ticks = itco_seconds_to_ticks(seconds);
    if (g_itco.tco_version == 1) {
        uint8_t tmr = itco_in8(TCO_TMR1);
        if (ticks > TCO_RLD1_TMR_MAX) ticks = TCO_RLD1_TMR_MAX;
        tmr = (uint8_t)((tmr & (uint8_t)~TCO_RLD1_TMR_MAX) | (uint8_t)ticks);
        itco_out8(TCO_TMR1, tmr);
    } else {
        uint16_t tmr = itco_in16(TCO_TMR2);
        tmr = (uint16_t)((tmr & (uint16_t)~TCO_RLD2_TMR_MAX) | (uint16_t)ticks);
        itco_out16(TCO_TMR2, tmr);
    }
    g_itco.timeout_sec = seconds;
    itco_timer_enable_locked();
    itco_reload_locked();
    return 0;
}

static int itco_enable(void) {
    int rc;
    uint64_t flags;
    if (!g_itco.present) return -EDGE_ENODEV;
    flags = spin_lock_irqsave(&g_itco.lock);
    rc = itco_program_timeout_locked(g_itco.timeout_sec > 0 ? g_itco.timeout_sec :
                                     INTEL_TCO_DEFAULT_TIMEOUT_SEC);
    spin_unlock_irqrestore(&g_itco.lock, flags);
    return rc;
}

static int itco_disable(void) {
    uint64_t flags;
    if (!g_itco.present) return -EDGE_ENODEV;
    flags = spin_lock_irqsave(&g_itco.lock);
    itco_reload_locked();
    itco_timer_disable_locked();
    spin_unlock_irqrestore(&g_itco.lock, flags);
    return 0;
}

static int itco_keepalive(void) {
    int rc = 0;
    uint64_t flags;
    if (!g_itco.present) return -EDGE_ENODEV;
    flags = spin_lock_irqsave(&g_itco.lock);
    if (g_itco.running) itco_reload_locked();
    else rc = itco_program_timeout_locked(g_itco.timeout_sec > 0 ? g_itco.timeout_sec :
                                          INTEL_TCO_DEFAULT_TIMEOUT_SEC);
    spin_unlock_irqrestore(&g_itco.lock, flags);
    return rc;
}

static int itco_set_timeout(int seconds) {
    int rc;
    uint64_t flags;
    if (!g_itco.present) return -EDGE_ENODEV;
    flags = spin_lock_irqsave(&g_itco.lock);
    rc = itco_program_timeout_locked(seconds);
    spin_unlock_irqrestore(&g_itco.lock, flags);
    return rc;
}

static int itco_get_timeout(void) {
    if (!g_itco.present) return -EDGE_ENODEV;
    return g_itco.timeout_sec > 0 ? g_itco.timeout_sec : INTEL_TCO_DEFAULT_TIMEOUT_SEC;
}

static int itco_get_timeleft(void) {
    uint64_t now;
    uint64_t elapsed_sec;
    int timeout;
    if (!g_itco.present) return -EDGE_ENODEV;
    if (!g_itco.running) return 0;
    timeout = itco_get_timeout();
    now = boottime_monotonic_us();
    elapsed_sec = (now > g_itco.last_ping_us) ? ((now - g_itco.last_ping_us) / 1000000ull) : 0;
    if (elapsed_sec >= (uint64_t)timeout) return 0;
    return timeout - (int)elapsed_sec;
}

static int itco_is_running(void) {
    return g_itco.present && g_itco.running;
}

static int itco_write(const char *buf, uint32_t len) {
    (void)buf;
    if (!g_itco.present) return -EDGE_ENODEV;
    if (len == 0) return 0;
    {
        int rc = itco_keepalive();
        if (rc < 0) return rc;
    }
    return (int)len;
}

static const struct watchdog_ops itco_ops = {
    itco_enable, itco_disable, itco_keepalive, itco_set_timeout,
    itco_get_timeout, itco_get_timeleft, itco_is_running, itco_write
};

static int intel_tco_probe_one(uint8_t bus, uint8_t slot, uint8_t func, uint16_t device) {
    const struct intel_tco_id *id = intel_tco_lookup(device);
    uint16_t pmbase;
    uint32_t smi;
    uint32_t rcba;
    if (!id) return -EDGE_ENODEV;

    pmbase = (uint16_t)(pci_cfg_read16(bus, slot, func, ICH_PMBASE) & ICH_PMBASE_MASK);
    if (!pmbase) return -EDGE_ENODEV;

    g_itco.present = 1;
    g_itco.bus = bus;
    g_itco.slot = slot;
    g_itco.func = func;
    g_itco.device = device;
    g_itco.tco_version = id->tco_version;
    g_itco.pmbase = pmbase;
    g_itco.smi_base = (uint16_t)(pmbase + SMI_BASE);
    g_itco.tco_base = (uint16_t)(pmbase + TCO_BASE);
    g_itco.timeout_sec = INTEL_TCO_DEFAULT_TIMEOUT_SEC;
    spinlock_init(&g_itco.lock);

    if (g_itco.tco_version == 1) {
        uint8_t gen = pci_cfg_read8(bus, slot, func, ICH_GEN_STA);
        pci_cfg_write8(bus, slot, func, ICH_GEN_STA, (uint8_t)(gen & (uint8_t)~ICH_GEN_STA_NO_REBOOT));
        if (pci_cfg_read8(bus, slot, func, ICH_GEN_STA) & ICH_GEN_STA_NO_REBOOT) {
            g_itco.present = 0;
            return -EDGE_EIO;
        }
    } else {
        rcba = pci_cfg_read32(bus, slot, func, ICH_RCBA);
        if ((rcba & 1u) != 0 && (rcba & 0xffffc000u) != 0) {
            volatile uint32_t *gcs = (volatile uint32_t *)edge_mmio_low_alias((uint64_t)((rcba & 0xffffc000u) + ICH_GCS_OFFSET));
            uint32_t status = *gcs & ~ICH_GCS_NO_REBOOT;
            *gcs = status;
            if ((*gcs & ICH_GCS_NO_REBOOT) != 0) {
                g_itco.present = 0;
                return -EDGE_EIO;
            }
        }
    }

    itco_sts_reset();
    itco_timer_disable_locked();
    smi = itco_smi_in32(SMI_EN);
    itco_smi_out32(SMI_EN, smi & ~SMI_TCO_EN);
    g_itco.last_ping_us = boottime_monotonic_us();

    printf("[watchdog] Intel TCO ready at %02x:%02x.%u io=0x%x smi=0x%x version=%u timeout=%ds\n",
           (uint32_t)bus, (uint32_t)slot, (uint32_t)func,
           (uint32_t)g_itco.tco_base, (uint32_t)g_itco.smi_base,
           (uint32_t)g_itco.tco_version, g_itco.timeout_sec);
    return watchdog_register_provider(id->name, &itco_ops, bus, slot, func);
}

static int amd_program_timeout_locked(int seconds) {
    if (!g_amdwd.present) return -EDGE_ENODEV;
    if (seconds <= 0 || seconds > AMD_TCO_MAX_TIMEOUT_SEC) return -EDGE_EINVAL;
    amd_mmio_write32(AMDSB_WD_COUNT, (uint32_t)seconds);
    g_amdwd.timeout_sec = seconds;
    amd_mmio_write32(AMDSB_WD_CTRL, amd_mmio_read32(AMDSB_WD_CTRL) | AMDSB_WD_RUN | AMDSB_WD_RELOAD);
    g_amdwd.running = 1;
    g_amdwd.last_ping_us = boottime_monotonic_us();
    return 0;
}

static int amd_enable(void) {
    int rc;
    uint64_t flags;
    if (!g_amdwd.present) return -EDGE_ENODEV;
    flags = spin_lock_irqsave(&g_amdwd.lock);
    rc = amd_program_timeout_locked(g_amdwd.timeout_sec > 0 ? g_amdwd.timeout_sec :
                                    AMD_TCO_DEFAULT_TIMEOUT_SEC);
    spin_unlock_irqrestore(&g_amdwd.lock, flags);
    return rc;
}

static int amd_disable(void) {
    uint64_t flags;
    if (!g_amdwd.present) return -EDGE_ENODEV;
    flags = spin_lock_irqsave(&g_amdwd.lock);
    amd_mmio_write32(AMDSB_WD_CTRL, amd_mmio_read32(AMDSB_WD_CTRL) & ~AMDSB_WD_RUN);
    g_amdwd.running = 0;
    spin_unlock_irqrestore(&g_amdwd.lock, flags);
    return 0;
}

static int amd_keepalive(void) {
    int rc = 0;
    uint64_t flags;
    if (!g_amdwd.present) return -EDGE_ENODEV;
    flags = spin_lock_irqsave(&g_amdwd.lock);
    if (g_amdwd.running) {
        amd_mmio_write32(AMDSB_WD_CTRL, amd_mmio_read32(AMDSB_WD_CTRL) | AMDSB_WD_RELOAD);
        g_amdwd.last_ping_us = boottime_monotonic_us();
    } else {
        rc = amd_program_timeout_locked(g_amdwd.timeout_sec > 0 ? g_amdwd.timeout_sec :
                                        AMD_TCO_DEFAULT_TIMEOUT_SEC);
    }
    spin_unlock_irqrestore(&g_amdwd.lock, flags);
    return rc;
}

static int amd_set_timeout(int seconds) {
    int rc;
    uint64_t flags;
    if (!g_amdwd.present) return -EDGE_ENODEV;
    flags = spin_lock_irqsave(&g_amdwd.lock);
    rc = amd_program_timeout_locked(seconds);
    spin_unlock_irqrestore(&g_amdwd.lock, flags);
    return rc;
}

static int amd_get_timeout(void) {
    if (!g_amdwd.present) return -EDGE_ENODEV;
    return g_amdwd.timeout_sec > 0 ? g_amdwd.timeout_sec : AMD_TCO_DEFAULT_TIMEOUT_SEC;
}

static int amd_get_timeleft(void) {
    uint64_t now;
    uint64_t elapsed_sec;
    int timeout;
    if (!g_amdwd.present) return -EDGE_ENODEV;
    if (!g_amdwd.running) return 0;
    timeout = amd_get_timeout();
    now = boottime_monotonic_us();
    elapsed_sec = (now > g_amdwd.last_ping_us) ? ((now - g_amdwd.last_ping_us) / 1000000ull) : 0;
    if (elapsed_sec >= (uint64_t)timeout) return 0;
    return timeout - (int)elapsed_sec;
}

static int amd_is_running(void) {
    return g_amdwd.present && g_amdwd.running;
}

static int amd_write(const char *buf, uint32_t len) {
    (void)buf;
    if (!g_amdwd.present) return -EDGE_ENODEV;
    if (len == 0) return 0;
    {
        int rc = amd_keepalive();
        if (rc < 0) return rc;
    }
    return (int)len;
}

static const struct watchdog_ops amd_ops = {
    amd_enable, amd_disable, amd_keepalive, amd_set_timeout,
    amd_get_timeout, amd_get_timeleft, amd_is_running, amd_write
};

static int amd_tco_probe_one(uint8_t bus, uint8_t slot, uint8_t func, uint16_t device) {
    uint8_t rev = pci_cfg_read8(bus, slot, func, 0x08);
    uint32_t addr = 0;
    if (!((device == AMDSB_SMBUS_DEVICE && pci_cfg_read16(bus, slot, func, 0x00) == PCI_VENDOR_AMD) ||
          (device == AMDFCH_SMBUS_DEVICE && pci_cfg_read16(bus, slot, func, 0x00) == PCI_VENDOR_AMD) ||
          (device == AMDCZ_SMBUS_DEVICE && (pci_cfg_read16(bus, slot, func, 0x00) == PCI_VENDOR_AMD ||
                                            pci_cfg_read16(bus, slot, func, 0x00) == PCI_VENDOR_HYGON)))) {
        return -EDGE_ENODEV;
    }

    if (device == AMDSB_SMBUS_DEVICE && rev < AMDSB8_REVID) {
        uint8_t val;
        for (int i = 0; i < 4; ++i) {
            addr <<= 8;
            addr |= pmio_read8((uint8_t)(AMDSB_PM_WDT_BASE_MSB - i));
        }
        addr &= ~0x07u;
        val = pmio_read8(AMDSB_PM_WDT_CTRL);
        val = (uint8_t)((val & (uint8_t)~AMDSB_WDT_RES_MASK) | AMDSB_WDT_RES_1S);
        val &= (uint8_t)~AMDSB_WDT_DISABLE;
        pmio_write8(AMDSB_PM_WDT_CTRL, val);
    } else if (device == AMDSB_SMBUS_DEVICE ||
               (device == AMDFCH_SMBUS_DEVICE && rev < AMDFCH41_REVID) ||
               (device == AMDCZ_SMBUS_DEVICE && rev < AMDCZ49_REVID)) {
        uint8_t val;
        for (int i = 0; i < 4; ++i) {
            addr <<= 8;
            addr |= pmio_read8((uint8_t)(AMDSB8_PM_WDT_EN + 3 - i));
        }
        addr &= ~0x07u;
        val = pmio_read8(AMDSB8_PM_WDT_CTRL);
        val = (uint8_t)((val & (uint8_t)~AMDSB8_WDT_RES_MASK) | AMDSB8_WDT_1HZ);
        pmio_write8(AMDSB8_PM_WDT_CTRL, val);
        val = pmio_read8(AMDSB8_PM_WDT_EN);
        val = (uint8_t)((val & (uint8_t)~AMDSB8_WDT_DISABLE) | AMDSB8_WDT_DEC_EN);
        pmio_write8(AMDSB8_PM_WDT_EN, val);
    } else {
        uint8_t val;
        val = pmio_read8(AMDFCH41_PM_DECODE_EN0);
        pmio_write8(AMDFCH41_PM_DECODE_EN0, (uint8_t)(val | AMDFCH41_WDT_EN));
        val = pmio_read8(AMDFCH41_PM_ISA_CTRL);
        addr = (val & AMDFCH41_MMIO_EN) ?
            (AMDFCH41_MMIO_ADDR + AMDFCH41_MMIO_WDT_OFF) : AMDFCH41_WDT_FIXED_ADDR;
        val = pmio_read8(AMDFCH41_PM_DECODE_EN3);
        val &= (uint8_t)~AMDFCH41_WDT_RES_MASK;
        val |= AMDFCH41_WDT_RES_1S;
        val &= (uint8_t)~AMDFCH41_WDT_EN_MASK;
        val |= AMDFCH41_WDT_ENABLE;
        pmio_write8(AMDFCH41_PM_DECODE_EN3, val);
    }

    if (addr == 0) return -EDGE_ENODEV;
    g_amdwd.present = 1;
    g_amdwd.bus = bus;
    g_amdwd.slot = slot;
    g_amdwd.func = func;
    g_amdwd.device = device;
    g_amdwd.revision = rev;
    g_amdwd.mmio_phys = addr;
    g_amdwd.mmio = (volatile uint8_t *)edge_mmio_low_alias(addr);
    g_amdwd.timeout_sec = AMD_TCO_DEFAULT_TIMEOUT_SEC;
    spinlock_init(&g_amdwd.lock);

    amd_mmio_write32(AMDSB_WD_CTRL, AMDSB_WD_FIRED);
    if (amd_mmio_read8(AMDSB_WD_CTRL) & AMDSB_WD_DISABLE) {
        g_amdwd.present = 0;
        return -EDGE_EIO;
    }
    (void)amd_disable();
    g_amdwd.last_ping_us = boottime_monotonic_us();

    printf("[watchdog] AMD SP5100/SB/FCH TCO ready at %02x:%02x.%u mmio=0x%llx rev=0x%x timeout=%ds\n",
           (uint32_t)bus, (uint32_t)slot, (uint32_t)func,
           (unsigned long long)g_amdwd.mmio_phys, (uint32_t)rev,
           g_amdwd.timeout_sec);
    return watchdog_register_provider("AMD SP5100/SB/FCH TCO Watchdog Timer", &amd_ops, bus, slot, func);
}

int watchdog_available(void) {
    if (g_watchdog.ops) return 1;
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    return bsd_watchdog_available();
#else
    return 0;
#endif
}

int watchdog_pci_function_ready(uint8_t bus, uint8_t slot, uint8_t func) {
    return g_watchdog.ops && g_watchdog.bus == bus && g_watchdog.slot == slot && g_watchdog.func == func;
}

int watchdog_pci_device_supported(uint16_t vendor, uint16_t device) {
    if (vendor == PCI_VENDOR_INTEL && device == DEVICEID_6300ESB_2) return 1;
    if (vendor == PCI_VENDOR_INTEL && intel_tco_lookup(device)) return 1;
    if ((vendor == PCI_VENDOR_AMD || vendor == PCI_VENDOR_HYGON) &&
        (device == AMDSB_SMBUS_DEVICE || device == AMDFCH_SMBUS_DEVICE ||
         device == AMDCZ_SMBUS_DEVICE)) return 1;
    return 0;
}

const char *watchdog_pci_device_name(uint16_t vendor, uint16_t device) {
    if (vendor == PCI_VENDOR_INTEL && device == DEVICEID_6300ESB_2) return "Intel 6300ESB watchdog";
    if (vendor == PCI_VENDOR_INTEL && intel_tco_lookup(device)) return "Intel TCO watchdog";
    if ((vendor == PCI_VENDOR_AMD || vendor == PCI_VENDOR_HYGON) &&
        (device == AMDSB_SMBUS_DEVICE || device == AMDFCH_SMBUS_DEVICE ||
         device == AMDCZ_SMBUS_DEVICE)) return "AMD SP5100/SB/FCH TCO watchdog";
    return 0;
}

const char *watchdog_identity(void) {
    if (g_watchdog.ops) return g_watchdog.identity;
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    return bsd_watchdog_identity();
#else
    return "no watchdog";
#endif
}

int watchdog_is_running(void) {
    if (g_watchdog.ops) return g_watchdog.ops->is_running();
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    return bsd_watchdog_is_running();
#else
    return 0;
#endif
}

int watchdog_set_timeout(int seconds) {
    if (g_watchdog.ops) return g_watchdog.ops->set_timeout(seconds);
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    return bsd_watchdog_set_timeout_seconds(seconds);
#else
    return -EDGE_ENODEV;
#endif
}

int watchdog_enable(void) {
    if (g_watchdog.ops) return g_watchdog.ops->enable();
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    return bsd_watchdog_enable();
#else
    return -EDGE_ENODEV;
#endif
}

int watchdog_disable(void) {
    if (g_watchdog.ops) return g_watchdog.ops->disable();
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    return bsd_watchdog_disable();
#else
    return -EDGE_ENODEV;
#endif
}

int watchdog_keepalive(void) {
    if (g_watchdog.ops) return g_watchdog.ops->keepalive();
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    return bsd_watchdog_keepalive();
#else
    return -EDGE_ENODEV;
#endif
}

int watchdog_get_timeout(void) {
    if (g_watchdog.ops) return g_watchdog.ops->get_timeout();
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    return bsd_watchdog_get_timeout_seconds();
#else
    return -EDGE_ENODEV;
#endif
}

int watchdog_get_timeleft(void) {
    if (g_watchdog.ops) return g_watchdog.ops->get_timeleft();
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    return bsd_watchdog_get_timeleft_seconds();
#else
    return -EDGE_ENODEV;
#endif
}

int watchdog_write(const char *buf, uint32_t len) {
    if (g_watchdog.ops) return g_watchdog.ops->write(buf, len);
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    return bsd_watchdog_write(buf, len);
#else
    return -EDGE_ENODEV;
#endif
}

void watchdog_init(void) {
    for (uint32_t bus = 0; bus < 256u; ++bus) {
        for (uint8_t slot = 0; slot < 32u; ++slot) {
            for (uint8_t func = 0; func < 8u; ++func) {
                uint8_t hdr;
                uint16_t vendor = pci_cfg_read16((uint8_t)bus, slot, func, 0x00);
                uint16_t device;
                if (vendor == PCI_VENDOR_INVALID) continue;
                device = pci_cfg_read16((uint8_t)bus, slot, func, 0x02);
#ifdef CONFIG_BSD_DRIVER_BRIDGE
                if (bsd_bridge_x86_64_native_pci_reserved(
                    (uint8_t)bus, slot, func))
                    continue;
#endif

                if (vendor == PCI_VENDOR_INTEL && device == DEVICEID_6300ESB_2 &&
                    i6300_probe_one((uint8_t)bus, slot, func, device) == 0) return;
                if (vendor == PCI_VENDOR_INTEL && intel_tco_lookup(device) &&
                    intel_tco_probe_one((uint8_t)bus, slot, func, device) == 0) return;
                if ((vendor == PCI_VENDOR_AMD || vendor == PCI_VENDOR_HYGON) &&
                    amd_tco_probe_one((uint8_t)bus, slot, func, device) == 0) return;

                if (func == 0) {
                    hdr = pci_header_type((uint8_t)bus, slot, func);
                    if ((hdr & 0x80u) == 0) break;
                }
            }
        }
    }
    printf("[watchdog] no supported hardware found\n");
}
