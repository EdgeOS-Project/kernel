/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * PCI driver coverage probe.
 *
 * This module is intentionally read-only.  It does not claim devices, enable
 * bus mastering, rewrite BARs, or install IRQ handlers.  Its job is to make
 * driver coverage visible in dmesg so unsupported hardware is explicit instead
 * of silently ignored.  Keep it side-effect free; functional drivers must own
 * their device initialization paths.
 */

#include "drivers/pci_probe.h"
#include "drivers/pci.h"
#ifdef CONFIG_SMBUS
#include "drivers/smbus.h"
#endif
#ifdef CONFIG_WATCHDOG
#include "drivers/watchdog.h"
#endif
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO)
#include "drivers/audio.h"
#endif
#include "stdio.h"

#include <stdint.h>

#define PCI_CLASS_STORAGE      0x01u
#define PCI_CLASS_NETWORK      0x02u
#define PCI_CLASS_DISPLAY      0x03u
#define PCI_CLASS_MULTIMEDIA   0x04u
#define PCI_CLASS_SERIAL_BUS   0x0Cu

#define PCI_SUB_STORAGE_SCSI   0x00u
#define PCI_SUB_STORAGE_IDE    0x01u
#define PCI_SUB_STORAGE_SATA   0x06u
#define PCI_SUB_STORAGE_NVME   0x08u
#define PCI_SUB_NET_ETHERNET   0x00u
#define PCI_SUB_DISPLAY_VGA    0x00u
#define PCI_SUB_DISPLAY_3D     0x02u
#define PCI_SUB_AUDIO_AC97     0x01u
#define PCI_SUB_AUDIO_HDA      0x03u
#define PCI_SUB_USB            0x03u
#define PCI_SUB_SMBUS          0x05u

#define PCI_PROGIF_AHCI        0x01u
#define PCI_PROGIF_NVME_NVM    0x02u
#define PCI_PROGIF_UHCI        0x00u
#define PCI_PROGIF_OHCI        0x10u
#define PCI_PROGIF_EHCI        0x20u
#define PCI_PROGIF_XHCI        0x30u

#define PCI_VENDOR_INTEL       0x8086u
#define PCI_VENDOR_REALTEK     0x10ECu
#define PCI_VENDOR_VIRTIO      0x1AF4u
#define PCI_VENDOR_VMWARE      0x15ADu
#define PCI_VENDOR_BOCHS_QEMU  0x1234u
#define PCI_VENDOR_REDHAT_QXL  0x1B36u

enum pci_driver_state {
    PCI_DRV_SUPPORTED,
    PCI_DRV_PARTIAL,
    PCI_DRV_MISSING,
};

struct pci_devinfo {
    uint8_t bus;
    uint8_t slot;
    uint8_t func;
    uint16_t vendor;
    uint16_t device;
    uint8_t class_code;
    uint8_t subclass;
    uint8_t prog_if;
    uint8_t revision;
    uint8_t irq_line;
    uint8_t has_msi;
    uint8_t has_msix;
    uint8_t has_pcie;
};

struct pci_match {
    enum pci_driver_state state;
    const char *name;
};

static const char *state_name(enum pci_driver_state state) {
    switch (state) {
    case PCI_DRV_SUPPORTED: return "supported";
    case PCI_DRV_PARTIAL: return "partial";
    default: return "missing";
    }
}

static int is_intel_e1000_supported(uint16_t device) {
    switch (device) {
    case 0x100Eu:
    case 0x100Fu:
    case 0x10D3u:
    case 0x153Au:
        return 1;
    default:
        return 0;
    }
}

static int is_intel_e1000e_ethernet(uint16_t device) {
    switch (device) {
    case 0x156Fu: case 0x1570u: case 0x15B7u: case 0x15B8u:
    case 0x15B9u: case 0x15D7u: case 0x15D8u: case 0x15E3u:
    case 0x15D6u: case 0x15BDu: case 0x15BEu: case 0x15BBu:
    case 0x15BCu: case 0x15DFu: case 0x15E0u: case 0x15E1u:
    case 0x15E2u: case 0x0D4Eu: case 0x0D4Fu: case 0x0D4Cu:
    case 0x0D4Du: case 0x0D53u: case 0x0D55u: case 0x15FBu:
    case 0x15FCu: case 0x15F9u: case 0x15FAu: case 0x15F4u:
    case 0x15F5u: case 0x1A1Eu: case 0x1A1Fu: case 0x1A1Cu:
    case 0x1A1Du: case 0x550Au: case 0x550Bu: case 0x550Cu:
    case 0x550Du: case 0x550Eu: case 0x550Fu: case 0x5510u:
    case 0x5511u: case 0x0DC7u: case 0x0DC8u: case 0x0DC5u:
    case 0x0DC6u: case 0x57A0u: case 0x57A1u: case 0x57B3u:
    case 0x57B4u: case 0x57B5u: case 0x57B6u: case 0x57B7u:
    case 0x57B8u:
        return 1;
    default:
        return 0;
    }
}

static int is_intel_igc_ethernet(uint16_t device) {
    switch (device) {
    case 0x15F2u: case 0x15F3u: case 0x15F8u: case 0x5502u:
    case 0x125Bu: case 0x125Cu: case 0x125Du:
        return 1;
    default:
        return 0;
    }
}

static int intel_e1000e_ethernet_supported(void) {
#ifdef CONFIG_NET_INTEL_E1000E
    return 1;
#else
    return 0;
#endif
}

static int is_intel_wifi_requested(uint16_t device) {
    switch (device) {
    case 0x08B1u: case 0x08B2u: /* Intel 7265 family */
    case 0x24F3u: case 0x24FDu: /* Intel 8265 family */
    case 0x2723u: case 0x2725u: /* Intel AX200/AX210 family */
    case 0x06F0u: case 0x06F1u: /* Intel AX201 family */
    case 0x51F0u: case 0x51F1u: /* Intel AX211 family */
        return 1;
    default:
        return 0;
    }
}

static int is_realtek_wired_requested(uint16_t device) {
    switch (device) {
    case 0x8125u:
    case 0x8161u:
    case 0x8168u:
    case 0x8169u:
        return 1;
    default:
        return 0;
    }
}

static int is_virtio_modern_or_legacy(uint16_t device) {
    return (device >= 0x1000u && device <= 0x103Fu) ||
           (device >= 0x1040u && device <= 0x107Fu);
}

static struct pci_match classify_virtio(uint16_t device) {
    switch (device) {
    case 0x1000u:
    case 0x1041u:
        return (struct pci_match){ PCI_DRV_SUPPORTED, "VirtIO network" };
    case 0x1001u:
    case 0x1042u:
        return (struct pci_match){ PCI_DRV_SUPPORTED, "VirtIO block" };
    case 0x1010u:
    case 0x1050u:
        return (struct pci_match){ PCI_DRV_SUPPORTED, "VirtIO GPU" };
    case 0x1002u:
    case 0x1045u:
        return (struct pci_match){ PCI_DRV_SUPPORTED, "VirtIO balloon" };
    case 0x1003u:
    case 0x1043u:
        return (struct pci_match){ PCI_DRV_SUPPORTED, "VirtIO console" };
    case 0x1004u:
    case 0x1048u:
#ifdef CONFIG_VIRTIO_SCSI
        return (struct pci_match){ PCI_DRV_SUPPORTED, "VirtIO SCSI" };
#else
        return (struct pci_match){ PCI_DRV_MISSING, "VirtIO SCSI" };
#endif
    case 0x1005u:
    case 0x1044u:
        return (struct pci_match){ PCI_DRV_SUPPORTED, "VirtIO RNG" };
    case 0x1049u:
    case 0x105Au:
        return (struct pci_match){ PCI_DRV_MISSING, "VirtIO filesystem" };
    case 0x1052u:
#ifdef CONFIG_VIRTIO_INPUT
        return (struct pci_match){ PCI_DRV_SUPPORTED, "VirtIO input" };
#else
        return (struct pci_match){ PCI_DRV_MISSING, "VirtIO input" };
#endif
    default:
        if (is_virtio_modern_or_legacy(device)) {
            return (struct pci_match){ PCI_DRV_MISSING, "VirtIO device" };
        }
        return (struct pci_match){ PCI_DRV_MISSING, 0 };
    }
}

static struct pci_match classify_device(const struct pci_devinfo *d) {
#ifdef CONFIG_WATCHDOG
    if (watchdog_pci_function_ready(d->bus, d->slot, d->func)) {
        return (struct pci_match){ PCI_DRV_SUPPORTED, watchdog_pci_device_name(d->vendor, d->device) };
    }
    if (watchdog_pci_device_supported(d->vendor, d->device)) {
        return (struct pci_match){ PCI_DRV_MISSING, watchdog_pci_device_name(d->vendor, d->device) };
    }
#endif

    if (d->vendor == PCI_VENDOR_VIRTIO) {
        return classify_virtio(d->device);
    }

    if (d->class_code == PCI_CLASS_STORAGE &&
        d->subclass == PCI_SUB_STORAGE_SATA &&
        d->prog_if == PCI_PROGIF_AHCI) {
        return (struct pci_match){ PCI_DRV_SUPPORTED, "AHCI SATA" };
    }
    if (d->class_code == PCI_CLASS_STORAGE &&
        d->subclass == PCI_SUB_STORAGE_NVME &&
        d->prog_if == PCI_PROGIF_NVME_NVM) {
        return (struct pci_match){ PCI_DRV_SUPPORTED, "NVMe NVM" };
    }
    if (d->class_code == PCI_CLASS_STORAGE &&
        d->subclass == PCI_SUB_STORAGE_IDE) {
        return (struct pci_match){ PCI_DRV_SUPPORTED, "legacy ATA/IDE" };
    }
    if (d->class_code == PCI_CLASS_STORAGE &&
        d->subclass == PCI_SUB_STORAGE_SCSI) {
        if (d->vendor == PCI_VENDOR_VMWARE && d->device == 0x07C0u) {
#ifdef CONFIG_VMWARE_PVSCSI
            return (struct pci_match){ PCI_DRV_SUPPORTED, "VMware PVSCSI" };
#else
            return (struct pci_match){ PCI_DRV_MISSING, "VMware PVSCSI" };
#endif
        }
        return (struct pci_match){ PCI_DRV_MISSING, "SCSI storage controller" };
    }

    if (d->class_code == PCI_CLASS_NETWORK && d->subclass == PCI_SUB_NET_ETHERNET) {
        if (d->vendor == PCI_VENDOR_INTEL && is_intel_e1000_supported(d->device)) {
            return (struct pci_match){ PCI_DRV_SUPPORTED, "Intel e1000/e1000e Ethernet" };
        }
        if (d->vendor == PCI_VENDOR_INTEL && is_intel_e1000e_ethernet(d->device)) {
            if (intel_e1000e_ethernet_supported()) {
                return (struct pci_match){ PCI_DRV_SUPPORTED, "Intel e1000e/I219 Ethernet" };
            }
            return (struct pci_match){ PCI_DRV_MISSING, "Intel e1000e/I219 Ethernet" };
        }
        if (d->vendor == PCI_VENDOR_INTEL && is_intel_igc_ethernet(d->device)) {
#ifdef CONFIG_BSD_DRIVER_BRIDGE
            return (struct pci_match){ PCI_DRV_SUPPORTED, "FreeBSD Intel I225/I226 igc Ethernet" };
#else
            return (struct pci_match){ PCI_DRV_MISSING, "Intel I225/I226 igc Ethernet" };
#endif
        }
        if (d->vendor == PCI_VENDOR_REALTEK && is_realtek_wired_requested(d->device)) {
#ifdef CONFIG_NET_REALTEK_R8169
            return (struct pci_match){ PCI_DRV_SUPPORTED, "Realtek RTL8111/8168/8125 Ethernet" };
#else
            return (struct pci_match){ PCI_DRV_MISSING, "Realtek RTL8111/8168/8125 Ethernet" };
#endif
        }
        if (d->vendor == PCI_VENDOR_VMWARE && d->device == 0x07B0u) {
#ifdef CONFIG_BSD_DRIVER_BRIDGE
            return (struct pci_match){ PCI_DRV_SUPPORTED, "FreeBSD vmxnet3 Ethernet" };
#elif defined(CONFIG_VMWARE_VMXNET3)
            return (struct pci_match){ PCI_DRV_PARTIAL, "VMware vmxnet3 Ethernet (probe/quiesce only)" };
#else
            return (struct pci_match){ PCI_DRV_MISSING, "VMware vmxnet3 Ethernet" };
#endif
        }
        return (struct pci_match){ PCI_DRV_MISSING, "Ethernet controller" };
    }
    if (d->class_code == PCI_CLASS_NETWORK &&
        d->vendor == PCI_VENDOR_INTEL &&
        is_intel_wifi_requested(d->device)) {
#ifdef CONFIG_WIFI_INTEL_IWLWIFI
        return (struct pci_match){ PCI_DRV_PARTIAL, "Intel iwlwifi Wi-Fi (probe/quiesce only)" };
#else
        return (struct pci_match){ PCI_DRV_MISSING, "Intel Wi-Fi" };
#endif
    }

    if (d->class_code == PCI_CLASS_DISPLAY) {
        if (d->vendor == PCI_VENDOR_VMWARE && d->device == 0x0405u) {
            return (struct pci_match){ PCI_DRV_SUPPORTED, "VMware SVGA framebuffer" };
        }
        if (d->vendor == PCI_VENDOR_BOCHS_QEMU && d->device == 0x1111u) {
            return (struct pci_match){ PCI_DRV_SUPPORTED, "Bochs/QEMU BGA framebuffer" };
        }
        if (d->vendor == PCI_VENDOR_REDHAT_QXL && d->device == 0x0100u) {
            return (struct pci_match){ PCI_DRV_MISSING, "QXL display adapter" };
        }
        if (d->vendor == PCI_VENDOR_INTEL) {
#ifdef CONFIG_GRAPHICS_INTEL
            return (struct pci_match){ PCI_DRV_PARTIAL, "Intel UHD/Iris Xe graphics (probe only)" };
#else
            return (struct pci_match){ PCI_DRV_MISSING, "Intel integrated graphics" };
#endif
        }
        if (d->subclass == PCI_SUB_DISPLAY_VGA || d->subclass == PCI_SUB_DISPLAY_3D) {
            return (struct pci_match){ PCI_DRV_PARTIAL, "generic framebuffer/VGA display" };
        }
    }

    if (d->class_code == PCI_CLASS_MULTIMEDIA) {
        if (d->subclass == PCI_SUB_AUDIO_HDA) {
#ifdef CONFIG_AUDIO_HDA
            if (audio_hda_pci_function_ready(d->bus, d->slot, d->func)) {
                return (struct pci_match){ PCI_DRV_SUPPORTED, "Intel HD Audio compatible controller" };
            }
#endif
            return (struct pci_match){ PCI_DRV_MISSING, "Intel HD Audio compatible controller" };
        }
        if (d->subclass == PCI_SUB_AUDIO_AC97) {
#ifdef CONFIG_AUDIO_AC97
            if (audio_ac97_pci_function_ready(d->bus, d->slot, d->func)) {
                return (struct pci_match){ PCI_DRV_SUPPORTED, "AC97 audio controller" };
            }
#endif
            return (struct pci_match){ PCI_DRV_MISSING, "AC97 audio controller" };
        }
    }

    if (d->class_code == PCI_CLASS_SERIAL_BUS) {
        if (d->subclass == PCI_SUB_USB) {
            switch (d->prog_if) {
            case PCI_PROGIF_UHCI:
                return (struct pci_match){ PCI_DRV_SUPPORTED, "UHCI USB host controller" };
            case PCI_PROGIF_OHCI:
#ifdef CONFIG_USB_OHCI
                return (struct pci_match){ PCI_DRV_SUPPORTED, "OHCI USB host controller" };
#else
                return (struct pci_match){ PCI_DRV_MISSING, "OHCI USB host controller" };
#endif
            case PCI_PROGIF_EHCI:
#ifdef CONFIG_USB_EHCI
                return (struct pci_match){ PCI_DRV_SUPPORTED, "EHCI USB host controller" };
#else
                return (struct pci_match){ PCI_DRV_MISSING, "EHCI USB host controller" };
#endif
            case PCI_PROGIF_XHCI:
                return (struct pci_match){ PCI_DRV_SUPPORTED, "xHCI USB host controller" };
            default:
                return (struct pci_match){ PCI_DRV_MISSING, "USB host controller" };
            }
        }
        if (d->subclass == PCI_SUB_SMBUS) {
#ifdef CONFIG_SMBUS
            if (smbus_pci_function_ready(d->bus, d->slot, d->func)) {
                return (struct pci_match){ PCI_DRV_SUPPORTED, "Intel ICH/PCH SMBus controller" };
            }
            if (smbus_pci_device_supported(d->vendor, d->device)) {
                return (struct pci_match){ PCI_DRV_MISSING, "Intel ICH/PCH SMBus controller (not initialized)" };
            }
#endif
            return (struct pci_match){ PCI_DRV_MISSING, "SMBus controller" };
        }
    }

    return (struct pci_match){ PCI_DRV_MISSING, 0 };
}

static void probe_function(uint8_t bus, uint8_t slot, uint8_t func,
                           uint32_t *recognized, uint32_t *supported,
                           uint32_t *partial, uint32_t *missing) {
    struct pci_devinfo d;
    struct pci_match m;

    d.bus = bus;
    d.slot = slot;
    d.func = func;
    d.vendor = pci_cfg_read16(bus, slot, func, 0x00);
    if (d.vendor == PCI_VENDOR_INVALID) return;
    d.device = pci_cfg_read16(bus, slot, func, 0x02);
    d.revision = pci_cfg_read8(bus, slot, func, 0x08);
    d.prog_if = pci_cfg_read8(bus, slot, func, 0x09);
    d.subclass = pci_cfg_read8(bus, slot, func, 0x0A);
    d.class_code = pci_cfg_read8(bus, slot, func, 0x0B);
    d.irq_line = pci_interrupt_line(bus, slot, func);
    d.has_msi = pci_has_msi(bus, slot, func) ? 1 : 0;
    d.has_msix = pci_has_msix(bus, slot, func) ? 1 : 0;
    d.has_pcie = pci_has_pcie(bus, slot, func) ? 1 : 0;

    printf("[pci][inventory] %02x:%02x.%u %04x:%04x class=%02x/%02x/%02x rev=%02x irq=%u pcie=%u msi=%u msix=%u\n",
           d.bus, d.slot, d.func, d.vendor, d.device,
           d.class_code, d.subclass, d.prog_if, d.revision,
           (uint32_t)d.irq_line, (uint32_t)d.has_pcie,
           (uint32_t)d.has_msi, (uint32_t)d.has_msix);

    m = classify_device(&d);
    if (!m.name) return;

    (*recognized)++;
    if (m.state == PCI_DRV_SUPPORTED) (*supported)++;
    else if (m.state == PCI_DRV_PARTIAL) (*partial)++;
    else (*missing)++;

    printf("[pci][drv] %02x:%02x.%u %04x:%04x class=%02x/%02x/%02x rev=%02x irq=%u pcie=%u msi=%u msix=%u %s: %s\n",
           d.bus, d.slot, d.func, d.vendor, d.device,
           d.class_code, d.subclass, d.prog_if, d.revision,
           (uint32_t)d.irq_line, (uint32_t)d.has_pcie,
           (uint32_t)d.has_msi, (uint32_t)d.has_msix,
           state_name(m.state), m.name);
}

void pci_driver_probe_init(void) {
    uint32_t functions = 0;
    uint32_t recognized = 0;
    uint32_t supported = 0;
    uint32_t partial = 0;
    uint32_t missing = 0;

    for (uint32_t bus = 0; bus < 256; ++bus) {
        for (uint32_t slot = 0; slot < 32; ++slot) {
            uint16_t vendor0 = pci_cfg_read16((uint8_t)bus, (uint8_t)slot, 0, 0x00);
            uint8_t header_type;
            uint32_t max_func;
            if (vendor0 == PCI_VENDOR_INVALID) continue;

            header_type = pci_cfg_read8((uint8_t)bus, (uint8_t)slot, 0, 0x0E);
            max_func = (header_type & 0x80u) ? 8u : 1u;
            for (uint32_t func = 0; func < max_func; ++func) {
                uint16_t vendor = pci_cfg_read16((uint8_t)bus, (uint8_t)slot,
                                                 (uint8_t)func, 0x00);
                if (vendor == PCI_VENDOR_INVALID) continue;
                functions++;
                probe_function((uint8_t)bus, (uint8_t)slot, (uint8_t)func,
                               &recognized, &supported, &partial, &missing);
            }
        }
    }

    printf("[pci][drv] scanned %u function(s), recognized=%u supported=%u partial=%u missing=%u\n",
           functions, recognized, supported, partial, missing);
}
