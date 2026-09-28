/* SPDX-License-Identifier: MPL-2.0 */
/*
 * PCI configuration-space helpers for EdgeOS.
 *
 * Copyright (c) EdgeOS Contributors.
 *
 * Keep this interface side-effect minimal.  Device-specific drivers may use
 * these helpers to inspect standard PCI/PCIe capabilities, but enabling bus
 * mastering, MSI/MSI-X, BAR allocation, or interrupts must stay in the owning
 * driver after its Linux-visible behavior is understood.
 */

#ifndef EDGEOS_DRIVERS_PCI_H
#define EDGEOS_DRIVERS_PCI_H

#include <stdint.h>

#define PCI_VENDOR_INVALID 0xFFFFu

#define PCI_CAP_ID_PM       0x01u
#define PCI_CAP_ID_MSI      0x05u
#define PCI_CAP_ID_PCIX     0x07u
#define PCI_CAP_ID_VENDOR   0x09u
#define PCI_CAP_ID_PCIE     0x10u
#define PCI_CAP_ID_MSIX     0x11u

#define PCI_SYSFS_PATH_NONE 0
#define PCI_SYSFS_PATH_DIR  1
#define PCI_SYSFS_PATH_FILE 2
#define PCI_SYSFS_PATH_LINK 3

uint32_t pci_cfg_read32(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off);
void pci_cfg_write32(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off, uint32_t v);
uint16_t pci_cfg_read16(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off);
void pci_cfg_write16(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off, uint16_t v);
uint8_t pci_cfg_read8(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off);
void pci_cfg_write8(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off, uint8_t v);

/*
 * Discover PCI functions once before driver probing.  Vendor/device identity
 * is immutable for an attached function, so every driver can reuse the same
 * BDF inventory instead of issuing a complete 256-bus configuration scan.
 * A future hotplug controller must call pci_inventory_refresh() after its bus
 * rescan has quiesced.
 */
void pci_inventory_init(void);
void pci_inventory_refresh(void);
uint32_t pci_function_count(void);
int pci_function_at(uint32_t index, uint8_t *bus, uint8_t *slot,
                    uint8_t *function);

int pci_find_capability(uint8_t bus, uint8_t slot, uint8_t func, uint8_t cap_id);
uint32_t pci_read_bar(uint8_t bus, uint8_t slot, uint8_t func, uint8_t bar_index);
uint8_t pci_header_type(uint8_t bus, uint8_t slot, uint8_t func);
uint8_t pci_interrupt_line(uint8_t bus, uint8_t slot, uint8_t func);
int pci_has_msi(uint8_t bus, uint8_t slot, uint8_t func);
int pci_has_msix(uint8_t bus, uint8_t slot, uint8_t func);
int pci_has_pcie(uint8_t bus, uint8_t slot, uint8_t func);
int pci_inventory_snapshot(char *buf, uint32_t max);
int pci_device_name_by_index(uint32_t index, char *out, uint32_t out_sz);
int pci_sysfs_path_kind(const char *path);
int pci_sysfs_read_file(const char *path, char *out, uint32_t max);
int pci_sysfs_readlink(const char *path, char *out, uint32_t max);

#endif
