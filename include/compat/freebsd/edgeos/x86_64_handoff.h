/* SPDX-License-Identifier: MPL-2.0 */
/* x86-64 PCI ownership adapter for the BSD Driver Bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_X86_64_HANDOFF_H
#define EDGEOS_COMPAT_FREEBSD_X86_64_HANDOFF_H

#include "handoff.h"

int bsd_bridge_x86_64_reserve_native_devices(
    const char *command_line);
int bsd_bridge_x86_64_native_pci_reserved(
    uint8_t bus, uint8_t slot, uint8_t function);
int bsd_bridge_x86_64_release_reserved_native_devices(void);
int bsd_bridge_x86_64_handoff_start(const char *command_line,
    bsd_bridge_handoff_status_t *status);

#endif
