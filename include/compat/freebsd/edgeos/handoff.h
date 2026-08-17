/* SPDX-License-Identifier: MPL-2.0 */
/* Controlled device handoff for the EdgeOS BSD Driver Bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_HANDOFF_H
#define EDGEOS_COMPAT_FREEBSD_HANDOFF_H

#include <stddef.h>
#include <stdint.h>

#include "pci.h"

#define BSD_BRIDGE_HANDOFF_MAX_PCI_DEVICES 32
#define BSD_BRIDGE_HANDOFF_MAX_PLATFORM_DEVICES 32

typedef enum {
    BSD_BRIDGE_PLATFORM_VIRTIO_MMIO = 1,
} bsd_bridge_platform_kind_t;

typedef struct {
    bsd_bridge_platform_kind_t kind;
    uint32_t device;
    uint32_t instance;
} bsd_bridge_platform_request_t;

typedef struct {
    bsd_pci_location_t pci_locations[
        BSD_BRIDGE_HANDOFF_MAX_PCI_DEVICES];
    size_t pci_location_count;
    bsd_bridge_platform_request_t platform_requests[
        BSD_BRIDGE_HANDOFF_MAX_PLATFORM_DEVICES];
    size_t platform_request_count;
} bsd_bridge_handoff_config_t;

typedef struct {
    int enabled;
    device_t pci_bus;
    bsd_pci_bus_status_t pci;
    size_t platform_selected;
    size_t platform_attached;
} bsd_bridge_handoff_status_t;

typedef struct {
    int (*attach)(void *context, device_t parent,
        const bsd_bridge_platform_request_t *request,
        unsigned int unit, device_t *result);
    int (*detach)(void *context, device_t parent, device_t device);
    void *context;
} bsd_bridge_platform_handoff_ops_t;

typedef struct {
    int (*prepare)(void *context,
        const bsd_pci_location_t *locations, size_t count);
    int (*activate)(void *context);
    int (*deactivate)(void *context);
    int (*restore)(void *context);
    void *context;
} bsd_bridge_pci_handoff_ops_t;

int bsd_bridge_handoff_parse_command_line(const char *command_line,
    bsd_bridge_handoff_config_t *config);
int bsd_bridge_handoff_start_with_ops(
    const bsd_bridge_handoff_config_t *config,
    const bsd_bridge_pci_handoff_ops_t *pci_ops,
    const bsd_bridge_platform_handoff_ops_t *platform_ops,
    bsd_bridge_handoff_status_t *status);
int bsd_bridge_handoff_start_with_platform(
    const bsd_bridge_handoff_config_t *config,
    const bsd_bridge_platform_handoff_ops_t *platform_ops,
    bsd_bridge_handoff_status_t *status);
int bsd_bridge_handoff_start(
    const bsd_bridge_handoff_config_t *config,
    bsd_bridge_handoff_status_t *status);
int bsd_bridge_handoff_start_from_command_line_with_platform(
    const char *command_line,
    const bsd_bridge_platform_handoff_ops_t *platform_ops,
    bsd_bridge_handoff_status_t *status);
int bsd_bridge_handoff_start_from_command_line(
    const char *command_line, bsd_bridge_handoff_status_t *status);
int bsd_bridge_handoff_stop(void);

#endif
