/* SPDX-License-Identifier: MPL-2.0 */
/* Shared firmware metadata contract for imported BSD platform drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_FIRMWARE_H
#define EDGEOS_COMPAT_FREEBSD_FIRMWARE_H

#include <stddef.h>
#include <stdint.h>

#ifndef _SYS_BUS_H_
#include "newbus.h"
#endif
#include "../dev/ofw/openfirm.h"

typedef enum bsd_firmware_kind {
    BSD_FIRMWARE_NONE = 0,
    BSD_FIRMWARE_ACPI = 1,
    BSD_FIRMWARE_FDT = 2,
} bsd_firmware_kind_t;

typedef struct bsd_firmware_description {
    bsd_firmware_kind_t kind;
    int enabled;
    void *acpi_handle;
    const char *hardware_id;
    const char *const *compatible;
    size_t compatible_count;
    phandle_t node;
} bsd_firmware_description_t;

int bsd_firmware_bind(device_t device,
    const bsd_firmware_description_t *description);
int bsd_firmware_set_acpi_handle(device_t device, void *handle);
int bsd_firmware_is_bound(device_t device);
bsd_firmware_kind_t bsd_firmware_get_kind(device_t device);
int bsd_firmware_status_okay(device_t device);
int bsd_firmware_acpi_match(device_t device, const char *hardware_id);
void *bsd_firmware_acpi_handle(device_t device);
uint32_t bsd_firmware_acpi_get_flags(device_t device);
int bsd_firmware_acpi_set_flags(device_t device, uint32_t flags);
int bsd_firmware_acpi_get_domain(device_t device);
int bsd_firmware_acpi_set_domain(device_t device, int domain);
void *bsd_firmware_acpi_get_private(device_t device);
int bsd_firmware_acpi_set_private(device_t device, void *private_data);
int bsd_firmware_fdt_match(device_t device, const char *compatible);
phandle_t bsd_firmware_fdt_node(device_t device);
const char *bsd_firmware_fdt_first_compatible(device_t device);
int bsd_firmware_file_alias_register(const char *request_name,
    const char *file_name);

#endif
