/* SPDX-License-Identifier: MPL-2.0 */
/* Linux-facing snapshots from imported ACPI power drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_ACPI_POWER_H
#define EDGEOS_COMPAT_FREEBSD_ACPI_POWER_H

#include <stddef.h>
#include <stdint.h>

#define BSD_ACPI_BATTERY_TEXT_SIZE 33

typedef struct bsd_acpi_battery_snapshot {
    uint32_t present;
    uint32_t state;
    uint32_t units;
    uint32_t design_capacity;
    uint32_t full_capacity;
    uint32_t remaining_capacity;
    uint32_t rate;
    uint32_t voltage;
    uint32_t design_voltage;
    uint32_t cycle_count;
    int32_t capacity_percent;
    int32_t remaining_minutes;
    char model[BSD_ACPI_BATTERY_TEXT_SIZE];
    char serial[BSD_ACPI_BATTERY_TEXT_SIZE];
    char technology[BSD_ACPI_BATTERY_TEXT_SIZE];
    char manufacturer[BSD_ACPI_BATTERY_TEXT_SIZE];
} bsd_acpi_battery_snapshot_t;

int bsd_acpi_ac_adapter_snapshot(int *online);
size_t bsd_acpi_battery_count(void);
int bsd_acpi_battery_snapshot(size_t unit,
    bsd_acpi_battery_snapshot_t *snapshot);

#endif
