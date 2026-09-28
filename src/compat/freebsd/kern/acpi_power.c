/* SPDX-License-Identifier: MPL-2.0 */
/* Linux-facing snapshots from complete imported ACPI power drivers. */

#include <stddef.h>
#include <stdint.h>
#include <sys/param.h>

#include "compat/freebsd/edgeos/acpi_power.h"
#include "compat/freebsd/edgeos/newbus.h"
#include "compat/freebsd/edgeos/systm.h"

#if defined(__x86_64__)
#include <dev/acpica/acpiio.h>
#include "compat/freebsd/dev/acpica/acpivar.h"

static void
acpi_power_copy_text(char *destination, size_t destination_size,
    const char *source, size_t source_size)
{
    size_t length = 0;

    if (!destination || destination_size == 0)
        return;
    while (length + 1 < destination_size && length < source_size &&
        source[length] != '\0') {
        destination[length] = source[length];
        length++;
    }
    destination[length] = '\0';
}
#endif

int
bsd_acpi_ac_adapter_snapshot(int *online)
{
#if defined(__x86_64__)
    devclass_t device_class;

    if (!online)
        return -1;
    device_class = devclass_find("acpi_acad");
    if (!device_class || devclass_get_count(device_class) == 0)
        return -1;
    if (acpi_acad_get_acline(online) != 0 ||
        (*online != 0 && *online != 1))
        return -1;
    return 0;
#else
    (void)online;
    return -1;
#endif
}

size_t
bsd_acpi_battery_count(void)
{
#if defined(__x86_64__)
    devclass_t device_class = devclass_find("battery");

    return device_class ? (size_t)devclass_get_count(device_class) : 0;
#else
    return 0;
#endif
}

int
bsd_acpi_battery_snapshot(size_t unit,
    bsd_acpi_battery_snapshot_t *snapshot)
{
#if defined(__x86_64__)
    devclass_t device_class;
    device_t device;
    struct acpi_battinfo summary;
    struct acpi_bix information;
    struct acpi_bst status;

    if (!snapshot || unit > INT32_MAX)
        return -1;
    device_class = devclass_find("battery");
    if (!device_class)
        return -1;
    device = devclass_get_device(device_class, (int)unit);
    if (!device)
        return -1;
    bsd_memset(&summary, 0, sizeof(summary));
    bsd_memset(&information, 0, sizeof(information));
    bsd_memset(&status, 0, sizeof(status));
    if (ACPI_BATT_GET_STATUS(device, &status) != 0 ||
        ACPI_BATT_GET_INFO(device, &information,
            sizeof(information)) != 0 ||
        acpi_battery_get_battinfo(device, &summary) != 0)
        return -1;
    bsd_memset(snapshot, 0, sizeof(*snapshot));
    snapshot->present =
        status.state != ACPI_BATT_STAT_NOT_PRESENT ? 1u : 0u;
    snapshot->state = status.state;
    snapshot->units = information.units;
    snapshot->design_capacity = information.dcap;
    snapshot->full_capacity = information.lfcap;
    snapshot->remaining_capacity = status.cap;
    snapshot->rate = status.rate;
    snapshot->voltage = status.volt;
    snapshot->design_voltage = information.dvol;
    snapshot->cycle_count = information.cycles;
    snapshot->capacity_percent = summary.cap;
    snapshot->remaining_minutes = summary.min;
    acpi_power_copy_text(snapshot->model, sizeof(snapshot->model),
        information.model, sizeof(information.model));
    acpi_power_copy_text(snapshot->serial, sizeof(snapshot->serial),
        information.serial, sizeof(information.serial));
    acpi_power_copy_text(snapshot->technology,
        sizeof(snapshot->technology), information.type,
        sizeof(information.type));
    acpi_power_copy_text(snapshot->manufacturer,
        sizeof(snapshot->manufacturer), information.oeminfo,
        sizeof(information.oeminfo));
    return 0;
#else
    (void)unit;
    (void)snapshot;
    return -1;
#endif
}
