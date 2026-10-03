/* SPDX-License-Identifier: MPL-2.0 */
#include <assert.h>
#include <stdio.h>
#include "compat/freebsd/edgeos/i8042_policy.h"

int main(void)
{
    const char *const ids[] = {"PNP0303", "PNP030B", "PNP0320"};
    const char *const compatible[] = {0, "VENDOR0001", "PNP0303"};
    const char *const unrelated[] = {"PNP0C0C", "PNP0A08", "PNP0F13", "ACPI0007"};

    for (size_t index = 0; index < sizeof(ids) / sizeof(ids[0]); ++index) {
        assert(!bsd_i8042_acpi_probe_allowed(0, ids[index], 0, 0));
        assert(bsd_i8042_acpi_probe_allowed(1, ids[index], 0, 0));
        assert(!bsd_i8042_acpi_probe_allowed(0, "VENDOR0001", &ids[index], 1));
        assert(bsd_i8042_acpi_probe_allowed(1, "VENDOR0001", &ids[index], 1));
    }
    assert(!bsd_i8042_acpi_probe_allowed(0, "VENDOR0001", compatible, 3));
    assert(bsd_i8042_acpi_probe_allowed(0, "VENDOR0001", compatible, 2));
    assert(bsd_i8042_acpi_probe_allowed(1, "VENDOR0001", compatible, 3));
    for (size_t index = 0; index < sizeof(unrelated) / sizeof(unrelated[0]); ++index)
        assert(bsd_i8042_acpi_probe_allowed(0, unrelated[index], 0, 0));
    assert(bsd_i8042_acpi_probe_allowed(0, 0, 0, 0));
    assert(bsd_i8042_acpi_probe_allowed(0, "", 0, 0));
    assert(bsd_i8042_acpi_probe_allowed(0, "PNP030", 0, 0));
    assert(bsd_i8042_acpi_probe_allowed(0, "PNP03030", 0, 0));
    puts("bsd_bridge_i8042_policy_unit: PASS");
    return 0;
}
