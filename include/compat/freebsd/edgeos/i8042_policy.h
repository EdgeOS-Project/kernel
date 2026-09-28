/* SPDX-License-Identifier: MPL-2.0 */
/* Keep ACPI enumeration consistent with native i8042 ownership. */
#ifndef EDGEOS_COMPAT_FREEBSD_I8042_POLICY_H
#define EDGEOS_COMPAT_FREEBSD_I8042_POLICY_H

#include <stddef.h>

static inline int
bsd_i8042_identifier_matches(const char *identifier)
{
    /* These are the controller IDs accepted by atkbdc_isa_probe(). */
    static const char *const identifiers[] = {
        "PNP0303", "PNP030B", "PNP0320",
    };

    if (!identifier)
        return 0;
    for (size_t index = 0; index < sizeof(identifiers) / sizeof(identifiers[0]);
         ++index) {
        const char *expected = identifiers[index];
        size_t offset = 0;

        while (expected[offset] && identifier[offset] == expected[offset])
            ++offset;
        if (!expected[offset] && !identifier[offset])
            return 1;
    }
    return 0;
}

static inline int
bsd_i8042_acpi_probe_allowed(int bridge_selected, const char *hardware_id,
    const char *const *compatible, size_t compatible_count)
{
    if (bridge_selected)
        return 1;
    if (bsd_i8042_identifier_matches(hardware_id))
        return 0;
    for (size_t index = 0; compatible && index < compatible_count; ++index) {
        if (bsd_i8042_identifier_matches(compatible[index]))
            return 0;
    }
    return 1;
}

#endif
