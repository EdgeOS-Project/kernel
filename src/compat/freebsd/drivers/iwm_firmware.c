/* SPDX-License-Identifier: MPL-2.0 */
/* File aliases for the unmodified FreeBSD Intel iwm driver family. */

#include <stddef.h>

#include "compat/freebsd/edgeos/firmware.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/kernel.h"

typedef struct {
    const char *request_name;
    const char *file_name;
} iwm_firmware_alias_t;

static const iwm_firmware_alias_t g_iwm_firmware_aliases[] = {
    { "iwm3160fw", "iwm-3160-17.fw" },
    { "iwm3160fw", "iwlwifi-3160-17.ucode" },
    { "iwm3168fw", "iwm-3168-22.fw" },
    { "iwm3168fw", "iwlwifi-3168-22.ucode" },
    { "iwm7260fw", "iwm-7260-17.fw" },
    { "iwm7260fw", "iwlwifi-7260-17.ucode" },
    { "iwm7265fw", "iwm-7265-17.fw" },
    { "iwm7265fw", "iwlwifi-7265-17.ucode" },
    { "iwm7265Dfw", "iwm-7265D-22.fw" },
    { "iwm7265Dfw", "iwlwifi-7265D-22.ucode" },
    { "iwm8000Cfw", "iwm-8000C-22.fw" },
    { "iwm8000Cfw", "iwlwifi-8000C-22.ucode" },
    { "iwm8265fw", "iwm-8265-22.fw" },
    { "iwm8265fw", "iwlwifi-8265-22.ucode" },
    { "iwm9000fw", "iwm-9000-34.fw" },
    { "iwm9000fw", "iwlwifi-9000-pu-b0-jf-b0-34.ucode" },
    { "iwm9260fw", "iwm-9260-34.fw" },
    { "iwm9260fw", "iwlwifi-9260-th-b0-jf-b0-34.ucode" },
};

static void
iwm_firmware_aliases_register(void *argument)
{
    (void)argument;
    for (size_t index = 0;
        index < sizeof(g_iwm_firmware_aliases) /
        sizeof(g_iwm_firmware_aliases[0]); ++index) {
        const iwm_firmware_alias_t *alias =
            &g_iwm_firmware_aliases[index];

        if (bsd_firmware_file_alias_register(
            alias->request_name, alias->file_name) != 0) {
            printf("[bsd-bridge] iwm firmware alias registration failed\n");
            return;
        }
    }
}

SYSINIT(iwm_firmware_aliases, SI_SUB_DRIVERS, SI_ORDER_FIRST,
    iwm_firmware_aliases_register, 0);
