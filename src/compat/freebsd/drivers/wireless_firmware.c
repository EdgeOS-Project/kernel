/* SPDX-License-Identifier: MPL-2.0 */
/*
 * External firmware file aliases for unmodified FreeBSD wireless drivers.
 *
 * EdgeOS follows the Linux firmware-loading model: distributable driver code
 * remains in the kernel while independently licensed firmware is supplied in
 * /lib/firmware, /usr/lib/firmware, or /boot/firmware.  FreeBSD firmware
 * modules register names without a file suffix, so these aliases preserve the
 * driver's exact request names without embedding firmware in the kernel.
 */

#include <stddef.h>

#include "compat/freebsd/edgeos/firmware.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/kernel.h"

typedef struct {
    const char *request_name;
    const char *file_name;
} wireless_firmware_alias_t;

static const wireless_firmware_alias_t g_wireless_firmware_aliases[] = {
    { "rtwn-rtl8188eefw", "rtwn-rtl8188eefw.fw" },
    { "rtwn-rtl8188eufw", "rtwn-rtl8188eufw.fw" },
    { "rtwn-rtl8192cfwE", "rtwn-rtl8192cfwE.fw" },
    { "rtwn-rtl8192cfwE_B", "rtwn-rtl8192cfwE_B.fw" },
    { "rtwn-rtl8192cfwT", "rtwn-rtl8192cfwT.fw" },
    { "rtwn-rtl8192cfwU", "rtwn-rtl8192cfwU.fw" },
    { "rtwn-rtl8192eufw", "rtwn-rtl8192eufw.fw" },
    { "rtwn-rtl8812aufw", "rtwn-rtl8812aufw.fw" },
    { "rtwn-rtl8821aufw", "rtwn-rtl8821aufw.fw" },
    { "rt2561sfw", "rt2561s.fw" },
    { "rt2561fw", "rt2561.fw" },
    { "rt2661fw", "rt2661.fw" },
    { "rt2860fw", "rt2860.fw" },
    { "mw88W8363fw", "mw88W8363.fw" },
    { "mwlboot", "mwlboot.fw" },
    { "ipw_bss", "ipw2100-1.3.fw" },
    { "ipw_ibss", "ipw2100-1.3-i.fw" },
    { "ipw_monitor", "ipw2100-1.3-p.fw" },
    { "malo8335-h", "malo8335-h.fw" },
    { "malo8335-m", "malo8335-m.fw" },
    { "otusfw_init", "otus-init" },
    { "otusfw_main", "otus-main" },
    { "rsu-rtl8712fw", "rsu-rtl8712fw.fw" },
    { "runfw", "rt2870.fw" },
    { "upgt-gw3887", "upgt-gw3887.fw" },
};

static void
wireless_firmware_aliases_register(void *argument)
{
    (void)argument;
    for (size_t index = 0;
        index < sizeof(g_wireless_firmware_aliases) /
        sizeof(g_wireless_firmware_aliases[0]); ++index) {
        const wireless_firmware_alias_t *alias =
            &g_wireless_firmware_aliases[index];

        if (bsd_firmware_file_alias_register(
            alias->request_name, alias->file_name) != 0) {
            printf(
                "[bsd-bridge] wireless firmware alias registration failed\n");
            return;
        }
    }
}

SYSINIT(wireless_firmware_aliases, SI_SUB_DRIVERS, SI_ORDER_FIRST,
    wireless_firmware_aliases_register, 0);
