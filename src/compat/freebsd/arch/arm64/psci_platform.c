/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS ARM64 platform integration for the unmodified FreeBSD PSCI driver. */

#include "compat/freebsd/edgeos/ofw.h"

#include <sys/kernel.h>
#include <sys/systm.h>
#include <machine/machdep.h>
#include <dev/psci/psci.h>

enum arm64_bus arm64_bus_method = ARM64_BUS_NONE;

static void
edgeos_psci_platform_initialize(void *argument)
{
    (void)argument;
    if (!bsd_ofw_fdt_available()) {
        printf("[psci] firmware device tree unavailable\n");
        return;
    }
    arm64_bus_method = ARM64_BUS_FDT;
    psci_init(0);
    if (psci_present)
        printf("[psci] BSD PSCI/SMCCC conduit ready\n");
}

SYSINIT(edgeos_psci_platform, SI_SUB_CPU, SI_ORDER_FIRST,
    edgeos_psci_platform_initialize, NULL);
