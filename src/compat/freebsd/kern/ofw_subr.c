/* SPDX-License-Identifier: MPL-2.0 */
/* Address and command-line helpers for the shared Device Tree backend. */

#include <stddef.h>
#include <stdint.h>

#include <machine/bus.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_subr.h>
#include "compat/freebsd/edgeos/ofw.h"
#include "kernel/boot_command_line.h"

#define BSD_OFW_SUBR_EINVAL 22
#define BSD_OFW_SUBR_ENXIO 6
#define BSD_OFW_SUBR_BOOTARGS_MAX 2048

int
ofw_reg_to_paddr(phandle_t node, int index, bus_addr_t *address,
    bus_size_t *size, pcell_t *pci_high)
{
    uint64_t decoded_address;
    uint64_t decoded_size;
    int error;

    if (node == 0 || node == (phandle_t)-1 || index < 0 ||
        !address || !size)
        return BSD_OFW_SUBR_EINVAL;
    error = bsd_ofw_fdt_get_reg(
        node, (unsigned int)index, &decoded_address, &decoded_size);
    if (error != 0)
        return error == 2 ? BSD_OFW_SUBR_ENXIO : error;
    if ((uint64_t)(bus_addr_t)decoded_address != decoded_address ||
        (uint64_t)(bus_size_t)decoded_size != decoded_size)
        return BSD_OFW_SUBR_EINVAL;
    *address = (bus_addr_t)decoded_address;
    *size = (bus_size_t)decoded_size;
    if (pci_high)
        *pci_high = OFW_PADDR_NOT_PCI;
    return 0;
}

int
ofw_parse_bootargs(void)
{
    char bootargs[BSD_OFW_SUBR_BOOTARGS_MAX];
    phandle_t chosen = OF_finddevice("/chosen");
    ssize_t length;

    if (chosen == 0 || chosen == (phandle_t)-1)
        return BSD_OFW_SUBR_ENXIO;
    length = OF_getprop(
        chosen, "bootargs", bootargs, sizeof(bootargs) - 1);
    if (length < 0)
        return BSD_OFW_SUBR_ENXIO;
    if ((size_t)length >= sizeof(bootargs))
        length = (ssize_t)sizeof(bootargs) - 1;
    bootargs[length] = '\0';
    kernel_boot_command_line_set(bootargs);
    return 0;
}
