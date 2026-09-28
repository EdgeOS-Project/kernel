/* SPDX-License-Identifier: MPL-2.0 */
/* Immutable Device Tree context for the EdgeOS BSD Driver Bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_OFW_H
#define EDGEOS_COMPAT_FREEBSD_OFW_H

#include <stddef.h>

#include "../dev/ofw/openfirm.h"

int bsd_ofw_fdt_install(const void *blob, size_t available_size);
void bsd_ofw_fdt_reset(void);
int bsd_ofw_fdt_available(void);
size_t bsd_ofw_fdt_size(void);
size_t bsd_ofw_fdt_node_count(void);
int bsd_ofw_fdt_node_valid(phandle_t node);
const void *bsd_ofw_fdt_get_property(phandle_t node,
    const char *property, int *length);
const char *bsd_ofw_fdt_get_name(phandle_t node, int *length);
phandle_t bsd_ofw_fdt_find_compatible(const char *compatible,
    unsigned int index);
phandle_t bsd_ofw_fdt_stdout_node(void);
int bsd_ofw_fdt_node_is_compatible(phandle_t node,
    const char *compatible);
int bsd_ofw_fdt_node_status_okay(phandle_t node);
int bsd_ofw_fdt_get_reg_count(phandle_t node, size_t *count);
int bsd_ofw_fdt_get_reg(phandle_t node, unsigned int index,
    uint64_t *address, uint64_t *size);
int bsd_ofw_fdt_get_interrupt_count(phandle_t node, size_t *count);
int bsd_ofw_fdt_get_interrupt(phandle_t node, unsigned int index,
    uint32_t *interrupt, uint32_t *flags);

#endif
