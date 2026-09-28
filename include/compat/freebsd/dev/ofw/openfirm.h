/* SPDX-License-Identifier: MPL-2.0 */
/* Open Firmware Device Tree interface for imported BSD drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_OPENFIRM_H
#define EDGEOS_COMPAT_FREEBSD_OPENFIRM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../edgeos/malloc.h"
#include "../../machine/bus.h"
#include "../../machine/ofw_machdep.h"

#ifndef _SYS_BUS_H_
#include "../../edgeos/newbus.h"
#endif

#ifndef _SSIZE_T_DECLARED
typedef __PTRDIFF_TYPE__ ssize_t;
#define _SSIZE_T_DECLARED
#endif

typedef uint32_t ihandle_t;
typedef uint32_t phandle_t;
typedef uint32_t pcell_t;

#define OFW_FDT "ofw_fdt"

MALLOC_DECLARE(M_OFWPROP);

bool OF_install(char *name, int priority);
int OF_init(void *cookie);
int OF_test(const char *name);

phandle_t OF_peer(phandle_t node);
phandle_t OF_child(phandle_t node);
phandle_t OF_parent(phandle_t node);
ssize_t OF_getproplen(phandle_t node, const char *property);
ssize_t OF_getprop(phandle_t node, const char *property, void *buffer,
    size_t length);
ssize_t OF_getencprop(phandle_t node, const char *property, pcell_t *buffer,
    size_t length);
bool OF_hasprop(phandle_t node, const char *property);
ssize_t OF_searchprop(phandle_t node, const char *property, void *buffer,
    size_t length);
ssize_t OF_searchencprop(phandle_t node, const char *property,
    pcell_t *buffer, size_t length);
ssize_t OF_getprop_alloc(phandle_t node, const char *property,
    void **buffer);
ssize_t OF_getprop_alloc_multi(phandle_t node, const char *property,
    int element_size, void **buffer);
ssize_t OF_getencprop_alloc(phandle_t node, const char *property,
    void **buffer);
ssize_t OF_getencprop_alloc_multi(phandle_t node, const char *property,
    int element_size, void **buffer);
void OF_prop_free(void *buffer);
int OF_nextprop(phandle_t node, const char *previous, char *buffer,
    size_t length);
int OF_setprop(phandle_t node, const char *property, const void *buffer,
    size_t length);
ssize_t OF_canon(const char *path, char *buffer, size_t length);
phandle_t OF_finddevice(const char *path);
ssize_t OF_package_to_path(phandle_t node, char *buffer, size_t length);

phandle_t OF_instance_to_package(ihandle_t instance);
ssize_t OF_instance_to_path(ihandle_t instance, char *buffer, size_t length);
phandle_t OF_node_from_xref(phandle_t xref);
phandle_t OF_xref_from_node(phandle_t node);
device_t OF_device_from_xref(phandle_t xref);
phandle_t OF_xref_from_device(device_t device);
int OF_device_register_xref(phandle_t xref, device_t device);
void OF_device_unregister_xref(phandle_t xref, device_t device);
int OF_decode_addr(phandle_t device, int register_index,
    bus_space_tag_t *tag, bus_space_handle_t *handle, bus_size_t *size);

#endif
