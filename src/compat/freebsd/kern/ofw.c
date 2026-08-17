/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS immutable Open Firmware Device Tree implementation.
 *
 * The parser is the unmodified BSD-licensed libfdt package. This file owns
 * the FreeBSD-compatible handle model and read-only OF interface used by
 * source-built BSD drivers.
 */

#include <libfdt.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef BSD_BRIDGE_HOST_TEST
void *malloc(size_t size);
void free(void *allocation);
#endif

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/ofw.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/dev/ofw/ofw_bus_subr.h"

#define BSD_OFW_EINVAL 22
#define BSD_OFW_ENOENT 2
#define BSD_OFW_ENOMEM 12
#define BSD_OFW_ERANGE 34
#define BSD_OFW_PATH_MAX 1024

MALLOC_DEFINE(M_OFWPROP, "ofwprop", "Open Firmware properties");

typedef struct bsd_ofw_xref {
    phandle_t xref;
    device_t device;
    struct bsd_ofw_xref *next;
} bsd_ofw_xref_t;

static const void *g_fdt_blob;
static size_t g_fdt_size;
static size_t g_fdt_node_count;
static bsd_ofw_xref_t *g_xrefs;
static volatile unsigned char g_xref_guard;

static void
ofw_lock(void)
{
    while (__atomic_test_and_set(&g_xref_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
ofw_unlock(void)
{
    __atomic_clear(&g_xref_guard, __ATOMIC_RELEASE);
}

static void *
ofw_allocate(size_t size)
{
#ifdef BSD_BRIDGE_HOST_TEST
    return malloc(size);
#else
    return bsd_malloc(size, M_OFWPROP, M_WAITOK | M_ZERO);
#endif
}

static void
ofw_release(void *allocation)
{
#ifdef BSD_BRIDGE_HOST_TEST
    free(allocation);
#else
    bsd_free(allocation, M_OFWPROP);
#endif
}

static const void *
ofw_blob(void)
{
    return __atomic_load_n(&g_fdt_blob, __ATOMIC_ACQUIRE);
}

static int
ofw_validate_structure(const void *blob, size_t *node_count)
{
    int depth = 0;
    int node = -1;
    size_t count = 0;

    for (;;) {
        int next = fdt_next_node(blob, node, &depth);
        int property;

        if (next < 0) {
            if (next != -FDT_ERR_NOTFOUND)
                return BSD_OFW_EINVAL;
            break;
        }
        node = next;
        ++count;
        property = fdt_first_property_offset(blob, node);
        while (property >= 0) {
            if (!fdt_get_property_by_offset(blob, property, 0))
                return BSD_OFW_EINVAL;
            property = fdt_next_property_offset(blob, property);
        }
        if (property != -FDT_ERR_NOTFOUND)
            return BSD_OFW_EINVAL;
    }
    if (count == 0 || fdt_path_offset(blob, "/") != 0)
        return BSD_OFW_EINVAL;
    *node_count = count;
    return 0;
}

int
bsd_ofw_fdt_install(const void *blob, size_t available_size)
{
    size_t node_count;
    uint32_t total_size;

    if (!blob || available_size < sizeof(struct fdt_header) ||
        fdt_check_header(blob) != 0)
        return BSD_OFW_EINVAL;
    total_size = fdt_totalsize(blob);
    if (total_size < sizeof(struct fdt_header) ||
        (size_t)total_size > available_size ||
        ofw_validate_structure(blob, &node_count) != 0)
        return BSD_OFW_EINVAL;

    bsd_ofw_fdt_reset();
    g_fdt_size = total_size;
    g_fdt_node_count = node_count;
    __atomic_store_n(&g_fdt_blob, blob, __ATOMIC_RELEASE);
    return 0;
}

void
bsd_ofw_fdt_reset(void)
{
    bsd_ofw_xref_t *entry;

    __atomic_store_n(&g_fdt_blob, 0, __ATOMIC_RELEASE);
    g_fdt_size = 0;
    g_fdt_node_count = 0;
    ofw_lock();
    entry = g_xrefs;
    g_xrefs = 0;
    ofw_unlock();
    while (entry) {
        bsd_ofw_xref_t *next = entry->next;

        ofw_release(entry);
        entry = next;
    }
}

int
bsd_ofw_fdt_available(void)
{
    return ofw_blob() != 0;
}

size_t
bsd_ofw_fdt_size(void)
{
    return ofw_blob() ? g_fdt_size : 0;
}

size_t
bsd_ofw_fdt_node_count(void)
{
    return ofw_blob() ? g_fdt_node_count : 0;
}

static phandle_t
ofw_node_to_handle(const void *blob, int node)
{
    uint32_t structure_offset;

    if (!blob || node < 0)
        return 0;
    structure_offset = fdt_off_dt_struct(blob);
    if ((uint32_t)node > UINT32_MAX - structure_offset)
        return 0;
    return structure_offset + (uint32_t)node;
}

static int
ofw_handle_to_node(const void *blob, phandle_t handle)
{
    uint32_t structure_offset;
    int node;

    if (!blob)
        return -FDT_ERR_NOTFOUND;
    structure_offset = fdt_off_dt_struct(blob);
    if (handle < structure_offset ||
        handle - structure_offset > (uint32_t)INT32_MAX)
        return -FDT_ERR_BADOFFSET;
    node = (int)(handle - structure_offset);
    return fdt_get_name(blob, node, 0) ? node : -FDT_ERR_BADOFFSET;
}

int
bsd_ofw_fdt_node_valid(phandle_t node)
{
    const void *blob = ofw_blob();

    return ofw_handle_to_node(blob, node) >= 0;
}

const void *
bsd_ofw_fdt_get_property(phandle_t node, const char *property, int *length)
{
    const void *blob = ofw_blob();
    int offset;

    if (length)
        *length = -1;
    if (!blob || !property)
        return 0;
    offset = ofw_handle_to_node(blob, node);
    if (offset < 0)
        return 0;
    return fdt_getprop(blob, offset, property, length);
}

const char *
bsd_ofw_fdt_get_name(phandle_t node, int *length)
{
    const void *blob = ofw_blob();
    int offset;

    if (length)
        *length = -1;
    if (!blob)
        return 0;
    offset = ofw_handle_to_node(blob, node);
    return offset < 0 ? 0 : fdt_get_name(blob, offset, length);
}

phandle_t
bsd_ofw_fdt_find_compatible(const char *compatible, unsigned int index)
{
    const void *blob = ofw_blob();
    int offset = -1;

    if (!blob || !compatible)
        return 0;
    for (;;) {
        offset = fdt_node_offset_by_compatible(blob, offset, compatible);
        if (offset < 0)
            return 0;
        if (index == 0)
            return ofw_node_to_handle(blob, offset);
        --index;
    }
}

static int
ofw_read_cells(const fdt32_t *cells, unsigned int count, uint64_t *value)
{
    uint64_t decoded = 0;

    if (!cells || !value || count == 0 || count > 2)
        return BSD_OFW_EINVAL;
    for (unsigned int index = 0; index < count; ++index)
        decoded = (decoded << 32) | fdt32_to_cpu(cells[index]);
    *value = decoded;
    return 0;
}

static int
ofw_read_address_cells(const fdt32_t *cells, unsigned int count,
    uint64_t *value)
{
    /* A three-cell PCI address stores space/type metadata in cell zero. */
    if (count == 3)
        return ofw_read_cells(cells + 1, 2, value);
    return ofw_read_cells(cells, count, value);
}

static unsigned int
ofw_node_cell_count(phandle_t node, const char *property,
    unsigned int fallback)
{
    int length;
    const fdt32_t *value = bsd_ofw_fdt_get_property(
        node, property, &length);

    return value && length == (int)sizeof(*value) ?
        fdt32_to_cpu(*value) : fallback;
}

static int
ofw_translate_address(phandle_t bus, uint64_t *address)
{
    while (bus != 0 && OF_parent(bus) != 0) {
        phandle_t parent = OF_parent(bus);
        unsigned int child_cells = ofw_node_cell_count(
            bus, "#address-cells", 2);
        unsigned int parent_cells = ofw_node_cell_count(
            parent, "#address-cells", 2);
        unsigned int size_cells = ofw_node_cell_count(
            bus, "#size-cells", 1);
        unsigned int stride = child_cells + parent_cells + size_cells;
        int length;
        const fdt32_t *ranges = bsd_ofw_fdt_get_property(
            bus, "ranges", &length);
        int matched = 0;

        if (!ranges)
            return BSD_OFW_ENOENT;
        if (length == 0) {
            bus = parent;
            continue;
        }
        if (stride == 0 || child_cells > 3 || parent_cells > 3 ||
            size_cells > 2 ||
            length < 0 || ((unsigned int)length / sizeof(*ranges)) %
            stride != 0)
            return BSD_OFW_EINVAL;
        for (unsigned int offset = 0;
            offset < (unsigned int)length / sizeof(*ranges);
            offset += stride) {
            uint64_t child_base;
            uint64_t parent_base;
            uint64_t range_size;
            uint64_t delta;

            if (ofw_read_address_cells(ranges + offset, child_cells,
                    &child_base) != 0 ||
                ofw_read_address_cells(ranges + offset + child_cells,
                    parent_cells, &parent_base) != 0 ||
                ofw_read_cells(ranges + offset + child_cells +
                    parent_cells, size_cells, &range_size) != 0)
                return BSD_OFW_EINVAL;
            if (*address < child_base)
                continue;
            delta = *address - child_base;
            if (delta >= range_size ||
                parent_base > UINT64_MAX - delta)
                continue;
            *address = parent_base + delta;
            matched = 1;
            break;
        }
        if (!matched)
            return BSD_OFW_ERANGE;
        bus = parent;
    }
    return 0;
}

int
bsd_ofw_fdt_get_reg_count(phandle_t node, size_t *count)
{
    phandle_t parent = OF_parent(node);
    unsigned int address_cells;
    unsigned int size_cells;
    unsigned int stride;
    const fdt32_t *registers;
    int length;

    if (!count || parent == 0)
        return BSD_OFW_EINVAL;
    *count = 0;
    address_cells = ofw_node_cell_count(parent, "#address-cells", 2);
    size_cells = ofw_node_cell_count(parent, "#size-cells", 1);
    stride = address_cells + size_cells;
    registers = bsd_ofw_fdt_get_property(node, "reg", &length);
    if (!registers)
        return BSD_OFW_ENOENT;
    if (stride == 0 || address_cells > 3 || size_cells > 2 ||
        length < 0 ||
        (unsigned int)length % (stride * sizeof(*registers)) != 0)
        return BSD_OFW_EINVAL;
    *count = (size_t)length / (stride * sizeof(*registers));
    return 0;
}

int
bsd_ofw_fdt_get_reg(phandle_t node, unsigned int index,
    uint64_t *address, uint64_t *size)
{
    phandle_t parent = OF_parent(node);
    unsigned int address_cells;
    unsigned int size_cells;
    unsigned int stride;
    const fdt32_t *registers;
    unsigned int offset;
    int length;
    uint64_t decoded_address;
    uint64_t decoded_size;
    size_t count;
    int error;

    if (!address || !size)
        return BSD_OFW_EINVAL;
    error = bsd_ofw_fdt_get_reg_count(node, &count);
    if (error)
        return error;
    if (index >= count)
        return BSD_OFW_EINVAL;
    address_cells = ofw_node_cell_count(parent, "#address-cells", 2);
    size_cells = ofw_node_cell_count(parent, "#size-cells", 1);
    stride = address_cells + size_cells;
    registers = bsd_ofw_fdt_get_property(node, "reg", &length);
    offset = index * stride;
    if (ofw_read_address_cells(registers + offset, address_cells,
            &decoded_address) != 0 ||
        ofw_read_cells(registers + offset + address_cells,
            size_cells, &decoded_size) != 0)
        return BSD_OFW_EINVAL;
    if (ofw_translate_address(parent, &decoded_address) != 0)
        return BSD_OFW_ERANGE;
    *address = decoded_address;
    *size = decoded_size;
    return 0;
}

static phandle_t
ofw_interrupt_parent(phandle_t node)
{
    for (phandle_t current = node; current != 0;
        current = OF_parent(current)) {
        int length;
        const fdt32_t *property = bsd_ofw_fdt_get_property(
            current, "interrupt-parent", &length);

        if (property && length == (int)sizeof(*property))
            return OF_node_from_xref(fdt32_to_cpu(*property));
    }
    return 0;
}

int
bsd_ofw_fdt_get_interrupt_count(phandle_t node, size_t *count)
{
    phandle_t parent;
    unsigned int cells;
    const fdt32_t *specifiers;
    int length;

    if (!count)
        return BSD_OFW_EINVAL;
    *count = 0;
    parent = ofw_interrupt_parent(node);
    if (parent == 0)
        return BSD_OFW_ENOENT;
    cells = ofw_node_cell_count(parent, "#interrupt-cells", 0);
    specifiers = bsd_ofw_fdt_get_property(node, "interrupts", &length);
    if (!specifiers)
        return BSD_OFW_ENOENT;
    if (cells == 0 || cells > 3 || length < 0 ||
        (unsigned int)length % (cells * sizeof(*specifiers)) != 0)
        return BSD_OFW_EINVAL;
    *count = (size_t)length / (cells * sizeof(*specifiers));
    return 0;
}

int
bsd_ofw_fdt_get_interrupt(phandle_t node, unsigned int index,
    uint32_t *interrupt, uint32_t *flags)
{
    phandle_t parent;
    unsigned int cells;
    const fdt32_t *specifiers;
    unsigned int offset;
    int length;
    uint32_t number;
    uint32_t decoded_flags = 0;
    size_t count;
    int error;

    if (!interrupt || !flags)
        return BSD_OFW_EINVAL;
    error = bsd_ofw_fdt_get_interrupt_count(node, &count);
    if (error)
        return error;
    if (index >= count)
        return BSD_OFW_EINVAL;
    parent = ofw_interrupt_parent(node);
    cells = ofw_node_cell_count(parent, "#interrupt-cells", 0);
    specifiers = bsd_ofw_fdt_get_property(node, "interrupts", &length);
    offset = index * cells;
    if (cells == 3 && (ofw_bus_node_is_compatible(
            parent, "arm,gic-v3") ||
        ofw_bus_node_is_compatible(parent, "arm,gic-400"))) {
        uint32_t kind = fdt32_to_cpu(specifiers[offset]);
        uint32_t source = fdt32_to_cpu(specifiers[offset + 1]);

        if ((kind == 0 && source > 987) ||
            (kind == 1 && source > 15) || kind > 1)
            return BSD_OFW_ERANGE;
        number = source + (kind == 0 ? 32 : 16);
        decoded_flags = fdt32_to_cpu(specifiers[offset + 2]);
    } else if (cells <= 2) {
        number = fdt32_to_cpu(specifiers[offset]);
        if (cells == 2)
            decoded_flags = fdt32_to_cpu(specifiers[offset + 1]);
    } else {
        return BSD_OFW_EINVAL;
    }
    *interrupt = number;
    *flags = decoded_flags;
    return 0;
}

bool
OF_install(char *name, int priority)
{
    (void)priority;
    return name && bsd_strcmp(name, OFW_FDT) == 0;
}

int
OF_init(void *cookie)
{
    if (!cookie || fdt_check_header(cookie) != 0)
        return BSD_OFW_EINVAL;
    return bsd_ofw_fdt_install(cookie, fdt_totalsize(cookie));
}

int
OF_test(const char *name)
{
    return bsd_ofw_fdt_available() && name &&
        bsd_strcmp(name, OFW_FDT) == 0 ? 0 : -1;
}

phandle_t
OF_peer(phandle_t node)
{
    const void *blob = ofw_blob();
    int offset;

    if (!blob)
        return 0;
    if (node == 0)
        return ofw_node_to_handle(blob, fdt_path_offset(blob, "/"));
    offset = ofw_handle_to_node(blob, node);
    return offset < 0 ? 0 :
        ofw_node_to_handle(blob, fdt_next_subnode(blob, offset));
}

phandle_t
OF_child(phandle_t node)
{
    const void *blob = ofw_blob();
    int offset = ofw_handle_to_node(blob, node);

    return offset < 0 ? 0 :
        ofw_node_to_handle(blob, fdt_first_subnode(blob, offset));
}

phandle_t
OF_parent(phandle_t node)
{
    const void *blob = ofw_blob();
    int offset = ofw_handle_to_node(blob, node);

    return offset < 0 ? 0 :
        ofw_node_to_handle(blob, fdt_parent_offset(blob, offset));
}

ssize_t
OF_getproplen(phandle_t node, const char *property)
{
    int length = -1;

    if (!property)
        return -1;
    if (bsd_ofw_fdt_get_property(node, property, &length))
        return length;
    if (bsd_strcmp(property, "name") == 0 &&
        bsd_ofw_fdt_get_name(node, &length))
        return length + 1;
    return -1;
}

ssize_t
OF_getprop(phandle_t node, const char *property, void *buffer,
    size_t length)
{
    const void *value;
    int value_length = -1;
    size_t copied;

    if (!property || (!buffer && length != 0))
        return -1;
    value = bsd_ofw_fdt_get_property(node, property, &value_length);
    if (!value && bsd_strcmp(property, "name") == 0) {
        value = bsd_ofw_fdt_get_name(node, &value_length);
        if (value)
            ++value_length;
    }
    if (!value || value_length < 0)
        return -1;
    copied = (size_t)value_length < length ?
        (size_t)value_length : length;
    if (copied)
        bsd_memcpy(buffer, value, copied);
    return value_length;
}

ssize_t
OF_getencprop(phandle_t node, const char *property, pcell_t *buffer,
    size_t length)
{
    ssize_t result;
    size_t converted;

    if (length % sizeof(*buffer) != 0)
        return -1;
    result = OF_getprop(node, property, buffer, length);
    if (result <= 0 || result % (ssize_t)sizeof(*buffer) != 0)
        return result <= 0 ? result : -1;
    converted = (size_t)result < length ? (size_t)result : length;
    for (size_t index = 0; index < converted / sizeof(*buffer); ++index)
        buffer[index] = fdt32_to_cpu((fdt32_t)buffer[index]);
    return result;
}

bool
OF_hasprop(phandle_t node, const char *property)
{
    return OF_getproplen(node, property) >= 0;
}

ssize_t
OF_searchprop(phandle_t node, const char *property, void *buffer,
    size_t length)
{
    while (node != 0) {
        ssize_t result = OF_getprop(node, property, buffer, length);

        if (result >= 0)
            return result;
        node = OF_parent(node);
    }
    return -1;
}

ssize_t
OF_searchencprop(phandle_t node, const char *property, pcell_t *buffer,
    size_t length)
{
    while (node != 0) {
        ssize_t result = OF_getencprop(node, property, buffer, length);

        if (result >= 0)
            return result;
        node = OF_parent(node);
    }
    return -1;
}

ssize_t
OF_getprop_alloc(phandle_t node, const char *property, void **buffer)
{
    ssize_t length;

    if (!buffer)
        return -1;
    *buffer = 0;
    length = OF_getproplen(node, property);
    if (length < 0)
        return -1;
    if (length == 0)
        return 0;
    *buffer = ofw_allocate((size_t)length);
    if (!*buffer)
        return -1;
    if (OF_getprop(node, property, *buffer, (size_t)length) != length) {
        ofw_release(*buffer);
        *buffer = 0;
        return -1;
    }
    return length;
}

ssize_t
OF_getprop_alloc_multi(phandle_t node, const char *property,
    int element_size, void **buffer)
{
    ssize_t length;

    if (element_size <= 0 || !buffer)
        return -1;
    length = OF_getprop_alloc(node, property, buffer);
    if (length < 0 || length % element_size != 0) {
        if (length >= 0) {
            ofw_release(*buffer);
            *buffer = 0;
        }
        return -1;
    }
    return length / element_size;
}

ssize_t
OF_getencprop_alloc_multi(phandle_t node, const char *property,
    int element_size, void **buffer)
{
    ssize_t count;

    if (element_size <= 0 ||
        element_size % (int)sizeof(pcell_t) != 0)
        return -1;
    count = OF_getprop_alloc_multi(node, property, element_size, buffer);
    if (count < 0)
        return -1;
    for (size_t index = 0;
         index < (size_t)count * (size_t)element_size / sizeof(pcell_t);
         ++index) {
        pcell_t *cells = *buffer;

        cells[index] = fdt32_to_cpu((fdt32_t)cells[index]);
    }
    return count;
}

ssize_t
OF_getencprop_alloc(phandle_t node, const char *property, void **buffer)
{
    ssize_t count = OF_getencprop_alloc_multi(
        node, property, sizeof(pcell_t), buffer);

    return count < 0 ? -1 : count * (ssize_t)sizeof(pcell_t);
}

void
OF_prop_free(void *buffer)
{
    if (buffer)
        ofw_release(buffer);
}

int
OF_nextprop(phandle_t node, const char *previous, char *buffer,
    size_t length)
{
    const void *blob = ofw_blob();
    int node_offset = ofw_handle_to_node(blob, node);
    int property;
    int found_previous = 0;
    const char *name = 0;

    if (node_offset < 0 || !buffer || length == 0)
        return -1;
    property = fdt_first_property_offset(blob, node_offset);
    if (previous && previous[0] != '\0') {
        while (property >= 0) {
            if (!fdt_getprop_by_offset(blob, property, &name, 0))
                return -1;
            property = fdt_next_property_offset(blob, property);
            if (bsd_strcmp(name, previous) == 0) {
                found_previous = 1;
                break;
            }
        }
        if (!found_previous)
            return -1;
    }
    if (property < 0)
        return property == -FDT_ERR_NOTFOUND ? 0 : -1;
    if (!fdt_getprop_by_offset(blob, property, &name, 0) || !name)
        return -1;
    bsd_strlcpy(buffer, name, length);
    return 1;
}

int
OF_setprop(phandle_t node, const char *property, const void *buffer,
    size_t length)
{
    (void)node;
    (void)property;
    (void)buffer;
    (void)length;
    return -1;
}

phandle_t
OF_finddevice(const char *path)
{
    const void *blob = ofw_blob();
    char canonical[BSD_OFW_PATH_MAX];
    const char *lookup = path;
    int node;

    if (!blob || !path)
        return (phandle_t)-1;
    if (path[0] != '/') {
        const char *separator = path;
        const char *alias_path;
        size_t alias_length;
        size_t suffix_length;
        int aliases;
        int property_length;

        while (*separator != '\0' && *separator != '/' &&
            *separator != ':')
            ++separator;
        alias_length = (size_t)(separator - path);
        aliases = fdt_path_offset(blob, "/aliases");
        if (aliases < 0 || alias_length == 0 ||
            alias_length >= sizeof(canonical))
            return (phandle_t)-1;
        for (size_t index = 0; index < alias_length; ++index)
            canonical[index] = path[index];
        canonical[alias_length] = '\0';
        alias_path = fdt_getprop(blob, aliases, canonical,
            &property_length);
        if (!alias_path || property_length <= 1 ||
            alias_path[property_length - 1] != '\0')
            return (phandle_t)-1;
        suffix_length = 0;
        if (*separator == '/') {
            const char *end = separator;

            while (*end != '\0' && *end != ':')
                ++end;
            suffix_length = (size_t)(end - separator);
        }
        if ((size_t)property_length + suffix_length >
            sizeof(canonical))
            return (phandle_t)-1;
        for (int index = 0; index < property_length; ++index)
            canonical[index] = alias_path[index];
        for (size_t index = 0; index < suffix_length; ++index)
            canonical[(size_t)property_length - 1 + index] =
                separator[index];
        canonical[(size_t)property_length - 1 + suffix_length] = '\0';
        lookup = canonical;
    } else {
        const char *options = path;
        size_t path_length;

        while (*options != '\0' && *options != ':')
            ++options;
        path_length = (size_t)(options - path);
        if (*options == ':' && path_length < sizeof(canonical)) {
            for (size_t index = 0; index < path_length; ++index)
                canonical[index] = path[index];
            canonical[path_length] = '\0';
            lookup = canonical;
        }
    }
    node = fdt_path_offset(blob, lookup);
    return node < 0 ? (phandle_t)-1 :
        ofw_node_to_handle(blob, node);
}

phandle_t
bsd_ofw_fdt_stdout_node(void)
{
    static const char *const properties[] = {
        "stdout-path",
        "linux,stdout-path",
    };
    char path[BSD_OFW_PATH_MAX];
    phandle_t chosen = OF_finddevice("/chosen");

    if (chosen == 0 || chosen == (phandle_t)-1)
        return 0;
    for (size_t index = 0;
        index < sizeof(properties) / sizeof(properties[0]); ++index) {
        ssize_t length = OF_getprop(chosen, properties[index], path,
            sizeof(path) - 1);
        phandle_t node;

        if (length <= 0 || (size_t)length >= sizeof(path))
            continue;
        path[length] = '\0';
        node = OF_finddevice(path);
        if (node != 0 && node != (phandle_t)-1)
            return node;
    }
    return 0;
}

int
bsd_ofw_fdt_node_is_compatible(phandle_t node, const char *compatible)
{
    return ofw_bus_node_is_compatible(node, compatible);
}

int
bsd_ofw_fdt_node_status_okay(phandle_t node)
{
    return ofw_bus_node_status_okay(node);
}

ssize_t
OF_package_to_path(phandle_t node, char *buffer, size_t length)
{
    const void *blob = ofw_blob();
    int offset = ofw_handle_to_node(blob, node);

    if (offset < 0 || !buffer || length == 0 ||
        length > (size_t)INT32_MAX ||
        fdt_get_path(blob, offset, buffer, (int)length) != 0)
        return -1;
    return (ssize_t)bsd_strlen(buffer);
}

ssize_t
OF_canon(const char *path, char *buffer, size_t length)
{
    phandle_t node = OF_finddevice(path);

    return node == (phandle_t)-1 ? -1 :
        OF_package_to_path(node, buffer, length);
}

phandle_t
OF_instance_to_package(ihandle_t instance)
{
    return OF_node_from_xref(instance);
}

ssize_t
OF_instance_to_path(ihandle_t instance, char *buffer, size_t length)
{
    return OF_package_to_path(OF_instance_to_package(instance),
        buffer, length);
}

phandle_t
OF_node_from_xref(phandle_t xref)
{
    const void *blob = ofw_blob();
    int node;

    if (!blob)
        return xref;
    node = fdt_node_offset_by_phandle(blob, xref);
    if (node >= 0)
        return ofw_node_to_handle(blob, node);
    return xref;
}

phandle_t
OF_xref_from_node(phandle_t node)
{
    const void *blob = ofw_blob();
    int offset = ofw_handle_to_node(blob, node);
    uint32_t xref;

    if (offset < 0)
        return node;
    xref = fdt_get_phandle(blob, offset);
    return xref == 0 ? node : xref;
}

device_t
OF_device_from_xref(phandle_t xref)
{
    device_t device = 0;

    ofw_lock();
    for (bsd_ofw_xref_t *entry = g_xrefs; entry; entry = entry->next) {
        if (entry->xref == xref) {
            device = entry->device;
            break;
        }
    }
    ofw_unlock();
    return device;
}

phandle_t
OF_xref_from_device(device_t device)
{
    phandle_t xref = 0;

    ofw_lock();
    for (bsd_ofw_xref_t *entry = g_xrefs; entry; entry = entry->next) {
        if (entry->device == device) {
            xref = entry->xref;
            break;
        }
    }
    ofw_unlock();
    return xref;
}

int
OF_device_register_xref(phandle_t xref, device_t device)
{
    bsd_ofw_xref_t *candidate;

    if (xref == 0 || !device)
        return BSD_OFW_EINVAL;
    candidate = ofw_allocate(sizeof(*candidate));
    if (!candidate)
        return 12;
    candidate->xref = xref;
    candidate->device = device;
    candidate->next = 0;

    ofw_lock();
    for (bsd_ofw_xref_t *entry = g_xrefs; entry; entry = entry->next) {
        if (entry->xref == xref) {
            entry->device = device;
            ofw_unlock();
            ofw_release(candidate);
            return 0;
        }
    }
    candidate->next = g_xrefs;
    g_xrefs = candidate;
    ofw_unlock();
    return 0;
}

void
OF_device_unregister_xref(phandle_t xref, device_t device)
{
    bsd_ofw_xref_t *removed = 0;
    bsd_ofw_xref_t **link;

    (void)device;
    ofw_lock();
    for (link = &g_xrefs; *link; link = &(*link)->next) {
        if ((*link)->xref == xref) {
            removed = *link;
            *link = removed->next;
            break;
        }
    }
    ofw_unlock();
    if (removed)
        ofw_release(removed);
}

static unsigned char
ofw_ascii_lower(unsigned char value)
{
    return value >= 'A' && value <= 'Z' ?
        (unsigned char)(value + ('a' - 'A')) : value;
}

static int
ofw_compatible_equal(const char *left, size_t left_length,
    const char *right)
{
    size_t right_length = bsd_strlen(right);

    if (left_length != right_length)
        return 0;
    for (size_t index = 0; index < left_length; ++index) {
        if (ofw_ascii_lower((unsigned char)left[index]) !=
            ofw_ascii_lower((unsigned char)right[index]))
            return 0;
    }
    return 1;
}

int
ofw_bus_node_status_okay(phandle_t node)
{
    int length;
    const char *status = bsd_ofw_fdt_get_property(
        node, "status", &length);

    if (!status || length <= 0)
        return 1;
    if (status[length - 1] == '\0')
        --length;
    return (length == 2 &&
        status[0] == 'o' && status[1] == 'k') ||
        (length == 4 &&
        status[0] == 'o' && status[1] == 'k' &&
        status[2] == 'a' && status[3] == 'y');
}

int
ofw_bus_node_is_compatible(phandle_t node, const char *compatible)
{
    int length;
    const char *list;
    size_t offset = 0;

    if (!compatible)
        return 0;
    list = bsd_ofw_fdt_get_property(node, "compatible", &length);
    if (!list || length <= 0)
        return 0;
    while (offset < (size_t)length) {
        size_t remaining = (size_t)length - offset;
        size_t item_length = bsd_strnlen(list + offset, remaining);

        if (item_length == remaining)
            return 0;
        if (ofw_compatible_equal(
            list + offset, item_length, compatible))
            return 1;
        offset += item_length + 1;
    }
    return 0;
}

bool
ofw_bus_is_machine_compatible(const char *compatible)
{
    return ofw_bus_node_is_compatible(OF_peer(0), compatible) != 0;
}

phandle_t
ofw_bus_find_child(phandle_t node, const char *name)
{
    if (!name)
        return 0;
    for (phandle_t child = OF_child(node);
         child != 0; child = OF_peer(child)) {
        int length;
        const char *child_name = bsd_ofw_fdt_get_name(child, &length);

        if (child_name && (size_t)length == bsd_strlen(name) &&
            bsd_strncmp(child_name, name, (size_t)length) == 0)
            return child;
    }
    return 0;
}

phandle_t
ofw_bus_find_compatible(phandle_t node, const char *compatible)
{
    for (phandle_t child = OF_child(node);
         child != 0; child = OF_peer(child)) {
        phandle_t nested;

        if (ofw_bus_node_is_compatible(child, compatible))
            return child;
        nested = ofw_bus_find_compatible(child, compatible);
        if (nested != 0)
            return nested;
    }
    return 0;
}

int
ofw_bus_find_string_index(phandle_t node, const char *list_name,
    const char *name, int *result)
{
    const char *items;
    int length;
    size_t offset = 0;
    int index = 0;

    if (!list_name || !name || !result)
        return BSD_OFW_EINVAL;
    items = bsd_ofw_fdt_get_property(node, list_name, &length);
    if (!items || length <= 0)
        return BSD_OFW_ENOENT;
    while (offset < (size_t)length) {
        size_t remaining = (size_t)length - offset;
        size_t item_length = bsd_strnlen(items + offset, remaining);

        if (item_length == remaining)
            return BSD_OFW_EINVAL;
        if (item_length == bsd_strlen(name) &&
            bsd_strncmp(items + offset, name, item_length) == 0) {
            *result = index;
            return 0;
        }
        offset += item_length + 1;
        ++index;
    }
    return BSD_OFW_ENOENT;
}

static int
ofw_bus_parse_xref_list(phandle_t node, const char *list_name,
    const char *cells_name, int requested_index, phandle_t *producer,
    int *result_count, pcell_t **result_cells)
{
    pcell_t *list = 0;
    ssize_t byte_count;
    size_t cell_count;
    size_t cursor = 0;
    int entry_count = 0;
    int error = BSD_OFW_ENOENT;

    if (node == 0 || !list_name || !cells_name || !result_count ||
        requested_index < -1 ||
        (requested_index >= 0 && (!producer || !result_cells)))
        return BSD_OFW_EINVAL;
    if (producer)
        *producer = 0;
    if (result_cells)
        *result_cells = 0;
    *result_count = 0;

    byte_count = OF_getencprop_alloc(node, list_name, (void **)&list);
    if (byte_count <= 0)
        return BSD_OFW_ENOENT;
    if ((size_t)byte_count % sizeof(*list) != 0) {
        OF_prop_free(list);
        return BSD_OFW_ERANGE;
    }
    cell_count = (size_t)byte_count / sizeof(*list);
    while (cursor < cell_count) {
        phandle_t xref = list[cursor++];
        phandle_t provider = OF_node_from_xref(xref);
        pcell_t provider_cell_count;
        ssize_t property_length;

        if (provider == 0) {
            error = BSD_OFW_ENOENT;
            break;
        }
        property_length = OF_getencprop(provider, cells_name,
            &provider_cell_count, sizeof(provider_cell_count));
        if (property_length != (ssize_t)sizeof(provider_cell_count)) {
            error = BSD_OFW_ENOENT;
            break;
        }
        if ((size_t)provider_cell_count > cell_count - cursor) {
            error = BSD_OFW_ERANGE;
            break;
        }
        if (entry_count == requested_index) {
            pcell_t *copy = 0;
            size_t allocation_size =
                (size_t)provider_cell_count * sizeof(*copy);

            if (allocation_size != 0) {
                copy = ofw_allocate(allocation_size);
                if (!copy) {
                    error = BSD_OFW_ENOMEM;
                    break;
                }
                for (size_t index = 0;
                    index < (size_t)provider_cell_count; ++index)
                    copy[index] = list[cursor + index];
            }
            *producer = xref;
            *result_count = (int)provider_cell_count;
            *result_cells = copy;
            error = 0;
            break;
        }
        cursor += provider_cell_count;
        ++entry_count;
        if (requested_index == -1)
            error = 0;
    }
    if (requested_index == -1 && error == 0)
        *result_count = entry_count;
    OF_prop_free(list);
    return error;
}

int
ofw_bus_parse_xref_list_alloc(phandle_t node, const char *list_name,
    const char *cells_name, int index, phandle_t *producer,
    int *cell_count, pcell_t **cells)
{
    if (index < 0)
        return BSD_OFW_EINVAL;
    return ofw_bus_parse_xref_list(node, list_name, cells_name, index,
        producer, cell_count, cells);
}

int
ofw_bus_parse_xref_list_get_length(phandle_t node,
    const char *list_name, const char *cells_name, int *count)
{
    return ofw_bus_parse_xref_list(node, list_name, cells_name, -1,
        0, count, 0);
}

int
ofw_bus_string_list_to_array(phandle_t node, const char *list_name,
    const char ***result)
{
    char *property = 0;
    const char **array;
    ssize_t byte_count;
    size_t count = 0;
    size_t cursor = 0;
    size_t allocation_size;
    char *strings;

    if (result)
        *result = 0;
    if (!result || !list_name || node == 0 ||
        node == (phandle_t)-1)
        return -BSD_OFW_EINVAL;
    byte_count = OF_getprop_alloc(
        node, list_name, (void **)&property);
    if (byte_count <= 0)
        return (int)byte_count;
    while (cursor < (size_t)byte_count) {
        size_t start = cursor;

        while (cursor < (size_t)byte_count &&
            property[cursor] != '\0')
            ++cursor;
        if (cursor == (size_t)byte_count || cursor == start) {
            OF_prop_free(property);
            return -BSD_OFW_EINVAL;
        }
        ++count;
        ++cursor;
    }
    if (count > (SIZE_MAX / sizeof(*array)) - 1 ||
        (count + 1) * sizeof(*array) >
        SIZE_MAX - (size_t)byte_count) {
        OF_prop_free(property);
        return -BSD_OFW_ERANGE;
    }
    allocation_size =
        (count + 1) * sizeof(*array) + (size_t)byte_count;
    array = ofw_allocate(allocation_size);
    if (!array) {
        OF_prop_free(property);
        return -BSD_OFW_ENOMEM;
    }
    strings = (char *)(array + count + 1);
    bsd_memcpy(strings, property, (size_t)byte_count);
    OF_prop_free(property);
    cursor = 0;
    for (size_t index = 0; index < count; ++index) {
        array[index] = strings + cursor;
        cursor += bsd_strlen(strings + cursor) + 1;
    }
    array[count] = 0;
    if (count > (size_t)INT32_MAX) {
        ofw_release(array);
        return -BSD_OFW_ERANGE;
    }
    *result = array;
    return (int)count;
}
