/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS hardware reset framework for imported BSD drivers.
 *
 * Providers retain their hardware-specific reset implementation. This
 * shared layer resolves Device Tree references and owns consumer handles.
 */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/dev/hwreset/hwreset.h"
#include "compat/freebsd/dev/ofw/ofw_bus_subr.h"
#include "compat/freebsd/dev/ofw/openfirm.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/newbus.h"
#include "hwreset_if.h"

#define BSD_HWRESET_ENOENT 2
#define BSD_HWRESET_ENXIO 6
#define BSD_HWRESET_ENOMEM 12
#define BSD_HWRESET_ENODEV 19
#define BSD_HWRESET_EINVAL 22
#define BSD_HWRESET_ERANGE 34

struct bsd_hwreset {
    device_t consumer;
    device_t provider;
    intptr_t id;
};

struct bsd_hwreset_array {
    size_t count;
    hwreset_t resets[];
};

int
hwreset_get_by_id(device_t consumer, device_t provider, intptr_t id,
    hwreset_t *result)
{
    struct bsd_hwreset *reset;

    if (result)
        *result = 0;
    if (!provider || !result ||
        !bsd_device_implements_method(provider, &hwreset_assert_desc))
        return BSD_HWRESET_ENODEV;
    reset = bsd_malloc(sizeof(*reset), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!reset)
        return BSD_HWRESET_ENOMEM;
    reset->consumer = consumer;
    reset->provider = provider;
    reset->id = id;
    *result = reset;
    return 0;
}

void
hwreset_release(hwreset_t reset)
{
    if (reset)
        bsd_free(reset, M_DEVBUF);
}

int
hwreset_assert(hwreset_t reset)
{
    if (!reset || !reset->provider ||
        !bsd_device_implements_method(
        reset->provider, &hwreset_assert_desc))
        return BSD_HWRESET_EINVAL;
    return HWRESET_ASSERT(reset->provider, reset->id, true);
}

int
hwreset_deassert(hwreset_t reset)
{
    if (!reset || !reset->provider ||
        !bsd_device_implements_method(
        reset->provider, &hwreset_assert_desc))
        return BSD_HWRESET_EINVAL;
    return HWRESET_ASSERT(reset->provider, reset->id, false);
}

int
hwreset_is_asserted(hwreset_t reset, bool *asserted)
{
    if (!reset || !reset->provider || !asserted ||
        !bsd_device_implements_method(
        reset->provider, &hwreset_is_asserted_desc))
        return BSD_HWRESET_EINVAL;
    return HWRESET_IS_ASSERTED(reset->provider, reset->id, asserted);
}

int
hwreset_default_ofw_map(device_t provider, phandle_t xref,
    int cell_count, pcell_t *cells, intptr_t *id)
{
    (void)provider;
    (void)xref;
    if (!id || cell_count < 0 || (cell_count > 0 && !cells))
        return BSD_HWRESET_EINVAL;
    if (cell_count == 0)
        *id = 1;
    else if (cell_count == 1)
        *id = (intptr_t)cells[0];
    else
        return BSD_HWRESET_ERANGE;
    return 0;
}

int
hwreset_get_by_ofw_idx(device_t consumer, phandle_t node,
    int index, hwreset_t *result)
{
    pcell_t *cells = 0;
    phandle_t xref = 0;
    device_t provider;
    intptr_t id;
    int cell_count = 0;
    int error;

    if (result)
        *result = 0;
    if (!consumer || !result || index < 0)
        return BSD_HWRESET_EINVAL;
    if (node <= 0)
        node = ofw_bus_get_node(consumer);
    if (node <= 0)
        return BSD_HWRESET_ENXIO;
    error = ofw_bus_parse_xref_list_alloc(node, "resets",
        "#reset-cells", index, &xref, &cell_count, &cells);
    if (error != 0)
        return error;
    provider = OF_device_from_xref(xref);
    if (!provider) {
        OF_prop_free(cells);
        return BSD_HWRESET_ENODEV;
    }
    error = HWRESET_MAP(provider, xref, cell_count, cells, &id);
    OF_prop_free(cells);
    if (error != 0)
        return error;
    return hwreset_get_by_id(consumer, provider, id, result);
}

int
hwreset_get_by_ofw_name(device_t consumer, phandle_t node,
    char *name, hwreset_t *result)
{
    int index;
    int error;

    if (result)
        *result = 0;
    if (!consumer || !name || !name[0] || !result)
        return BSD_HWRESET_EINVAL;
    if (node <= 0)
        node = ofw_bus_get_node(consumer);
    if (node <= 0)
        return BSD_HWRESET_ENXIO;
    error = ofw_bus_find_string_index(
        node, "reset-names", name, &index);
    if (error != 0)
        return error;
    return hwreset_get_by_ofw_idx(consumer, node, index, result);
}

void
hwreset_register_ofw_provider(device_t provider)
{
    phandle_t node;

    if (!provider)
        return;
    node = ofw_bus_get_node(provider);
    if (node > 0)
        (void)OF_device_register_xref(
            OF_xref_from_node(node), provider);
}

void
hwreset_unregister_ofw_provider(device_t provider)
{
    phandle_t xref;

    if (!provider)
        return;
    xref = OF_xref_from_device(provider);
    if (xref != 0)
        OF_device_unregister_xref(xref, provider);
}

int
hwreset_array_get_ofw(device_t consumer, phandle_t node,
    hwreset_array_t *result)
{
    struct bsd_hwreset_array *array;
    int count;
    int error;

    if (result)
        *result = 0;
    if (!consumer || !result)
        return BSD_HWRESET_EINVAL;
    if (node <= 0)
        node = ofw_bus_get_node(consumer);
    if (node <= 0)
        return BSD_HWRESET_ENXIO;
    error = ofw_bus_parse_xref_list_get_length(
        node, "resets", "#reset-cells", &count);
    if (error != 0)
        return error;
    if (count < 0 ||
        (size_t)count > (SIZE_MAX - sizeof(*array)) /
        sizeof(array->resets[0]))
        return BSD_HWRESET_ERANGE;
    array = bsd_malloc(sizeof(*array) +
        (size_t)count * sizeof(array->resets[0]),
        M_DEVBUF, M_WAITOK | M_ZERO);
    if (!array)
        return BSD_HWRESET_ENOMEM;
    for (int index = 0; index < count; ++index) {
        error = hwreset_get_by_ofw_idx(
            consumer, node, index, &array->resets[index]);
        if (error != 0) {
            array->count = (size_t)index;
            hwreset_array_release(array);
            return error;
        }
    }
    array->count = (size_t)count;
    *result = array;
    return 0;
}

void
hwreset_array_release(hwreset_array_t resets)
{
    if (!resets)
        return;
    for (size_t index = 0; index < resets->count; ++index)
        hwreset_release(resets->resets[index]);
    bsd_free(resets, M_DEVBUF);
}

int
hwreset_array_assert(hwreset_array_t resets)
{
    if (!resets)
        return BSD_HWRESET_EINVAL;
    for (size_t index = 0; index < resets->count; ++index) {
        int error = hwreset_assert(resets->resets[index]);

        if (error != 0)
            return error;
    }
    return 0;
}

int
hwreset_array_deassert(hwreset_array_t resets)
{
    if (!resets)
        return BSD_HWRESET_EINVAL;
    for (size_t index = 0; index < resets->count; ++index) {
        int error = hwreset_deassert(resets->resets[index]);

        if (error != 0)
            return error;
    }
    return 0;
}
