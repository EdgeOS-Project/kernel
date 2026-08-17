/* SPDX-License-Identifier: MPL-2.0 */
/* Shared hardware reset provider and consumer API for imported BSD drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_DEV_HWRESET_HWRESET_H
#define EDGEOS_COMPAT_FREEBSD_DEV_HWRESET_HWRESET_H

#include <stdbool.h>
#include <stdint.h>

#include <sys/bus.h>
#include "../ofw/ofw_bus.h"

typedef struct bsd_hwreset *hwreset_t;
typedef struct bsd_hwreset_array *hwreset_array_t;

void hwreset_register_ofw_provider(device_t provider);
void hwreset_unregister_ofw_provider(device_t provider);

int hwreset_get_by_id(device_t consumer, device_t provider, intptr_t id,
    hwreset_t *result);
void hwreset_release(hwreset_t reset);

int hwreset_assert(hwreset_t reset);
int hwreset_deassert(hwreset_t reset);
int hwreset_is_asserted(hwreset_t reset, bool *asserted);

int hwreset_get_by_ofw_name(device_t consumer, phandle_t node,
    char *name, hwreset_t *result);
int hwreset_get_by_ofw_idx(device_t consumer, phandle_t node,
    int index, hwreset_t *result);

void hwreset_array_release(hwreset_array_t resets);
int hwreset_array_assert(hwreset_array_t resets);
int hwreset_array_deassert(hwreset_array_t resets);
int hwreset_array_get_ofw(device_t consumer, phandle_t node,
    hwreset_array_t *result);

#endif
