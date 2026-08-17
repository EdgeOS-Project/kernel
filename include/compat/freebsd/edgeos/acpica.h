/* SPDX-License-Identifier: MPL-2.0 */
/* ACPICA operating-system services for the EdgeOS BSD Driver Bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_ACPICA_H
#define EDGEOS_COMPAT_FREEBSD_ACPICA_H

#include <stdint.h>

typedef struct bsd_acpica_runtime_status {
    uint8_t initialized;
    uint8_t namespace_loaded;
    uint8_t objects_initialized;
    uint32_t device_count;
    uint32_t registered_device_count;
    uint32_t present_device_count;
    uint32_t matched_device_count;
    uint32_t failure_status;
} bsd_acpica_runtime_status_t;

int bsd_acpica_runtime_initialize(void);
void bsd_acpica_runtime_get_status(bsd_acpica_runtime_status_t *status);
void *bsd_acpica_device_for_handle(void *handle);
int bsd_acpica_handle_match(void *handle, const char *hardware_id);
int bsd_acpica_bind_device_handle(void *device, void *handle);

#endif
