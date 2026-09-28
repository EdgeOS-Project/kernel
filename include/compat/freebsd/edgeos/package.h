/* SPDX-License-Identifier: MPL-2.0 */
/* Source-built driver package lifecycle for the BSD Driver Bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_PACKAGE_H
#define EDGEOS_COMPAT_FREEBSD_PACKAGE_H

#include <stddef.h>

typedef enum bsd_driver_package_state {
    BSD_DRIVER_PACKAGE_DISABLED = 0,
    BSD_DRIVER_PACKAGE_REGISTERED = 1,
    BSD_DRIVER_PACKAGE_STARTING = 2,
    BSD_DRIVER_PACKAGE_ACTIVE = 3,
    BSD_DRIVER_PACKAGE_STOPPING = 4,
    BSD_DRIVER_PACKAGE_STOPPED = 5,
    BSD_DRIVER_PACKAGE_FAILED = 6,
} bsd_driver_package_state_t;

typedef struct bsd_driver_package_descriptor {
    const char *id;
    const char *provider;
    const char *upstream_commit;
    size_t source_count;
    size_t builtin_module_count;
    size_t loadable_module_count;
    size_t disabled_module_count;
} bsd_driver_package_descriptor_t;

typedef struct bsd_driver_package_record {
    bsd_driver_package_descriptor_t descriptor;
    volatile int state;
    volatile int error;
} bsd_driver_package_record_t;

typedef struct bsd_driver_package_status {
    bsd_driver_package_descriptor_t descriptor;
    bsd_driver_package_state_t state;
    int error;
} bsd_driver_package_status_t;

extern bsd_driver_package_record_t bsd_driver_package_registry[];
extern const size_t bsd_driver_package_registry_count;

size_t bsd_driver_package_count(void);
int bsd_driver_package_get(size_t index,
    bsd_driver_package_status_t *status);
int bsd_driver_package_find(const char *id,
    bsd_driver_package_status_t *status);

int bsd_driver_packages_prepare(void);
int bsd_driver_packages_activate(void);
int bsd_driver_packages_begin_stop(void);
int bsd_driver_packages_finish_stop(void);
void bsd_driver_packages_fail(int error);

#endif
