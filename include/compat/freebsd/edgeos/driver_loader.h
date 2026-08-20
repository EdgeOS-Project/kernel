/* SPDX-License-Identifier: MPL-2.0 */
/* External BSD driver loading and kernel symbol export contract. */

#ifndef EDGEOS_COMPAT_FREEBSD_DRIVER_LOADER_H
#define EDGEOS_COMPAT_FREEBSD_DRIVER_LOADER_H

#include <stddef.h>
#include <stdint.h>

struct linker_file;

#define BSD_DRIVER_MODULE_PATH_MAX 512u

int bsd_driver_symbol_resolve(const char *name, uint64_t *address,
    void *context);
size_t bsd_driver_symbol_count(void);

int bsd_driver_module_resolve_path(const char *name, size_t length,
    char *path, size_t capacity);
int bsd_driver_module_load_path(const char *path,
    struct linker_file **file_out);
int bsd_driver_module_load_image(const void *image, uint32_t image_size,
    const char *name, struct linker_file **file_out);
int bsd_driver_modules_load_config(const char *path);
int bsd_driver_modules_load_default(void);

#endif
