/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS filesystem path resolution for BSD driver modules.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stddef.h>

#include "compat/freebsd/edgeos/driver_loader.h"

#define BSD_DRIVER_PATH_EINVAL 22

#ifndef CONFIG_BSD_DRIVER_MODULE_DIRECTORY
#define CONFIG_BSD_DRIVER_MODULE_DIRECTORY "/usr/lib/edgeos/modules"
#endif

static size_t
driver_path_length(const char *text)
{
    size_t length = 0;

    if (!text)
        return 0;
    while (text[length])
        length++;
    return length;
}

static int
driver_path_has_suffix(const char *name, size_t length,
    const char *suffix, size_t suffix_length)
{
    size_t index;

    if (length < suffix_length)
        return 0;
    for (index = 0; index < suffix_length; ++index) {
        if (name[length - suffix_length + index] != suffix[index])
            return 0;
    }
    return 1;
}

static void
driver_path_copy(char *destination, const char *source, size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index)
        destination[index] = source[index];
}

int
bsd_driver_module_resolve_path(const char *name, size_t length,
    char *path, size_t capacity)
{
    static const char directory[] = CONFIG_BSD_DRIVER_MODULE_DIRECTORY;
    static const char suffix[] = ".ko";
    size_t directory_length;
    size_t suffix_length = sizeof(suffix) - 1u;
    size_t output_length;
    int append_separator;
    int append_suffix;

    if (!name || !length || !path || !capacity)
        return BSD_DRIVER_PATH_EINVAL;
    if (name[0] == '/') {
        if (length + 1u > capacity)
            return BSD_DRIVER_PATH_EINVAL;
        driver_path_copy(path, name, length);
        path[length] = 0;
        return 0;
    }

    directory_length = driver_path_length(directory);
    if (!directory_length || directory[0] != '/')
        return BSD_DRIVER_PATH_EINVAL;
    while (directory_length > 1u &&
        directory[directory_length - 1u] == '/')
        directory_length--;
    append_separator = directory[directory_length - 1u] != '/';
    append_suffix = !driver_path_has_suffix(
        name, length, suffix, suffix_length);
    output_length = directory_length + (size_t)append_separator + length +
        (append_suffix ? suffix_length : 0u);
    if (output_length + 1u > capacity)
        return BSD_DRIVER_PATH_EINVAL;

    driver_path_copy(path, directory, directory_length);
    if (append_separator)
        path[directory_length++] = '/';
    driver_path_copy(path + directory_length, name, length);
    output_length = directory_length + length;
    if (append_suffix) {
        driver_path_copy(path + output_length, suffix, suffix_length);
        output_length += suffix_length;
    }
    path[output_length] = 0;
    return 0;
}
