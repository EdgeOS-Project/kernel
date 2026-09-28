/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent boot logging policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/boot_log_policy.h"

#include <stdint.h>

#include "kernel/boot_command_line.h"
#include "string.h"

#define EDGEOS_DEFAULT_CONSOLE_LOGLEVEL 7
#define EDGEOS_QUIET_CONSOLE_LOGLEVEL 4
#define EDGEOS_MAX_CONSOLE_LOGLEVEL 8

static int boot_log_parse_level(const char *text, int *level) {
    uint32_t value = 0;

    if (!text || !text[0] || !level) return -1;
    while (*text) {
        uint32_t digit;

        if (*text < '0' || *text > '9') return -1;
        digit = (uint32_t)(*text++ - '0');
        if (value > (UINT32_MAX - digit) / 10u) return -1;
        value = value * 10u + digit;
    }
    if (value < 1u || value > EDGEOS_MAX_CONSOLE_LOGLEVEL) return -1;
    *level = (int)value;
    return 0;
}

static int boot_log_component_invalid(const char *start, size_t length) {
    if (!start || length == 0) return 1;
    if (length == 1u && start[0] == '.') return 1;
    if (length == 2u && start[0] == '.' && start[1] == '.') return 1;
    return 0;
}

int kernel_boot_log_path_valid(const char *path) {
    const char *component;
    size_t length;

    if (!path || path[0] != '/' || path[1] == 0) return 0;
    length = strlen(path);
    if (length >= EDGEOS_BOOT_LOG_PATH_MAX || path[length - 1u] == '/')
        return 0;

    component = path + 1;
    for (const char *cursor = component;; ++cursor) {
        unsigned char value = (unsigned char)*cursor;

        if (value != 0 && (value < 0x20u || value == 0x7fu)) return 0;
        if (value == '/' || value == 0) {
            if (boot_log_component_invalid(
                    component, (size_t)(cursor - component)))
                return 0;
            if (value == 0) break;
            component = cursor + 1;
        }
    }
    return 1;
}

int kernel_boot_log_policy_load(kernel_boot_log_policy_t *policy) {
    char level[16];
    int loglevel_ordinal;
    int quiet_ordinal;
    int result;
    int status = 0;

    if (!policy) return -1;
    memset(policy, 0, sizeof(*policy));
    policy->console_loglevel = EDGEOS_DEFAULT_CONSOLE_LOGLEVEL;

    quiet_ordinal = kernel_boot_option_last_ordinal("quiet");
    policy->quiet = quiet_ordinal > 0;
    if (policy->quiet)
        policy->console_loglevel = EDGEOS_QUIET_CONSOLE_LOGLEVEL;

    result = kernel_boot_option_get("loglevel", level, sizeof(level));
    loglevel_ordinal = kernel_boot_option_last_ordinal("loglevel");
    if (result < 0 ||
        (result > 0 &&
         boot_log_parse_level(level, &policy->console_loglevel) < 0)) {
        policy->console_loglevel = policy->quiet ?
            EDGEOS_QUIET_CONSOLE_LOGLEVEL :
            EDGEOS_DEFAULT_CONSOLE_LOGLEVEL;
        status = -1;
    } else if (result > 0) {
        policy->console_loglevel_explicit = 1;
        if (quiet_ordinal > loglevel_ordinal)
            policy->console_loglevel = EDGEOS_QUIET_CONSOLE_LOGLEVEL;
    }

    result = kernel_boot_option_get(
        "logfile", policy->file_path, sizeof(policy->file_path));
    if (result < 0 ||
        (result > 0 && !kernel_boot_log_path_valid(policy->file_path))) {
        policy->file_path[0] = 0;
        status = -1;
    } else if (result > 0) {
        policy->file_enabled = 1;
    }
    return status;
}
