/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS code. */

#include "kernel/boot_command_line.h"

static char g_boot_command_line[EDGEOS_BOOT_COMMAND_LINE_MAX];

static int command_line_space(char value) {
    return value == ' ' || value == '\t' || value == '\n' || value == '\r';
}

static int command_line_name_equal(const char *start, size_t length,
                                   const char *name) {
    size_t index = 0;

    if (!start || !name) return 0;
    while (index < length && name[index] && start[index] == name[index])
        index++;
    return index == length && name[index] == 0;
}

static int command_line_value_equal(const char *value, const char *expected) {
    size_t index = 0;

    if (!value || !expected) return 0;
    while (value[index] && expected[index] &&
           value[index] == expected[index])
        index++;
    return value[index] == 0 && expected[index] == 0;
}

void kernel_boot_command_line_set(const char *command_line) {
    size_t length = 0;

    if (command_line) {
        while (command_line[length] &&
               length + 1u < sizeof(g_boot_command_line)) {
            g_boot_command_line[length] = command_line[length];
            length++;
        }
    }
    g_boot_command_line[length] = 0;
}

const char *kernel_boot_command_line_get(void) {
    return g_boot_command_line;
}

int kernel_boot_option_get(const char *name, char *value, size_t capacity) {
    const char *cursor = g_boot_command_line;
    size_t name_length = 0;
    int found = 0;
    int overflow = 0;

    if (!name || !name[0] || !value || capacity == 0) return -1;
    while (name[name_length]) {
        if (command_line_space(name[name_length]) ||
            name[name_length] == '=')
            return -1;
        name_length++;
    }
    value[0] = 0;

    while (*cursor) {
        const char *token_name;
        size_t token_name_length = 0;
        char quote = 0;
        int matches;

        while (command_line_space(*cursor)) cursor++;
        if (!*cursor) break;

        token_name = cursor;
        while (*cursor && !command_line_space(*cursor) && *cursor != '=') {
            token_name_length++;
            cursor++;
        }
        matches = command_line_name_equal(token_name, token_name_length, name);

        if (*cursor != '=') {
            if (matches) {
                value[0] = 0;
                found = 1;
                overflow = 0;
            }
            while (*cursor && !command_line_space(*cursor)) cursor++;
            continue;
        }

        cursor++;
        if (*cursor == '\'' || *cursor == '"') quote = *cursor++;
        if (matches) {
            size_t output = 0;

            found = 1;
            overflow = 0;
            while (*cursor &&
                   (quote ? *cursor != quote :
                            !command_line_space(*cursor))) {
                char next = *cursor++;

                if (quote && next == '\\' &&
                    (*cursor == quote || *cursor == '\\'))
                    next = *cursor++;
                if (output + 1u < capacity)
                    value[output++] = next;
                else
                    overflow = 1;
            }
            value[output] = 0;
        } else {
            while (*cursor &&
                   (quote ? *cursor != quote :
                            !command_line_space(*cursor))) {
                if (quote && *cursor == '\\' &&
                    (cursor[1] == quote || cursor[1] == '\\'))
                    cursor++;
                cursor++;
            }
        }
        if (quote && *cursor == quote) cursor++;
        while (*cursor && !command_line_space(*cursor)) cursor++;
    }

    if (!found) return 0;
    return overflow ? -1 : 1;
}

int kernel_boot_option_present(const char *name) {
    char value[2];

    return kernel_boot_option_get(name, value, sizeof(value)) != 0;
}

int kernel_boot_option_enabled(const char *name, int default_value) {
    char value[16];
    int result = kernel_boot_option_get(name, value, sizeof(value));

    if (result == 0) return default_value != 0;
    if (result < 0) return default_value != 0;
    if (!value[0] ||
        command_line_value_equal(value, "1") ||
        command_line_value_equal(value, "y") ||
        command_line_value_equal(value, "yes") ||
        command_line_value_equal(value, "on") ||
        command_line_value_equal(value, "true"))
        return 1;
    if (command_line_value_equal(value, "0") ||
        command_line_value_equal(value, "n") ||
        command_line_value_equal(value, "no") ||
        command_line_value_equal(value, "off") ||
        command_line_value_equal(value, "false"))
        return 0;
    return default_value != 0;
}

int kernel_boot_option_last_ordinal(const char *name) {
    const char *cursor = g_boot_command_line;
    size_t name_length = 0;
    int ordinal = 0;
    int matched_ordinal = 0;

    if (!name || !name[0]) return -1;
    while (name[name_length]) {
        if (command_line_space(name[name_length]) ||
            name[name_length] == '=')
            return -1;
        ++name_length;
    }
    while (*cursor) {
        const char *token_name;
        size_t token_name_length = 0;
        char quote = 0;

        while (command_line_space(*cursor)) ++cursor;
        if (!*cursor) break;
        ++ordinal;
        token_name = cursor;
        while (*cursor && !command_line_space(*cursor) && *cursor != '=') {
            ++token_name_length;
            ++cursor;
        }
        if (command_line_name_equal(
                token_name, token_name_length, name))
            matched_ordinal = ordinal;
        if (*cursor == '=') {
            ++cursor;
            if (*cursor == '\'' || *cursor == '"') quote = *cursor++;
            while (*cursor &&
                   (quote ? *cursor != quote :
                            !command_line_space(*cursor))) {
                if (quote && *cursor == '\\' &&
                    (cursor[1] == quote || cursor[1] == '\\'))
                    ++cursor;
                ++cursor;
            }
            if (quote && *cursor == quote) ++cursor;
        } else {
            while (*cursor && !command_line_space(*cursor)) ++cursor;
        }
        while (*cursor && !command_line_space(*cursor)) ++cursor;
    }
    return matched_ordinal;
}

int kernel_boot_init_path(int initramfs_root, char *path, size_t capacity) {
    const char *fallback = initramfs_root ? "/init" : "/sbin/init";
    int result = 0;
    size_t length = 0;

    if (!path || capacity < 2u) return -1;
    if (initramfs_root)
        result = kernel_boot_option_get("rdinit", path, capacity);
    if (result <= 0)
        result = kernel_boot_option_get("init", path, capacity);
    if (result < 0) return -1;
    if (result == 0) {
        while (fallback[length] && length + 1u < capacity) {
            path[length] = fallback[length];
            length++;
        }
        path[length] = 0;
        return fallback[length] == 0 ? 0 : -1;
    }
    return path[0] == '/' ? 0 : -1;
}
