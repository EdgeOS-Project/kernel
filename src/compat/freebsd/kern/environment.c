/* SPDX-License-Identifier: MPL-2.0 */
/* Shared kernel environment for imported FreeBSD drivers. */

#include <limits.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/kernel.h"
#include "compat/freebsd/sys/malloc.h"
#include "kernel/boot_command_line.h"

#define BSD_ENVIRONMENT_ENTRY_MAX 64u
#define BSD_ENVIRONMENT_NAME_MAX 64u
#define BSD_ENVIRONMENT_VALUE_MAX 256u
#define BSD_ENVIRONMENT_ENOENT 2
#define BSD_ENVIRONMENT_EINVAL 22
typedef struct {
    char name[BSD_ENVIRONMENT_NAME_MAX];
    char value[BSD_ENVIRONMENT_VALUE_MAX];
    uint8_t present;
} bsd_environment_entry_t;

static bsd_environment_entry_t
    g_environment_entries[BSD_ENVIRONMENT_ENTRY_MAX];
static char
    g_environment_hint_names[BSD_ENVIRONMENT_ENTRY_MAX]
        [BSD_ENVIRONMENT_NAME_MAX];
static volatile uint32_t g_environment_guard;

static void
environment_relax(void)
{
#if defined(__x86_64__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__) || defined(_M_ARM64)
    __asm__ __volatile__("yield");
#endif
}

static void
environment_lock(void)
{
    while (__atomic_test_and_set(&g_environment_guard, __ATOMIC_ACQUIRE))
        environment_relax();
}

static void
environment_unlock(void)
{
    __atomic_clear(&g_environment_guard, __ATOMIC_RELEASE);
}

static int
environment_name_valid(const char *name)
{
    size_t length = 0;

    if (!name || !name[0])
        return 0;
    while (name[length]) {
        if (name[length] == '=' || name[length] == ' ' ||
            name[length] == '\t' || name[length] == '\n' ||
            length + 1u >= BSD_ENVIRONMENT_NAME_MAX)
            return 0;
        ++length;
    }
    return 1;
}

static bsd_environment_entry_t *
environment_find_locked(const char *name)
{
    for (size_t index = 0; index < BSD_ENVIRONMENT_ENTRY_MAX; ++index) {
        bsd_environment_entry_t *entry = &g_environment_entries[index];

        if (entry->present && bsd_strcmp(entry->name, name) == 0)
            return entry;
    }
    return 0;
}

static char *
environment_copy_value(const char *value)
{
    size_t length;
    char *copy;

    if (!value)
        return 0;
    length = bsd_strlen(value);
    copy = bsd_malloc(length + 1u, M_TEMP, M_WAITOK);
    if (!copy)
        return 0;
    bsd_memcpy(copy, value, length + 1u);
    return copy;
}

char *
kern_getenv(const char *name)
{
    bsd_environment_entry_t *entry;
    char value[BSD_ENVIRONMENT_VALUE_MAX];
    int found;

    if (!environment_name_valid(name))
        return 0;
    environment_lock();
    entry = environment_find_locked(name);
    found = entry != 0;
    if (found)
        (void)bsd_strlcpy(value, entry->value, sizeof(value));
    environment_unlock();
    if (found)
        return environment_copy_value(value);
    if (kernel_boot_option_get(name, value, sizeof(value)) <= 0)
        return 0;
    return environment_copy_value(value);
}

int
bsd_tunable_str_fetch(const char *path, char *value, size_t capacity)
{
    char *environment;

    if (!path || !value || capacity == 0)
        return 0;
    environment = kern_getenv(path);
    if (!environment)
        return 0;
    (void)bsd_strlcpy(value, environment, capacity);
    freeenv(environment);
    return 1;
}

void
tunable_int_init(const void *data)
{
    const struct tunable_int *tunable = data;

    if (tunable && tunable->path && tunable->var)
        (void)getenv_int(tunable->path, tunable->var);
}

void
freeenv(char *environment)
{
    if (environment)
        bsd_free(environment, M_TEMP);
}

int
testenv(const char *name)
{
    char *value = kern_getenv(name);

    if (!value)
        return 0;
    freeenv(value);
    return 1;
}

int
kern_setenv(const char *name, const char *value)
{
    bsd_environment_entry_t *entry = 0;

    if (!environment_name_valid(name) || !value ||
        bsd_strlen(value) >= BSD_ENVIRONMENT_VALUE_MAX)
        return -1;
    environment_lock();
    entry = environment_find_locked(name);
    if (!entry) {
        for (size_t index = 0; index < BSD_ENVIRONMENT_ENTRY_MAX; ++index) {
            if (!g_environment_entries[index].present) {
                entry = &g_environment_entries[index];
                break;
            }
        }
    }
    if (!entry) {
        environment_unlock();
        return -1;
    }
    (void)bsd_strlcpy(entry->name, name, sizeof(entry->name));
    (void)bsd_strlcpy(entry->value, value, sizeof(entry->value));
    entry->present = 1;
    environment_unlock();
    return 0;
}

int
kern_unsetenv(const char *name)
{
    bsd_environment_entry_t *entry;

    if (!environment_name_valid(name))
        return -1;
    environment_lock();
    entry = environment_find_locked(name);
    if (entry) {
        bsd_memset(entry, 0, sizeof(*entry));
        environment_unlock();
        return 0;
    }
    environment_unlock();
    return -1;
}

static int
resource_key(char *buffer, size_t capacity, const char *name, int unit,
    const char *resource_name)
{
    char unit_text[16];
    size_t offset = 0;
    size_t unit_length = 0;
    unsigned int value;

    if (!buffer || !name || !name[0] || unit < 0 ||
        !resource_name || !resource_name[0])
        return BSD_ENVIRONMENT_EINVAL;
    value = (unsigned int)unit;
    do {
        unit_text[unit_length++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value != 0 && unit_length < sizeof(unit_text));
#define RESOURCE_APPEND_CHARACTER(character) do { \
    if (offset + 1u >= capacity) \
        return BSD_ENVIRONMENT_EINVAL; \
    buffer[offset++] = (character); \
} while (0)
#define RESOURCE_APPEND_TEXT(text) do { \
    const char *_cursor = (text); \
    while (*_cursor) \
        RESOURCE_APPEND_CHARACTER(*_cursor++); \
} while (0)
    RESOURCE_APPEND_TEXT("hint.");
    RESOURCE_APPEND_TEXT(name);
    RESOURCE_APPEND_CHARACTER('.');
    while (unit_length != 0)
        RESOURCE_APPEND_CHARACTER(unit_text[--unit_length]);
    RESOURCE_APPEND_CHARACTER('.');
    RESOURCE_APPEND_TEXT(resource_name);
    if (offset >= capacity)
        return BSD_ENVIRONMENT_EINVAL;
    buffer[offset] = '\0';
#undef RESOURCE_APPEND_TEXT
#undef RESOURCE_APPEND_CHARACTER
    return 0;
}

static int
resource_parse_integer(const char *text, unsigned long *value, int *negative)
{
    unsigned int base = 10;
    unsigned long parsed = 0;
    const char *cursor;

    if (!text || !text[0] || !value || !negative)
        return BSD_ENVIRONMENT_EINVAL;
    cursor = text;
    *negative = 0;
    if (*cursor == '-' || *cursor == '+') {
        *negative = *cursor == '-';
        cursor++;
    }
    if (cursor[0] == '0' && (cursor[1] == 'x' || cursor[1] == 'X')) {
        base = 16;
        cursor += 2;
    } else if (cursor[0] == '0' && cursor[1] != '\0') {
        base = 8;
        cursor++;
    }
    if (*cursor == '\0')
        return BSD_ENVIRONMENT_EINVAL;
    while (*cursor) {
        unsigned int digit;

        if (*cursor >= '0' && *cursor <= '9')
            digit = (unsigned int)(*cursor - '0');
        else if (*cursor >= 'a' && *cursor <= 'f')
            digit = (unsigned int)(*cursor - 'a') + 10u;
        else if (*cursor >= 'A' && *cursor <= 'F')
            digit = (unsigned int)(*cursor - 'A') + 10u;
        else
            return BSD_ENVIRONMENT_EINVAL;
        if (digit >= base)
            return BSD_ENVIRONMENT_EINVAL;
        if (parsed > (~0UL - digit) / base)
            return BSD_ENVIRONMENT_EINVAL;
        parsed = parsed * base + digit;
        cursor++;
    }
    *value = parsed;
    return 0;
}

int
getenv_int(const char *name, int *data)
{
    char *value;
    unsigned long parsed;
    int negative;
    int error;

    if (!data)
        return 0;
    value = kern_getenv(name);
    if (!value)
        return 0;
    error = resource_parse_integer(value, &parsed, &negative);
    freeenv(value);
    if (error)
        return 0;
    *data = negative ? (int)(0UL - parsed) : (int)parsed;
    return 1;
}

int
getenv_uint64(const char *name, uint64_t *data)
{
    char *value;
    unsigned long parsed;
    int negative;
    int error;

    if (!data)
        return 0;
    value = kern_getenv(name);
    if (!value)
        return 0;
    error = resource_parse_integer(value, &parsed, &negative);
    freeenv(value);
    if (error || negative)
        return 0;
    *data = (uint64_t)parsed;
    return 1;
}

int
getenv_ulong(const char *name, unsigned long *data)
{
    char *value;
    unsigned long parsed;
    int negative;
    int error;

    if (!data)
        return 0;
    value = kern_getenv(name);
    if (!value)
        return 0;
    error = resource_parse_integer(value, &parsed, &negative);
    freeenv(value);
    if (error || negative)
        return 0;
    *data = parsed;
    return 1;
}

int
bsd_tunable_long_fetch(const char *path, long *data)
{
    char *value;
    unsigned long parsed;
    int negative;
    int error;

    if (!data)
        return 0;
    value = kern_getenv(path);
    if (!value)
        return 0;
    error = resource_parse_integer(value, &parsed, &negative);
    freeenv(value);
    if (error || (!negative && parsed > (unsigned long)LONG_MAX) ||
        (negative && parsed > (unsigned long)LONG_MAX + 1ul))
        return 0;
    if (!negative)
        *data = (long)parsed;
    else if (parsed == (unsigned long)LONG_MAX + 1ul)
        *data = LONG_MIN;
    else
        *data = -(long)parsed;
    return 1;
}

int
getenv_bool(const char *name, bool *data)
{
    char *value;
    int found = 0;

    if (!data)
        return 0;
    value = kern_getenv(name);
    if (!value)
        return 0;
    if (bsd_strcmp(value, "1") == 0 ||
        bsd_strcasecmp(value, "true") == 0) {
        *data = true;
        found = 1;
    } else if (bsd_strcmp(value, "0") == 0 ||
        bsd_strcasecmp(value, "false") == 0) {
        *data = false;
        found = 1;
    }
    freeenv(value);
    return found;
}

static int
environment_store_integer(void *data, int index, int type_size,
    uint64_t value)
{
    uint8_t *destination = data;

    switch (type_size) {
    case 1:
        destination[index] = (uint8_t)value;
        return 0;
    case 2:
        ((uint16_t *)data)[index] = (uint16_t)value;
        return 0;
    case 4:
        ((uint32_t *)data)[index] = (uint32_t)value;
        return 0;
    case 8:
        ((uint64_t *)data)[index] = value;
        return 0;
    default:
        return BSD_ENVIRONMENT_EINVAL;
    }
}

int
getenv_array(const char *name, void *data, int size, int *result_size,
    int type_size, bool allow_signed)
{
    char *value;
    const char *cursor;
    int count = 0;
    int capacity;

    if (result_size)
        *result_size = 0;
    if (!data || !result_size || size < 0 ||
        (type_size != 1 && type_size != 2 &&
        type_size != 4 && type_size != 8))
        return 0;
    value = kern_getenv(name);
    if (!value)
        return 0;
    cursor = value;
    capacity = size / type_size;
    while (*cursor) {
        const char *start;
        char *end;
        unsigned long parsed;
        uint64_t stored;
        unsigned int shift = 0;
        int negative = 0;

        while (*cursor == ' ' || *cursor == '\t' || *cursor == ',')
            ++cursor;
        if (!*cursor)
            break;
        if (*cursor == '-' || *cursor == '+') {
            negative = *cursor == '-';
            ++cursor;
        }
        if (negative && !allow_signed)
            goto invalid;
        start = cursor;
        parsed = bsd_strtoul(cursor, &end, 0);
        if (end == start)
            goto invalid;
        cursor = end;
        if (*cursor == 'k' || *cursor == 'K')
            shift = 10;
        else if (*cursor == 'm' || *cursor == 'M')
            shift = 20;
        else if (*cursor == 'g' || *cursor == 'G')
            shift = 30;
        else if (*cursor == 't' || *cursor == 'T')
            shift = 40;
        if (shift != 0)
            ++cursor;
        if (*cursor != '\0' && *cursor != ' ' &&
            *cursor != '\t' && *cursor != ',')
            goto invalid;
        if ((uint64_t)parsed > (UINT64_MAX >> shift) || count >= capacity)
            goto invalid;
        stored = (uint64_t)parsed << shift;
        if (negative)
            stored = UINT64_C(0) - stored;
        if (environment_store_integer(
            data, count++, type_size, stored) != 0)
            goto invalid;
    }
    freeenv(value);
    *result_size = count * type_size;
    return count != 0;

invalid:
    freeenv(value);
    return 0;
}

int
resource_int_value(const char *name, int unit, const char *resource_name,
    int *result)
{
    char key[BSD_ENVIRONMENT_NAME_MAX];
    char *value;
    unsigned long parsed;
    int negative;
    int error;

    if (!result)
        return BSD_ENVIRONMENT_EINVAL;
    error = resource_key(key, sizeof(key), name, unit, resource_name);
    if (error)
        return error;
    value = kern_getenv(key);
    if (!value)
        return BSD_ENVIRONMENT_ENOENT;
    error = resource_parse_integer(value, &parsed, &negative);
    freeenv(value);
    if (error)
        return error;
    if (negative) {
        if (parsed > (unsigned long)INT32_MAX + 1UL)
            return BSD_ENVIRONMENT_EINVAL;
        *result = parsed == (unsigned long)INT32_MAX + 1UL ?
            INT32_MIN : -(int)parsed;
    } else {
        *result = (int)parsed;
    }
    return 0;
}

int
resource_long_value(const char *name, int unit, const char *resource_name,
    long *result)
{
    char key[BSD_ENVIRONMENT_NAME_MAX];
    char *value;
    unsigned long parsed;
    int negative;
    int error;

    if (!result)
        return BSD_ENVIRONMENT_EINVAL;
    error = resource_key(key, sizeof(key), name, unit, resource_name);
    if (error)
        return error;
    value = kern_getenv(key);
    if (!value)
        return BSD_ENVIRONMENT_ENOENT;
    error = resource_parse_integer(value, &parsed, &negative);
    freeenv(value);
    if (error)
        return error;
    *result = negative ? (long)(0UL - parsed) : (long)parsed;
    return 0;
}

int
resource_string_value(const char *name, int unit,
    const char *resource_name, const char **result)
{
    char key[BSD_ENVIRONMENT_NAME_MAX];
    bsd_environment_entry_t *entry;
    char *value;
    int error;

    if (!result)
        return BSD_ENVIRONMENT_EINVAL;
    error = resource_key(key, sizeof(key), name, unit, resource_name);
    if (error)
        return error;
    value = kern_getenv(key);
    if (!value)
        return BSD_ENVIRONMENT_ENOENT;
    if (kern_setenv(key, value) != 0) {
        freeenv(value);
        return BSD_ENVIRONMENT_EINVAL;
    }
    freeenv(value);
    environment_lock();
    entry = environment_find_locked(key);
    if (!entry) {
        environment_unlock();
        return BSD_ENVIRONMENT_ENOENT;
    }
    *result = entry->value;
    environment_unlock();
    return 0;
}

int
resource_disabled(const char *name, int unit)
{
    int disabled = 0;

    return resource_int_value(name, unit, "disabled", &disabled) == 0 &&
        disabled != 0;
}

static int
resource_parse_hint_key(const char *key, const char *resource_name,
    char *device_name, size_t name_capacity, int *unit)
{
    const char *name_start;
    const char *name_end;
    const char *unit_start;
    const char *unit_end;
    unsigned long parsed_unit;
    int negative;
    char unit_text[16];
    size_t name_length;
    size_t unit_length;

    if (!key || key[0] != 'h' || key[1] != 'i' || key[2] != 'n' ||
        key[3] != 't' || key[4] != '.')
        return BSD_ENVIRONMENT_ENOENT;
    name_start = key + 5;
    name_end = name_start;
    while (*name_end && *name_end != '.')
        name_end++;
    if (!name_end || name_end == name_start)
        return BSD_ENVIRONMENT_ENOENT;
    unit_start = name_end + 1;
    unit_end = unit_start;
    while (*unit_end && *unit_end != '.')
        unit_end++;
    if (!unit_end || unit_end == unit_start ||
        bsd_strcmp(unit_end + 1, resource_name) != 0)
        return BSD_ENVIRONMENT_ENOENT;
    name_length = (size_t)(name_end - name_start);
    unit_length = (size_t)(unit_end - unit_start);
    if (name_length + 1 > name_capacity ||
        unit_length == 0 || unit_length >= sizeof(unit_text))
        return BSD_ENVIRONMENT_EINVAL;
    bsd_memcpy(device_name, name_start, name_length);
    device_name[name_length] = '\0';
    bsd_memcpy(unit_text, unit_start, unit_length);
    unit_text[unit_length] = '\0';
    if (resource_parse_integer(unit_text, &parsed_unit, &negative) != 0 ||
        negative ||
        parsed_unit > INT32_MAX)
        return BSD_ENVIRONMENT_EINVAL;
    *unit = (int)parsed_unit;
    return 0;
}

int
resource_find_match(int *anchor, const char **name, int *unit,
    const char *resource_name, const char *value)
{
    int start;

    if (!anchor || !name || !unit || !resource_name || !value)
        return BSD_ENVIRONMENT_EINVAL;
    start = *anchor < 0 ? 0 : *anchor;
    environment_lock();
    for (int index = start;
        index < (int)BSD_ENVIRONMENT_ENTRY_MAX; ++index) {
        bsd_environment_entry_t *entry = &g_environment_entries[index];
        char *hint_name = g_environment_hint_names[index];
        int hint_unit;

        if (!entry->present || bsd_strcmp(entry->value, value) != 0)
            continue;
        if (resource_parse_hint_key(entry->name, resource_name,
            hint_name, BSD_ENVIRONMENT_NAME_MAX, &hint_unit) != 0)
            continue;
        *anchor = index + 1;
        *name = hint_name;
        *unit = hint_unit;
        environment_unlock();
        return 0;
    }
    environment_unlock();
    return BSD_ENVIRONMENT_ENOENT;
}

int
resource_find_dev(int *anchor, const char *name, int *unit,
    const char *resource_name, const char *value)
{
    const char *candidate;
    int candidate_unit;
    int error;

    if (!name || !unit)
        return BSD_ENVIRONMENT_EINVAL;
    do {
        error = resource_find_match(anchor, &candidate, &candidate_unit,
            resource_name, value);
        if (error)
            return error;
    } while (bsd_strcmp(candidate, name) != 0);
    *unit = candidate_unit;
    return 0;
}

int
resource_unset_value(const char *name, int unit,
    const char *resource_name)
{
    char key[BSD_ENVIRONMENT_NAME_MAX];
    int error;

    error = resource_key(key, sizeof(key), name, unit, resource_name);
    if (error)
        return error;
    return kern_unsetenv(key) == 0 ? 0 : BSD_ENVIRONMENT_ENOENT;
}
