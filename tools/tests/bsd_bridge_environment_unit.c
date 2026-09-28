/* SPDX-License-Identifier: MPL-2.0 */
/* Host behavior tests for the shared BSD kernel environment. */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <edgeos/malloc.h>

#define TEST_ALLOCATION_BYTES 512u

static uint8_t g_allocation[TEST_ALLOCATION_BYTES];
static int g_allocation_used;

struct malloc_type M_TEMP[1];

char *kern_getenv(const char *name);
void freeenv(char *environment);
int testenv(const char *name);
int kern_setenv(const char *name, const char *value);
int kern_unsetenv(const char *name);
int getenv_bool(const char *name, bool *data);
int getenv_array(const char *name, void *data, int size, int *result_size,
    int type_size, bool allow_signed);
int resource_int_value(const char *name, int unit,
    const char *resource_name, int *result);
int resource_long_value(const char *name, int unit,
    const char *resource_name, long *result);
int resource_string_value(const char *name, int unit,
    const char *resource_name, const char **result);
int resource_disabled(const char *name, int unit);
int resource_find_match(int *anchor, const char **name, int *unit,
    const char *resource_name, const char *value);
int resource_unset_value(const char *name, int unit,
    const char *resource_name);
struct tunable_int {
    const char *path;
    int *var;
};
void tunable_int_init(const void *data);

static int
test_fail(const char *expression, int line)
{
    printf("bsd_bridge_environment_unit: FAIL line %d: %s\n",
        line, expression);
    return (1);
}

#define CHECK(expression) do { \
    if (!(expression)) \
        return (test_fail(#expression, __LINE__)); \
} while (0)

size_t
bsd_strlen(const char *text)
{
    size_t length = 0;

    while (text[length] != '\0')
        ++length;
    return (length);
}

int
bsd_strcmp(const char *left, const char *right)
{
    while (*left != '\0' && *left == *right) {
        ++left;
        ++right;
    }
    return ((unsigned char)*left - (unsigned char)*right);
}

int
bsd_strcasecmp(const char *left, const char *right)
{
    while (*left != '\0' || *right != '\0') {
        unsigned char left_byte = (unsigned char)*left;
        unsigned char right_byte = (unsigned char)*right;

        if (left_byte >= 'A' && left_byte <= 'Z')
            left_byte = (unsigned char)(left_byte - 'A' + 'a');
        if (right_byte >= 'A' && right_byte <= 'Z')
            right_byte = (unsigned char)(right_byte - 'A' + 'a');
        if (left_byte != right_byte)
            return ((int)left_byte - (int)right_byte);
        if (*left != '\0')
            ++left;
        if (*right != '\0')
            ++right;
    }
    return (0);
}

unsigned long
bsd_strtoul(const char *text, char **end, int base)
{
    const char *cursor = text;
    unsigned long value = 0;
    int digit;

    if (base == 0) {
        if (cursor[0] == '0' &&
            (cursor[1] == 'x' || cursor[1] == 'X')) {
            base = 16;
            cursor += 2;
        } else if (cursor[0] == '0') {
            base = 8;
        } else {
            base = 10;
        }
    }
    while (*cursor != '\0') {
        if (*cursor >= '0' && *cursor <= '9')
            digit = *cursor - '0';
        else if (*cursor >= 'a' && *cursor <= 'f')
            digit = *cursor - 'a' + 10;
        else if (*cursor >= 'A' && *cursor <= 'F')
            digit = *cursor - 'A' + 10;
        else
            break;
        if (digit >= base)
            break;
        value = value * (unsigned long)base + (unsigned long)digit;
        ++cursor;
    }
    if (end)
        *end = (char *)cursor;
    return (value);
}

void *
bsd_memcpy(void *destination, const void *source, size_t length)
{
    uint8_t *output = destination;
    const uint8_t *input = source;

    for (size_t index = 0; index < length; ++index)
        output[index] = input[index];
    return (destination);
}

void *
bsd_memset(void *destination, int value, size_t length)
{
    uint8_t *bytes = destination;

    for (size_t index = 0; index < length; ++index)
        bytes[index] = (uint8_t)value;
    return (destination);
}

size_t
bsd_strlcpy(char *destination, const char *source, size_t capacity)
{
    size_t length = bsd_strlen(source);

    if (capacity != 0) {
        size_t copied = length < capacity - 1u ? length : capacity - 1u;
        (void)bsd_memcpy(destination, source, copied);
        destination[copied] = '\0';
    }
    return (length);
}

void *
bsd_malloc(size_t size, struct malloc_type *type, int flags)
{
    (void)type;
    (void)flags;
    if (g_allocation_used || size > sizeof(g_allocation))
        return (NULL);
    g_allocation_used = 1;
    (void)bsd_memset(g_allocation, 0, sizeof(g_allocation));
    return (g_allocation);
}

void
bsd_free(void *allocation, struct malloc_type *type)
{
    (void)type;
    if (allocation == g_allocation)
        g_allocation_used = 0;
}

int
kernel_boot_option_get(const char *name, char *value, size_t capacity)
{
    static const char expected_name[] = "boot.value";
    static const char expected_value[] = "from-command-line";

    if (bsd_strcmp(name, expected_name) != 0)
        return (0);
    if (capacity <= sizeof(expected_value))
        return (-1);
    (void)bsd_strlcpy(value, expected_value, capacity);
    return (1);
}

int
main(void)
{
    const char *hint_name;
    const char *string_value;
    int32_t array_values[3];
    char *value;
    bool bool_value;
    long long_value;
    int array_size;
    int anchor;
    int hint_unit;
    int int_value;
    int tunable_value;
    struct tunable_int tunable = {
        .path = "driver.tunable",
        .var = &tunable_value,
    };

    CHECK(kern_getenv("missing") == NULL);
    CHECK(testenv("missing") == 0);
    CHECK(kern_setenv("", "value") == -1);
    CHECK(kern_setenv("invalid name", "value") == -1);
    CHECK(kern_setenv("driver.mode", "enabled") == 0);
    CHECK(testenv("driver.mode") == 1);
    value = kern_getenv("driver.mode");
    CHECK(value != NULL);
    CHECK(bsd_strcmp(value, "enabled") == 0);
    freeenv(value);
    CHECK(kern_setenv("driver.mode", "updated") == 0);
    value = kern_getenv("driver.mode");
    CHECK(value != NULL);
    CHECK(bsd_strcmp(value, "updated") == 0);
    freeenv(value);
    CHECK(kern_unsetenv("driver.mode") == 0);
    CHECK(kern_unsetenv("driver.mode") == -1);
    tunable_value = 17;
    tunable_int_init(&tunable);
    CHECK(tunable_value == 17);
    CHECK(kern_setenv("driver.tunable", "42") == 0);
    tunable_int_init(&tunable);
    CHECK(tunable_value == 42);
    CHECK(kern_setenv("driver.boolean", "TrUe") == 0);
    bool_value = false;
    CHECK(getenv_bool("driver.boolean", &bool_value) == 1);
    CHECK(bool_value);
    CHECK(kern_setenv("driver.array", "1, 2k, -3") == 0);
    array_size = 0;
    CHECK(getenv_array("driver.array", array_values,
        sizeof(array_values), &array_size, sizeof(array_values[0]), true) == 1);
    CHECK(array_size == (int)sizeof(array_values));
    CHECK(array_values[0] == 1);
    CHECK(array_values[1] == 2048);
    CHECK(array_values[2] == -3);
    value = kern_getenv("boot.value");
    CHECK(value != NULL);
    CHECK(bsd_strcmp(value, "from-command-line") == 0);
    freeenv(value);
    CHECK(kern_setenv("hint.ure.0.phymask", "0xffffffff") == 0);
    CHECK(resource_int_value("ure", 0, "phymask", &int_value) == 0);
    CHECK((unsigned int)int_value == 0xffffffffu);
    CHECK(kern_setenv("hint.ure.0.speed", "2500") == 0);
    CHECK(resource_long_value("ure", 0, "speed", &long_value) == 0);
    CHECK(long_value == 2500);
    CHECK(kern_setenv("hint.ure.0.offset", "-42") == 0);
    CHECK(resource_int_value("ure", 0, "offset", &int_value) == 0);
    CHECK(int_value == -42);
    CHECK(resource_long_value("ure", 0, "offset", &long_value) == 0);
    CHECK(long_value == -42);
    CHECK(kern_setenv("hint.ure.0.at", "uhub0") == 0);
    CHECK(resource_string_value("ure", 0, "at", &string_value) == 0);
    CHECK(bsd_strcmp(string_value, "uhub0") == 0);
    anchor = 0;
    CHECK(resource_find_match(&anchor, &hint_name, &hint_unit,
        "at", "uhub0") == 0);
    CHECK(bsd_strcmp(hint_name, "ure") == 0);
    CHECK(hint_unit == 0);
    CHECK(kern_setenv("hint.ure.0.disabled", "1") == 0);
    CHECK(resource_disabled("ure", 0) == 1);
    CHECK(resource_unset_value("ure", 0, "disabled") == 0);
    CHECK(resource_disabled("ure", 0) == 0);
    printf("bsd_bridge_environment_unit: PASS\n");
    return (0);
}
