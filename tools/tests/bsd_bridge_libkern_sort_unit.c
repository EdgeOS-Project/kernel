/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the shared FreeBSD libkern sorting helpers. */

#include <stdint.h>
#include <sys/libkern.h>

static int
compare_uint32(const void *left, const void *right)
{
    uint32_t left_value = *(const uint32_t *)left;
    uint32_t right_value = *(const uint32_t *)right;

    return (left_value > right_value) - (left_value < right_value);
}

int
main(void)
{
    uint32_t values[] = {
        90, 2, 17, 17, 0, UINT32_MAX, 8, 3, 42, 1,
    };

    if (bitcount16(UINT16_C(0xa501)) != 5)
        return 1;
    if (bitcount32(UINT32_C(0xf0f0a501)) != 13)
        return 2;
    if (bitcount64(UINT64_C(0xf0f0a501f0f0a501)) != 26)
        return 3;
    if (uqmax(17, 42) != 42)
        return 4;
    qsort(values, sizeof(values) / sizeof(values[0]),
        sizeof(values[0]), compare_uint32);
    for (size_t index = 1; index < sizeof(values) / sizeof(values[0]);
        ++index)
        if (values[index - 1] > values[index])
            return 5;
    if (values[0] != 0)
        return 6;
    if (values[9] != UINT32_MAX)
        return 7;
    return 0;
}
