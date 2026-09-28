/* SPDX-License-Identifier: MPL-2.0 */

#ifndef EDGEOS_TEST_BSD_VIDEOMODE_SYS_SYSTM_H
#define EDGEOS_TEST_BSD_VIDEOMODE_SYS_SYSTM_H

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

extern int bootverbose;

static inline size_t
strlcpy(char *destination, const char *source, size_t capacity)
{
    size_t length;

    length = strlen(source);
    if (capacity != 0) {
        size_t copied = length >= capacity ? capacity - 1 : length;
        memcpy(destination, source, copied);
        destination[copied] = '\0';
    }
    return length;
}

#endif
