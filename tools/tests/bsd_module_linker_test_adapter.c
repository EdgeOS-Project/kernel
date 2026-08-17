/* SPDX-License-Identifier: MPL-2.0 */
/* Test-owned linker image used to isolate module lifecycle behavior. */

#include <stdlib.h>

#include "bsd_module_linker_test_adapter.h"

struct bsd_linker_image {
    bsd_linker_record_set_t records;
};

static size_t g_release_count;

bsd_linker_image_t *
bsd_test_linker_image_create(const bsd_linker_record_set_t *records)
{
    bsd_linker_image_t *image;

    if (!records)
        return 0;
    image = calloc(1, sizeof(*image));
    if (!image)
        return 0;
    image->records = *records;
    return image;
}

void
bsd_linker_release_image(bsd_linker_image_t *image)
{
    if (!image)
        return;
    g_release_count++;
    free(image);
}

int
bsd_linker_image_records(const bsd_linker_image_t *image,
    bsd_linker_record_set_t *records)
{
    if (!image || !records)
        return BSD_LINKER_ERR_INVALID;
    *records = image->records;
    return 0;
}

const void *
bsd_linker_image_base(const bsd_linker_image_t *image)
{
    return image;
}

size_t
bsd_test_linker_image_release_count(void)
{
    return g_release_count;
}
