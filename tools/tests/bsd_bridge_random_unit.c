/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the BSD random-source adapter. */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/random.h"
#include "compat/freebsd/sys/random.h"
#include "compat/freebsd/dev/random/randomdev.h"

unsigned long random(void);

static unsigned int
test_read(void *buffer, unsigned int length)
{
    uint8_t *bytes = buffer;

    if (length > 7)
        length = 7;
    for (unsigned int index = 0; index < length; ++index)
        bytes[index] = (uint8_t)(0xa0U + index);
    return length;
}

int
main(void)
{
    static const struct random_source source = {
        .rs_ident = "test source",
        .rs_source = RANDOM_PURE_VIRTIO,
        .rs_read = test_read,
    };
    uint8_t output[20] = { 0 };

    assert(bsd_random_fill(output, sizeof(output)) == 0);
    random_source_register(&source);
    assert(bsd_random_fill(output, sizeof(output)) == sizeof(output));
    for (size_t index = 0; index < sizeof(output); ++index)
        assert(output[index] == (uint8_t)(0xa0U + (index % 7)));
    assert(random() <= UINT32_C(0x7fffffff));
    read_random(output, sizeof(output));
    for (size_t index = 0; index < sizeof(output); ++index)
        assert(output[index] == (uint8_t)(0xa0U + (index % 7)));
    arc4random_buf(output, sizeof(output));
    for (size_t index = 0; index < sizeof(output); ++index)
        assert(output[index] == (uint8_t)(0xa0U + (index % 7)));
    random_source_deregister(&source);
    assert(bsd_random_fill(output, sizeof(output)) == 0);
    return 0;
}
