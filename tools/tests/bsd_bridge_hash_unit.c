/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the EdgeOS BSD Driver Bridge hash-table allocator. */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/hash.h"
#include "compat/freebsd/edgeos/malloc.h"

#define TEST_PAGE_SIZE 4096U

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    void *memory = NULL;

    (void)context;
    if (page_count > SIZE_MAX / TEST_PAGE_SIZE)
        return NULL;
    if (posix_memalign(&memory, TEST_PAGE_SIZE,
        (size_t)page_count * TEST_PAGE_SIZE) != 0)
        return NULL;
    memset(memory, 0xa5, (size_t)page_count * TEST_PAGE_SIZE);
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)page_count;
    (void)context;
    free(base);
}

static void
test_power_of_two_table(void)
{
    void **table;
    unsigned long mask = 0;

    table = hashinit(33, M_TEMP, &mask);
    assert(table != NULL);
    assert(mask == 31);
    for (unsigned long index = 0; index <= mask; ++index)
        assert(table[index] == NULL);
    hashdestroy(table, M_TEMP, mask);

    table = hashinit_flags(1, M_TEMP, &mask, HASH_NOWAIT);
    assert(table != NULL);
    assert(mask == 0);
    assert(table[0] == NULL);
    hashdestroy(table, M_TEMP, mask);
    hashdestroy(NULL, M_TEMP, 0);
}

static void
test_prime_table(void)
{
    void **table;
    unsigned long entries = 0;

    table = phashinit(1000, M_TEMP, &entries);
    assert(table != NULL);
    assert(entries == 761);
    for (unsigned long index = 0; index < entries; ++index)
        assert(table[index] == NULL);
    bsd_free(table, M_TEMP);

    table = phashinit_flags(40000, M_TEMP, &entries, HASH_NOWAIT);
    assert(table != NULL);
    assert(entries == 32749);
    bsd_free(table, M_TEMP);
}

int
main(void)
{
    bsd_allocator_ops_t ops = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };

    assert(bsd_allocator_initialize(&ops) == 0);
    test_power_of_two_table();
    test_prime_table();
    assert(M_TEMP->bytes_allocated == M_TEMP->bytes_freed);
    return 0;
}
