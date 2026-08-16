/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include <sys/bitstring.h>

static void
test_ranges(void)
{
    bitstr_t bits[bitstr_size(130) / sizeof(bitstr_t)] = {0};
    int result;

    bit_nset(bits, 3, 6);
    bit_nset(bits, 63, 68);
    bit_nset(bits, 127, 129);
    assert(bit_ntest(bits, 3, 6, 1));
    assert(bit_ntest(bits, 7, 62, 0));

    bit_ffs_area(bits, 130, 4, &result);
    assert(result == 3);
    bit_ffs_area_at(bits, 7, 130, 6, &result);
    assert(result == 63);
    bit_ffs_area_at(bits, 69, 130, 4, &result);
    assert(result == -1);

    bit_ffc_area(bits, 130, 12, &result);
    assert(result == 7);
    bit_ffc_area_at(bits, 60, 130, 58, &result);
    assert(result == 69);
    bit_ffc_area_at(bits, 70, 130, 57, &result);
    assert(result == 70);
    bit_ffc_area_at(bits, 71, 130, 60, &result);
    assert(result == -1);

    bit_count(bits, 0, 130, &result);
    assert(result == 13);
    bit_count(bits, 64, 130, &result);
    assert(result == 8);
    bit_count(bits, 130, 130, &result);
    assert(result == 0);

    bit_nclear(bits, 63, 68);
    bit_count(bits, 0, 130, &result);
    assert(result == 7);
}

static void
test_fixed_width_mask(void)
{
    uint32_t mask = UINT32_C(0x80010021);
    int bit;
    int expected[] = {0, 5, 16, 31};
    size_t index = 0;

    bit_foreach((bitstr_t *)(void *)&mask, 32, bit) {
        assert(index < sizeof(expected) / sizeof(expected[0]));
        assert(bit == expected[index]);
        ++index;
    }
    assert(index == sizeof(expected) / sizeof(expected[0]));
}

int
main(void)
{
    test_ranges();
    test_fixed_width_mask();
    puts("bsd_bridge_bitstring_unit: PASS");
    return 0;
}
