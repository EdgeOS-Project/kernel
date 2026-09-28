/* SPDX-License-Identifier: MPL-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "fs/ext4_acl.h"

/* The compact ACL returned from the Ubuntu journal directory. */
static const uint8_t journal_disk[] = {
    1,0,0,0, 1,0,7,0, 4,0,5,0, 8,0,5,0,4,0,0,0, 16,0,5,0, 32,0,5,0
};
static const uint8_t journal_xattr[] = {
    2,0,0,0,
    1,0,7,0,255,255,255,255,
    4,0,5,0,255,255,255,255,
    8,0,5,0,4,0,0,0,
    16,0,5,0,255,255,255,255,
    32,0,5,0,255,255,255,255
};
static const uint8_t minimal_disk[] = {
    1,0,0,0, 1,0,7,0, 4,0,5,0, 32,0,1,0
};
static const uint8_t minimal_xattr[] = {
    2,0,0,0, 1,0,7,0,255,255,255,255,
    4,0,5,0,255,255,255,255, 32,0,1,0,255,255,255,255
};

static void assert_untouched(const uint8_t *bytes, size_t size) {
    for (size_t index = 0; index < size; ++index) assert(bytes[index] == 0xa5);
}

static void roundtrip(const uint8_t *disk, uint32_t disk_size,
                      const uint8_t *xattr, uint32_t xattr_size) {
    uint8_t encoded[128], decoded[128], unaligned[129];
    assert(edge_ext4_acl_from_disk(disk, disk_size, NULL, 0) == (int)xattr_size);
    assert(edge_ext4_acl_to_disk(xattr, xattr_size, NULL, 0) == (int)disk_size);
    assert(edge_ext4_acl_from_disk(disk, disk_size, decoded, sizeof(decoded)) == (int)xattr_size);
    assert(memcmp(decoded, xattr, xattr_size) == 0);
    assert(edge_ext4_acl_to_disk(xattr, xattr_size, encoded, sizeof(encoded)) == (int)disk_size);
    assert(memcmp(encoded, disk, disk_size) == 0);
    memcpy(unaligned + 1, disk, disk_size);
    assert(edge_ext4_acl_from_disk(unaligned + 1, disk_size, decoded, sizeof(decoded)) == (int)xattr_size);
    assert(memcmp(decoded, xattr, xattr_size) == 0);
    memset(decoded, 0xa5, sizeof(decoded));
    assert(edge_ext4_acl_from_disk(disk, disk_size, decoded, xattr_size - 1u) == EDGE_EXT4_ACL_RANGE);
    assert_untouched(decoded, sizeof(decoded));
    memset(encoded, 0xa5, sizeof(encoded));
    assert(edge_ext4_acl_to_disk(xattr, xattr_size, encoded, disk_size - 1u) == EDGE_EXT4_ACL_RANGE);
    assert_untouched(encoded, sizeof(encoded));
}

static void invalid(const void *value, uint32_t size, int disk) {
    uint8_t output[128];
    memset(output, 0xa5, sizeof(output));
    int result = disk ? edge_ext4_acl_from_disk(value, size, output, sizeof(output)) :
                        edge_ext4_acl_to_disk(value, size, output, sizeof(output));
    assert(result == EDGE_EXT4_ACL_INVALID);
    assert_untouched(output, sizeof(output));
}

static void test_invalid(void) {
    uint8_t data[sizeof(journal_xattr) + 1u];
    invalid(NULL, 0, 1);
    for (uint32_t size = 0; size < 4u; ++size) invalid(journal_disk, size, 1);
    /* Every nonempty prefix is incomplete; the four-byte header means no ACL. */
    for (uint32_t size = 5u; size < sizeof(journal_disk); ++size)
        invalid(journal_disk, size, 1);
    for (uint32_t size = 5u; size < sizeof(journal_xattr); ++size)
        invalid(journal_xattr, size, 0);
    memcpy(data, journal_xattr, sizeof(journal_xattr));
    data[0] = 3; invalid(data, sizeof(journal_xattr), 0);
    data[0] = 2; data[6] = 8; invalid(data, sizeof(journal_xattr), 0);
    memcpy(data, journal_xattr, sizeof(journal_xattr));
    data[12] = 1; invalid(data, sizeof(journal_xattr), 0); /* Repeated owner. */
    memcpy(data, journal_xattr, sizeof(journal_xattr));
    data[4] = 64; invalid(data, sizeof(journal_xattr), 0);
    memcpy(data, journal_xattr, sizeof(journal_xattr));
    memset(data + 24, 255, 4); invalid(data, sizeof(journal_xattr), 0);
    memcpy(data, journal_xattr, sizeof(journal_xattr));
    data[sizeof(journal_xattr)] = 0; invalid(data, sizeof(data), 0);
    /* A named group requires a mask; removing it must not weaken permissions. */
    memcpy(data, journal_xattr, 28);
    memcpy(data + 28, journal_xattr + 36, 8);
    invalid(data, 36, 0);
}

static void test_named_users_and_legacy(void) {
    const uint8_t disk[] = {
        1,0,0,0, 1,0,7,0,
        2,0,0,0,232,3,0,0,
        2,0,4,0,254,255,255,255,
        4,0,5,0, 16,0,5,0, 32,0,1,0
    };
    const uint8_t xattr[] = {
        2,0,0,0, 1,0,7,0,255,255,255,255,
        2,0,0,0,232,3,0,0,
        2,0,4,0,254,255,255,255,
        4,0,5,0,255,255,255,255,
        16,0,5,0,255,255,255,255,
        32,0,1,0,255,255,255,255
    };
    uint8_t decoded[128], duplicate[sizeof(xattr)];
    roundtrip(disk, sizeof(disk), xattr, sizeof(xattr));
    assert(edge_ext4_acl_from_disk(xattr, sizeof(xattr), decoded, sizeof(decoded)) == sizeof(xattr));
    assert(memcmp(decoded, xattr, sizeof(xattr)) == 0);
    /* Linux's tag validator does not impose a named-ID uniqueness rule. */
    memcpy(duplicate, xattr, sizeof(xattr));
    memcpy(duplicate + 24, duplicate + 16, 4);
    assert(edge_ext4_acl_to_disk(duplicate, sizeof(duplicate), decoded, sizeof(decoded)) == sizeof(disk));
}

int main(void) {
    uint8_t header[4];
    const uint8_t empty_disk[] = {1,0,0,0}, empty_xattr[] = {2,0,0,0};
    roundtrip(journal_disk, sizeof(journal_disk), journal_xattr, sizeof(journal_xattr));
    roundtrip(minimal_disk, sizeof(minimal_disk), minimal_xattr, sizeof(minimal_xattr));
    test_invalid();
    test_named_users_and_legacy();
    assert(edge_ext4_acl_from_disk(empty_disk, 4, header, 4) == 4);
    assert(memcmp(header, empty_xattr, 4) == 0);
    assert(edge_ext4_acl_to_disk(empty_xattr, 4, header, 4) == 4);
    assert(memcmp(header, empty_disk, 4) == 0);
    puts("ext4_acl_codec_unit: PASS");
    return 0;
}
