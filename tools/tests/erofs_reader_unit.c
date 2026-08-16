/* SPDX-License-Identifier: MPL-2.0 */
/* Host-side EROFS reader test against a real image. */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fs/erofs/erofs_reader.h"
#include "fs/erofs/lz4_decode.h"

uint64_t block_device_size_bytes(const block_device_t *device) {
    return device ? (uint64_t)device->sector_size * device->sector_count : 0;
}

int64_t block_read_bytes(block_device_t *device, uint64_t offset, void *buffer,
                         uint32_t length) {
    FILE *image;

    if (!device || !device->ctx || !buffer) return -1;
    image = device->ctx;
    if (fseeko(image, (off_t)offset, SEEK_SET) != 0) return -1;
    return (int64_t)fread(buffer, 1u, length, image);
}

static void load_path(edge_erofs_reader_t *reader, const char *path,
                      edge_erofs_inode_t *inode) {
    edge_erofs_inode_t current;
    char component[256];
    const char *cursor = path;

    assert(edge_erofs_inode_load(reader, reader->root_nid, &current) == 0);
    while (*cursor == '/') ++cursor;
    while (*cursor) {
        uint32_t length = 0;
        uint64_t nid;
        while (cursor[length] && cursor[length] != '/') ++length;
        assert(length > 0 && length < sizeof(component));
        memcpy(component, cursor, length);
        component[length] = 0;
        assert(edge_erofs_directory_lookup(
            reader, &current, component, &nid) == 0);
        assert(edge_erofs_inode_load(reader, nid, &current) == 0);
        cursor += length;
        while (*cursor == '/') ++cursor;
    }
    *inode = current;
}

static uint8_t mixed_expected(uint32_t offset) {
    static const char prefix[] = "EdgeOS compressed extent validation. ";
    static const char suffix[] = "Shared x86_64 arm64 EROFS reader. ";

    if (offset < 98304u)
        return (uint8_t)prefix[offset % (sizeof(prefix) - 1u)];
    if (offset < 98304u + 65536u) {
        uint32_t index = offset - 98304u;
        return (uint8_t)(((index * 73u + (index >> 3) * 19u) ^
                          ((index * 13u) >> 7)) & 0xffu);
    }
    offset -= 98304u + 65536u;
    return (uint8_t)suffix[offset % (sizeof(suffix) - 1u)];
}

int main(int argc, char **argv) {
    block_device_t device;
    edge_erofs_reader_t reader;
    edge_erofs_inode_t inode;
    edge_erofs_directory_entry_t entry;
    FILE *image;
    long image_size;
    char buffer[256];
    uint8_t *compressed_workspace = NULL;
    uint8_t *history_workspace = NULL;
    int xattr_size;
    int found_marker = 0;
    int found_payload = 0;

    assert(argc == 2);
    image = fopen(argv[1], "rb");
    assert(image != NULL);
    assert(fseeko(image, 0, SEEK_END) == 0);
    image_size = ftello(image);
    assert(image_size > 0 && (uint64_t)image_size <= UINT32_MAX);
    memset(&device, 0, sizeof(device));
    device.present = 1;
    device.sector_size = 1u;
    device.sector_count = (uint32_t)image_size;
    device.ctx = image;

    assert(edge_erofs_reader_init(&reader, &device) == 0);
    if (reader.compression_algorithms) {
        size_t compressed_size =
            (size_t)reader.maximum_pcluster_blocks * reader.block_size;
        compressed_workspace = malloc(compressed_size);
        history_workspace = malloc(EDGE_LZ4_HISTORY_SIZE);
        assert(compressed_workspace != NULL && history_workspace != NULL);
        assert(edge_erofs_reader_set_compression_workspace(
            &reader, compressed_workspace, (uint32_t)compressed_size,
            history_workspace, EDGE_LZ4_HISTORY_SIZE) == 0);
    }
    assert(reader.block_size == 4096u);
    assert(edge_erofs_inode_load(&reader, reader.root_nid, &inode) == 0);
    assert((inode.mode & 0xf000u) == 0x4000u);
    for (uint32_t index = 0;; ++index) {
        int result = edge_erofs_directory_entry(
            &reader, &inode, index, &entry);
        if (result == -2) break;
        assert(result == 0);
        if (strcmp(entry.name, "marker.txt") == 0) found_marker = 1;
        if (strcmp(entry.name, "payload") == 0) found_payload = 1;
    }
    assert(found_marker && found_payload);

    load_path(&reader, "/marker.txt", &inode);
    memset(buffer, 0, sizeof(buffer));
    assert(edge_erofs_inode_read(
        &reader, &inode, 0, buffer, sizeof(buffer)) == 21);
    assert(strcmp(buffer, "edgeos-erofs-runtime\n") == 0);
    xattr_size = edge_erofs_getxattr(
        &reader, &inode, "user.edgeos", buffer, sizeof(buffer));
    assert(xattr_size == 8);
    assert(memcmp(buffer, "verified", 8u) == 0);

    load_path(&reader, "/marker-link", &inode);
    memset(buffer, 0, sizeof(buffer));
    assert(edge_erofs_inode_read(
        &reader, &inode, 0, buffer, sizeof(buffer) - 1u) == 10);
    assert(strcmp(buffer, "marker.txt") == 0);

    load_path(&reader, "/payload/large-zero.bin", &inode);
    memset(buffer, 0xff, sizeof(buffer));
    assert(edge_erofs_inode_read(
        &reader, &inode, 4080u, buffer, sizeof(buffer)) == sizeof(buffer));
    for (uint32_t index = 0; index < sizeof(buffer); ++index)
        assert(buffer[index] == 0);

    load_path(&reader, "/payload/nested/value.txt", &inode);
    memset(buffer, 0, sizeof(buffer));
    assert(edge_erofs_inode_read(
        &reader, &inode, 0, buffer, sizeof(buffer)) == 13);
    assert(strcmp(buffer, "nested-value\n") == 0);

    if (reader.compression_algorithms) {
        static const uint32_t offsets[] = {
            0u, 4080u, 65520u, 98280u, 98304u, 130000u,
            163824u, 200000u, 294656u
        };
        load_path(&reader, "/payload/mixed.bin", &inode);
        assert(inode.size == 294912u);
        for (uint32_t sample = 0;
             sample < sizeof(offsets) / sizeof(offsets[0]); ++sample) {
            memset(buffer, 0, sizeof(buffer));
            assert(edge_erofs_inode_read(
                &reader, &inode, offsets[sample], buffer,
                sizeof(buffer)) == sizeof(buffer));
            for (uint32_t index = 0; index < sizeof(buffer); ++index) {
                uint8_t expected = mixed_expected(offsets[sample] + index);
                if ((uint8_t)buffer[index] != expected)
                    fprintf(stderr,
                        "mixed data mismatch at %u: got %u expected %u\n",
                        offsets[sample] + index,
                        (uint8_t)buffer[index], expected);
                assert((uint8_t)buffer[index] == expected);
            }
        }
    }

    free(history_workspace);
    free(compressed_workspace);
    fclose(image);
    puts("erofs_reader_unit: PASS");
    return 0;
}
