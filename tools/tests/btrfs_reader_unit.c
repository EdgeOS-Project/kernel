/* SPDX-License-Identifier: MPL-2.0 */
/* Host-side Btrfs reader test against a real mkfs.btrfs image. */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fs/btrfs/btrfs_reader.h"

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

static void load_path(edge_btrfs_reader_t *reader, const char *path,
                      edge_btrfs_inode_t *inode) {
    edge_btrfs_inode_t current;
    char component[256];
    const char *cursor = path;

    assert(edge_btrfs_inode_load(
        reader, EDGE_BTRFS_ROOT_INODE, &current) == 0);
    while (*cursor == '/') ++cursor;
    while (*cursor) {
        uint32_t length = 0;
        uint64_t inode_number;
        while (cursor[length] && cursor[length] != '/') ++length;
        assert(length > 0 && length < sizeof(component));
        memcpy(component, cursor, length);
        component[length] = 0;
        assert(edge_btrfs_directory_lookup(
            reader, &current, component, &inode_number) == 0);
        assert(edge_btrfs_inode_load(reader, inode_number, &current) == 0);
        cursor += length;
        while (*cursor == '/') ++cursor;
    }
    *inode = current;
}

int main(int argc, char **argv) {
    block_device_t device;
    edge_btrfs_reader_t reader;
    edge_btrfs_inode_t inode;
    edge_btrfs_directory_entry_t entry;
    FILE *image;
    off_t image_size;
    char buffer[256];
    int found_marker = 0;
    int found_nested = 0;

    assert(argc == 2);
    image = fopen(argv[1], "rb");
    assert(image != NULL);
    assert(fseeko(image, 0, SEEK_END) == 0);
    image_size = ftello(image);
    assert(image_size > 0 && (uint64_t)image_size / 512u <= UINT32_MAX);
    memset(&device, 0, sizeof(device));
    device.present = 1;
    device.sector_size = 512u;
    device.sector_count = (uint32_t)((uint64_t)image_size / 512u);
    device.ctx = image;

    {
        int result = edge_btrfs_reader_init(&reader, &device);
        if (result != 0) fprintf(stderr, "Btrfs init failed: %d\n", result);
        assert(result == 0);
    }
    assert(reader.node_size >= 4096u && reader.node_size <= 65536u);
    assert(edge_btrfs_inode_load(
        &reader, EDGE_BTRFS_ROOT_INODE, &inode) == 0);
    assert((inode.mode & 0xf000u) == 0x4000u);
    for (uint32_t index = 0;; ++index) {
        int result = edge_btrfs_directory_entry(
            &reader, &inode, index, &entry);
        if (result == -2) break;
        assert(result == 0);
        if (strcmp(entry.name, "marker.txt") == 0) found_marker = 1;
        if (strcmp(entry.name, "nested") == 0) found_nested = 1;
    }
    assert(found_marker && found_nested);

    load_path(&reader, "/marker.txt", &inode);
    memset(buffer, 0, sizeof(buffer));
    assert(edge_btrfs_inode_read(
        &reader, &inode, 0, buffer, sizeof(buffer)) == 21);
    assert(strcmp(buffer, "edgeos-btrfs-runtime\n") == 0);

    load_path(&reader, "/nested/data.txt", &inode);
    memset(buffer, 0, sizeof(buffer));
    assert(edge_btrfs_inode_read(
        &reader, &inode, 0, buffer, sizeof(buffer)) == 12);
    assert(strcmp(buffer, "nested-data\n") == 0);

    load_path(&reader, "/marker-link", &inode);
    memset(buffer, 0, sizeof(buffer));
    assert(edge_btrfs_inode_read(
        &reader, &inode, 0, buffer, sizeof(buffer) - 1u) == 10);
    assert(strcmp(buffer, "marker.txt") == 0);

    load_path(&reader, "/sparse.bin", &inode);
    memset(buffer, 0xff, sizeof(buffer));
    assert(edge_btrfs_inode_read(
        &reader, &inode, 524288u, buffer, sizeof(buffer)) == sizeof(buffer));
    for (uint32_t index = 0; index < sizeof(buffer); ++index)
        assert(buffer[index] == 0);
    memset(buffer, 0, sizeof(buffer));
    assert(edge_btrfs_inode_read(
        &reader, &inode, 1048567u, buffer, 9u) == 9);
    assert(memcmp(buffer, "tail-data", 9u) == 0);

    load_path(&reader, "/large-dir/entry-119.txt", &inode);
    memset(buffer, 0, sizeof(buffer));
    assert(edge_btrfs_inode_read(
        &reader, &inode, 0, buffer, sizeof(buffer)) == 15);
    assert(strcmp(buffer, "entry-119-data\n") == 0);

    fclose(image);
    puts("btrfs_reader_unit: PASS");
    return 0;
}
