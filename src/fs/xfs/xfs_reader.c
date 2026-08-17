/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-neutral XFS v5 read-only metadata and data reader. */

#include <stdint.h>

#include "xfs_format.h"
#include "xfs_reader.h"
#ifdef EDGEOS_XFS_HOST_TEST
#include <string.h>
#else
#include "string.h"
#endif

#define EDGE_XFS_MIN_BLOCK_LOG 9u
#define EDGE_XFS_MAX_BLOCK_LOG 16u
#define EDGE_XFS_MAX_BTREE_DEPTH 16u

typedef struct edge_xfs_extent {
    uint64_t logical_block;
    uint64_t physical_block;
    uint32_t block_count;
    uint8_t unwritten;
} edge_xfs_extent_t;

static uint16_t edge_xfs_be16(const void *pointer) {
    const uint8_t *bytes = pointer;
    return ((uint16_t)bytes[0] << 8) | bytes[1];
}

static uint32_t edge_xfs_be32(const void *pointer) {
    const uint8_t *bytes = pointer;
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static uint64_t edge_xfs_be64(const void *pointer) {
    const uint8_t *bytes = pointer;
    return ((uint64_t)edge_xfs_be32(bytes) << 32) |
           edge_xfs_be32(bytes + 4);
}

static int edge_xfs_range_valid(const edge_xfs_reader_t *reader,
                                uint64_t offset, uint64_t length) {
    return reader && offset <= reader->device_bytes &&
           length <= reader->device_bytes - offset;
}

static int edge_xfs_read(const edge_xfs_reader_t *reader, uint64_t offset,
                         void *buffer, uint32_t length) {
    int64_t result;

    if (!reader || (!buffer && length) ||
        !edge_xfs_range_valid(reader, offset, length))
        return -1;
    if (!length) return 0;
    result = block_read_bytes(reader->device, offset, buffer, length);
    return result == (int64_t)length ? 0 : -1;
}

static int64_t edge_xfs_timestamp(const uint8_t *seconds,
                                  const uint8_t *nanoseconds,
                                  uint64_t flags2) {
    uint32_t high = edge_xfs_be32(seconds);
    uint32_t low = edge_xfs_be32(nanoseconds);

    if (flags2 & EDGE_XFS_DIFLAG2_BIGTIME) {
        uint64_t packed = ((uint64_t)high << 32) | low;
        return (int64_t)(packed >> 30) - 2147483648ll;
    }
    return (int64_t)(int32_t)high;
}

int edge_xfs_reader_init(edge_xfs_reader_t *reader, block_device_t *device) {
    uint8_t superblock[264];
    uint16_t version;
    uint64_t filesystem_bytes;

    if (!reader || !device) return -1;
    memset(reader, 0, sizeof(*reader));
    reader->device = device;
    reader->device_bytes = block_device_size_bytes(device);
    if (reader->device_bytes < sizeof(superblock) ||
        edge_xfs_read(reader, 0, superblock, sizeof(superblock)) < 0 ||
        edge_xfs_be32(superblock) != EDGE_XFS_SUPER_MAGIC)
        return -1;

    reader->block_size = edge_xfs_be32(superblock + 4);
    reader->data_blocks = edge_xfs_be64(superblock + 8);
    reader->root_inode = edge_xfs_be64(superblock + 56);
    reader->allocation_group_blocks = edge_xfs_be32(superblock + 84);
    reader->allocation_group_count = edge_xfs_be32(superblock + 88);
    version = edge_xfs_be16(superblock + 100);
    reader->inode_size = edge_xfs_be16(superblock + 104);
    reader->inodes_per_block = edge_xfs_be16(superblock + 106);
    reader->block_log = superblock[120];
    reader->inode_log = superblock[122];
    reader->inodes_per_block_log = superblock[123];
    reader->allocation_group_block_log = superblock[124];
    reader->directory_block_log = superblock[192];
    reader->inode_count = edge_xfs_be64(superblock + 128);
    reader->free_data_blocks = edge_xfs_be64(superblock + 144);
    reader->feature_ro_compat = edge_xfs_be32(superblock + 212);
    reader->feature_incompat = edge_xfs_be32(superblock + 216);
    reader->has_file_type = !!(reader->feature_incompat &
                               EDGE_XFS_FEAT_INCOMPAT_FTYPE);

    if ((version & EDGE_XFS_SB_VERSION_NUMBITS) != EDGE_XFS_SB_VERSION_5 ||
        reader->block_log < EDGE_XFS_MIN_BLOCK_LOG ||
        reader->block_log > EDGE_XFS_MAX_BLOCK_LOG ||
        reader->block_size != (1u << reader->block_log) ||
        reader->inode_log < 8u || reader->inode_log > reader->block_log ||
        reader->inode_size != (1u << reader->inode_log) ||
        reader->inodes_per_block !=
            (1u << reader->inodes_per_block_log) ||
        reader->allocation_group_block_log >= 32u ||
        !reader->allocation_group_blocks ||
        !reader->allocation_group_count || !reader->root_inode ||
        (reader->feature_ro_compat & ~EDGE_XFS_FEAT_RO_KNOWN) ||
        (reader->feature_incompat & ~EDGE_XFS_FEAT_INCOMPAT_KNOWN) ||
        (reader->feature_incompat & EDGE_XFS_FEAT_INCOMPAT_NEEDSREPAIR))
        return -1;
    if (reader->directory_block_log > 4u) return -1;
    reader->directory_block_size =
        reader->block_size << reader->directory_block_log;
    filesystem_bytes = reader->data_blocks * (uint64_t)reader->block_size;
    if (reader->data_blocks > UINT64_MAX / reader->block_size ||
        filesystem_bytes > reader->device_bytes)
        return -1;
    return 0;
}

static int edge_xfs_inode_offset(const edge_xfs_reader_t *reader,
                                 uint64_t inode_number, uint64_t *offset) {
    uint32_t shift;
    uint64_t allocation_group;
    uint64_t allocation_group_inode;
    uint64_t allocation_group_block;
    uint64_t inode_index;
    uint64_t filesystem_block;

    if (!reader || !offset) return -1;
    shift = reader->allocation_group_block_log +
            reader->inodes_per_block_log;
    if (shift >= 63u) return -1;
    allocation_group = inode_number >> shift;
    allocation_group_inode = inode_number & ((1ull << shift) - 1ull);
    allocation_group_block = allocation_group_inode >>
                             reader->inodes_per_block_log;
    inode_index = allocation_group_inode &
                  ((1ull << reader->inodes_per_block_log) - 1ull);
    if (allocation_group >= reader->allocation_group_count ||
        allocation_group_block >= reader->allocation_group_blocks)
        return -1;
    filesystem_block = allocation_group * reader->allocation_group_blocks +
                       allocation_group_block;
    *offset = filesystem_block * reader->block_size +
              inode_index * reader->inode_size;
    return edge_xfs_range_valid(reader, *offset, reader->inode_size) ? 0 : -1;
}

int edge_xfs_inode_load(edge_xfs_reader_t *reader, uint64_t inode_number,
                        edge_xfs_inode_t *inode) {
    uint8_t core[EDGE_XFS_DINODE_V3_CORE_SIZE];
    uint64_t offset;
    uint64_t flags2;
    uint16_t core_size;
    uint16_t fork_bytes;

    if (!reader || !inode ||
        edge_xfs_inode_offset(reader, inode_number, &offset) < 0 ||
        edge_xfs_read(reader, offset, core, sizeof(core)) < 0 ||
        edge_xfs_be16(core) != EDGE_XFS_INODE_MAGIC)
        return -1;
    core_size = core[4] == 3u ? EDGE_XFS_DINODE_V3_CORE_SIZE :
                               EDGE_XFS_DINODE_V2_CORE_SIZE;
    if ((core[4] != 2u && core[4] != 3u) ||
        reader->inode_size < core_size)
        return -1;
    flags2 = core[4] == 3u ? edge_xfs_be64(core + 120) : 0;
    fork_bytes = core[82] ? (uint16_t)((uint16_t)core[82] * 8u) :
                            (uint16_t)(reader->inode_size - core_size);
    if (fork_bytes > reader->inode_size - core_size)
        return -1;

    memset(inode, 0, sizeof(*inode));
    inode->number = inode_number;
    inode->disk_offset = offset;
    inode->mode = edge_xfs_be16(core + 2);
    inode->version = core[4];
    inode->format = core[5];
    inode->uid = edge_xfs_be32(core + 8);
    inode->gid = edge_xfs_be32(core + 12);
    inode->link_count = edge_xfs_be32(core + 16);
    inode->size = edge_xfs_be64(core + 56);
    inode->blocks = edge_xfs_be64(core + 64);
    inode->extent_count = (flags2 & EDGE_XFS_DIFLAG2_NREXT64) ?
        edge_xfs_be64(core + 24) : edge_xfs_be32(core + 76);
    inode->fork_offset = core[82];
    inode->generation = edge_xfs_be32(core + 92);
    inode->flags2 = flags2;
    inode->core_size = core_size;
    inode->data_fork_size = fork_bytes;
    inode->atime = edge_xfs_timestamp(core + 32, core + 36, flags2);
    inode->mtime = edge_xfs_timestamp(core + 40, core + 44, flags2);
    inode->ctime = edge_xfs_timestamp(core + 48, core + 52, flags2);
    if (inode->format > EDGE_XFS_DINODE_FMT_BTREE ||
        inode->size > INT64_MAX ||
        (inode->format == EDGE_XFS_DINODE_FMT_LOCAL &&
         inode->size > inode->data_fork_size) ||
        (inode->format == EDGE_XFS_DINODE_FMT_EXTENTS &&
         inode->extent_count > inode->data_fork_size /
                               EDGE_XFS_BMBT_EXTENT_SIZE))
        return -1;
    return 0;
}

static void edge_xfs_extent_decode(const uint8_t *record,
                                   edge_xfs_extent_t *extent) {
    uint64_t word0 = edge_xfs_be64(record);
    uint64_t word1 = edge_xfs_be64(record + 8);

    extent->unwritten = (uint8_t)(word0 >> 63);
    extent->logical_block = (word0 & 0x7fffffffffffffffull) >> 9;
    extent->physical_block = ((word0 & 0x1ffull) << 43) | (word1 >> 21);
    extent->block_count = (uint32_t)(word1 &
                                     EDGE_XFS_BMBT_BLOCK_COUNT_MASK);
}

static int edge_xfs_extent_contains(const edge_xfs_extent_t *extent,
                                    uint64_t logical_block) {
    return extent && extent->block_count &&
           logical_block >= extent->logical_block &&
           logical_block - extent->logical_block < extent->block_count;
}

static int edge_xfs_direct_extent(edge_xfs_reader_t *reader,
                                  const edge_xfs_inode_t *inode,
                                  uint64_t logical_block,
                                  edge_xfs_extent_t *extent) {
    uint8_t record[EDGE_XFS_BMBT_EXTENT_SIZE];
    uint64_t base = inode->disk_offset + inode->core_size;

    for (uint64_t index = 0; index < inode->extent_count; ++index) {
        if (edge_xfs_read(reader,
                base + index * EDGE_XFS_BMBT_EXTENT_SIZE,
                record, sizeof(record)) < 0)
            return -1;
        edge_xfs_extent_decode(record, extent);
        if (edge_xfs_extent_contains(extent, logical_block)) return 0;
        if (extent->logical_block > logical_block) break;
    }
    return -2;
}

static int edge_xfs_btree_extent(edge_xfs_reader_t *reader,
                                 const edge_xfs_inode_t *inode,
                                 uint64_t logical_block,
                                 edge_xfs_extent_t *extent) {
    uint8_t header[72];
    uint8_t record[16];
    uint64_t location = inode->disk_offset + inode->core_size;
    uint32_t size = inode->data_fork_size;
    int embedded = 1;

    for (uint32_t depth = 0; depth < EDGE_XFS_MAX_BTREE_DEPTH; ++depth) {
        uint16_t level;
        uint16_t records;
        uint32_t header_size;
        uint32_t maximum_records;

        if (embedded) {
            if (edge_xfs_read(reader, location, header, 4u) < 0) return -1;
            level = edge_xfs_be16(header);
            records = edge_xfs_be16(header + 2);
            header_size = 4u;
        } else {
            uint32_t magic;
            if (edge_xfs_read(reader, location, header, sizeof(header)) < 0)
                return -1;
            magic = edge_xfs_be32(header);
            if (magic != EDGE_XFS_BMAP_CRC_MAGIC &&
                magic != EDGE_XFS_BMAP_MAGIC)
                return -1;
            level = edge_xfs_be16(header + 4);
            records = edge_xfs_be16(header + 6);
            header_size = magic == EDGE_XFS_BMAP_CRC_MAGIC ? 72u : 24u;
        }
        maximum_records = (size - header_size) / 16u;
        if (!records || records > maximum_records) return -1;
        if (!level) {
            for (uint32_t index = 0; index < records; ++index) {
                if (edge_xfs_read(reader,
                        location + header_size + (uint64_t)index * 16u,
                        record, sizeof(record)) < 0)
                    return -1;
                edge_xfs_extent_decode(record, extent);
                if (edge_xfs_extent_contains(extent, logical_block)) return 0;
                if (extent->logical_block > logical_block) break;
            }
            return -2;
        }
        {
            uint32_t selected = 0;
            uint64_t key;
            uint64_t pointer;
            int found = 0;

            for (uint32_t index = 0; index < records; ++index) {
                if (edge_xfs_read(reader,
                        location + header_size + (uint64_t)index * 8u,
                        record, 8u) < 0)
                    return -1;
                key = edge_xfs_be64(record);
                if (key > logical_block) break;
                selected = index;
                found = 1;
            }
            if (!found) return -2;
            if (edge_xfs_read(reader,
                    location + header_size + (uint64_t)maximum_records * 8u +
                    (uint64_t)selected * 8u, record, 8u) < 0)
                return -1;
            pointer = edge_xfs_be64(record);
            if (!pointer || pointer >= reader->data_blocks) return -1;
            location = pointer * reader->block_size;
            size = reader->block_size;
            embedded = 0;
        }
    }
    return -1;
}

static int edge_xfs_find_extent(edge_xfs_reader_t *reader,
                                const edge_xfs_inode_t *inode,
                                uint64_t logical_block,
                                edge_xfs_extent_t *extent) {
    if (inode->format == EDGE_XFS_DINODE_FMT_EXTENTS)
        return edge_xfs_direct_extent(reader, inode, logical_block, extent);
    if (inode->format == EDGE_XFS_DINODE_FMT_BTREE)
        return edge_xfs_btree_extent(reader, inode, logical_block, extent);
    return -2;
}

int64_t edge_xfs_inode_read(edge_xfs_reader_t *reader,
                            const edge_xfs_inode_t *inode,
                            uint64_t offset, void *buffer, uint32_t length) {
    uint8_t *output = buffer;
    uint32_t completed = 0;

    if (!reader || !inode || (!buffer && length)) return -1;
    if (offset >= inode->size) return 0;
    if (length > inode->size - offset)
        length = (uint32_t)(inode->size - offset);
    if (inode->format == EDGE_XFS_DINODE_FMT_LOCAL) {
        if (offset > inode->data_fork_size ||
            length > inode->data_fork_size - offset ||
            edge_xfs_read(reader,
                inode->disk_offset + inode->core_size + offset,
                output, length) < 0)
            return -1;
        return length;
    }
    if (inode->format != EDGE_XFS_DINODE_FMT_EXTENTS &&
        inode->format != EDGE_XFS_DINODE_FMT_BTREE)
        return -1;
    while (completed < length) {
        edge_xfs_extent_t extent = {0};
        uint64_t position = offset + completed;
        uint64_t logical_block = position >> reader->block_log;
        uint32_t within = (uint32_t)(position & (reader->block_size - 1u));
        uint32_t chunk = reader->block_size - within;
        int result;

        if (chunk > length - completed) chunk = length - completed;
        result = edge_xfs_find_extent(reader, inode, logical_block, &extent);
        if (result == -2 || extent.unwritten) {
            memset(output + completed, 0, chunk);
        } else if (result < 0) {
            return -1;
        } else {
            uint64_t physical = extent.physical_block +
                logical_block - extent.logical_block;
            if (physical >= reader->data_blocks ||
                edge_xfs_read(reader,
                    physical * reader->block_size + within,
                    output + completed, chunk) < 0)
                return -1;
        }
        completed += chunk;
    }
    return completed;
}

static int edge_xfs_short_directory_entry(
    edge_xfs_reader_t *reader, const edge_xfs_inode_t *directory,
    uint32_t index, edge_xfs_directory_entry_t *entry) {
    uint8_t header[10];
    uint64_t cursor = 0;
    uint32_t inode_bytes;

    if (edge_xfs_inode_read(reader, directory, 0, header, 2u) != 2)
        return -1;
    inode_bytes = header[1] ? 8u : 4u;
    if (index == 0u) {
        entry->inode_number = directory->number;
        entry->file_type = 2u;
        strcpy(entry->name, ".");
        return 0;
    }
    if (index == 1u) {
        if (edge_xfs_inode_read(reader, directory, 2u, header,
                                inode_bytes) != (int64_t)inode_bytes)
            return -1;
        entry->inode_number = inode_bytes == 8u ? edge_xfs_be64(header) :
                                                 edge_xfs_be32(header);
        entry->file_type = 2u;
        strcpy(entry->name, "..");
        return 0;
    }
    index -= 2u;
    if (index >= header[0]) return -2;
    cursor = 2u + inode_bytes;
    for (uint32_t current = 0; current <= index; ++current) {
        uint8_t fixed[3];
        uint8_t trailer[9];
        uint32_t name_length;
        uint32_t trailer_length = inode_bytes +
            (reader->has_file_type ? 1u : 0u);

        if (edge_xfs_inode_read(reader, directory, cursor,
                                fixed, sizeof(fixed)) != sizeof(fixed))
            return -1;
        name_length = fixed[0];
        if (!name_length || name_length >= sizeof(entry->name) ||
            cursor + 3u + name_length + trailer_length > directory->size)
            return -1;
        if (current == index) {
            if (edge_xfs_inode_read(reader, directory, cursor + 3u,
                    entry->name, name_length) != (int64_t)name_length ||
                edge_xfs_inode_read(reader, directory,
                    cursor + 3u + name_length, trailer,
                    trailer_length) != (int64_t)trailer_length)
                return -1;
            entry->name[name_length] = 0;
            entry->file_type = reader->has_file_type ? trailer[0] : 0u;
            entry->inode_number = inode_bytes == 8u ?
                edge_xfs_be64(trailer + (reader->has_file_type ? 1u : 0u)) :
                edge_xfs_be32(trailer + (reader->has_file_type ? 1u : 0u));
            return 0;
        }
        cursor += 3u + name_length + trailer_length;
    }
    return -2;
}

static uint32_t edge_xfs_align8(uint32_t value) {
    return (value + 7u) & ~7u;
}

static int edge_xfs_block_directory_entry(
    edge_xfs_reader_t *reader, const edge_xfs_inode_t *directory,
    uint32_t wanted, edge_xfs_directory_entry_t *entry) {
    uint64_t block_offset = 0;
    uint32_t seen = 0;

    while (block_offset < directory->size) {
        uint8_t header[64];
        uint32_t magic;
        uint32_t header_size;
        uint32_t data_end = reader->directory_block_size;
        uint32_t cursor;
        uint32_t available = (uint32_t)(directory->size - block_offset);

        if (available < 16u) return -1;
        if (available < reader->directory_block_size)
            data_end = available;
        if (edge_xfs_inode_read(reader, directory, block_offset,
                                header, sizeof(header)) != sizeof(header))
            return -1;
        magic = edge_xfs_be32(header);
        if (magic == EDGE_XFS_DIR3_BLOCK_MAGIC ||
            magic == EDGE_XFS_DIR3_DATA_MAGIC)
            header_size = 64u;
        else if (magic == EDGE_XFS_DIR2_BLOCK_MAGIC ||
                 magic == EDGE_XFS_DIR2_DATA_MAGIC)
            header_size = 16u;
        else
            return -1;
        if (magic == EDGE_XFS_DIR3_BLOCK_MAGIC ||
            magic == EDGE_XFS_DIR2_BLOCK_MAGIC) {
            uint8_t tail[8];
            uint32_t leaf_count;
            if (data_end < 8u || edge_xfs_inode_read(reader, directory,
                    block_offset + data_end - 8u, tail, sizeof(tail)) !=
                    sizeof(tail))
                return -1;
            leaf_count = edge_xfs_be32(tail);
            if (leaf_count > (data_end - header_size - 8u) / 8u)
                return -1;
            data_end -= 8u + leaf_count * 8u;
        }
        cursor = header_size;
        while (cursor + 4u <= data_end) {
            uint8_t fixed[9];
            uint16_t marker;
            uint32_t record_size;
            uint32_t name_length;

            if (edge_xfs_inode_read(reader, directory,
                    block_offset + cursor, fixed, sizeof(fixed)) !=
                    sizeof(fixed))
                return -1;
            marker = edge_xfs_be16(fixed);
            if (marker == EDGE_XFS_DIR_FREE_TAG) {
                record_size = edge_xfs_be16(fixed + 2);
                if (record_size < 8u || cursor + record_size > data_end)
                    return -1;
                cursor += record_size;
                continue;
            }
            name_length = fixed[8];
            record_size = edge_xfs_align8(8u + 1u + name_length +
                (reader->has_file_type ? 1u : 0u) + 2u);
            if (!name_length || name_length >= sizeof(entry->name) ||
                cursor + record_size > data_end)
                return -1;
            if (seen++ == wanted) {
                uint8_t file_type = 0;
                if (edge_xfs_inode_read(reader, directory,
                        block_offset + cursor + 9u,
                        entry->name, name_length) != (int64_t)name_length)
                    return -1;
                entry->name[name_length] = 0;
                entry->inode_number = edge_xfs_be64(fixed);
                if (reader->has_file_type &&
                    edge_xfs_inode_read(reader, directory,
                        block_offset + cursor + 9u + name_length,
                        &file_type, 1u) != 1)
                    return -1;
                entry->file_type = file_type;
                return 0;
            }
            cursor += record_size;
        }
        block_offset += reader->directory_block_size;
    }
    return -2;
}

int edge_xfs_directory_entry(edge_xfs_reader_t *reader,
                             const edge_xfs_inode_t *directory,
                             uint32_t index,
                             edge_xfs_directory_entry_t *entry) {
    if (!reader || !directory || !entry ||
        (directory->mode & 0xf000u) != EDGE_XFS_DIRECTORY_TYPE)
        return -1;
    memset(entry, 0, sizeof(*entry));
    if (directory->format == EDGE_XFS_DINODE_FMT_LOCAL)
        return edge_xfs_short_directory_entry(
            reader, directory, index, entry);
    if (directory->format == EDGE_XFS_DINODE_FMT_EXTENTS ||
        directory->format == EDGE_XFS_DINODE_FMT_BTREE)
        return edge_xfs_block_directory_entry(
            reader, directory, index, entry);
    return -1;
}

int edge_xfs_directory_lookup(edge_xfs_reader_t *reader,
                              const edge_xfs_inode_t *directory,
                              const char *name, uint64_t *inode_number) {
    edge_xfs_directory_entry_t entry;

    if (!reader || !directory || !name || !inode_number) return -1;
    for (uint32_t index = 0;; ++index) {
        int result = edge_xfs_directory_entry(
            reader, directory, index, &entry);
        if (result == -2) return -2;
        if (result < 0) return -1;
        if (strcmp(entry.name, name) == 0) {
            *inode_number = entry.inode_number;
            return 0;
        }
    }
}
