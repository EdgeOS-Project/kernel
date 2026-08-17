/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-neutral EROFS metadata and uncompressed data reader. */

#include <stdint.h>

#include "erofs_format.h"
#include "erofs_reader.h"
#include "lz4_decode.h"
#ifdef EDGEOS_EROFS_HOST_TEST
#include <string.h>
#else
#include "string.h"
#endif

#define EDGE_EROFS_MIN_BLOCK_BITS 9u
#define EDGE_EROFS_MAX_BLOCK_BITS 16u
#define EDGE_EROFS_INODE_SLOT_SIZE 32u
#define EDGE_EROFS_MAX_XATTR_NAME 255u

static uint16_t edge_erofs_le16(const void *pointer) {
    const uint8_t *bytes = pointer;
    return (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
}

static uint32_t edge_erofs_le32(const void *pointer) {
    const uint8_t *bytes = pointer;
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint64_t edge_erofs_le64(const void *pointer) {
    const uint8_t *bytes = pointer;
    return (uint64_t)edge_erofs_le32(bytes) |
           ((uint64_t)edge_erofs_le32(bytes + 4) << 32);
}

static uint64_t edge_erofs_align(uint64_t value, uint64_t alignment) {
    return (value + alignment - 1u) & ~(alignment - 1u);
}

static int edge_erofs_range_valid(const edge_erofs_reader_t *reader,
                                  uint64_t offset, uint64_t length) {
    return reader && offset <= reader->device_bytes &&
           length <= reader->device_bytes - offset;
}

static int edge_erofs_read(const edge_erofs_reader_t *reader,
                           uint64_t offset, void *buffer, uint32_t length) {
    int64_t result;

    if (!reader || !buffer || !edge_erofs_range_valid(reader, offset, length))
        return -1;
    result = block_read_bytes(reader->device, offset, buffer, length);
    return result == (int64_t)length ? 0 : -1;
}

static uint32_t edge_erofs_crc32c(uint32_t crc, const uint8_t *data,
                                  uint32_t length) {
    for (uint32_t index = 0; index < length; ++index) {
        crc ^= data[index];
        for (uint32_t bit = 0; bit < 8u; ++bit)
            crc = (crc >> 1) ^ (0x82f63b78u &
                  (uint32_t)-(int32_t)(crc & 1u));
    }
    return crc;
}

static int edge_erofs_checksum_valid(const edge_erofs_reader_t *reader,
                                     uint32_t expected) {
    uint8_t buffer[256];
    uint64_t offset = EDGE_EROFS_SUPER_OFFSET + 8u;
    uint64_t end = reader->block_size;
    uint32_t crc = 0x5045b54au;

    if (end <= offset || !edge_erofs_range_valid(reader, offset, end - offset))
        return 0;
    while (offset < end) {
        uint32_t length = (uint32_t)(end - offset);
        if (length > sizeof(buffer)) length = sizeof(buffer);
        if (edge_erofs_read(reader, offset, buffer, length) < 0) return 0;
        crc = edge_erofs_crc32c(crc, buffer, length);
        offset += length;
    }
    return crc == expected;
}

int edge_erofs_reader_init(edge_erofs_reader_t *reader,
                           block_device_t *device) {
    edge_erofs_super_disk_t superblock;
    edge_erofs_lz4_config_disk_t lz4_config;
    uint64_t blocks;
    uint64_t config_offset;
    uint64_t root_nid;
    uint32_t incompatibility;
    uint16_t config_size;

    if (!reader || !device) return -1;
    memset(reader, 0, sizeof(*reader));
    reader->device = device;
    reader->device_bytes = block_device_size_bytes(device);
    if (reader->device_bytes < EDGE_EROFS_SUPER_OFFSET + sizeof(superblock) ||
        edge_erofs_read(reader, EDGE_EROFS_SUPER_OFFSET,
                        &superblock, sizeof(superblock)) < 0 ||
        edge_erofs_le32(&superblock.magic) != EDGE_EROFS_MAGIC)
        return -1;
    if (superblock.block_bits < EDGE_EROFS_MIN_BLOCK_BITS ||
        superblock.block_bits > EDGE_EROFS_MAX_BLOCK_BITS)
        return -1;
    reader->block_size = 1u << superblock.block_bits;
    reader->directory_block_size = superblock.directory_block_bits ?
        1u << superblock.directory_block_bits : reader->block_size;
    if (reader->directory_block_size < 512u ||
        reader->directory_block_size > reader->block_size)
        return -1;

    reader->feature_compat = edge_erofs_le32(&superblock.feature_compat);
    incompatibility = edge_erofs_le32(&superblock.feature_incompat);
    if (incompatibility & ~(
            EDGE_EROFS_FEATURE_INCOMPAT_LZ4_0PADDING |
            EDGE_EROFS_FEATURE_INCOMPAT_COMPR_CFGS |
            EDGE_EROFS_FEATURE_INCOMPAT_CHUNKED_FILE |
            EDGE_EROFS_FEATURE_INCOMPAT_COMPR_HEAD2 |
            EDGE_EROFS_FEATURE_INCOMPAT_48BIT))
        return -1;
    if (edge_erofs_le16(&superblock.extra_devices) != 0u ||
        (incompatibility & EDGE_EROFS_FEATURE_INCOMPAT_METABOX))
        return -1;
    reader->feature_incompat = incompatibility;
    reader->maximum_pcluster_blocks = 1u;
    reader->lz4_maximum_distance = EDGE_LZ4_HISTORY_SIZE - 1u;
    if (incompatibility & EDGE_EROFS_FEATURE_INCOMPAT_COMPR_CFGS) {
        reader->compression_algorithms =
            edge_erofs_le16(&superblock.compression);
        if (!reader->compression_algorithms ||
            (reader->compression_algorithms &
             ~EDGE_EROFS_COMPRESSION_LZ4_MASK))
            return -1;
        config_offset = EDGE_EROFS_SUPER_OFFSET + 128u +
                        (uint64_t)superblock.extension_slots * 16u;
        if (edge_erofs_read(reader, config_offset,
                            &config_size, sizeof(config_size)) < 0 ||
            edge_erofs_le16(&config_size) != sizeof(lz4_config) ||
            edge_erofs_read(reader, config_offset + sizeof(config_size),
                            &lz4_config, sizeof(lz4_config)) < 0)
            return -1;
        reader->lz4_maximum_distance =
            edge_erofs_le16(&lz4_config.maximum_distance);
        reader->maximum_pcluster_blocks =
            edge_erofs_le16(&lz4_config.maximum_pcluster_blocks);
        if (!reader->maximum_pcluster_blocks)
            reader->maximum_pcluster_blocks = 1u;
        if (!reader->lz4_maximum_distance ||
            reader->lz4_maximum_distance >= EDGE_LZ4_HISTORY_SIZE)
            reader->lz4_maximum_distance = EDGE_LZ4_HISTORY_SIZE - 1u;
    } else if (incompatibility &
               EDGE_EROFS_FEATURE_INCOMPAT_LZ4_0PADDING) {
        reader->compression_algorithms = EDGE_EROFS_COMPRESSION_LZ4_MASK;
        config_size = edge_erofs_le16(&superblock.compression);
        if (config_size)
            reader->lz4_maximum_distance = config_size;
    }
    if (reader->maximum_pcluster_blocks >
            (1024u * 1024u) / reader->block_size)
        return -1;
    blocks = edge_erofs_le32(&superblock.blocks_low);
    root_nid = edge_erofs_le16(&superblock.root_nid_16);
    if (incompatibility & EDGE_EROFS_FEATURE_INCOMPAT_48BIT) {
        blocks |= (uint64_t)edge_erofs_le16(&superblock.root_nid_16) << 32;
        root_nid = edge_erofs_le64(&superblock.root_nid_64);
    }
    if (!blocks || blocks > reader->device_bytes / reader->block_size + 1u)
        return -1;
    reader->block_count = blocks;
    reader->inode_count = edge_erofs_le64(&superblock.inode_count);
    reader->root_nid = root_nid;
    reader->metadata_offset =
        (uint64_t)edge_erofs_le32(&superblock.metadata_block) *
        reader->block_size;
    reader->xattr_offset =
        (uint64_t)edge_erofs_le32(&superblock.xattr_block) *
        reader->block_size;
    if (!edge_erofs_range_valid(reader, reader->metadata_offset,
                                EDGE_EROFS_INODE_SLOT_SIZE))
        return -1;
    if ((reader->feature_compat & EDGE_EROFS_FEATURE_COMPAT_SB_CHKSUM) &&
        !edge_erofs_checksum_valid(reader,
            edge_erofs_le32(&superblock.checksum)))
        return -1;
    return 0;
}

int edge_erofs_reader_set_compression_workspace(
    edge_erofs_reader_t *reader, void *compressed, uint32_t compressed_size,
    void *history, uint32_t history_size) {
    uint64_t required;

    if (!reader) return -1;
    if (!reader->compression_algorithms) {
        reader->compressed_workspace = 0;
        reader->compressed_workspace_size = 0;
        reader->history_workspace = 0;
        reader->history_workspace_size = 0;
        return 0;
    }
    required = (uint64_t)reader->maximum_pcluster_blocks *
               reader->block_size;
    if (!compressed || required > compressed_size || !history ||
        history_size < EDGE_LZ4_HISTORY_SIZE)
        return -1;
    reader->compressed_workspace = compressed;
    reader->compressed_workspace_size = compressed_size;
    reader->history_workspace = history;
    reader->history_workspace_size = history_size;
    return 0;
}

static uint32_t edge_erofs_xattr_size(uint16_t count) {
    if (!count) return 0;
    return (uint32_t)sizeof(edge_erofs_xattr_header_disk_t) +
           ((uint32_t)count - 1u) * 4u;
}

int edge_erofs_inode_load(edge_erofs_reader_t *reader, uint64_t nid,
                          edge_erofs_inode_t *inode) {
    edge_erofs_inode_extended_disk_t disk;
    uint64_t inode_offset;
    uint16_t format;
    uint16_t xattr_count;

    if (!reader || !inode || nid > (UINT64_MAX - reader->metadata_offset) /
                                    EDGE_EROFS_INODE_SLOT_SIZE)
        return -1;
    inode_offset = reader->metadata_offset + nid * EDGE_EROFS_INODE_SLOT_SIZE;
    if (edge_erofs_read(reader, inode_offset, &disk,
                        sizeof(edge_erofs_inode_compact_disk_t)) < 0)
        return -1;
    format = edge_erofs_le16(&disk.format);
    memset(inode, 0, sizeof(*inode));
    inode->nid = nid;
    inode->inode_offset = inode_offset;
    inode->format = format;
    inode->data_layout = (uint8_t)((format >> EDGE_EROFS_INODE_DATALAYOUT_BIT) &
                                   EDGE_EROFS_INODE_DATALAYOUT_MASK);
    if (inode->data_layout > EDGE_EROFS_INODE_CHUNK_BASED) return -1;
    xattr_count = edge_erofs_le16(&disk.xattr_count);
    inode->xattr_size = edge_erofs_xattr_size(xattr_count);
    if (!inode->xattr_size && xattr_count) return -1;

    if (format & EDGE_EROFS_INODE_VERSION_MASK) {
        if (edge_erofs_read(reader, inode_offset, &disk, sizeof(disk)) < 0)
            return -1;
        inode->inode_size = sizeof(disk);
        inode->mode = edge_erofs_le16(&disk.mode);
        inode->size = edge_erofs_le64(&disk.size);
        inode->start_block = edge_erofs_le32(&disk.data);
        inode->inode_number = edge_erofs_le32(&disk.inode_number);
        inode->uid = edge_erofs_le32(&disk.uid);
        inode->gid = edge_erofs_le32(&disk.gid);
        inode->mtime = edge_erofs_le64(&disk.mtime);
        inode->link_count = edge_erofs_le32(&disk.link_count);
    } else {
        const edge_erofs_inode_compact_disk_t *compact =
            (const edge_erofs_inode_compact_disk_t *)&disk;
        inode->inode_size = sizeof(*compact);
        inode->mode = edge_erofs_le16(&compact->mode);
        inode->size = edge_erofs_le32(&compact->size);
        inode->start_block = edge_erofs_le32(&compact->data);
        inode->inode_number = edge_erofs_le32(&compact->inode_number);
        inode->uid = edge_erofs_le16(&compact->uid);
        inode->gid = edge_erofs_le16(&compact->gid);
        inode->mtime = edge_erofs_le32(&compact->mtime);
        inode->link_count = edge_erofs_le16(&compact->link_count);
    }
    if (reader->feature_incompat & EDGE_EROFS_FEATURE_INCOMPAT_48BIT) {
        uint16_t high = edge_erofs_le16((const uint8_t *)&disk + 6u);
        inode->start_block |= (uint64_t)high << 32;
        inode->link_count = 1u;
    }
    if (!inode->link_count) inode->link_count = 1u;
    if (inode->data_layout == EDGE_EROFS_INODE_CHUNK_BASED)
        inode->chunk_format = (uint16_t)inode->start_block;
    if ((inode->mode & 0xf000u) == 0x2000u ||
        (inode->mode & 0xf000u) == 0x6000u)
        inode->rdev = (uint32_t)inode->start_block;
    if (!edge_erofs_range_valid(reader, inode_offset,
            (uint64_t)inode->inode_size + inode->xattr_size))
        return -1;
    return 0;
}

static int64_t edge_erofs_read_flat(edge_erofs_reader_t *reader,
                                    const edge_erofs_inode_t *inode,
                                    uint64_t offset, void *buffer,
                                    uint32_t length) {
    uint8_t *output = buffer;
    uint64_t full_bytes = inode->size & ~(uint64_t)(reader->block_size - 1u);
    uint32_t completed = 0;

    if (inode->data_layout == EDGE_EROFS_INODE_FLAT_PLAIN) {
        if (edge_erofs_read(reader,
                inode->start_block * reader->block_size + offset,
                buffer, length) < 0)
            return -1;
        return length;
    }
    if (offset < full_bytes) {
        uint32_t part = length;
        if ((uint64_t)part > full_bytes - offset)
            part = (uint32_t)(full_bytes - offset);
        if (edge_erofs_read(reader,
                inode->start_block * reader->block_size + offset,
                output, part) < 0)
            return -1;
        completed = part;
    }
    if (completed < length) {
        uint64_t tail_offset = edge_erofs_align(
            inode->inode_offset + inode->inode_size + inode->xattr_size, 4u);
        uint64_t logical = offset + completed;
        if (logical < full_bytes ||
            edge_erofs_read(reader, tail_offset + logical - full_bytes,
                            output + completed, length - completed) < 0)
            return -1;
        completed = length;
    }
    return completed;
}

static int64_t edge_erofs_read_chunked(edge_erofs_reader_t *reader,
                                       const edge_erofs_inode_t *inode,
                                       uint64_t offset, void *buffer,
                                       uint32_t length) {
    uint8_t *output = buffer;
    uint32_t completed = 0;
    uint32_t chunk_bits = inode->chunk_format &
                          EDGE_EROFS_CHUNK_FORMAT_BLKBITS_MASK;
    uint64_t chunk_size;
    uint32_t index_size;
    uint64_t indexes;

    if (chunk_bits > 20u ||
        (inode->chunk_format & ~(EDGE_EROFS_CHUNK_FORMAT_BLKBITS_MASK |
                                 EDGE_EROFS_CHUNK_FORMAT_INDEXES |
                                 EDGE_EROFS_CHUNK_FORMAT_48BIT)))
        return -1;
    chunk_size = (uint64_t)reader->block_size << chunk_bits;
    index_size = (inode->chunk_format & EDGE_EROFS_CHUNK_FORMAT_INDEXES) ?
                 sizeof(edge_erofs_chunk_index_disk_t) : sizeof(uint32_t);
    indexes = edge_erofs_align(inode->inode_offset + inode->inode_size +
                               inode->xattr_size, index_size);
    while (completed < length) {
        edge_erofs_chunk_index_disk_t index;
        uint64_t logical = offset + completed;
        uint64_t chunk = logical / chunk_size;
        uint32_t inside = (uint32_t)(logical % chunk_size);
        uint32_t part = length - completed;
        uint64_t block;
        if ((uint64_t)part > chunk_size - inside)
            part = (uint32_t)(chunk_size - inside);
        memset(&index, 0, sizeof(index));
        if (edge_erofs_read(reader, indexes + chunk * index_size,
                            &index, index_size) < 0)
            return -1;
        if (index_size == sizeof(uint32_t)) {
            block = edge_erofs_le32(&index);
        } else {
            if (edge_erofs_le16(&index.device_id) != 0u) return -1;
            block = edge_erofs_le32(&index.start_block_low);
            if (inode->chunk_format & EDGE_EROFS_CHUNK_FORMAT_48BIT)
                block |= (uint64_t)edge_erofs_le16(&index.start_block_high) << 32;
        }
        if ((uint32_t)block == EDGE_EROFS_NULL_ADDR32) {
            memset(output + completed, 0, part);
        } else if (edge_erofs_read(reader,
                       block * reader->block_size + inside,
                       output + completed, part) < 0) {
            return -1;
        }
        completed += part;
    }
    return completed;
}

typedef struct edge_erofs_lcluster {
    uint64_t logical_cluster;
    uint64_t physical_block;
    uint32_t compressed_blocks;
    uint32_t lookback;
    uint32_t cluster_offset;
    uint8_t type;
    uint8_t hole;
} edge_erofs_lcluster_t;

typedef struct edge_erofs_compression_info {
    uint64_t index_base;
    uint64_t logical_cluster_size;
    uint64_t logical_cluster_count;
    uint16_t advise;
    uint8_t algorithms;
    uint8_t compact;
    uint8_t logical_cluster_bits;
} edge_erofs_compression_info_t;

typedef struct edge_erofs_compression_extent {
    uint64_t logical_start;
    uint64_t logical_length;
    uint64_t physical_block;
    uint32_t compressed_blocks;
    uint8_t algorithm;
    uint8_t hole;
} edge_erofs_compression_extent_t;

static int edge_erofs_compression_info(
    edge_erofs_reader_t *reader, const edge_erofs_inode_t *inode,
    edge_erofs_compression_info_t *info) {
    edge_erofs_compression_header_disk_t header;
    uint64_t header_offset;
    uint32_t cluster_shift;
    uint16_t supported_advise;

    if (!reader || !inode || !info ||
        (inode->data_layout != EDGE_EROFS_INODE_COMPRESSED_FULL &&
         inode->data_layout != EDGE_EROFS_INODE_COMPRESSED_COMPACT))
        return -1;
    header_offset = edge_erofs_align(
        inode->inode_offset + inode->inode_size + inode->xattr_size, 8u);
    if (edge_erofs_read(reader, header_offset, &header, sizeof(header)) < 0)
        return -1;
    memset(info, 0, sizeof(*info));
    info->compact = inode->data_layout == EDGE_EROFS_INODE_COMPRESSED_COMPACT;
    info->advise = edge_erofs_le16(&header.advise);
    info->algorithms = header.algorithms;
    if (header.cluster_bits & 0xf0u) return -1;
    cluster_shift = (uint32_t)header.cluster_bits +
                    __builtin_ctz(reader->block_size);
    if (cluster_shift > 24u) return -1;
    info->logical_cluster_bits = (uint8_t)cluster_shift;
    info->logical_cluster_size = 1ull << cluster_shift;
    info->logical_cluster_count =
        (inode->size + info->logical_cluster_size - 1u) /
        info->logical_cluster_size;
    supported_advise = EDGE_EROFS_ADVISE_BIG_PCLUSTER_1 |
                       EDGE_EROFS_ADVISE_BIG_PCLUSTER_2;
    if (info->compact)
        supported_advise |= EDGE_EROFS_ADVISE_COMPACTED_2B;
    if (info->advise & ~supported_advise) return -1;
    info->index_base = header_offset + sizeof(header);
    if (!info->compact)
        info->index_base += sizeof(edge_erofs_lcluster_index_disk_t);
    return 0;
}

static uint32_t edge_erofs_compact_value(
    const uint8_t *pack, uint32_t bit_offset, uint32_t low_bits,
    uint8_t *type) {
    uint32_t value = edge_erofs_le32(pack + bit_offset / 8u) >>
                     (bit_offset & 7u);
    uint32_t mask = (1u << low_bits) - 1u;

    *type = (uint8_t)((value >> low_bits) &
                      EDGE_EROFS_LCLUSTER_TYPE_MASK);
    return value & mask;
}

static int edge_erofs_compact_lcluster(
    edge_erofs_reader_t *reader, const edge_erofs_compression_info_t *info,
    uint64_t logical_cluster, edge_erofs_lcluster_t *record) {
    uint8_t pack[32];
    uint64_t relative_cluster = logical_cluster;
    uint64_t position;
    uint64_t pack_base;
    uint32_t initial_four_byte;
    uint32_t compact_two_byte = 0;
    uint32_t entry_bytes = 4u;
    uint32_t entries_per_pack = 2u;
    uint32_t pack_bytes;
    uint32_t pack_index;
    uint32_t low_bits;
    uint32_t encoded_bits;
    uint32_t low;
    uint32_t physical_delta;
    int32_t scan;
    int big_pcluster;

    if (logical_cluster >= info->logical_cluster_count ||
        info->logical_cluster_bits > 14u)
        return -1;
    initial_four_byte = (uint32_t)(((32u - (info->index_base & 31u)) /
                                    4u) & 7u);
    if ((info->advise & EDGE_EROFS_ADVISE_COMPACTED_2B) &&
        initial_four_byte < info->logical_cluster_count)
        compact_two_byte = (uint32_t)(
            (info->logical_cluster_count - initial_four_byte) & ~15ull);
    position = info->index_base;
    if (relative_cluster >= initial_four_byte) {
        position += (uint64_t)initial_four_byte * 4u;
        relative_cluster -= initial_four_byte;
        if (relative_cluster < compact_two_byte) {
            entry_bytes = 2u;
            entries_per_pack = 16u;
        } else {
            position += (uint64_t)compact_two_byte * 2u;
            relative_cluster -= compact_two_byte;
        }
    }
    position += relative_cluster * entry_bytes;
    pack_bytes = entries_per_pack * entry_bytes;
    pack_base = position & ~(uint64_t)(pack_bytes - 1u);
    pack_index = (uint32_t)((position - pack_base) / entry_bytes);
    if (edge_erofs_read(reader, pack_base, pack, pack_bytes) < 0)
        return -1;
    low_bits = info->logical_cluster_bits > 12u ?
               info->logical_cluster_bits : 12u;
    encoded_bits = (pack_bytes - sizeof(uint32_t)) * 8u /
                   entries_per_pack;
    memset(record, 0, sizeof(*record));
    record->logical_cluster = logical_cluster;
    low = edge_erofs_compact_value(
        pack, encoded_bits * pack_index, low_bits, &record->type);
    big_pcluster = (info->advise &
                    EDGE_EROFS_ADVISE_BIG_PCLUSTER_1) != 0;
    if (record->type == EDGE_EROFS_LCLUSTER_NONHEAD) {
        record->cluster_offset = (uint32_t)info->logical_cluster_size;
        if (low & EDGE_EROFS_LCLUSTER_CBLKCNT) {
            if (!big_pcluster) return -1;
            record->compressed_blocks =
                low & ~EDGE_EROFS_LCLUSTER_CBLKCNT;
            record->lookback = 1u;
        } else if (pack_index + 1u != entries_per_pack) {
            record->lookback = low;
        } else {
            uint8_t previous_type;
            if (!pack_index) return -1;
            low = edge_erofs_compact_value(
                pack, encoded_bits * (pack_index - 1u),
                low_bits, &previous_type);
            if (previous_type != EDGE_EROFS_LCLUSTER_NONHEAD)
                low = 0;
            else if (low & EDGE_EROFS_LCLUSTER_CBLKCNT)
                low = 1u;
            record->lookback = low + 1u;
        }
        return record->lookback ? 0 : -1;
    }
    record->cluster_offset = low;
    physical_delta = big_pcluster ? 0u : 1u;
    scan = (int32_t)pack_index;
    while (scan > 0) {
        uint8_t previous_type;
        --scan;
        low = edge_erofs_compact_value(
            pack, encoded_bits * (uint32_t)scan,
            low_bits, &previous_type);
        if (!big_pcluster) {
            if (previous_type == EDGE_EROFS_LCLUSTER_NONHEAD)
                scan -= (int32_t)low;
            if (scan >= 0) ++physical_delta;
        } else if (previous_type == EDGE_EROFS_LCLUSTER_NONHEAD) {
            if (low & EDGE_EROFS_LCLUSTER_CBLKCNT) {
                --scan;
                physical_delta += low & ~EDGE_EROFS_LCLUSTER_CBLKCNT;
            } else {
                if (low <= 1u) return -1;
                scan -= (int32_t)low - 2;
            }
        } else {
            ++physical_delta;
        }
    }
    record->physical_block =
        edge_erofs_le32(pack + pack_bytes - sizeof(uint32_t)) +
        physical_delta;
    return 0;
}

static int edge_erofs_full_lcluster(
    edge_erofs_reader_t *reader, const edge_erofs_compression_info_t *info,
    uint64_t logical_cluster, edge_erofs_lcluster_t *record) {
    edge_erofs_lcluster_index_disk_t disk;
    uint16_t advise;

    if (logical_cluster >= info->logical_cluster_count ||
        edge_erofs_read(reader,
            info->index_base + logical_cluster * sizeof(disk),
            &disk, sizeof(disk)) < 0)
        return -1;
    memset(record, 0, sizeof(*record));
    record->logical_cluster = logical_cluster;
    advise = edge_erofs_le16(&disk.advise);
    record->type = (uint8_t)(advise & EDGE_EROFS_LCLUSTER_TYPE_MASK);
    if (record->type == EDGE_EROFS_LCLUSTER_NONHEAD) {
        record->cluster_offset = (uint32_t)info->logical_cluster_size;
        record->lookback = edge_erofs_le16(&disk.data.delta[0]);
        if (record->lookback & EDGE_EROFS_LCLUSTER_CBLKCNT) {
            record->compressed_blocks =
                record->lookback & ~EDGE_EROFS_LCLUSTER_CBLKCNT;
            record->lookback = 1u;
        }
        return record->lookback ? 0 : -1;
    }
    record->cluster_offset = edge_erofs_le16(&disk.cluster_offset);
    record->hole = (advise & EDGE_EROFS_LCLUSTER_HOLE) != 0;
    record->physical_block = edge_erofs_le32(&disk.data.start_block);
    return 0;
}

static int edge_erofs_load_lcluster(
    edge_erofs_reader_t *reader, const edge_erofs_compression_info_t *info,
    uint64_t logical_cluster, edge_erofs_lcluster_t *record) {
    int result;

    result = info->compact ?
        edge_erofs_compact_lcluster(
            reader, info, logical_cluster, record) :
        edge_erofs_full_lcluster(reader, info, logical_cluster, record);
    if (result < 0 || record->type > EDGE_EROFS_LCLUSTER_HEAD2 ||
        (record->type != EDGE_EROFS_LCLUSTER_NONHEAD &&
         record->cluster_offset >= info->logical_cluster_size))
        return -1;
    return 0;
}

static int edge_erofs_compression_extent(
    edge_erofs_reader_t *reader, const edge_erofs_inode_t *inode,
    uint64_t offset, edge_erofs_compression_extent_t *extent) {
    edge_erofs_compression_info_t info;
    edge_erofs_lcluster_t record;
    edge_erofs_lcluster_t following;
    uint64_t cluster;
    uint64_t logical_start;
    uint64_t logical_end;
    uint32_t compressed_blocks = 1u;
    int big;

    if (!extent || edge_erofs_compression_info(reader, inode, &info) < 0 ||
        offset >= inode->size)
        return -1;
    cluster = offset / info.logical_cluster_size;
    if (edge_erofs_load_lcluster(reader, &info, cluster, &record) < 0)
        return -1;
    if (record.type == EDGE_EROFS_LCLUSTER_NONHEAD ||
        offset % info.logical_cluster_size < record.cluster_offset) {
        uint32_t lookback = record.type == EDGE_EROFS_LCLUSTER_NONHEAD ?
                            record.lookback : 1u;
        for (;;) {
            if (!lookback || lookback > cluster) return -1;
            cluster -= lookback;
            if (edge_erofs_load_lcluster(
                    reader, &info, cluster, &record) < 0)
                return -1;
            if (record.type != EDGE_EROFS_LCLUSTER_NONHEAD) break;
            lookback = record.lookback;
        }
    }
    logical_start = cluster * info.logical_cluster_size +
                    record.cluster_offset;
    logical_end = inode->size;
    for (uint64_t scan = cluster + 1u;
         scan < info.logical_cluster_count; ++scan) {
        if (edge_erofs_load_lcluster(reader, &info, scan, &following) < 0)
            return -1;
        if (following.type != EDGE_EROFS_LCLUSTER_NONHEAD) {
            logical_end = scan * info.logical_cluster_size +
                          following.cluster_offset;
            break;
        }
    }
    if (logical_end > inode->size) logical_end = inode->size;
    if (offset < logical_start || offset >= logical_end ||
        logical_end <= logical_start)
        return -1;
    big = (record.type == EDGE_EROFS_LCLUSTER_HEAD1) ?
          (info.advise & EDGE_EROFS_ADVISE_BIG_PCLUSTER_1) :
          (info.advise & EDGE_EROFS_ADVISE_BIG_PCLUSTER_2);
    if (big && cluster + 1u < info.logical_cluster_count) {
        if (edge_erofs_load_lcluster(
                reader, &info, cluster + 1u, &following) < 0)
            return -1;
        if (following.type == EDGE_EROFS_LCLUSTER_NONHEAD &&
            following.compressed_blocks)
            compressed_blocks = following.compressed_blocks;
    }
    if (!compressed_blocks ||
        compressed_blocks > reader->maximum_pcluster_blocks)
        return -1;
    memset(extent, 0, sizeof(*extent));
    extent->logical_start = logical_start;
    extent->logical_length = logical_end - logical_start;
    extent->physical_block = record.physical_block;
    extent->compressed_blocks = compressed_blocks;
    extent->hole = record.hole;
    if (record.type == EDGE_EROFS_LCLUSTER_HEAD1)
        extent->algorithm = info.algorithms & 0x0fu;
    else if (record.type == EDGE_EROFS_LCLUSTER_HEAD2)
        extent->algorithm = info.algorithms >> 4;
    else
        extent->algorithm = 0xffu;
    return 0;
}

static int64_t edge_erofs_read_compressed(edge_erofs_reader_t *reader,
                                          const edge_erofs_inode_t *inode,
                                          uint64_t offset, void *buffer,
                                          uint32_t length) {
    uint8_t *output = buffer;
    uint32_t completed = 0;

    while (completed < length) {
        edge_erofs_compression_extent_t extent;
        uint64_t logical = offset + completed;
        uint64_t inside;
        uint64_t physical_offset;
        uint64_t physical_size;
        uint32_t part = length - completed;
        uint32_t leading = 0;

        if (edge_erofs_compression_extent(
                reader, inode, logical, &extent) < 0)
            return -1;
        inside = logical - extent.logical_start;
        if ((uint64_t)part > extent.logical_length - inside)
            part = (uint32_t)(extent.logical_length - inside);
        if (extent.hole) {
            memset(output + completed, 0, part);
            completed += part;
            continue;
        }
        physical_offset = extent.physical_block * reader->block_size;
        physical_size = (uint64_t)extent.compressed_blocks *
                        reader->block_size;
        if (extent.algorithm == 0xffu) {
            if (inside + part > physical_size ||
                edge_erofs_read(reader, physical_offset + inside,
                                output + completed, part) < 0)
                return -1;
            completed += part;
            continue;
        }
        if (extent.algorithm != EDGE_EROFS_COMPRESSION_LZ4 ||
            !reader->compressed_workspace ||
            physical_size > reader->compressed_workspace_size ||
            edge_erofs_read(reader, physical_offset,
                reader->compressed_workspace, (uint32_t)physical_size) < 0)
            return -1;
        if (reader->feature_incompat &
            EDGE_EROFS_FEATURE_INCOMPAT_LZ4_0PADDING) {
            while (leading < physical_size &&
                   !reader->compressed_workspace[leading])
                ++leading;
        }
        if (leading == physical_size ||
            edge_lz4_extract(reader->compressed_workspace + leading,
                (uint32_t)physical_size - leading, extent.logical_length,
                inside, output + completed, part,
                reader->history_workspace,
                reader->history_workspace_size) != (int)part)
            return -1;
        completed += part;
    }
    return completed;
}

int64_t edge_erofs_inode_read(edge_erofs_reader_t *reader,
                              const edge_erofs_inode_t *inode,
                              uint64_t offset, void *buffer,
                              uint32_t length) {
    if (!reader || !inode || (!buffer && length)) return -1;
    if (offset >= inode->size) return 0;
    if ((uint64_t)length > inode->size - offset)
        length = (uint32_t)(inode->size - offset);
    if (!length) return 0;
    if (inode->data_layout == EDGE_EROFS_INODE_FLAT_PLAIN ||
        inode->data_layout == EDGE_EROFS_INODE_FLAT_INLINE)
        return edge_erofs_read_flat(reader, inode, offset, buffer, length);
    if (inode->data_layout == EDGE_EROFS_INODE_CHUNK_BASED)
        return edge_erofs_read_chunked(reader, inode, offset, buffer, length);
    if (inode->data_layout == EDGE_EROFS_INODE_COMPRESSED_FULL ||
        inode->data_layout == EDGE_EROFS_INODE_COMPRESSED_COMPACT)
        return edge_erofs_read_compressed(
            reader, inode, offset, buffer, length);
    return -1;
}

static int edge_erofs_directory_entry_at(
    edge_erofs_reader_t *reader, const edge_erofs_inode_t *directory,
    uint64_t block_offset, uint32_t entry_index,
    edge_erofs_directory_entry_t *entry) {
    edge_erofs_directory_entry_disk_t first;
    edge_erofs_directory_entry_disk_t current;
    edge_erofs_directory_entry_disk_t next;
    uint64_t remaining = directory->size - block_offset;
    uint32_t block_length = reader->directory_block_size;
    uint32_t entry_count;
    uint32_t name_offset;
    uint32_t name_end;
    uint32_t name_length;

    if (remaining < block_length) block_length = (uint32_t)remaining;
    if (block_length < sizeof(first) ||
        edge_erofs_inode_read(reader, directory, block_offset,
                              &first, sizeof(first)) != sizeof(first))
        return -1;
    name_offset = edge_erofs_le16(&first.name_offset);
    if (!name_offset || name_offset % sizeof(first) != 0u ||
        name_offset > block_length)
        return -1;
    entry_count = name_offset / sizeof(first);
    if (entry_index >= entry_count) return -2;
    if (edge_erofs_inode_read(reader, directory,
            block_offset + (uint64_t)entry_index * sizeof(current),
            &current, sizeof(current)) != sizeof(current))
        return -1;
    name_offset = edge_erofs_le16(&current.name_offset);
    if (entry_index + 1u < entry_count) {
        if (edge_erofs_inode_read(reader, directory,
                block_offset + (uint64_t)(entry_index + 1u) * sizeof(next),
                &next, sizeof(next)) != sizeof(next))
            return -1;
        name_end = edge_erofs_le16(&next.name_offset);
    } else {
        name_end = block_length;
    }
    if (name_offset < entry_count * sizeof(current) ||
        name_end <= name_offset || name_end > block_length)
        return -1;
    name_length = name_end - name_offset;
    while (name_length) {
        uint8_t last;
        if (edge_erofs_inode_read(reader, directory,
                block_offset + name_offset + name_length - 1u,
                &last, 1u) != 1)
            return -1;
        if (last) break;
        --name_length;
    }
    if (!name_length || name_length >= sizeof(entry->name)) return -1;
    if (edge_erofs_inode_read(reader, directory,
            block_offset + name_offset, entry->name,
            name_length) != name_length)
        return -1;
    entry->name[name_length] = 0;
    entry->nid = edge_erofs_le64(&current.nid);
    entry->file_type = current.file_type;
    return 0;
}

int edge_erofs_directory_entry(edge_erofs_reader_t *reader,
                               const edge_erofs_inode_t *directory,
                               uint32_t index,
                               edge_erofs_directory_entry_t *entry) {
    uint64_t block_offset = 0;

    if (!reader || !directory || !entry ||
        (directory->mode & 0xf000u) != 0x4000u)
        return -1;
    while (block_offset < directory->size) {
        edge_erofs_directory_entry_disk_t first;
        uint32_t block_length = reader->directory_block_size;
        uint64_t remaining = directory->size - block_offset;
        uint32_t entries;
        int result;
        if (remaining < block_length) block_length = (uint32_t)remaining;
        if (block_length < sizeof(first) ||
            edge_erofs_inode_read(reader, directory, block_offset,
                                  &first, sizeof(first)) != sizeof(first))
            return -1;
        entries = edge_erofs_le16(&first.name_offset) / sizeof(first);
        if (!entries || entries > block_length / sizeof(first)) return -1;
        if (index < entries) {
            result = edge_erofs_directory_entry_at(
                reader, directory, block_offset, index, entry);
            return result;
        }
        index -= entries;
        block_offset += block_length;
    }
    return -2;
}

int edge_erofs_directory_lookup(edge_erofs_reader_t *reader,
                                const edge_erofs_inode_t *directory,
                                const char *name, uint64_t *nid) {
    edge_erofs_directory_entry_t entry;

    if (!name || !nid) return -1;
    for (uint32_t index = 0;; ++index) {
        int result = edge_erofs_directory_entry(
            reader, directory, index, &entry);
        if (result == -2) return -2;
        if (result < 0) return -1;
        if (strcmp(entry.name, name) == 0) {
            *nid = entry.nid;
            return 0;
        }
        if (index == UINT32_MAX) return -1;
    }
}

static const char *edge_erofs_xattr_prefix(uint8_t index) {
    switch (index) {
        case 0: return "";
        case EDGE_EROFS_XATTR_INDEX_USER: return "user.";
        case EDGE_EROFS_XATTR_INDEX_POSIX_ACL_ACCESS:
            return "system.posix_acl_access";
        case EDGE_EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT:
            return "system.posix_acl_default";
        case EDGE_EROFS_XATTR_INDEX_TRUSTED: return "trusted.";
        case EDGE_EROFS_XATTR_INDEX_LUSTRE: return "lustre.";
        case EDGE_EROFS_XATTR_INDEX_SECURITY: return "security.";
        default: return 0;
    }
}

static int edge_erofs_xattr_entry(
    edge_erofs_reader_t *reader, uint64_t offset, const char *wanted,
    void *value, uint32_t capacity, uint32_t *entry_size, int *matched) {
    edge_erofs_xattr_entry_disk_t entry;
    char suffix[EDGE_EROFS_MAX_XATTR_NAME + 1u];
    const char *prefix;
    uint32_t value_size;
    uint32_t prefix_size;
    uint32_t total;

    *matched = 0;
    if (edge_erofs_read(reader, offset, &entry, sizeof(entry)) < 0) return -1;
    value_size = edge_erofs_le16(&entry.value_size);
    total = sizeof(entry) + entry.name_length + value_size;
    if (total < sizeof(entry) || total > UINT32_MAX - 3u ||
        !edge_erofs_range_valid(reader, offset, total))
        return -1;
    *entry_size = (total + 3u) & ~3u;
    if (entry.name_index & EDGE_EROFS_XATTR_LONG_PREFIX)
        return 0;
    prefix = edge_erofs_xattr_prefix(entry.name_index);
    if (!prefix) return 0;
    prefix_size = strlen(prefix);
    if ((uint32_t)strlen(wanted) != prefix_size + entry.name_length ||
        memcmp(wanted, prefix, prefix_size) != 0)
        return 0;
    if (entry.name_length &&
        edge_erofs_read(reader, offset + sizeof(entry), suffix,
                        entry.name_length) < 0)
        return -1;
    if (entry.name_length &&
        memcmp(wanted + prefix_size, suffix, entry.name_length) != 0)
        return 0;
    *matched = 1;
    if (!value) return (int)value_size;
    if (capacity < value_size) return -3;
    if (value_size && edge_erofs_read(reader,
            offset + sizeof(entry) + entry.name_length,
            value, value_size) < 0)
        return -1;
    return (int)value_size;
}

int edge_erofs_getxattr(edge_erofs_reader_t *reader,
                        const edge_erofs_inode_t *inode,
                        const char *name, void *value,
                        uint32_t capacity) {
    edge_erofs_xattr_header_disk_t header;
    uint64_t body;
    uint64_t offset;
    uint64_t end;

    if (!reader || !inode || !name) return -1;
    if (!inode->xattr_size) return -2;
    body = inode->inode_offset + inode->inode_size;
    if (edge_erofs_read(reader, body, &header, sizeof(header)) < 0 ||
        header.shared_count > (inode->xattr_size - sizeof(header)) / 4u)
        return -1;
    for (uint32_t index = 0; index < header.shared_count; ++index) {
        uint32_t shared_id;
        uint32_t entry_size;
        int matched;
        int result;
        if (edge_erofs_read(reader, body + sizeof(header) + index * 4u,
                            &shared_id, sizeof(shared_id)) < 0)
            return -1;
        offset = reader->xattr_offset +
                 (uint64_t)edge_erofs_le32(&shared_id) * 4u;
        result = edge_erofs_xattr_entry(
            reader, offset, name, value, capacity, &entry_size, &matched);
        if (result < 0 || matched) return result;
    }
    offset = body + sizeof(header) + (uint64_t)header.shared_count * 4u;
    end = body + inode->xattr_size;
    while (offset < end) {
        uint32_t entry_size = 0;
        int matched;
        int result = edge_erofs_xattr_entry(
            reader, offset, name, value, capacity, &entry_size, &matched);
        if (result < 0 || matched) return result;
        if (!entry_size || entry_size > end - offset) return -1;
        offset += entry_size;
    }
    return offset == end ? -2 : -1;
}
