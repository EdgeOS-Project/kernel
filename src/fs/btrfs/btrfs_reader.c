/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-neutral Btrfs read-only tree and extent reader. */

#include "btrfs_reader.h"

#include "btrfs_format.h"
#include "string.h"

#define EDGE_BTRFS_MAX_TREE_DEPTH 8u

/* Tree blocks must survive recursive descent, so keep bounded shared scratch
 * storage outside the small kernel stacks and serialize reader entry points. */
static uint8_t g_btrfs_tree_scratch[EDGE_BTRFS_MAX_TREE_DEPTH][65536];
static uint8_t g_btrfs_super_scratch[EDGE_BTRFS_SUPER_SIZE];
static volatile uint32_t g_btrfs_reader_lock;

static void btrfs_reader_lock(void) {
    while (__atomic_exchange_n(&g_btrfs_reader_lock, 1u,
                               __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&g_btrfs_reader_lock, __ATOMIC_RELAXED)) {
#if defined(__x86_64__)
            __asm__ __volatile__("pause");
#elif defined(__aarch64__)
            __asm__ __volatile__("yield");
#endif
        }
    }
}

static void btrfs_reader_unlock(void) {
    __atomic_store_n(&g_btrfs_reader_lock, 0u, __ATOMIC_RELEASE);
}

typedef struct edge_btrfs_key {
    uint64_t objectid;
    uint64_t offset;
    uint8_t type;
} edge_btrfs_key_t;

typedef int (*edge_btrfs_item_callback_t)(
    edge_btrfs_reader_t *reader, const edge_btrfs_key_t *key,
    const uint8_t *data, uint32_t size, void *context);

static uint16_t btrfs_le16(const void *pointer) {
    const uint8_t *p = pointer;
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t btrfs_le32(const void *pointer) {
    const uint8_t *p = pointer;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t btrfs_le64(const void *pointer) {
    const uint8_t *p = pointer;
    return (uint64_t)btrfs_le32(p) |
           ((uint64_t)btrfs_le32(p + 4) << 32);
}

static void btrfs_key_decode(const uint8_t *data, edge_btrfs_key_t *key) {
    key->objectid = btrfs_le64(data);
    key->type = data[8];
    key->offset = btrfs_le64(data + 9);
}

static int btrfs_read_physical(edge_btrfs_reader_t *reader, uint64_t offset,
                               void *buffer, uint32_t length) {
    if (!reader || !reader->device || (!buffer && length) ||
        offset > reader->device_bytes ||
        length > reader->device_bytes - offset)
        return -1;
    return block_read_bytes(reader->device, offset, buffer, length) ==
                   (int64_t)length ? 0 : -1;
}

static int btrfs_chunk_add(edge_btrfs_reader_t *reader, uint64_t logical,
                           uint64_t length, uint64_t physical,
                           uint64_t type) {
    edge_btrfs_chunk_t *chunk;

    if (!reader || !length || physical > reader->device_bytes ||
        length > reader->device_bytes - physical ||
        (type & EDGE_BTRFS_UNSUPPORTED_PROFILES))
        return -1;
    for (uint32_t index = 0; index < reader->chunk_count; ++index) {
        chunk = &reader->chunks[index];
        if (chunk->logical == logical) {
            chunk->length = length;
            chunk->physical = physical;
            chunk->type = type;
            return 0;
        }
    }
    if (reader->chunk_count >= EDGE_BTRFS_MAX_CHUNKS) return -1;
    chunk = &reader->chunks[reader->chunk_count++];
    chunk->logical = logical;
    chunk->length = length;
    chunk->physical = physical;
    chunk->type = type;
    return 0;
}

static int btrfs_chunk_parse(edge_btrfs_reader_t *reader,
                             uint64_t logical, const uint8_t *data,
                             uint32_t size) {
    uint64_t length;
    uint64_t type;
    uint64_t physical;
    uint16_t stripes;

    if (!reader || !data || size < 80u) return -1;
    length = btrfs_le64(data);
    type = btrfs_le64(data + 24);
    stripes = btrfs_le16(data + 44);
    if (!stripes || size < 48u + (uint32_t)stripes * 32u) return -1;
    physical = btrfs_le64(data + 56);
    return btrfs_chunk_add(reader, logical, length, physical, type);
}

static int btrfs_map_logical(edge_btrfs_reader_t *reader, uint64_t logical,
                             uint64_t *physical, uint64_t *available) {
    edge_btrfs_chunk_t *best = 0;

    if (!reader || !physical || !available) return -1;
    for (uint32_t index = 0; index < reader->chunk_count; ++index) {
        edge_btrfs_chunk_t *chunk = &reader->chunks[index];
        if (logical >= chunk->logical &&
            logical - chunk->logical < chunk->length &&
            (!best || chunk->logical > best->logical))
            best = chunk;
    }
    if (!best) return -1;
    *physical = best->physical + (logical - best->logical);
    *available = best->length - (logical - best->logical);
    return *physical <= reader->device_bytes &&
           *available <= reader->device_bytes - *physical ? 0 : -1;
}

static int btrfs_read_logical(edge_btrfs_reader_t *reader, uint64_t logical,
                              void *buffer, uint32_t length) {
    uint8_t *output = buffer;

    while (length) {
        uint64_t physical;
        uint64_t available;
        uint32_t take;
        if (btrfs_map_logical(
                reader, logical, &physical, &available) < 0)
            return -1;
        take = available < length ? (uint32_t)available : length;
        if (!take || btrfs_read_physical(
                reader, physical, output, take) < 0)
            return -1;
        logical += take;
        output += take;
        length -= take;
    }
    return 0;
}

static int btrfs_tree_walk(edge_btrfs_reader_t *reader, uint64_t logical,
                           uint32_t depth,
                           edge_btrfs_item_callback_t callback,
                           void *context) {
    uint8_t *node;
    uint32_t count;
    uint8_t level;

    if (!reader || !callback || depth >= EDGE_BTRFS_MAX_TREE_DEPTH ||
        reader->node_size > sizeof(g_btrfs_tree_scratch[0]))
        return -10;
    node = g_btrfs_tree_scratch[depth];
    if (btrfs_read_logical(reader, logical, node, reader->node_size) < 0)
        return -11;
    if (btrfs_le64(node + 48) != logical) return -12;
    count = btrfs_le32(node + EDGE_BTRFS_HEADER_ITEMS_OFFSET);
    level = node[EDGE_BTRFS_HEADER_LEVEL_OFFSET];
    if (level) {
        if (count > (reader->node_size - EDGE_BTRFS_HEADER_SIZE) /
                        EDGE_BTRFS_KEY_POINTER_SIZE)
            return -13;
        for (uint32_t index = 0; index < count; ++index) {
            const uint8_t *pointer = node + EDGE_BTRFS_HEADER_SIZE +
                                     index * EDGE_BTRFS_KEY_POINTER_SIZE;
            int result = btrfs_tree_walk(
                reader, btrfs_le64(pointer + EDGE_BTRFS_KEY_SIZE),
                depth + 1u, callback, context);
            if (result != 0) return result;
        }
        return 0;
    }
    if (count > (reader->node_size - EDGE_BTRFS_HEADER_SIZE) /
                    EDGE_BTRFS_LEAF_ITEM_SIZE)
        return -14;
    for (uint32_t index = 0; index < count; ++index) {
        const uint8_t *item = node + EDGE_BTRFS_HEADER_SIZE +
                              index * EDGE_BTRFS_LEAF_ITEM_SIZE;
        edge_btrfs_key_t key;
        uint32_t offset = btrfs_le32(item + EDGE_BTRFS_KEY_SIZE);
        uint32_t size = btrfs_le32(item + EDGE_BTRFS_KEY_SIZE + 4u);
        int result;
        if (offset > reader->node_size - EDGE_BTRFS_HEADER_SIZE ||
            size > reader->node_size - EDGE_BTRFS_HEADER_SIZE - offset)
            return -15;
        btrfs_key_decode(item, &key);
        result = callback(reader, &key,
                          node + EDGE_BTRFS_HEADER_SIZE + offset,
                          size, context);
        if (result != 0) return result;
    }
    return 0;
}

static int btrfs_chunk_callback(edge_btrfs_reader_t *reader,
                                const edge_btrfs_key_t *key,
                                const uint8_t *data, uint32_t size,
                                void *context) {
    (void)context;
    if (key->type != EDGE_BTRFS_CHUNK_ITEM_KEY ||
        key->objectid != EDGE_BTRFS_FIRST_CHUNK_OBJECTID)
        return 0;
    return btrfs_chunk_parse(reader, key->offset, data, size);
}

typedef struct btrfs_root_search {
    uint64_t bytenr;
    uint64_t generation;
    uint8_t level;
    uint8_t found;
} btrfs_root_search_t;

static int btrfs_root_callback(edge_btrfs_reader_t *reader,
                               const edge_btrfs_key_t *key,
                               const uint8_t *data, uint32_t size,
                               void *context) {
    btrfs_root_search_t *search = context;
    uint64_t generation;
    (void)reader;

    if (key->objectid != EDGE_BTRFS_FS_TREE_OBJECTID ||
        key->type != EDGE_BTRFS_ROOT_ITEM_KEY || size < 239u)
        return 0;
    generation = btrfs_le64(data + 160);
    if (!search->found || generation >= search->generation) {
        search->bytenr = btrfs_le64(data + 176);
        search->generation = generation;
        search->level = data[238];
        search->found = 1u;
    }
    return 0;
}

static int btrfs_reader_init_unlocked(edge_btrfs_reader_t *reader,
                                      block_device_t *device) {
    uint8_t *superblock = g_btrfs_super_scratch;
    uint32_t sys_size;
    uint32_t cursor = 0;
    int tree_result;
    btrfs_root_search_t root_search;

    if (!reader || !device) return -1;
    memset(reader, 0, sizeof(*reader));
    reader->device = device;
    reader->device_bytes = block_device_size_bytes(device);
    if (reader->device_bytes < EDGE_BTRFS_SUPER_OFFSET +
                                   EDGE_BTRFS_SUPER_SIZE ||
        btrfs_read_physical(reader, EDGE_BTRFS_SUPER_OFFSET,
                            superblock, EDGE_BTRFS_SUPER_SIZE) < 0 ||
        memcmp(superblock + EDGE_BTRFS_SUPER_MAGIC_OFFSET,
               "_BHRfS_M", 8u) != 0 ||
        btrfs_le16(superblock + EDGE_BTRFS_SUPER_CSUM_TYPE_OFFSET) != 0)
        return -2;
    reader->root_tree = btrfs_le64(
        superblock + EDGE_BTRFS_SUPER_ROOT_OFFSET);
    reader->chunk_tree = btrfs_le64(
        superblock + EDGE_BTRFS_SUPER_CHUNK_ROOT_OFFSET);
    reader->total_bytes = btrfs_le64(
        superblock + EDGE_BTRFS_SUPER_TOTAL_BYTES_OFFSET);
    reader->bytes_used = btrfs_le64(
        superblock + EDGE_BTRFS_SUPER_BYTES_USED_OFFSET);
    reader->sector_size = btrfs_le32(
        superblock + EDGE_BTRFS_SUPER_SECTOR_SIZE_OFFSET);
    reader->node_size = btrfs_le32(
        superblock + EDGE_BTRFS_SUPER_NODE_SIZE_OFFSET);
    reader->compat_ro_flags = btrfs_le64(
        superblock + EDGE_BTRFS_SUPER_COMPAT_RO_OFFSET);
    reader->incompat_flags = btrfs_le64(
        superblock + EDGE_BTRFS_SUPER_INCOMPAT_OFFSET);
    reader->root_level = superblock[EDGE_BTRFS_SUPER_ROOT_LEVEL_OFFSET];
    reader->chunk_level = superblock[EDGE_BTRFS_SUPER_CHUNK_LEVEL_OFFSET];
    sys_size = btrfs_le32(
        superblock + EDGE_BTRFS_SUPER_SYS_SIZE_OFFSET);
    if (!reader->root_tree || !reader->chunk_tree ||
        reader->total_bytes > reader->device_bytes ||
        reader->bytes_used > reader->total_bytes ||
        reader->sector_size < 4096u ||
        (reader->sector_size & (reader->sector_size - 1u)) ||
        reader->node_size < reader->sector_size ||
        reader->node_size > 65536u ||
        (reader->node_size & (reader->node_size - 1u)) ||
        sys_size > EDGE_BTRFS_SUPER_SIZE -
                       EDGE_BTRFS_SUPER_SYS_ARRAY_OFFSET ||
        (reader->incompat_flags & EDGE_BTRFS_UNSUPPORTED_INCOMPAT))
        return -3;
    while (cursor < sys_size) {
        const uint8_t *item = superblock +
                              EDGE_BTRFS_SUPER_SYS_ARRAY_OFFSET + cursor;
        edge_btrfs_key_t key;
        uint16_t stripes;
        uint32_t chunk_size;
        if (sys_size - cursor < EDGE_BTRFS_KEY_SIZE + 48u) return -4;
        btrfs_key_decode(item, &key);
        stripes = btrfs_le16(item + EDGE_BTRFS_KEY_SIZE + 44u);
        chunk_size = 48u + (uint32_t)stripes * 32u;
        if (key.type != EDGE_BTRFS_CHUNK_ITEM_KEY || !stripes ||
            chunk_size > sys_size - cursor - EDGE_BTRFS_KEY_SIZE ||
            btrfs_chunk_parse(reader, key.offset,
                              item + EDGE_BTRFS_KEY_SIZE,
                              chunk_size) < 0)
            return -4;
        cursor += EDGE_BTRFS_KEY_SIZE + chunk_size;
    }
    if (!reader->chunk_count) return -5;
    tree_result = btrfs_tree_walk(reader, reader->chunk_tree, 0,
                                  btrfs_chunk_callback, 0);
    if (tree_result < 0) return tree_result;
    memset(&root_search, 0, sizeof(root_search));
    tree_result = btrfs_tree_walk(reader, reader->root_tree, 0,
                                  btrfs_root_callback, &root_search);
    if (tree_result < 0 ||
        !root_search.found || !root_search.bytenr)
        return tree_result < 0 ? tree_result : -6;
    reader->fs_tree = root_search.bytenr;
    reader->fs_level = root_search.level;
    return 0;
}

int edge_btrfs_reader_init(edge_btrfs_reader_t *reader,
                           block_device_t *device) {
    int result;
    btrfs_reader_lock();
    result = btrfs_reader_init_unlocked(reader, device);
    btrfs_reader_unlock();
    return result;
}

typedef struct btrfs_inode_search {
    uint64_t number;
    edge_btrfs_inode_t *inode;
    uint8_t found;
} btrfs_inode_search_t;

static int btrfs_inode_callback(edge_btrfs_reader_t *reader,
                                const edge_btrfs_key_t *key,
                                const uint8_t *data, uint32_t size,
                                void *context) {
    btrfs_inode_search_t *search = context;
    edge_btrfs_inode_t *inode = search->inode;
    (void)reader;

    if (key->objectid != search->number ||
        key->type != EDGE_BTRFS_INODE_ITEM_KEY || size < 160u)
        return 0;
    memset(inode, 0, sizeof(*inode));
    inode->number = search->number;
    inode->generation = btrfs_le64(data);
    inode->size = btrfs_le64(data + 16);
    inode->bytes = btrfs_le64(data + 24);
    inode->link_count = btrfs_le32(data + 40);
    inode->uid = btrfs_le32(data + 44);
    inode->gid = btrfs_le32(data + 48);
    inode->mode = btrfs_le32(data + 52);
    inode->atime = (int64_t)btrfs_le64(data + 112);
    inode->ctime = (int64_t)btrfs_le64(data + 124);
    inode->mtime = (int64_t)btrfs_le64(data + 136);
    search->found = 1u;
    return 1;
}

static int btrfs_inode_load_unlocked(edge_btrfs_reader_t *reader,
                                     uint64_t inode_number,
                                     edge_btrfs_inode_t *inode) {
    btrfs_inode_search_t search;
    int result;

    if (!reader || !inode || !inode_number) return -1;
    memset(&search, 0, sizeof(search));
    search.number = inode_number;
    search.inode = inode;
    result = btrfs_tree_walk(
        reader, reader->fs_tree, 0, btrfs_inode_callback, &search);
    return (result == 1 && search.found) ? 0 : -1;
}

int edge_btrfs_inode_load(edge_btrfs_reader_t *reader,
                          uint64_t inode_number,
                          edge_btrfs_inode_t *inode) {
    int result;
    btrfs_reader_lock();
    result = btrfs_inode_load_unlocked(reader, inode_number, inode);
    btrfs_reader_unlock();
    return result;
}

typedef struct btrfs_extent_read {
    uint64_t inode_number;
    uint64_t offset;
    uint32_t length;
    uint8_t *output;
    uint8_t failed;
} btrfs_extent_read_t;

static int btrfs_extent_callback(edge_btrfs_reader_t *reader,
                                 const edge_btrfs_key_t *key,
                                 const uint8_t *data, uint32_t size,
                                 void *context) {
    btrfs_extent_read_t *read = context;
    uint64_t extent_start;
    uint64_t extent_length;
    uint64_t request_end = read->offset + read->length;
    uint64_t overlap_start;
    uint64_t overlap_end;
    uint64_t source;
    uint8_t compression;
    uint8_t type;

    if (key->objectid != read->inode_number ||
        key->type != EDGE_BTRFS_EXTENT_DATA_KEY || size < 21u)
        return 0;
    compression = data[16];
    type = data[20];
    extent_start = key->offset;
    if (type == EDGE_BTRFS_FILE_EXTENT_INLINE) {
        extent_length = btrfs_le64(data + 8);
        if (!extent_length || extent_length > size - 21u)
            extent_length = size - 21u;
        if (compression) {
            if (request_end > extent_start &&
                read->offset < extent_start + extent_length)
                read->failed = 1u;
            return read->failed ? -1 : 0;
        }
        overlap_start = read->offset > extent_start ?
                            read->offset : extent_start;
        overlap_end = request_end < extent_start + extent_length ?
                          request_end : extent_start + extent_length;
        if (overlap_start < overlap_end)
            memcpy(read->output + (overlap_start - read->offset),
                   data + 21u + (overlap_start - extent_start),
                   (uint32_t)(overlap_end - overlap_start));
        return 0;
    }
    if (size < 53u) return -1;
    extent_length = btrfs_le64(data + 45);
    overlap_start = read->offset > extent_start ? read->offset : extent_start;
    overlap_end = request_end < extent_start + extent_length ?
                      request_end : extent_start + extent_length;
    if (overlap_start >= overlap_end ||
        type == EDGE_BTRFS_FILE_EXTENT_PREALLOC)
        return 0;
    if (compression || type != EDGE_BTRFS_FILE_EXTENT_REGULAR) {
        read->failed = 1u;
        return -1;
    }
    source = btrfs_le64(data + 21);
    if (!source) return 0;
    source += btrfs_le64(data + 37) + overlap_start - extent_start;
    if (btrfs_read_logical(
            reader, source,
            read->output + (overlap_start - read->offset),
            (uint32_t)(overlap_end - overlap_start)) < 0) {
        read->failed = 1u;
        return -1;
    }
    return 0;
}

static int64_t btrfs_inode_read_unlocked(edge_btrfs_reader_t *reader,
                                         const edge_btrfs_inode_t *inode,
                                         uint64_t offset, void *buffer,
                                         uint32_t length) {
    btrfs_extent_read_t read;
    uint64_t remaining;
    int result;

    if (!reader || !inode || (!buffer && length)) return -1;
    if (offset >= inode->size || !length) return 0;
    remaining = inode->size - offset;
    if (remaining < length) length = (uint32_t)remaining;
    memset(buffer, 0, length);
    memset(&read, 0, sizeof(read));
    read.inode_number = inode->number;
    read.offset = offset;
    read.length = length;
    read.output = buffer;
    result = btrfs_tree_walk(
        reader, reader->fs_tree, 0, btrfs_extent_callback, &read);
    return (result < 0 || read.failed) ? -1 : (int64_t)length;
}

int64_t edge_btrfs_inode_read(edge_btrfs_reader_t *reader,
                              const edge_btrfs_inode_t *inode,
                              uint64_t offset, void *buffer,
                              uint32_t length) {
    int64_t result;
    btrfs_reader_lock();
    result = btrfs_inode_read_unlocked(
        reader, inode, offset, buffer, length);
    btrfs_reader_unlock();
    return result;
}

typedef struct btrfs_directory_search {
    uint64_t inode_number;
    uint32_t wanted_index;
    uint32_t current_index;
    const char *wanted_name;
    edge_btrfs_directory_entry_t *entry;
    uint64_t *result_inode;
    uint8_t found;
} btrfs_directory_search_t;

static int btrfs_directory_callback(edge_btrfs_reader_t *reader,
                                    const edge_btrfs_key_t *key,
                                    const uint8_t *data, uint32_t size,
                                    void *context) {
    btrfs_directory_search_t *search = context;
    uint32_t cursor = 0;
    (void)reader;

    if (key->objectid != search->inode_number ||
        key->type != EDGE_BTRFS_DIR_INDEX_KEY)
        return 0;
    while (cursor < size) {
        const uint8_t *item = data + cursor;
        uint16_t data_length;
        uint16_t name_length;
        uint32_t item_size;
        if (size - cursor < 30u) return -1;
        data_length = btrfs_le16(item + 25);
        name_length = btrfs_le16(item + 27);
        item_size = 30u + data_length + name_length;
        if (!name_length || name_length >= 256u ||
            item_size > size - cursor)
            return -1;
        if (search->wanted_name) {
            uint32_t wanted_length = (uint32_t)strlen(search->wanted_name);
            if (wanted_length == name_length &&
                memcmp(item + 30, search->wanted_name, name_length) == 0) {
                *search->result_inode = btrfs_le64(item);
                search->found = 1u;
                return 1;
            }
        } else if (search->current_index++ == search->wanted_index) {
            search->entry->inode_number = btrfs_le64(item);
            search->entry->file_type = item[29];
            memcpy(search->entry->name, item + 30, name_length);
            search->entry->name[name_length] = 0;
            search->found = 1u;
            return 1;
        }
        cursor += item_size;
    }
    return 0;
}

static int btrfs_directory_entry_unlocked(
    edge_btrfs_reader_t *reader, const edge_btrfs_inode_t *directory,
    uint32_t index, edge_btrfs_directory_entry_t *entry) {
    btrfs_directory_search_t search;
    int result;

    if (!reader || !directory || !entry) return -1;
    memset(&search, 0, sizeof(search));
    search.inode_number = directory->number;
    search.wanted_index = index;
    search.entry = entry;
    result = btrfs_tree_walk(
        reader, reader->fs_tree, 0, btrfs_directory_callback, &search);
    return (result == 1 && search.found) ? 0 : -2;
}

int edge_btrfs_directory_entry(edge_btrfs_reader_t *reader,
                               const edge_btrfs_inode_t *directory,
                               uint32_t index,
                               edge_btrfs_directory_entry_t *entry) {
    int result;
    btrfs_reader_lock();
    result = btrfs_directory_entry_unlocked(
        reader, directory, index, entry);
    btrfs_reader_unlock();
    return result;
}

static int btrfs_directory_lookup_unlocked(
    edge_btrfs_reader_t *reader, const edge_btrfs_inode_t *directory,
    const char *name, uint64_t *inode_number) {
    btrfs_directory_search_t search;
    int result;

    if (!reader || !directory || !name || !inode_number) return -1;
    memset(&search, 0, sizeof(search));
    search.inode_number = directory->number;
    search.wanted_name = name;
    search.result_inode = inode_number;
    result = btrfs_tree_walk(
        reader, reader->fs_tree, 0, btrfs_directory_callback, &search);
    return (result == 1 && search.found) ? 0 : -1;
}

int edge_btrfs_directory_lookup(edge_btrfs_reader_t *reader,
                                const edge_btrfs_inode_t *directory,
                                const char *name,
                                uint64_t *inode_number) {
    int result;
    btrfs_reader_lock();
    result = btrfs_directory_lookup_unlocked(
        reader, directory, name, inode_number);
    btrfs_reader_unlock();
    return result;
}
