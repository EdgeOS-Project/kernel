/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS device-mapper implementation.
 *
 * The control plane follows the stable Linux dm-ioctl userspace ABI.  The
 * mapping engine is architecture-neutral and operates in Linux 512-byte
 * sectors even when a backing device uses a different native sector size.
 */

#include <stdint.h>

#include "block/block.h"
#include "block/device_mapper.h"
#include "dev/devtmpfs.h"
#include "kernel/linux_errno.h"
#include "lib/aes.h"
#include "stdio.h"
#include "string.h"

#define EDGE_DM_MAX_TARGETS 32u
#define EDGE_DM_MAX_STRIPES 8u
#define EDGE_DM_IOCTL_BUFFER_SIZE (64u * 1024u)
#define EDGE_DM_SECTOR_SIZE 512u

enum edge_dm_target_kind {
    EDGE_DM_TARGET_LINEAR = 1,
    EDGE_DM_TARGET_ZERO,
    EDGE_DM_TARGET_ERROR,
    EDGE_DM_TARGET_STRIPED,
    EDGE_DM_TARGET_CRYPT
};

typedef struct edge_dm_stripe {
    block_device_t *device;
    uint64_t start_sector;
} edge_dm_stripe_t;

typedef struct edge_dm_target {
    uint64_t start;
    uint64_t length;
    uint32_t kind;
    uint32_t stripe_count;
    uint64_t chunk_sectors;
    uint64_t iv_offset;
    edge_aes_context_t crypt_data;
    edge_aes_context_t crypt_tweak;
    edge_dm_stripe_t stripes[EDGE_DM_MAX_STRIPES];
} edge_dm_target_t;

typedef struct edge_dm_table {
    uint32_t target_count;
    uint32_t read_only;
    uint64_t sectors;
    edge_dm_target_t targets[EDGE_DM_MAX_TARGETS];
    uint8_t present;
} edge_dm_table_t;

typedef struct edge_dm_device {
    volatile uint32_t lock;
    uint32_t minor;
    uint32_t active_io;
    uint32_t event_number;
    uint8_t used;
    uint8_t suspended;
    uint8_t removing;
    uint8_t reserved;
    char name[EDGE_DM_NAME_LEN];
    char uuid[EDGE_DM_UUID_LEN];
    block_device_t *block_device;
    edge_dm_table_t active;
    edge_dm_table_t inactive;
} edge_dm_device_t;

typedef struct edge_dm_name_list {
    uint64_t device;
    uint32_t next;
} edge_dm_name_list_t;

typedef struct edge_dm_target_versions {
    uint32_t next;
    uint32_t version[3];
} edge_dm_target_versions_t;

static edge_dm_device_t g_dm_devices[EDGE_DM_MAX_DEVICES];
static volatile uint32_t g_dm_global_lock;
static volatile uint32_t g_dm_ioctl_lock;
static uint8_t g_dm_ioctl_buffer[EDGE_DM_IOCTL_BUFFER_SIZE];
static edge_dm_table_t g_dm_table_scratch;

static uint64_t edge_dm_linux_device_number(uint32_t major, uint32_t minor) {
    return ((uint64_t)(minor & 0xffu)) |
           ((uint64_t)(major & 0xfffu) << 8) |
           ((uint64_t)(minor & ~0xffu) << 12) |
           ((uint64_t)(major & ~0xfffu) << 32);
}

static uint32_t edge_dm_linux_major(uint64_t device) {
    return (uint32_t)((device >> 8) & 0xfffu) |
           (uint32_t)((device >> 32) & 0xfffff000u);
}

static uint32_t edge_dm_linux_minor(uint64_t device) {
    return (uint32_t)(device & 0xffu) |
           (uint32_t)((device >> 12) & 0xffffff00u);
}

static void edge_dm_spin_lock(volatile uint32_t *lock) {
    while (__atomic_exchange_n(lock, 1u, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(lock, __ATOMIC_RELAXED))
            __asm__ __volatile__("" ::: "memory");
    }
}

static void edge_dm_spin_unlock(volatile uint32_t *lock) {
    __atomic_store_n(lock, 0u, __ATOMIC_RELEASE);
}

static void edge_dm_lock(edge_dm_device_t *device) {
    edge_dm_spin_lock(&device->lock);
}

static void edge_dm_unlock(edge_dm_device_t *device) {
    edge_dm_spin_unlock(&device->lock);
}

static uint32_t edge_dm_align8(uint32_t value) {
    return (value + 7u) & ~7u;
}

static int edge_dm_copy_string(char *destination, uint32_t capacity,
                               const char *source) {
    uint32_t length = 0;

    if (!destination || !capacity || !source) return -1;
    while (source[length]) {
        if (length + 1u >= capacity) return -1;
        destination[length] = source[length];
        length++;
    }
    destination[length] = 0;
    return 0;
}

static int edge_dm_bounded_string(const char *text, uint32_t capacity) {
    if (!text || !capacity) return 0;
    for (uint32_t index = 0; index < capacity; ++index)
        if (!text[index]) return 1;
    return 0;
}

static int edge_dm_valid_name(const char *name) {
    uint32_t length = 0;

    if (!name || !name[0]) return 0;
    while (name[length]) {
        char value = name[length++];
        if (length >= EDGE_DM_NAME_LEN || value == '/' || value == '\n' ||
            value == '\r' || value == '\t')
            return 0;
    }
    return 1;
}

static int edge_dm_parse_u64(const char **cursor, uint64_t *value) {
    const char *text;
    uint64_t result = 0;
    uint32_t digits = 0;

    if (!cursor || !*cursor || !value) return -1;
    text = *cursor;
    while (*text == ' ' || *text == '\t') text++;
    while (*text >= '0' && *text <= '9') {
        uint32_t digit = (uint32_t)(*text++ - '0');
        if (result > (UINT64_MAX - digit) / 10u) return -1;
        result = result * 10u + digit;
        digits++;
    }
    if (!digits) return -1;
    *cursor = text;
    *value = result;
    return 0;
}

static int edge_dm_next_word(const char **cursor, char *output,
                             uint32_t capacity) {
    const char *text;
    uint32_t length = 0;

    if (!cursor || !*cursor || !output || capacity < 2u) return -1;
    text = *cursor;
    while (*text == ' ' || *text == '\t') text++;
    while (*text && *text != ' ' && *text != '\t') {
        if (length + 1u >= capacity) return -1;
        output[length++] = *text++;
    }
    if (!length) return -1;
    output[length] = 0;
    *cursor = text;
    return 0;
}

static int edge_dm_no_more_words(const char *cursor) {
    if (!cursor) return 0;
    while (*cursor == ' ' || *cursor == '\t') cursor++;
    return *cursor == 0;
}

static block_device_t *edge_dm_parse_block_device(const char *word) {
    const char *cursor = word;
    uint64_t major;
    uint64_t minor;

    if (!word || !word[0]) return 0;
    if (word[0] == '/') {
        const char *name = word;
        const char *scan = word;
        while (*scan) {
            if (*scan == '/' && scan[1]) name = scan + 1;
            scan++;
        }
        return block_find(name);
    }
    if (edge_dm_parse_u64(&cursor, &major) == 0 && *cursor == ':') {
        cursor++;
        if (edge_dm_parse_u64(&cursor, &minor) == 0 &&
            edge_dm_no_more_words(cursor) && major <= UINT32_MAX &&
            minor <= UINT32_MAX)
            return block_find_linux_device(edge_dm_linux_device_number(
                (uint32_t)major, (uint32_t)minor));
    }
    return block_find(word);
}

static edge_dm_device_t *edge_dm_find_minor(uint32_t minor) {
    if (minor >= EDGE_DM_MAX_DEVICES || !g_dm_devices[minor].used) return 0;
    return &g_dm_devices[minor];
}

static edge_dm_device_t *edge_dm_find_name(const char *name) {
    if (!name || !name[0]) return 0;
    for (uint32_t index = 0; index < EDGE_DM_MAX_DEVICES; ++index)
        if (g_dm_devices[index].used &&
            strcmp(g_dm_devices[index].name, name) == 0)
            return &g_dm_devices[index];
    return 0;
}

static edge_dm_device_t *edge_dm_find_uuid(const char *uuid) {
    if (!uuid || !uuid[0]) return 0;
    for (uint32_t index = 0; index < EDGE_DM_MAX_DEVICES; ++index)
        if (g_dm_devices[index].used && g_dm_devices[index].uuid[0] &&
            strcmp(g_dm_devices[index].uuid, uuid) == 0)
            return &g_dm_devices[index];
    return 0;
}

static edge_dm_device_t *edge_dm_lookup(const edge_dm_ioctl_t *io) {
    uint32_t major;
    uint32_t minor;

    if (!io) return 0;
    if (io->uuid[0]) return edge_dm_find_uuid(io->uuid);
    if (io->name[0]) return edge_dm_find_name(io->name);
    major = edge_dm_linux_major(io->device);
    minor = edge_dm_linux_minor(io->device);
    return major == EDGE_DM_BLOCK_MAJOR ? edge_dm_find_minor(minor) : 0;
}

static int edge_dm_table_backend_is_self(const edge_dm_device_t *owner,
                                         const block_device_t *backend) {
    return owner && backend && owner->block_device == backend;
}

static int edge_dm_parse_linear(edge_dm_device_t *owner,
                                edge_dm_target_t *target,
                                const char *parameters) {
    char device_word[64];
    uint64_t offset;
    block_device_t *backend;

    if (edge_dm_next_word(&parameters, device_word, sizeof(device_word)) < 0 ||
        edge_dm_parse_u64(&parameters, &offset) < 0 ||
        !edge_dm_no_more_words(parameters))
        return -EDGE_LINUX_EINVAL;
    backend = edge_dm_parse_block_device(device_word);
    if (!backend) return -EDGE_LINUX_ENODEV;
    if (edge_dm_table_backend_is_self(owner, backend))
        return -EDGE_LINUX_ELOOP;
    if (offset > block_device_size_bytes(backend) / EDGE_DM_SECTOR_SIZE ||
        target->length >
            block_device_size_bytes(backend) / EDGE_DM_SECTOR_SIZE - offset)
        return -EDGE_LINUX_EINVAL;
    target->kind = EDGE_DM_TARGET_LINEAR;
    target->stripe_count = 1;
    target->stripes[0].device = backend;
    target->stripes[0].start_sector = offset;
    return 0;
}

static int edge_dm_parse_striped(edge_dm_device_t *owner,
                                 edge_dm_target_t *target,
                                 const char *parameters) {
    uint64_t stripe_count;
    uint64_t chunk_size;

    if (edge_dm_parse_u64(&parameters, &stripe_count) < 0 ||
        edge_dm_parse_u64(&parameters, &chunk_size) < 0 ||
        !stripe_count || stripe_count > EDGE_DM_MAX_STRIPES || !chunk_size)
        return -EDGE_LINUX_EINVAL;
    if (target->length % (stripe_count * chunk_size) != 0)
        return -EDGE_LINUX_EINVAL;
    target->kind = EDGE_DM_TARGET_STRIPED;
    target->stripe_count = (uint32_t)stripe_count;
    target->chunk_sectors = chunk_size;
    for (uint32_t stripe = 0; stripe < target->stripe_count; ++stripe) {
        char device_word[64];
        uint64_t offset;
        uint64_t required;
        block_device_t *backend;

        if (edge_dm_next_word(&parameters, device_word,
                              sizeof(device_word)) < 0 ||
            edge_dm_parse_u64(&parameters, &offset) < 0)
            return -EDGE_LINUX_EINVAL;
        backend = edge_dm_parse_block_device(device_word);
        if (!backend) return -EDGE_LINUX_ENODEV;
        if (edge_dm_table_backend_is_self(owner, backend))
            return -EDGE_LINUX_ELOOP;
        required = target->length / target->stripe_count;
        if (offset >
                block_device_size_bytes(backend) / EDGE_DM_SECTOR_SIZE ||
            required >
                block_device_size_bytes(backend) /
                    EDGE_DM_SECTOR_SIZE - offset)
            return -EDGE_LINUX_EINVAL;
        target->stripes[stripe].device = backend;
        target->stripes[stripe].start_sector = offset;
    }
    return edge_dm_no_more_words(parameters) ? 0 : -EDGE_LINUX_EINVAL;
}

static int edge_dm_hex_value(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int edge_dm_decode_key(const char *text, uint8_t *key,
                              uint32_t *key_bytes) {
    uint32_t length = 0;

    if (!text || !key || !key_bytes) return -1;
    while (text[length]) length++;
    if (length != 64u && length != 128u) return -1;
    for (uint32_t index = 0; index < length / 2u; ++index) {
        int high = edge_dm_hex_value(text[index * 2u]);
        int low = edge_dm_hex_value(text[index * 2u + 1u]);
        if (high < 0 || low < 0) return -1;
        key[index] = (uint8_t)((uint32_t)high << 4 | (uint32_t)low);
    }
    *key_bytes = length / 2u;
    return 0;
}

static void edge_dm_clear_key(uint8_t *key, uint32_t bytes) {
    volatile uint8_t *output = key;
    while (bytes--) *output++ = 0;
}

static int edge_dm_parse_crypt(edge_dm_device_t *owner,
                               edge_dm_target_t *target,
                               const char *parameters) {
    char cipher[32];
    char key_text[129];
    char device_word[64];
    char option[64];
    uint8_t key[64];
    uint32_t key_bytes = 0;
    uint64_t iv_offset;
    uint64_t offset;
    uint64_t option_count = 0;
    block_device_t *backend;
    int result = -EDGE_LINUX_EINVAL;

    memset(key, 0, sizeof(key));
    if (edge_dm_next_word(&parameters, cipher, sizeof(cipher)) < 0 ||
        strcmp(cipher, "aes-xts-plain64") != 0 ||
        edge_dm_next_word(&parameters, key_text, sizeof(key_text)) < 0 ||
        edge_dm_decode_key(key_text, key, &key_bytes) < 0 ||
        edge_dm_parse_u64(&parameters, &iv_offset) < 0 ||
        edge_dm_next_word(&parameters, device_word, sizeof(device_word)) < 0 ||
        edge_dm_parse_u64(&parameters, &offset) < 0)
        goto out;
    if (!edge_dm_no_more_words(parameters)) {
        if (edge_dm_parse_u64(&parameters, &option_count) < 0 ||
            option_count > 16u)
            goto out;
        for (uint64_t index = 0; index < option_count; ++index) {
            if (edge_dm_next_word(&parameters, option, sizeof(option)) < 0)
                goto out;
            if (strcmp(option, "allow_discards") != 0 &&
                strcmp(option, "same_cpu_crypt") != 0 &&
                strcmp(option, "submit_from_crypt_cpus") != 0 &&
                strcmp(option, "no_read_workqueue") != 0 &&
                strcmp(option, "no_write_workqueue") != 0 &&
                strcmp(option, "sector_size:512") != 0)
                goto out;
        }
        if (!edge_dm_no_more_words(parameters)) goto out;
    }
    backend = edge_dm_parse_block_device(device_word);
    if (!backend) {
        result = -EDGE_LINUX_ENODEV;
        goto out;
    }
    if (edge_dm_table_backend_is_self(owner, backend)) {
        result = -EDGE_LINUX_ELOOP;
        goto out;
    }
    if (offset > block_device_size_bytes(backend) / EDGE_DM_SECTOR_SIZE ||
        target->length > block_device_size_bytes(backend) /
                             EDGE_DM_SECTOR_SIZE - offset)
        goto out;
    if (edge_aes_initialize(&target->crypt_data, key,
                            key_bytes / 2u) < 0 ||
        edge_aes_initialize(&target->crypt_tweak, key + key_bytes / 2u,
                            key_bytes / 2u) < 0)
        goto out;
    target->kind = EDGE_DM_TARGET_CRYPT;
    target->stripe_count = 1u;
    target->iv_offset = iv_offset;
    target->stripes[0].device = backend;
    target->stripes[0].start_sector = offset;
    result = 0;

out:
    edge_dm_clear_key(key, sizeof(key));
    return result;
}

static int edge_dm_parse_target(edge_dm_device_t *owner,
                                edge_dm_target_t *target,
                                const edge_dm_target_spec_t *spec,
                                const char *parameters) {
    memset(target, 0, sizeof(*target));
    target->start = spec->sector_start;
    target->length = spec->length;
    if (!target->length || target->start > UINT64_MAX - target->length)
        return -EDGE_LINUX_EINVAL;
    if (strcmp(spec->target_type, "linear") == 0)
        return edge_dm_parse_linear(owner, target, parameters);
    if (strcmp(spec->target_type, "zero") == 0) {
        if (!edge_dm_no_more_words(parameters)) return -EDGE_LINUX_EINVAL;
        target->kind = EDGE_DM_TARGET_ZERO;
        return 0;
    }
    if (strcmp(spec->target_type, "error") == 0) {
        if (!edge_dm_no_more_words(parameters)) return -EDGE_LINUX_EINVAL;
        target->kind = EDGE_DM_TARGET_ERROR;
        return 0;
    }
    if (strcmp(spec->target_type, "striped") == 0)
        return edge_dm_parse_striped(owner, target, parameters);
    if (strcmp(spec->target_type, "crypt") == 0)
        return edge_dm_parse_crypt(owner, target, parameters);
    return -EDGE_LINUX_EOPNOTSUPP;
}

static int edge_dm_parse_table(edge_dm_device_t *device,
                               edge_dm_ioctl_t *io,
                               edge_dm_table_t *table) {
    uint8_t *base = (uint8_t *)io;
    uint32_t offset = io->data_start;
    uint64_t expected_start = 0;

    if (!io->target_count || io->target_count > EDGE_DM_MAX_TARGETS ||
        offset < sizeof(*io) || offset >= io->data_size)
        return -EDGE_LINUX_EINVAL;
    memset(table, 0, sizeof(*table));
    for (uint32_t index = 0; index < io->target_count; ++index) {
        edge_dm_target_spec_t *spec;
        uint32_t record_end;
        uint32_t parameter_capacity;
        const char *parameters;
        int result;

        if (offset > io->data_size - sizeof(*spec))
            return -EDGE_LINUX_EINVAL;
        spec = (edge_dm_target_spec_t *)(base + offset);
        if (!edge_dm_bounded_string(spec->target_type,
                                    sizeof(spec->target_type)))
            return -EDGE_LINUX_EINVAL;
        if (spec->next) {
            if (spec->next < sizeof(*spec) || spec->next > io->data_size - offset)
                return -EDGE_LINUX_EINVAL;
            record_end = offset + spec->next;
        } else {
            if (index + 1u != io->target_count)
                return -EDGE_LINUX_EINVAL;
            record_end = io->data_size;
        }
        parameter_capacity = record_end - offset - sizeof(*spec);
        parameters = (const char *)(spec + 1);
        if (!edge_dm_bounded_string(parameters, parameter_capacity))
            return -EDGE_LINUX_EINVAL;
        if (spec->sector_start != expected_start)
            return -EDGE_LINUX_EINVAL;
        result = edge_dm_parse_target(
            device, &table->targets[index], spec, parameters);
        if (result < 0) return result;
        expected_start = spec->sector_start + spec->length;
        offset = record_end;
    }
    if (!expected_start || expected_start > UINT32_MAX)
        return -EDGE_LINUX_EOVERFLOW;
    table->target_count = io->target_count;
    table->sectors = expected_start;
    table->read_only = (io->flags & EDGE_DM_READONLY_FLAG) != 0;
    table->present = 1;
    return 0;
}

static const edge_dm_target_t *edge_dm_target_for_sector(
    const edge_dm_table_t *table, uint64_t sector) {
    if (!table || !table->present) return 0;
    for (uint32_t index = 0; index < table->target_count; ++index) {
        const edge_dm_target_t *target = &table->targets[index];
        if (sector >= target->start &&
            sector - target->start < target->length)
            return target;
    }
    return 0;
}

static int edge_dm_begin_io(edge_dm_device_t *device,
                            const edge_dm_table_t **table) {
    edge_dm_lock(device);
    if (!device->used || device->removing || device->suspended ||
        !device->active.present) {
        edge_dm_unlock(device);
        return -1;
    }
    device->active_io++;
    *table = &device->active;
    edge_dm_unlock(device);
    return 0;
}

static void edge_dm_end_io(edge_dm_device_t *device) {
    edge_dm_lock(device);
    if (device->active_io) device->active_io--;
    edge_dm_unlock(device);
}

static uint32_t edge_dm_target_chunk(const edge_dm_target_t *target,
                                     uint64_t sector, uint32_t remaining) {
    uint64_t within = sector - target->start;
    uint64_t available = target->length - within;

    if (available < remaining) remaining = (uint32_t)available;
    if (target->kind == EDGE_DM_TARGET_STRIPED) {
        uint64_t chunk_left = target->chunk_sectors -
                              (within % target->chunk_sectors);
        if (chunk_left < remaining) remaining = (uint32_t)chunk_left;
    }
    if (target->kind == EDGE_DM_TARGET_CRYPT && remaining > 1u)
        remaining = 1u;
    return remaining;
}

static int edge_dm_target_backend(const edge_dm_target_t *target,
                                  uint64_t sector,
                                  block_device_t **backend,
                                  uint64_t *backend_sector) {
    uint64_t within = sector - target->start;

    if (target->kind == EDGE_DM_TARGET_LINEAR ||
        target->kind == EDGE_DM_TARGET_CRYPT) {
        *backend = target->stripes[0].device;
        *backend_sector = target->stripes[0].start_sector + within;
        return 0;
    }
    if (target->kind == EDGE_DM_TARGET_STRIPED) {
        uint64_t stripe_chunk = within / target->chunk_sectors;
        uint32_t stripe = (uint32_t)(stripe_chunk % target->stripe_count);
        uint64_t row = stripe_chunk / target->stripe_count;
        *backend = target->stripes[stripe].device;
        *backend_sector = target->stripes[stripe].start_sector +
                          row * target->chunk_sectors +
                          within % target->chunk_sectors;
        return 0;
    }
    return -1;
}

static void edge_dm_xts_multiply(uint8_t tweak[16]) {
    uint8_t carry = 0;

    for (uint32_t index = 0; index < 16u; ++index) {
        uint8_t next = (uint8_t)(tweak[index] >> 7);
        tweak[index] = (uint8_t)((tweak[index] << 1) | carry);
        carry = next;
    }
    if (carry) tweak[0] ^= 0x87u;
}

static void edge_dm_crypt_sector(const edge_dm_target_t *target,
                                 uint64_t sector,
                                 const uint8_t input[EDGE_DM_SECTOR_SIZE],
                                 uint8_t output[EDGE_DM_SECTOR_SIZE],
                                 int decrypt) {
    uint8_t iv[16];
    uint8_t tweak[16];
    uint8_t block[16];
    uint8_t transformed[16];
    uint64_t iv_sector = sector - target->start + target->iv_offset;

    memset(iv, 0, sizeof(iv));
    for (uint32_t index = 0; index < 8u; ++index)
        iv[index] = (uint8_t)(iv_sector >> (index * 8u));
    edge_aes_encrypt_block(&target->crypt_tweak, iv, tweak);
    for (uint32_t offset = 0; offset < EDGE_DM_SECTOR_SIZE; offset += 16u) {
        for (uint32_t index = 0; index < 16u; ++index)
            block[index] = input[offset + index] ^ tweak[index];
        if (decrypt)
            edge_aes_decrypt_block(&target->crypt_data, block, transformed);
        else
            edge_aes_encrypt_block(&target->crypt_data, block, transformed);
        for (uint32_t index = 0; index < 16u; ++index)
            output[offset + index] = transformed[index] ^ tweak[index];
        edge_dm_xts_multiply(tweak);
    }
}

static int edge_dm_transfer(block_device_t *block, uint32_t lba,
                            uint32_t count, void *buffer, int write) {
    edge_dm_device_t *device = (edge_dm_device_t *)block->ctx;
    const edge_dm_table_t *table;
    uint32_t completed = 0;
    int result = 0;

    if (!device || !buffer || edge_dm_begin_io(device, &table) < 0)
        return -1;
    if (write && table->read_only) {
        edge_dm_end_io(device);
        return -1;
    }
    while (completed < count) {
        uint64_t sector = (uint64_t)lba + completed;
        const edge_dm_target_t *target =
            edge_dm_target_for_sector(table, sector);
        uint32_t chunk;

        if (!target) {
            result = -1;
            break;
        }
        chunk = edge_dm_target_chunk(target, sector, count - completed);
        if (target->kind == EDGE_DM_TARGET_ZERO) {
            if (!write)
                memset((uint8_t *)buffer +
                           (uint64_t)completed * EDGE_DM_SECTOR_SIZE,
                       0, (uint64_t)chunk * EDGE_DM_SECTOR_SIZE);
        } else if (target->kind == EDGE_DM_TARGET_ERROR) {
            result = -1;
            break;
        } else {
            block_device_t *backend = 0;
            uint64_t backend_sector = 0;
            uint64_t byte_offset;
            uint32_t byte_count;
            uint8_t crypt_buffer[EDGE_DM_SECTOR_SIZE];
            int64_t transferred;

            if (edge_dm_target_backend(
                    target, sector, &backend, &backend_sector) < 0 ||
                backend_sector > UINT64_MAX / EDGE_DM_SECTOR_SIZE) {
                result = -1;
                break;
            }
            byte_offset = backend_sector * EDGE_DM_SECTOR_SIZE;
            if (chunk > UINT32_MAX / EDGE_DM_SECTOR_SIZE) {
                result = -1;
                break;
            }
            byte_count = chunk * EDGE_DM_SECTOR_SIZE;
            if (write && target->kind == EDGE_DM_TARGET_CRYPT) {
                edge_dm_crypt_sector(
                    target, sector,
                    (const uint8_t *)buffer +
                        (uint64_t)completed * EDGE_DM_SECTOR_SIZE,
                    crypt_buffer, 0);
                transferred = block_write_bytes(
                    backend, byte_offset, crypt_buffer, byte_count);
            } else if (write) {
                transferred = block_write_bytes(
                    backend, byte_offset,
                    (const uint8_t *)buffer +
                        (uint64_t)completed * EDGE_DM_SECTOR_SIZE,
                    byte_count);
            } else {
                transferred = block_read_bytes(
                    backend, byte_offset,
                    (uint8_t *)buffer +
                        (uint64_t)completed * EDGE_DM_SECTOR_SIZE,
                    byte_count);
                if (transferred == byte_count &&
                    target->kind == EDGE_DM_TARGET_CRYPT)
                    edge_dm_crypt_sector(
                        target, sector,
                        (const uint8_t *)buffer +
                            (uint64_t)completed * EDGE_DM_SECTOR_SIZE,
                        (uint8_t *)buffer +
                            (uint64_t)completed * EDGE_DM_SECTOR_SIZE,
                        1);
            }
            if (transferred != byte_count) {
                result = -1;
                break;
            }
        }
        completed += chunk;
    }
    edge_dm_end_io(device);
    return result;
}

static int edge_dm_read(block_device_t *block, uint32_t lba,
                        uint32_t count, void *output) {
    return edge_dm_transfer(block, lba, count, output, 0);
}

static int edge_dm_write(block_device_t *block, uint32_t lba,
                         uint32_t count, const void *input) {
    return edge_dm_transfer(block, lba, count, (void *)input, 1);
}

static int edge_dm_flush_table(const edge_dm_table_t *table) {
    int result = 0;

    if (!table || !table->present) return -1;
    for (uint32_t target_index = 0;
         target_index < table->target_count; ++target_index) {
        const edge_dm_target_t *target = &table->targets[target_index];
        for (uint32_t stripe = 0; stripe < target->stripe_count; ++stripe) {
            block_device_t *backend = target->stripes[stripe].device;
            int seen = 0;
            if (!backend) continue;
            for (uint32_t prior_target = 0;
                 prior_target <= target_index && !seen; ++prior_target) {
                const edge_dm_target_t *prior =
                    &table->targets[prior_target];
                uint32_t stripe_limit = prior_target == target_index ?
                                        stripe : prior->stripe_count;
                for (uint32_t prior_stripe = 0;
                     prior_stripe < stripe_limit; ++prior_stripe)
                    if (prior->stripes[prior_stripe].device == backend) {
                        seen = 1;
                        break;
                    }
            }
            if (seen) continue;
            if (block_flush(backend) < 0) result = -1;
        }
    }
    return result;
}

static int edge_dm_flush(block_device_t *block) {
    edge_dm_device_t *device = (edge_dm_device_t *)block->ctx;
    const edge_dm_table_t *table;
    int result;

    if (!device || edge_dm_begin_io(device, &table) < 0) return -1;
    result = edge_dm_flush_table(table);
    edge_dm_end_io(device);
    return result;
}

static void edge_dm_fill_version(edge_dm_ioctl_t *io) {
    io->version[0] = 4u;
    io->version[1] = 50u;
    io->version[2] = 0u;
}

static void edge_dm_fill_identity(edge_dm_ioctl_t *io,
                                  const edge_dm_device_t *device) {
    uint32_t input_flags = io->flags;

    io->device = edge_dm_linux_device_number(
        EDGE_DM_BLOCK_MAJOR, device->minor);
    io->open_count = 0;
    io->event_nr = device->event_number;
    io->target_count = device->active.present ?
                       device->active.target_count : 0u;
    io->flags = input_flags &
        ~(EDGE_DM_READONLY_FLAG | EDGE_DM_SUSPEND_FLAG |
          EDGE_DM_ACTIVE_PRESENT_FLAG | EDGE_DM_INACTIVE_PRESENT_FLAG |
          EDGE_DM_BUFFER_FULL_FLAG | EDGE_DM_UEVENT_GENERATED_FLAG |
          EDGE_DM_DATA_OUT_FLAG | EDGE_DM_INTERNAL_SUSPEND_FLAG);
    if (device->suspended) io->flags |= EDGE_DM_SUSPEND_FLAG;
    if (device->active.present) io->flags |= EDGE_DM_ACTIVE_PRESENT_FLAG;
    if (device->inactive.present) io->flags |= EDGE_DM_INACTIVE_PRESENT_FLAG;
    if (device->active.present && device->active.read_only)
        io->flags |= EDGE_DM_READONLY_FLAG;
    (void)edge_dm_copy_string(io->name, sizeof(io->name), device->name);
    (void)edge_dm_copy_string(io->uuid, sizeof(io->uuid), device->uuid);
}

static int edge_dm_allocate_minor(const edge_dm_ioctl_t *io,
                                  uint32_t *minor) {
    if ((io->flags & EDGE_DM_PERSISTENT_DEV_FLAG) != 0) {
        uint32_t major = edge_dm_linux_major(io->device);
        uint32_t requested = edge_dm_linux_minor(io->device);
        if (major != EDGE_DM_BLOCK_MAJOR || requested >= EDGE_DM_MAX_DEVICES)
            return -EDGE_LINUX_EINVAL;
        if (g_dm_devices[requested].used) return -EDGE_LINUX_EBUSY;
        *minor = requested;
        return 0;
    }
    for (uint32_t index = 0; index < EDGE_DM_MAX_DEVICES; ++index)
        if (!g_dm_devices[index].used) {
            *minor = index;
            return 0;
        }
    return -EDGE_LINUX_ENOSPC;
}

static int edge_dm_device_create(edge_dm_ioctl_t *io) {
    edge_dm_device_t *device;
    block_ops_t operations;
    char node[BLOCK_NAME_MAX];
    uint32_t minor;
    int registration;

    if (!edge_dm_valid_name(io->name) || edge_dm_find_name(io->name) ||
        (io->uuid[0] && edge_dm_find_uuid(io->uuid)))
        return edge_dm_find_name(io->name) ? -EDGE_LINUX_EEXIST :
               -EDGE_LINUX_EINVAL;
    registration = edge_dm_allocate_minor(io, &minor);
    if (registration < 0) return registration;
    device = &g_dm_devices[minor];
    memset(device, 0, sizeof(*device));
    device->used = 1;
    device->suspended = 1;
    device->minor = minor;
    if (edge_dm_copy_string(device->name, sizeof(device->name), io->name) < 0 ||
        edge_dm_copy_string(device->uuid, sizeof(device->uuid), io->uuid) < 0) {
        memset(device, 0, sizeof(*device));
        return -EDGE_LINUX_EINVAL;
    }
    node[0] = 'd';
    node[1] = 'm';
    node[2] = '-';
    if (minor >= 10u) node[3] = (char)('0' + minor / 10u);
    node[minor >= 10u ? 4u : 3u] = (char)('0' + minor % 10u);
    node[minor >= 10u ? 5u : 4u] = 0;
    memset(&operations, 0, sizeof(operations));
    operations.read_sectors = edge_dm_read;
    operations.write_sectors = edge_dm_write;
    operations.flush = edge_dm_flush;
    registration = block_register(
        node, EDGE_DM_SECTOR_SIZE, 0u, 0u, device, operations);
    if (registration < 0) {
        memset(device, 0, sizeof(*device));
        return -EDGE_LINUX_ENOSPC;
    }
    device->block_device = block_find(node);
    block_set_cache_enabled(device->block_device, 0);
    edge_dm_fill_identity(io, device);
    return 0;
}

static int edge_dm_device_remove(edge_dm_ioctl_t *io) {
    edge_dm_device_t *device = edge_dm_lookup(io);
    block_device_t *block;

    if (!device) return -EDGE_LINUX_ENXIO;
    edge_dm_lock(device);
    if (device->active_io || device->removing) {
        edge_dm_unlock(device);
        return -EDGE_LINUX_EBUSY;
    }
    device->removing = 1;
    block = device->block_device;
    edge_dm_unlock(device);
    if (block_unregister(block) < 0) {
        edge_dm_lock(device);
        device->removing = 0;
        edge_dm_unlock(device);
        return -EDGE_LINUX_EBUSY;
    }
    memset(device, 0, sizeof(*device));
    return 0;
}

static int edge_dm_remove_all(void) {
    int first_error = 0;

    for (uint32_t index = 0; index < EDGE_DM_MAX_DEVICES; ++index) {
        edge_dm_ioctl_t io;
        int result;
        if (!g_dm_devices[index].used) continue;
        memset(&io, 0, sizeof(io));
        io.device = edge_dm_linux_device_number(EDGE_DM_BLOCK_MAJOR, index);
        result = edge_dm_device_remove(&io);
        if (result < 0 && first_error == 0) first_error = result;
    }
    return first_error;
}

static int edge_dm_table_load(edge_dm_ioctl_t *io) {
    edge_dm_device_t *device = edge_dm_lookup(io);
    int result;

    if (!device) return -EDGE_LINUX_ENXIO;
    result = edge_dm_parse_table(device, io, &g_dm_table_scratch);
    if (result < 0) {
        memset(&g_dm_table_scratch, 0, sizeof(g_dm_table_scratch));
        return result;
    }
    edge_dm_lock(device);
    if (device->removing) {
        memset(&g_dm_table_scratch, 0, sizeof(g_dm_table_scratch));
        edge_dm_unlock(device);
        return -EDGE_LINUX_EBUSY;
    }
    device->inactive = g_dm_table_scratch;
    memset(&g_dm_table_scratch, 0, sizeof(g_dm_table_scratch));
    device->event_number++;
    edge_dm_fill_identity(io, device);
    edge_dm_unlock(device);
    return 0;
}

static int edge_dm_table_clear(edge_dm_ioctl_t *io) {
    edge_dm_device_t *device = edge_dm_lookup(io);

    if (!device) return -EDGE_LINUX_ENXIO;
    edge_dm_lock(device);
    memset(&device->inactive, 0, sizeof(device->inactive));
    device->event_number++;
    edge_dm_fill_identity(io, device);
    edge_dm_unlock(device);
    return 0;
}

static int edge_dm_device_suspend(edge_dm_ioctl_t *io) {
    edge_dm_device_t *device = edge_dm_lookup(io);
    uint32_t sectors = 0;
    int result = 0;

    if (!device) return -EDGE_LINUX_ENXIO;
    edge_dm_lock(device);
    if (device->removing) {
        edge_dm_unlock(device);
        return -EDGE_LINUX_EBUSY;
    }
    if (io->flags & EDGE_DM_SUSPEND_FLAG) {
        device->suspended = 1;
        edge_dm_unlock(device);
        for (;;) {
            uint32_t active_io;
            edge_dm_lock(device);
            active_io = device->active_io;
            edge_dm_unlock(device);
            if (!active_io) break;
#if defined(__x86_64__)
            __asm__ __volatile__("pause");
#elif defined(__aarch64__)
            __asm__ __volatile__("yield");
#endif
        }
        edge_dm_lock(device);
        if (device->active.present) {
            const edge_dm_table_t *active = &device->active;
            edge_dm_unlock(device);
            result = edge_dm_flush_table(active);
            edge_dm_lock(device);
        }
    } else {
        const edge_dm_table_t *next = device->inactive.present ?
                                      &device->inactive : &device->active;
        if (!next->present) {
            edge_dm_unlock(device);
            return -EDGE_LINUX_EINVAL;
        }
        sectors = (uint32_t)next->sectors;
        if (block_resize(device->block_device, sectors) < 0) {
            edge_dm_unlock(device);
            return -EDGE_LINUX_EBUSY;
        }
        if (device->inactive.present) {
            device->active = device->inactive;
            memset(&device->inactive, 0, sizeof(device->inactive));
        }
        device->suspended = 0;
    }
    device->event_number++;
    edge_dm_fill_identity(io, device);
    edge_dm_unlock(device);
    (void)sectors;
    return result < 0 ? -EDGE_LINUX_EIO : 0;
}

static int edge_dm_device_status(edge_dm_ioctl_t *io) {
    edge_dm_device_t *device = edge_dm_lookup(io);
    if (!device) return -EDGE_LINUX_ENXIO;
    edge_dm_lock(device);
    edge_dm_fill_identity(io, device);
    edge_dm_unlock(device);
    return 0;
}

static int edge_dm_device_rename(edge_dm_ioctl_t *io) {
    edge_dm_device_t *device = edge_dm_lookup(io);
    const char *replacement;
    uint32_t available;

    if (!device || io->data_start >= io->data_size)
        return -EDGE_LINUX_EINVAL;
    replacement = (const char *)io + io->data_start;
    available = io->data_size - io->data_start;
    if (!edge_dm_bounded_string(replacement, available))
        return -EDGE_LINUX_EINVAL;
    edge_dm_lock(device);
    if (io->flags & EDGE_DM_UUID_FLAG) {
        if (device->uuid[0] || !replacement[0] ||
            edge_dm_find_uuid(replacement) ||
            edge_dm_copy_string(device->uuid, sizeof(device->uuid),
                                replacement) < 0) {
            edge_dm_unlock(device);
            return -EDGE_LINUX_EINVAL;
        }
    } else {
        if (!edge_dm_valid_name(replacement) ||
            edge_dm_find_name(replacement) ||
            edge_dm_copy_string(device->name, sizeof(device->name),
                                replacement) < 0) {
            edge_dm_unlock(device);
            return -EDGE_LINUX_EINVAL;
        }
    }
    device->event_number++;
    edge_dm_fill_identity(io, device);
    edge_dm_unlock(device);
    return 0;
}

static int edge_dm_list_devices(edge_dm_ioctl_t *io) {
    uint8_t *base = (uint8_t *)io;
    uint32_t offset = io->data_start;
    edge_dm_name_list_t *previous = 0;

    if (offset < sizeof(*io) || offset > io->data_size)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < EDGE_DM_MAX_DEVICES; ++index) {
        edge_dm_device_t *device = &g_dm_devices[index];
        edge_dm_name_list_t *record;
        uint32_t name_length;
        uint32_t record_size;

        if (!device->used) continue;
        name_length = (uint32_t)strlen(device->name) + 1u;
        record_size = edge_dm_align8(sizeof(*record) + name_length);
        if (offset > io->data_size || record_size > io->data_size - offset) {
            io->flags |= EDGE_DM_BUFFER_FULL_FLAG;
            break;
        }
        record = (edge_dm_name_list_t *)(base + offset);
        memset(record, 0, record_size);
        record->device = edge_dm_linux_device_number(
            EDGE_DM_BLOCK_MAJOR, device->minor);
        memcpy(record + 1, device->name, name_length);
        if (previous) previous->next = (uint32_t)((uint8_t *)record -
                                                  (uint8_t *)previous);
        previous = record;
        offset += record_size;
    }
    io->data_size = offset;
    return 0;
}

static int edge_dm_append_target_version(edge_dm_ioctl_t *io,
                                         uint32_t *offset,
                                         edge_dm_target_versions_t **previous,
                                         const char *name,
                                         uint32_t major,
                                         uint32_t minor,
                                         uint32_t patch) {
    uint32_t name_length = (uint32_t)strlen(name) + 1u;
    uint32_t record_size = edge_dm_align8(
        sizeof(edge_dm_target_versions_t) + name_length);
    edge_dm_target_versions_t *record;

    if (*offset > io->data_size || record_size > io->data_size - *offset) {
        io->flags |= EDGE_DM_BUFFER_FULL_FLAG;
        return -EDGE_LINUX_ENOSPC;
    }
    record = (edge_dm_target_versions_t *)((uint8_t *)io + *offset);
    memset(record, 0, record_size);
    record->version[0] = major;
    record->version[1] = minor;
    record->version[2] = patch;
    memcpy(record + 1, name, name_length);
    if (*previous) (*previous)->next =
        (uint32_t)((uint8_t *)record - (uint8_t *)*previous);
    *previous = record;
    *offset += record_size;
    return 0;
}

static int edge_dm_list_versions(edge_dm_ioctl_t *io) {
    edge_dm_target_versions_t *previous = 0;
    uint32_t offset = io->data_start;

    if (offset < sizeof(*io) || offset > io->data_size)
        return -EDGE_LINUX_EINVAL;
    if (edge_dm_append_target_version(
            io, &offset, &previous, "linear", 1, 5, 0) < 0 ||
        edge_dm_append_target_version(
            io, &offset, &previous, "striped", 1, 6, 0) < 0 ||
        edge_dm_append_target_version(
            io, &offset, &previous, "zero", 1, 1, 0) < 0 ||
        edge_dm_append_target_version(
            io, &offset, &previous, "error", 1, 5, 0) < 0 ||
        edge_dm_append_target_version(
            io, &offset, &previous, "crypt", 1, 24, 0) < 0) {
        io->data_size = offset;
        return 0;
    }
    io->data_size = offset;
    return 0;
}

static uint32_t edge_dm_append_decimal(char *output, uint32_t capacity,
                                       uint64_t value) {
    char reverse[20];
    uint32_t digits = 0;
    uint32_t length = 0;

    do {
        reverse[digits++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value && digits < sizeof(reverse));
    if (digits + 1u > capacity) return 0;
    while (digits) output[length++] = reverse[--digits];
    output[length] = 0;
    return length;
}

static int edge_dm_target_status_parameters(const edge_dm_target_t *target,
                                            char *output,
                                            uint32_t capacity) {
    uint32_t position = 0;

    if (!output || !capacity) return -1;
    output[0] = 0;
    if (target->kind == EDGE_DM_TARGET_ZERO ||
        target->kind == EDGE_DM_TARGET_ERROR)
        return 0;
    if (target->kind == EDGE_DM_TARGET_CRYPT) {
        static const char prefix[] = "aes-xts-plain64 - ";
        uint32_t written;
        uint32_t major;
        uint32_t minor;

        if (sizeof(prefix) > capacity ||
            block_linux_major_minor(target->stripes[0].device,
                                    &major, &minor) < 0)
            return -1;
        memcpy(output, prefix, sizeof(prefix) - 1u);
        position = sizeof(prefix) - 1u;
        written = edge_dm_append_decimal(
            output + position, capacity - position, target->iv_offset);
        if (!written || position + written + 1u >= capacity) return -1;
        position += written;
        output[position++] = ' ';
        written = edge_dm_append_decimal(
            output + position, capacity - position, major);
        if (!written || position + written + 1u >= capacity) return -1;
        position += written;
        output[position++] = ':';
        written = edge_dm_append_decimal(
            output + position, capacity - position, minor);
        if (!written || position + written + 1u >= capacity) return -1;
        position += written;
        output[position++] = ' ';
        written = edge_dm_append_decimal(
            output + position, capacity - position,
            target->stripes[0].start_sector);
        return written ? 0 : -1;
    }
    if (target->kind == EDGE_DM_TARGET_STRIPED) {
        uint32_t written = edge_dm_append_decimal(
            output + position, capacity - position, target->stripe_count);
        if (!written || position + written + 1u >= capacity) return -1;
        position += written;
        output[position++] = ' ';
        written = edge_dm_append_decimal(
            output + position, capacity - position, target->chunk_sectors);
        if (!written) return -1;
        position += written;
    }
    for (uint32_t stripe = 0; stripe < target->stripe_count; ++stripe) {
        uint32_t major;
        uint32_t minor;
        uint32_t written;
        if (block_linux_major_minor(target->stripes[stripe].device,
                                    &major, &minor) < 0)
            return -1;
        if (position && position + 1u < capacity) output[position++] = ' ';
        written = edge_dm_append_decimal(
            output + position, capacity - position, major);
        if (!written || position + written + 1u >= capacity) return -1;
        position += written;
        output[position++] = ':';
        written = edge_dm_append_decimal(
            output + position, capacity - position, minor);
        if (!written || position + written + 1u >= capacity) return -1;
        position += written;
        output[position++] = ' ';
        written = edge_dm_append_decimal(
            output + position, capacity - position,
            target->stripes[stripe].start_sector);
        if (!written) return -1;
        position += written;
    }
    return 0;
}

static const char *edge_dm_target_name(const edge_dm_target_t *target) {
    if (target->kind == EDGE_DM_TARGET_LINEAR) return "linear";
    if (target->kind == EDGE_DM_TARGET_STRIPED) return "striped";
    if (target->kind == EDGE_DM_TARGET_CRYPT) return "crypt";
    if (target->kind == EDGE_DM_TARGET_ZERO) return "zero";
    return "error";
}

static int edge_dm_table_status(edge_dm_ioctl_t *io) {
    edge_dm_device_t *device = edge_dm_lookup(io);
    const edge_dm_table_t *table;
    uint8_t *base = (uint8_t *)io;
    uint32_t offset = io->data_start;
    edge_dm_target_spec_t *previous = 0;

    if (!device || offset < sizeof(*io) || offset > io->data_size)
        return -EDGE_LINUX_EINVAL;
    edge_dm_lock(device);
    table = (io->flags & EDGE_DM_QUERY_INACTIVE_TABLE_FLAG) ?
            &device->inactive : &device->active;
    edge_dm_fill_identity(io, device);
    io->target_count = table->present ? table->target_count : 0u;
    if (!table->present) {
        io->data_size = offset;
        edge_dm_unlock(device);
        return 0;
    }
    for (uint32_t index = 0; index < table->target_count; ++index) {
        const edge_dm_target_t *target = &table->targets[index];
        char parameters[256];
        edge_dm_target_spec_t *record;
        uint32_t parameter_length;
        uint32_t record_size;

        if (edge_dm_target_status_parameters(
                target, parameters, sizeof(parameters)) < 0) {
            edge_dm_unlock(device);
            return -EDGE_LINUX_EOVERFLOW;
        }
        parameter_length = (uint32_t)strlen(parameters) + 1u;
        record_size = edge_dm_align8(sizeof(*record) + parameter_length);
        if (offset > io->data_size || record_size > io->data_size - offset) {
            io->flags |= EDGE_DM_BUFFER_FULL_FLAG;
            break;
        }
        record = (edge_dm_target_spec_t *)(base + offset);
        memset(record, 0, record_size);
        record->sector_start = target->start;
        record->length = target->length;
        (void)edge_dm_copy_string(record->target_type,
                                  sizeof(record->target_type),
                                  edge_dm_target_name(target));
        memcpy(record + 1, parameters, parameter_length);
        if (previous) previous->next =
            (uint32_t)((uint8_t *)record - (uint8_t *)previous);
        previous = record;
        offset += record_size;
    }
    io->data_size = offset;
    edge_dm_unlock(device);
    return 0;
}

static int edge_dm_table_deps(edge_dm_ioctl_t *io) {
    edge_dm_device_t *device = edge_dm_lookup(io);
    const edge_dm_table_t *table;
    uint8_t *base = (uint8_t *)io;
    uint32_t offset = io->data_start;
    uint32_t count = 0;
    uint64_t *devices;

    if (!device || offset < sizeof(*io) || offset > io->data_size ||
        io->data_size - offset < 8u)
        return -EDGE_LINUX_EINVAL;
    edge_dm_lock(device);
    table = (io->flags & EDGE_DM_QUERY_INACTIVE_TABLE_FLAG) ?
            &device->inactive : &device->active;
    memset(base + offset, 0, io->data_size - offset);
    devices = (uint64_t *)(base + offset + 8u);
    if (table->present) {
        for (uint32_t target_index = 0;
             target_index < table->target_count; ++target_index) {
            const edge_dm_target_t *target = &table->targets[target_index];
            for (uint32_t stripe = 0; stripe < target->stripe_count; ++stripe) {
                uint32_t major;
                uint32_t minor;
                uint64_t encoded;
                uint32_t seen = 0;
                if (block_linux_major_minor(target->stripes[stripe].device,
                                            &major, &minor) < 0)
                    continue;
                encoded = edge_dm_linux_device_number(major, minor);
                for (uint32_t index = 0; index < count; ++index)
                    if (devices[index] == encoded) seen = 1;
                if (seen) continue;
                if (offset + 8u + (count + 1u) * 8u > io->data_size) {
                    io->flags |= EDGE_DM_BUFFER_FULL_FLAG;
                    goto done;
                }
                devices[count++] = encoded;
            }
        }
    }
done:
    *(uint32_t *)(base + offset) = count;
    io->data_size = offset + 8u + count * 8u;
    edge_dm_fill_identity(io, device);
    edge_dm_unlock(device);
    return 0;
}

static int edge_dm_command_execute(uint32_t command, edge_dm_ioctl_t *io,
                                   int privileged) {
    if (command != EDGE_DM_VERSION_CMD && !privileged)
        return -EDGE_LINUX_EPERM;
    switch (command) {
        case EDGE_DM_VERSION_CMD:
            return 0;
        case EDGE_DM_REMOVE_ALL_CMD:
            return edge_dm_remove_all();
        case EDGE_DM_LIST_DEVICES_CMD:
            return edge_dm_list_devices(io);
        case EDGE_DM_DEV_CREATE_CMD:
            return edge_dm_device_create(io);
        case EDGE_DM_DEV_REMOVE_CMD:
            return edge_dm_device_remove(io);
        case EDGE_DM_DEV_RENAME_CMD:
            return edge_dm_device_rename(io);
        case EDGE_DM_DEV_SUSPEND_CMD:
            return edge_dm_device_suspend(io);
        case EDGE_DM_DEV_STATUS_CMD:
            return edge_dm_device_status(io);
        case EDGE_DM_DEV_WAIT_CMD:
            return edge_dm_device_status(io);
        case EDGE_DM_TABLE_LOAD_CMD:
            return edge_dm_table_load(io);
        case EDGE_DM_TABLE_CLEAR_CMD:
            return edge_dm_table_clear(io);
        case EDGE_DM_TABLE_DEPS_CMD:
            return edge_dm_table_deps(io);
        case EDGE_DM_TABLE_STATUS_CMD:
            return edge_dm_table_status(io);
        case EDGE_DM_LIST_VERSIONS_CMD:
            return edge_dm_list_versions(io);
        case EDGE_DM_TARGET_MSG_CMD:
            return -EDGE_LINUX_EOPNOTSUPP;
        case EDGE_DM_DEV_SET_GEOMETRY_CMD:
            return edge_dm_device_status(io);
        default:
            return -EDGE_LINUX_ENOTTY;
    }
}

void edge_dm_initialize(void) {
    memset(g_dm_devices, 0, sizeof(g_dm_devices));
    g_dm_global_lock = 0;
    g_dm_ioctl_lock = 0;
}

int edge_dm_is_control_device_number(uint64_t device_number) {
    return edge_dm_linux_major(device_number) == EDGE_DM_CONTROL_MAJOR &&
           edge_dm_linux_minor(device_number) == EDGE_DM_CONTROL_MINOR;
}

int64_t edge_dm_ioctl_execute(const edge_dm_ioctl_request_t *request) {
    edge_dm_ioctl_t header;
    edge_dm_ioctl_t *io;
    uint32_t command;
    uint32_t copy_size;
    int result;

    if (!request || !edge_dm_is_control_device_number(request->device_number))
        return -EDGE_LINUX_ENOTTY;
    if (!request->argument || !request->copy_from_user ||
        !request->copy_to_user)
        return -EDGE_LINUX_EFAULT;
    if (((request->command >> 8) & 0xffu) != EDGE_DM_IOCTL_TYPE)
        return -EDGE_LINUX_ENOTTY;
    command = request->command & 0xffu;
    if (request->copy_from_user(request->copy_context, &header,
                                request->argument, sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (header.data_size < sizeof(header) ||
        header.data_size > EDGE_DM_IOCTL_BUFFER_SIZE ||
        header.data_start < sizeof(header) ||
        header.data_start > header.data_size)
        return -EDGE_LINUX_EINVAL;
    edge_dm_spin_lock(&g_dm_ioctl_lock);
    memset(g_dm_ioctl_buffer, 0, sizeof(g_dm_ioctl_buffer));
    if (request->copy_from_user(request->copy_context, g_dm_ioctl_buffer,
                                request->argument, header.data_size) < 0) {
        edge_dm_spin_unlock(&g_dm_ioctl_lock);
        return -EDGE_LINUX_EFAULT;
    }
    io = (edge_dm_ioctl_t *)g_dm_ioctl_buffer;
    if (!edge_dm_bounded_string(io->name, sizeof(io->name)) ||
        !edge_dm_bounded_string(io->uuid, sizeof(io->uuid))) {
        edge_dm_spin_unlock(&g_dm_ioctl_lock);
        return -EDGE_LINUX_EINVAL;
    }
    edge_dm_spin_lock(&g_dm_global_lock);
    result = edge_dm_command_execute(command, io, request->privileged);
    edge_dm_fill_version(io);
    edge_dm_spin_unlock(&g_dm_global_lock);
    if (command == EDGE_DM_DEV_CREATE_CMD ||
        command == EDGE_DM_DEV_REMOVE_CMD ||
        command == EDGE_DM_REMOVE_ALL_CMD ||
        command == EDGE_DM_DEV_RENAME_CMD)
        (void)devtmpfs_refresh_block_nodes();
    copy_size = io->data_size;
    if (copy_size < sizeof(*io)) copy_size = sizeof(*io);
    if (copy_size > header.data_size) copy_size = header.data_size;
    if (request->copy_to_user(request->copy_context, request->argument,
                              io, copy_size) < 0)
        result = -EDGE_LINUX_EFAULT;
    if (io->flags & EDGE_DM_SECURE_DATA_FLAG)
        memset(g_dm_ioctl_buffer, 0, sizeof(g_dm_ioctl_buffer));
    edge_dm_spin_unlock(&g_dm_ioctl_lock);
    return result;
}

uint32_t edge_dm_device_count(void) {
    uint32_t count = 0;
    edge_dm_spin_lock(&g_dm_global_lock);
    for (uint32_t index = 0; index < EDGE_DM_MAX_DEVICES; ++index)
        if (g_dm_devices[index].used) count++;
    edge_dm_spin_unlock(&g_dm_global_lock);
    return count;
}

int edge_dm_device_identity_at(uint32_t index, char *name,
                               uint32_t name_capacity,
                               char *node, uint32_t node_capacity,
                               uint32_t *minor) {
    uint32_t seen = 0;
    int result = -1;

    if (!name || !node || !minor || name_capacity < 2u ||
        node_capacity < 5u)
        return -1;
    edge_dm_spin_lock(&g_dm_global_lock);
    for (uint32_t slot = 0; slot < EDGE_DM_MAX_DEVICES; ++slot) {
        edge_dm_device_t *device = &g_dm_devices[slot];
        uint32_t position = 3u;
        if (!device->used || seen++ != index) continue;
        if (edge_dm_copy_string(name, name_capacity, device->name) < 0)
            break;
        node[0] = 'd';
        node[1] = 'm';
        node[2] = '-';
        if (slot >= 10u) {
            if (node_capacity < 6u) break;
            node[position++] = (char)('0' + slot / 10u);
        }
        node[position++] = (char)('0' + slot % 10u);
        node[position] = 0;
        *minor = slot;
        result = 0;
        break;
    }
    edge_dm_spin_unlock(&g_dm_global_lock);
    return result;
}
