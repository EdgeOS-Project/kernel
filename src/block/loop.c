/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux-compatible file-backed loop block devices. */

#include <stdint.h>

#include "block/block.h"
#include "block/loop.h"
#include "dev/devtmpfs.h"
#include "kernel/linux_errno.h"
#include "stdio.h"
#include "string.h"

#define EDGE_LOOP_DEFAULT_BLOCK_SIZE 512u
#define EDGE_LOOP_MAX_IO_BYTES (1024u * 1024u)
#define EDGE_LOOP_BOUNCE_BYTES (64u * 1024u)
#define EDGE_LINUX_O_ACCMODE 3u
#define EDGE_LINUX_O_RDONLY 0u

typedef struct edge_loop_device {
    volatile uint32_t lock;
    volatile uint32_t io_lock;
    uint32_t active_io;
    uint32_t block_size;
    uint32_t flags;
    uint64_t offset;
    uint64_t size_limit;
    uint8_t configured;
    uint8_t detaching;
    uint8_t direct_io;
    uint8_t reserved;
    edge_loop_backing_file_t backing;
    block_device_t *block_device;
    uint8_t io_buffer[EDGE_LOOP_BOUNCE_BYTES];
} edge_loop_device_t;

static edge_loop_device_t g_loop_devices[EDGE_LOOP_DEVICE_COUNT];

static int edge_loop_index_from_name(const char *name) {
    uint32_t index = 0;
    uint32_t digits = 0;

    if (!name || name[0] != 'l' || name[1] != 'o' ||
        name[2] != 'o' || name[3] != 'p')
        return -1;
    name += 4;
    while (*name) {
        if (*name < '0' || *name > '9') return -1;
        index = index * 10u + (uint32_t)(*name++ - '0');
        if (++digits > 2u || index >= EDGE_LOOP_DEVICE_COUNT) return -1;
    }
    return digits ? (int)index : -1;
}

static void edge_loop_lock(edge_loop_device_t *device) {
    while (__atomic_test_and_set(&device->lock, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&device->lock, __ATOMIC_RELAXED))
            __asm__ __volatile__("" ::: "memory");
    }
}

static void edge_loop_unlock(edge_loop_device_t *device) {
    __atomic_clear(&device->lock, __ATOMIC_RELEASE);
}

static void edge_loop_io_lock(edge_loop_device_t *device) {
    while (__atomic_exchange_n(&device->io_lock, 1u, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&device->io_lock, __ATOMIC_RELAXED))
            __asm__ __volatile__("" ::: "memory");
    }
}

static void edge_loop_io_unlock(edge_loop_device_t *device) {
    __atomic_store_n(&device->io_lock, 0u, __ATOMIC_RELEASE);
}

static uint32_t edge_linux_device_major(uint64_t device) {
    return (uint32_t)((device >> 8) & 0xfffu) |
           (uint32_t)((device >> 32) & 0xfffff000u);
}

static uint32_t edge_linux_device_minor(uint64_t device) {
    return (uint32_t)(device & 0xffu) |
           (uint32_t)((device >> 12) & 0xffffff00u);
}

static int edge_loop_index_from_device(uint64_t device_number) {
    uint32_t major = edge_linux_device_major(device_number);
    uint32_t minor = edge_linux_device_minor(device_number);

    if (major != 7u || minor >= EDGE_LOOP_DEVICE_COUNT) return -1;
    return (int)minor;
}

int edge_loop_is_device_number(uint64_t device_number) {
    return edge_loop_index_from_device(device_number) >= 0;
}

int edge_loop_is_control_device_number(uint64_t device_number) {
    return edge_linux_device_major(device_number) == 10u &&
           edge_linux_device_minor(device_number) == 237u;
}

static int edge_loop_append_u64(char *output, uint32_t capacity,
                                uint32_t *length, uint64_t value) {
    char digits[20];
    uint32_t count = 0;

    if (!output || !length || !capacity) return -1;
    do {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value && count < sizeof(digits));
    if (*length + count >= capacity) return -1;
    while (count) output[(*length)++] = digits[--count];
    output[*length] = 0;
    return 0;
}

int edge_loop_sysfs_path_kind(const char *device_name,
                              const char *relative_path) {
    static const char *const attributes[] = {
        "backing_file", "offset", "sizelimit", "autoclear", "partscan",
        "dio"
    };
    int index = edge_loop_index_from_name(device_name);

    if (index < 0 || !relative_path) return 0;
    edge_loop_lock(&g_loop_devices[index]);
    if (!g_loop_devices[index].configured) {
        edge_loop_unlock(&g_loop_devices[index]);
        return 0;
    }
    edge_loop_unlock(&g_loop_devices[index]);
    if (!relative_path[0]) return BLOCK_SYSFS_PATH_DIR;
    for (uint32_t attribute = 0;
         attribute < sizeof(attributes) / sizeof(attributes[0]);
         ++attribute)
        if (strcmp(relative_path, attributes[attribute]) == 0)
            return BLOCK_SYSFS_PATH_FILE;
    return 0;
}

int edge_loop_sysfs_read_file(const char *device_name,
                              const char *attribute,
                              char *output, uint32_t capacity) {
    edge_loop_device_t *device;
    uint64_t value;
    uint32_t length = 0;
    int index = edge_loop_index_from_name(device_name);

    if (index < 0 || !attribute || !output || capacity < 2u) return -1;
    device = &g_loop_devices[index];
    edge_loop_lock(device);
    if (!device->configured) {
        edge_loop_unlock(device);
        return -1;
    }
    if (strcmp(attribute, "backing_file") == 0) {
        while (device->backing.path[length] && length + 2u < capacity) {
            output[length] = device->backing.path[length];
            length++;
        }
        if (device->backing.path[length]) {
            edge_loop_unlock(device);
            return -1;
        }
        output[length++] = '\n';
        output[length] = 0;
        edge_loop_unlock(device);
        return (int)length;
    }
    if (strcmp(attribute, "offset") == 0)
        value = device->offset;
    else if (strcmp(attribute, "sizelimit") == 0)
        value = device->size_limit;
    else if (strcmp(attribute, "dio") == 0)
        value = device->direct_io != 0;
    else if (strcmp(attribute, "autoclear") == 0)
        value = (device->flags & EDGE_LOOP_FLAG_AUTOCLEAR) != 0;
    else if (strcmp(attribute, "partscan") == 0)
        value = (device->flags & EDGE_LOOP_FLAG_PARTSCAN) != 0;
    else {
        edge_loop_unlock(device);
        return -1;
    }
    if (edge_loop_append_u64(output, capacity, &length, value) < 0 ||
        length + 1u >= capacity) {
        edge_loop_unlock(device);
        return -1;
    }
    output[length++] = '\n';
    output[length] = 0;
    edge_loop_unlock(device);
    return (int)length;
}

static int edge_loop_validate_block_size(uint32_t block_size) {
    if (block_size < 512u || block_size > 4096u) return -EDGE_LINUX_EINVAL;
    if ((block_size & (block_size - 1u)) != 0u) return -EDGE_LINUX_EINVAL;
    return 0;
}

static int edge_loop_visible_sectors(const edge_loop_backing_file_t *backing,
                                     uint64_t offset, uint64_t size_limit,
                                     uint32_t block_size,
                                     uint32_t *sector_count) {
    uint64_t available;
    uint64_t visible;

    if (!backing || !sector_count || offset >= backing->inode.size)
        return -EDGE_LINUX_EINVAL;
    available = (uint64_t)backing->inode.size - offset;
    visible = size_limit && size_limit < available ? size_limit : available;
    visible -= visible % block_size;
    if (!visible || visible / block_size > UINT32_MAX)
        return -EDGE_LINUX_EOVERFLOW;
    *sector_count = (uint32_t)(visible / block_size);
    return 0;
}

static int edge_loop_begin_io(edge_loop_device_t *device,
                              edge_loop_backing_file_t *backing,
                              uint64_t *offset, uint32_t *block_size,
                              uint32_t *flags) {
    edge_loop_lock(device);
    if (!device->configured || device->detaching) {
        edge_loop_unlock(device);
        return -EDGE_LINUX_ENXIO;
    }
    device->active_io++;
    *backing = device->backing;
    *offset = device->offset;
    *block_size = device->block_size;
    *flags = device->flags;
    edge_loop_unlock(device);
    return 0;
}

static void edge_loop_end_io(edge_loop_device_t *device) {
    edge_loop_lock(device);
    if (device->active_io) device->active_io--;
    edge_loop_unlock(device);
}

static int edge_loop_read(block_device_t *block, uint32_t lba,
                          uint32_t count, void *output) {
    edge_loop_device_t *device = (edge_loop_device_t *)block->ctx;
    edge_loop_backing_file_t backing;
    uint64_t base;
    uint32_t block_size;
    uint32_t flags;
    uint64_t byte_offset;
    uint64_t byte_count;
    uint32_t completed = 0;
    int result = 0;

    if (!device || !output) return -1;
    result = edge_loop_begin_io(
        device, &backing, &base, &block_size, &flags);
    if (result < 0) return -1;
    (void)flags;
    byte_offset = base + (uint64_t)lba * block_size;
    byte_count = (uint64_t)count * block_size;
    if (byte_count > EDGE_LOOP_MAX_IO_BYTES || byte_offset > UINT32_MAX ||
        byte_count > UINT32_MAX - byte_offset) {
        edge_loop_end_io(device);
        return -1;
    }
    edge_loop_io_lock(device);
    while (completed < byte_count) {
        uint32_t chunk = (uint32_t)byte_count - completed;
        if (chunk > EDGE_LOOP_BOUNCE_BYTES) chunk = EDGE_LOOP_BOUNCE_BYTES;
        result = vfs_read_inode_exact(
            backing.superblock, &backing.inode,
            (uint32_t)byte_offset + completed, device->io_buffer, chunk);
        if (result < 0) break;
        memcpy((uint8_t *)output + completed, device->io_buffer, chunk);
        completed += chunk;
    }
    edge_loop_io_unlock(device);
    edge_loop_end_io(device);
    return result < 0 ? -1 : 0;
}

static int edge_loop_write(block_device_t *block, uint32_t lba,
                           uint32_t count, const void *input) {
    edge_loop_device_t *device = (edge_loop_device_t *)block->ctx;
    edge_loop_backing_file_t backing;
    uint64_t base;
    uint32_t block_size;
    uint32_t flags;
    uint64_t byte_offset;
    uint64_t byte_count;
    uint32_t completed = 0;
    int result = 0;

    if (!device || !input) return -1;
    if (edge_loop_begin_io(
            device, &backing, &base, &block_size, &flags) < 0) {
        printf("[loop] backing write rejected while device is unavailable\n");
        return -1;
    }
    if ((flags & EDGE_LOOP_FLAG_READ_ONLY) ||
        !backing.superblock || !backing.superblock->ops ||
        !backing.superblock->ops->write) {
        printf("[loop] backing write rejected path=%s flags=0x%x\n",
               backing.path, (unsigned)flags);
        edge_loop_end_io(device);
        return -1;
    }
    byte_offset = base + (uint64_t)lba * block_size;
    byte_count = (uint64_t)count * block_size;
    if (byte_count > EDGE_LOOP_MAX_IO_BYTES || byte_offset > UINT32_MAX ||
        byte_count > UINT32_MAX - byte_offset) {
        printf("[loop] backing write range unsupported path=%s offset=%llu length=%llu\n",
               backing.path, (unsigned long long)byte_offset,
               (unsigned long long)byte_count);
        edge_loop_end_io(device);
        return -1;
    }
    edge_loop_io_lock(device);
    while (completed < byte_count) {
        uint32_t remaining = (uint32_t)byte_count - completed;
        if (remaining > EDGE_LOOP_BOUNCE_BYTES)
            remaining = EDGE_LOOP_BOUNCE_BYTES;
        memcpy(device->io_buffer, (const uint8_t *)input + completed,
               remaining);
        int written = backing.superblock->ops->write(
            backing.superblock, &backing.inode,
            (uint32_t)byte_offset + completed,
            device->io_buffer, remaining);
        if (written <= 0 || (uint32_t)written > remaining) {
            printf("[loop] backing write failed path=%s offset=%u length=%u result=%d\n",
                   backing.path, (unsigned)((uint32_t)byte_offset + completed),
                   (unsigned)remaining, written);
            result = -1;
            break;
        }
        completed += (uint32_t)written;
    }
    edge_loop_io_unlock(device);
    edge_loop_end_io(device);
    return result;
}

static int edge_loop_flush(block_device_t *block) {
    edge_loop_device_t *device = (edge_loop_device_t *)block->ctx;
    edge_loop_backing_file_t backing;
    uint64_t offset;
    uint32_t block_size;
    uint32_t flags;
    int result = 0;

    if (!device || edge_loop_begin_io(
            device, &backing, &offset, &block_size, &flags) < 0)
        return -1;
    (void)offset;
    (void)block_size;
    (void)flags;
    if (backing.superblock && backing.superblock->ops) {
        if (backing.superblock->ops->sync_inode)
            result = backing.superblock->ops->sync_inode(
                backing.superblock, &backing.inode, 0);
        else if (backing.superblock->ops->sync)
            result = backing.superblock->ops->sync(backing.superblock);
    }
    if (result < 0)
        printf("[loop] backing flush failed path=%s result=%d\n",
               backing.path, result);
    edge_loop_end_io(device);
    return result < 0 ? -1 : 0;
}

static int edge_loop_copy_name(uint8_t destination[64], const char *source) {
    uint32_t length = 0;

    memset(destination, 0, 64u);
    if (!source) return 0;
    while (source[length] && length < 63u) {
        destination[length] = (uint8_t)source[length];
        length++;
    }
    return 0;
}

static int edge_loop_configure_device(
    uint32_t index, const edge_loop_backing_file_t *backing,
    const edge_loop_info64_t *information, uint32_t block_size) {
    edge_loop_device_t *device;
    block_ops_t operations;
    uint32_t sectors;
    uint32_t flags;
    char name[BLOCK_NAME_MAX];
    int registration;

    if (index >= EDGE_LOOP_DEVICE_COUNT || !backing || !information ||
        !backing->superblock ||
        (backing->inode.mode & 0xf000u) != VFS_INODE_FILE)
        return -EDGE_LINUX_EINVAL;
    if (edge_loop_validate_block_size(block_size) < 0)
        return -EDGE_LINUX_EINVAL;
    if (information->encryption_type || information->encryption_key_size)
        return -EDGE_LINUX_EINVAL;
    flags = information->flags;
    if (flags & ~(EDGE_LOOP_FLAG_READ_ONLY | EDGE_LOOP_FLAG_DIRECT_IO))
        return (flags & (EDGE_LOOP_FLAG_AUTOCLEAR |
                         EDGE_LOOP_FLAG_PARTSCAN)) ?
            -EDGE_LINUX_EOPNOTSUPP : -EDGE_LINUX_EINVAL;
    if ((backing->status_flags & EDGE_LINUX_O_ACCMODE) ==
        EDGE_LINUX_O_RDONLY)
        flags |= EDGE_LOOP_FLAG_READ_ONLY;
    if (edge_loop_visible_sectors(
            backing, information->offset, information->size_limit,
            block_size, &sectors) < 0)
        return -EDGE_LINUX_EINVAL;
    device = &g_loop_devices[index];
    edge_loop_lock(device);
    if (device->configured || device->detaching) {
        edge_loop_unlock(device);
        return -EDGE_LINUX_EBUSY;
    }
    device->detaching = 1;
    edge_loop_unlock(device);

    if (vfs_inode_open(backing->superblock, &backing->inode) < 0) {
        edge_loop_lock(device);
        device->detaching = 0;
        edge_loop_unlock(device);
        return -EDGE_LINUX_ENFILE;
    }
    name[0] = 'l';
    name[1] = 'o';
    name[2] = 'o';
    name[3] = 'p';
    if (index >= 10u) name[4] = (char)('0' + index / 10u);
    name[index >= 10u ? 5u : 4u] = (char)('0' + index % 10u);
    name[index >= 10u ? 6u : 5u] = 0;
    memset(&operations, 0, sizeof(operations));
    operations.read_sectors = edge_loop_read;
    if (!(flags & EDGE_LOOP_FLAG_READ_ONLY))
        operations.write_sectors = edge_loop_write;
    operations.flush = edge_loop_flush;
    registration = block_register(
        name, block_size, sectors, 0, device, operations);
    if (registration < 0) {
        vfs_inode_close(backing->superblock, &backing->inode);
        edge_loop_lock(device);
        device->detaching = 0;
        edge_loop_unlock(device);
        return -EDGE_LINUX_EBUSY;
    }
    edge_loop_lock(device);
    device->backing = *backing;
    device->block_size = block_size;
    device->flags = flags;
    device->offset = information->offset;
    device->size_limit = information->size_limit;
    device->direct_io = (flags & EDGE_LOOP_FLAG_DIRECT_IO) != 0;
    device->block_device = block_find(name);
    device->configured = 1;
    device->detaching = 0;
    edge_loop_unlock(device);
    block_set_cache_enabled(device->block_device, !device->direct_io);
    block_set_max_transfer_sectors(
        device->block_device, EDGE_LOOP_MAX_IO_BYTES / block_size);
    (void)devtmpfs_refresh_block_nodes();
    return 0;
}

static int edge_loop_clear_device(uint32_t index) {
    edge_loop_device_t *device;
    edge_loop_backing_file_t backing;
    block_device_t *block;

    if (index >= EDGE_LOOP_DEVICE_COUNT) return -EDGE_LINUX_ENXIO;
    device = &g_loop_devices[index];
    edge_loop_lock(device);
    if (!device->configured) {
        edge_loop_unlock(device);
        return -EDGE_LINUX_ENXIO;
    }
    if (device->active_io || device->detaching) {
        edge_loop_unlock(device);
        return -EDGE_LINUX_EBUSY;
    }
    device->detaching = 1;
    backing = device->backing;
    block = device->block_device;
    edge_loop_unlock(device);
    if (block && block_unregister(block) < 0) {
        edge_loop_lock(device);
        device->detaching = 0;
        edge_loop_unlock(device);
        return -EDGE_LINUX_EBUSY;
    }
    edge_loop_lock(device);
    memset(&device->backing, 0, sizeof(device->backing));
    device->block_device = 0;
    device->configured = 0;
    device->detaching = 0;
    device->flags = 0;
    device->offset = 0;
    device->size_limit = 0;
    device->block_size = EDGE_LOOP_DEFAULT_BLOCK_SIZE;
    device->direct_io = 0;
    edge_loop_unlock(device);
    vfs_inode_close(backing.superblock, &backing.inode);
    (void)devtmpfs_refresh_block_nodes();
    return 0;
}

static int edge_loop_update_status(uint32_t index,
                                   const edge_loop_info64_t *information) {
    edge_loop_device_t *device;
    edge_loop_backing_file_t backing;
    uint32_t flags;
    uint32_t sectors;
    int result;

    if (index >= EDGE_LOOP_DEVICE_COUNT || !information)
        return -EDGE_LINUX_EINVAL;
    if (information->encryption_type || information->encryption_key_size)
        return -EDGE_LINUX_EINVAL;
    flags = information->flags;
    if (flags & ~(EDGE_LOOP_FLAG_READ_ONLY | EDGE_LOOP_FLAG_DIRECT_IO))
        return (flags & (EDGE_LOOP_FLAG_AUTOCLEAR |
                         EDGE_LOOP_FLAG_PARTSCAN)) ?
            -EDGE_LINUX_EOPNOTSUPP : -EDGE_LINUX_EINVAL;
    device = &g_loop_devices[index];
    edge_loop_lock(device);
    if (!device->configured || device->detaching || device->active_io) {
        result = !device->configured ? -EDGE_LINUX_ENXIO :
                 -EDGE_LINUX_EBUSY;
        edge_loop_unlock(device);
        return result;
    }
    backing = device->backing;
    if ((backing.status_flags & EDGE_LINUX_O_ACCMODE) == EDGE_LINUX_O_RDONLY)
        flags |= EDGE_LOOP_FLAG_READ_ONLY;
    result = edge_loop_visible_sectors(
        &backing, information->offset, information->size_limit,
        device->block_size, &sectors);
    if (result < 0) {
        edge_loop_unlock(device);
        return result;
    }
    if (((device->flags ^ flags) & EDGE_LOOP_FLAG_READ_ONLY) != 0) {
        edge_loop_unlock(device);
        return -EDGE_LINUX_EINVAL;
    }
    result = block_resize(device->block_device, sectors);
    if (result == 0) {
        device->offset = information->offset;
        device->size_limit = information->size_limit;
        device->flags = flags;
        device->direct_io = (flags & EDGE_LOOP_FLAG_DIRECT_IO) != 0;
        block_set_cache_enabled(device->block_device, !device->direct_io);
    }
    edge_loop_unlock(device);
    return result < 0 ? -EDGE_LINUX_EBUSY : 0;
}

static int edge_loop_get_status(uint32_t index,
                                edge_loop_info64_t *information) {
    edge_loop_device_t *device;

    if (index >= EDGE_LOOP_DEVICE_COUNT || !information)
        return -EDGE_LINUX_EINVAL;
    device = &g_loop_devices[index];
    edge_loop_lock(device);
    if (!device->configured) {
        edge_loop_unlock(device);
        return -EDGE_LINUX_ENXIO;
    }
    memset(information, 0, sizeof(*information));
    information->device = device->backing.device_number;
    information->inode = device->backing.inode.ino;
    information->rdevice = device->backing.inode.rdev;
    information->offset = device->offset;
    information->size_limit = device->size_limit;
    information->number = index;
    information->flags = device->flags;
    edge_loop_copy_name(information->file_name, device->backing.path);
    edge_loop_unlock(device);
    return 0;
}

static int edge_loop_set_block_size(uint32_t index, uint32_t block_size) {
    edge_loop_device_t *device;
    uint32_t sectors;
    int result;

    if (index >= EDGE_LOOP_DEVICE_COUNT ||
        edge_loop_validate_block_size(block_size) < 0)
        return -EDGE_LINUX_EINVAL;
    device = &g_loop_devices[index];
    edge_loop_lock(device);
    if (!device->configured || device->active_io || device->detaching) {
        result = !device->configured ? -EDGE_LINUX_ENXIO :
                 -EDGE_LINUX_EBUSY;
        edge_loop_unlock(device);
        return result;
    }
    result = edge_loop_visible_sectors(
        &device->backing, device->offset, device->size_limit,
        block_size, &sectors);
    if (result == 0) result = block_resize(device->block_device, sectors);
    if (result == 0) {
        device->block_size = block_size;
        device->block_device->sector_size = block_size;
        block_set_max_transfer_sectors(
            device->block_device, EDGE_LOOP_MAX_IO_BYTES / block_size);
    }
    edge_loop_unlock(device);
    return result < 0 ? -EDGE_LINUX_EBUSY : 0;
}

static int edge_loop_refresh_capacity(uint32_t index) {
    edge_loop_device_t *device;
    edge_loop_backing_file_t *backing;
    block_device_t *block;
    uint64_t offset;
    uint64_t size_limit;
    uint32_t block_size;
    uint32_t sectors;
    int result;

    if (index >= EDGE_LOOP_DEVICE_COUNT) return -EDGE_LINUX_ENXIO;
    device = &g_loop_devices[index];
    edge_loop_lock(device);
    if (!device->configured || device->active_io || device->detaching) {
        result = !device->configured ? -EDGE_LINUX_ENXIO :
                 -EDGE_LINUX_EBUSY;
        edge_loop_unlock(device);
        return result;
    }
    device->detaching = 1;
    backing = &device->backing;
    block = device->block_device;
    offset = device->offset;
    size_limit = device->size_limit;
    block_size = device->block_size;
    edge_loop_unlock(device);
    if (vfs_inode_refresh(backing->superblock, &backing->inode) < 0) {
        edge_loop_lock(device);
        device->detaching = 0;
        edge_loop_unlock(device);
        return -EDGE_LINUX_EIO;
    }
    result = edge_loop_visible_sectors(
        backing, offset, size_limit, block_size, &sectors);
    if (result == 0) result = block_resize(block, sectors);
    edge_loop_lock(device);
    device->detaching = 0;
    edge_loop_unlock(device);
    return result < 0 ? -EDGE_LINUX_EBUSY : 0;
}

static int edge_loop_set_direct_io(uint32_t index, int enabled) {
    edge_loop_device_t *device;

    if (index >= EDGE_LOOP_DEVICE_COUNT) return -EDGE_LINUX_ENXIO;
    device = &g_loop_devices[index];
    edge_loop_lock(device);
    if (!device->configured) {
        edge_loop_unlock(device);
        return -EDGE_LINUX_ENXIO;
    }
    device->direct_io = enabled != 0;
    if (device->direct_io)
        device->flags |= EDGE_LOOP_FLAG_DIRECT_IO;
    else
        device->flags &= ~EDGE_LOOP_FLAG_DIRECT_IO;
    block_set_cache_enabled(device->block_device, !device->direct_io);
    edge_loop_unlock(device);
    return 0;
}

void edge_loop_initialize(void) {
    memset(g_loop_devices, 0, sizeof(g_loop_devices));
    for (uint32_t index = 0; index < EDGE_LOOP_DEVICE_COUNT; ++index)
        g_loop_devices[index].block_size = EDGE_LOOP_DEFAULT_BLOCK_SIZE;
}

static int64_t edge_loop_control_ioctl(
    const edge_loop_ioctl_request_t *request) {
    uint32_t index;

    switch (request->command) {
        case EDGE_LOOP_CTL_GET_FREE:
            for (index = 0; index < EDGE_LOOP_DEVICE_COUNT; ++index) {
                edge_loop_device_t *device = &g_loop_devices[index];
                int free;
                edge_loop_lock(device);
                free = !device->configured && !device->detaching;
                edge_loop_unlock(device);
                if (free) return index;
            }
            return -EDGE_LINUX_ENOSPC;
        case EDGE_LOOP_CTL_ADD:
            if (!request->privileged) return -EDGE_LINUX_EPERM;
            index = (uint32_t)request->argument;
            if (index >= EDGE_LOOP_DEVICE_COUNT)
                return -EDGE_LINUX_EINVAL;
            return index;
        case EDGE_LOOP_CTL_REMOVE:
            if (!request->privileged) return -EDGE_LINUX_EPERM;
            index = (uint32_t)request->argument;
            if (index >= EDGE_LOOP_DEVICE_COUNT)
                return -EDGE_LINUX_EINVAL;
            return edge_loop_clear_device(index);
        default:
            return -EDGE_LINUX_ENOTTY;
    }
}

static int64_t edge_loop_block_ioctl(
    uint32_t index, const edge_loop_ioctl_request_t *request) {
    edge_loop_device_t *device;
    block_device_t *block;
    uint64_t value = 0;
    uint32_t value_size = 0;
    int result;

    if (index >= EDGE_LOOP_DEVICE_COUNT)
        return -EDGE_LINUX_ENXIO;
    switch (request->command) {
        case 0x125eu: /* BLKROGET */
        case 0x1260u: /* BLKGETSIZE */
        case 0x1263u: /* BLKRAGET */
        case 0x1265u: /* BLKFRAGET */
        case 0x1267u: /* BLKSECTGET */
        case 0x1268u: /* BLKSSZGET */
        case 0x80081270u: /* BLKBSZGET */
        case 0x80081272u: /* BLKGETSIZE64 */
        case 0x1278u: /* BLKIOMIN */
        case 0x1279u: /* BLKIOOPT */
        case 0x127au: /* BLKALIGNOFF */
        case 0x127bu: /* BLKPBSZGET */
        case 0x127cu: /* BLKDISCARDZEROES */
            break;
        default:
            return -EDGE_LINUX_ENOTTY;
    }
    device = &g_loop_devices[index];
    edge_loop_lock(device);
    if (!device->configured || device->detaching || !device->block_device) {
        edge_loop_unlock(device);
        return -EDGE_LINUX_ENXIO;
    }
    block = device->block_device;
    if (request->command == 0x125eu) { /* BLKROGET */
        value = (device->flags & EDGE_LOOP_FLAG_READ_ONLY) != 0;
        value_size = sizeof(uint32_t);
        result = 0;
    } else {
        result = block_linux_ioctl_query(
            block, request->command, &value, &value_size);
    }
    edge_loop_unlock(device);
    if (result < 0) return result;
    if (!request->argument || !request->copy_to_user)
        return -EDGE_LINUX_EFAULT;
    return request->copy_to_user(
        request->copy_context, request->argument,
        &value, value_size) < 0 ? -EDGE_LINUX_EFAULT : 0;
}

int64_t edge_loop_ioctl_execute(const edge_loop_ioctl_request_t *request) {
    edge_loop_backing_file_t backing;
    edge_loop_info64_t information;
    edge_loop_config_t configuration;
    int index;
    int result;

    if (!request) return -EDGE_LINUX_EINVAL;
    if (edge_loop_is_control_device_number(request->device_number))
        return edge_loop_control_ioctl(request);
    index = edge_loop_index_from_device(request->device_number);
    if (index < 0) return -EDGE_LINUX_ENOTTY;
    result = (int)edge_loop_block_ioctl((uint32_t)index, request);
    if (result != -EDGE_LINUX_ENOTTY) return result;
    if (request->command != EDGE_LOOP_GET_STATUS64 &&
        !request->privileged)
        return -EDGE_LINUX_EPERM;
    switch (request->command) {
        case EDGE_LOOP_SET_FD:
            if (!request->resolve_backing) return -EDGE_LINUX_EBADF;
            memset(&backing, 0, sizeof(backing));
            result = request->resolve_backing(
                request->resolve_context, (int32_t)request->argument,
                &backing);
            if (result < 0) return result;
            memset(&information, 0, sizeof(information));
            return edge_loop_configure_device(
                (uint32_t)index, &backing, &information,
                EDGE_LOOP_DEFAULT_BLOCK_SIZE);
        case EDGE_LOOP_CONFIGURE:
            if (!request->argument || !request->copy_from_user ||
                !request->resolve_backing)
                return -EDGE_LINUX_EFAULT;
            if (request->copy_from_user(
                    request->copy_context, &configuration,
                    request->argument, sizeof(configuration)) < 0)
                return -EDGE_LINUX_EFAULT;
            for (uint32_t reserved = 0; reserved < 8u; ++reserved)
                if (configuration.reserved[reserved])
                    return -EDGE_LINUX_EINVAL;
            memset(&backing, 0, sizeof(backing));
            result = request->resolve_backing(
                request->resolve_context,
                (int32_t)configuration.descriptor, &backing);
            if (result < 0) return result;
            return edge_loop_configure_device(
                (uint32_t)index, &backing, &configuration.info,
                configuration.block_size ? configuration.block_size :
                    EDGE_LOOP_DEFAULT_BLOCK_SIZE);
        case EDGE_LOOP_CLR_FD:
            return edge_loop_clear_device((uint32_t)index);
        case EDGE_LOOP_SET_STATUS64:
            if (!request->argument || !request->copy_from_user)
                return -EDGE_LINUX_EFAULT;
            if (request->copy_from_user(
                    request->copy_context, &information,
                    request->argument, sizeof(information)) < 0)
                return -EDGE_LINUX_EFAULT;
            return edge_loop_update_status((uint32_t)index, &information);
        case EDGE_LOOP_GET_STATUS64:
            if (!request->argument || !request->copy_to_user)
                return -EDGE_LINUX_EFAULT;
            result = edge_loop_get_status((uint32_t)index, &information);
            if (result < 0) return result;
            return request->copy_to_user(
                request->copy_context, request->argument,
                &information, sizeof(information)) < 0 ?
                    -EDGE_LINUX_EFAULT : 0;
        case EDGE_LOOP_SET_CAPACITY:
            return edge_loop_refresh_capacity((uint32_t)index);
        case EDGE_LOOP_SET_DIRECT_IO:
            return edge_loop_set_direct_io(
                (uint32_t)index, request->argument != 0);
        case EDGE_LOOP_SET_BLOCK_SIZE:
            if (request->argument > UINT32_MAX)
                return -EDGE_LINUX_EINVAL;
            return edge_loop_set_block_size(
                (uint32_t)index, (uint32_t)request->argument);
        default:
            return -EDGE_LINUX_ENOTTY;
    }
}
