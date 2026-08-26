/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS block-device interface. */

#ifndef BLOCK_BLOCK_H
#define BLOCK_BLOCK_H

#include <stdint.h>

#define BLOCK_NAME_MAX 16
#define BLOCK_MAX_DEVICES 64
#define BLOCK_MAX_SECTOR_SIZE 65536u

enum {
    BLOCK_SYSFS_PATH_NONE = 0,
    BLOCK_SYSFS_PATH_DIR,
    BLOCK_SYSFS_PATH_FILE,
    BLOCK_SYSFS_PATH_LINK
};

typedef struct block_device block_device_t;

typedef struct {
    uint64_t read_ios;
    uint64_t read_sectors;
    uint64_t write_ios;
    uint64_t write_sectors;
    uint64_t flush_ios;
    uint32_t in_flight;
} block_io_statistics_t;

typedef void (*block_io_policy_begin_fn)(uint32_t major, uint32_t minor,
                                         int write, uint64_t bytes);
typedef void (*block_io_policy_complete_fn)(uint32_t major, uint32_t minor,
                                            int write, uint64_t bytes);

#define BLOCK_BATCH_MAX_SECTORS 1024u

typedef struct {
    int (*read_sectors)(block_device_t *dev, uint32_t lba, uint32_t count, void *out);
    int (*write_sectors)(block_device_t *dev, uint32_t lba, uint32_t count, const void *in);
    int (*flush)(block_device_t *dev);
} block_ops_t;

struct block_device {
    int present;
    char name[BLOCK_NAME_MAX];
    uint32_t sector_size;
    uint32_t sector_count;
    uint32_t start_lba;
    void *ctx;
    block_ops_t ops;
    block_device_t *cache_parent;
    uint32_t cache_lba_offset;
    uint32_t max_transfer_sectors;
    uint8_t cache_enabled;
    int32_t linux_disk_index;
    block_io_statistics_t io_statistics;
};

void block_init(void);
int block_register(const char *name, uint32_t sector_size, uint32_t sector_count, uint32_t start_lba, void *ctx, block_ops_t ops);
int block_unregister(block_device_t *device);
int block_resize(block_device_t *device, uint32_t sector_count);
void block_set_cache_parent(block_device_t *device, block_device_t *parent,
                            uint32_t lba_offset);
void block_set_cache_enabled(block_device_t *device, int enabled);
void block_set_max_transfer_sectors(block_device_t *device,
                                    uint32_t max_transfer_sectors);
uint32_t block_max_transfer_sectors(const block_device_t *device);
block_device_t *block_get(int idx);
block_device_t *block_find(const char *name);
block_device_t *block_find_linux_device(uint64_t device_number);
int block_count(void);
int block_read_sectors(block_device_t *dev, uint32_t lba, uint32_t count, void *out);
int block_write_sectors(block_device_t *dev, uint32_t lba, uint32_t count, const void *in);
int block_flush(block_device_t *dev);
uint64_t block_device_size_bytes(const block_device_t *dev);
int64_t block_read_bytes(block_device_t *dev, uint64_t offset, void *out,
                         uint32_t length);
int64_t block_write_bytes(block_device_t *dev, uint64_t offset,
                          const void *input, uint32_t length);
int block_discard_bytes(block_device_t *dev, uint64_t offset,
                        uint64_t length);
int block_linux_ioctl_query(const block_device_t *dev, uint32_t command,
                            uint64_t *value, uint32_t *value_size);
int block_is_partition(const block_device_t *dev);
int block_partition_parent_name(const block_device_t *dev, char *out, uint32_t max);
int block_partition_number(const block_device_t *dev);
int block_linux_major_minor(const block_device_t *dev, uint32_t *major, uint32_t *minor);
int block_io_statistics_snapshot(const block_device_t *dev,
                                 block_io_statistics_t *statistics);
void block_set_io_policy(block_io_policy_begin_fn begin,
                         block_io_policy_complete_fn complete);
int block_disk_name_by_index(uint32_t idx, char *out, uint32_t max);
int block_device_name_by_index(uint32_t idx, char *out, uint32_t max);
int block_partition_name_by_index(const char *disk_name, uint32_t idx, char *out, uint32_t max);
int block_sysfs_path_kind(const char *path);
int block_sysfs_read_file(const char *path, char *out, uint32_t max);
int block_sysfs_readlink(const char *path, char *out, uint32_t max);

#endif
