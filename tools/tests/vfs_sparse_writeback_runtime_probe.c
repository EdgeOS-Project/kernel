#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <unistd.h>

#define PAGE_BYTES 4096u
#define TEST_PATH "/var/tmp/edgeos-vfs-sparse-writeback"
#define FIEMAP_FLAG_SYNC 0x00000001u
#define FIEMAP_EXTENT_LAST 0x00000001u
#ifndef FALLOC_FL_KEEP_SIZE
#define FALLOC_FL_KEEP_SIZE 0x01
#endif
#ifndef FALLOC_FL_PUNCH_HOLE
#define FALLOC_FL_PUNCH_HOLE 0x02
#endif
#ifndef FALLOC_FL_COLLAPSE_RANGE
#define FALLOC_FL_COLLAPSE_RANGE 0x08
#endif
#ifndef FALLOC_FL_INSERT_RANGE
#define FALLOC_FL_INSERT_RANGE 0x20
#endif

struct fiemap_extent {
    uint64_t fe_logical;
    uint64_t fe_physical;
    uint64_t fe_length;
    uint64_t fe_reserved64[2];
    uint32_t fe_flags;
    uint32_t fe_reserved[3];
};

struct fiemap {
    uint64_t fm_start;
    uint64_t fm_length;
    uint32_t fm_flags;
    uint32_t fm_mapped_extents;
    uint32_t fm_extent_count;
    uint32_t fm_reserved;
    struct fiemap_extent fm_extents[];
};

#define FS_IOC_FIEMAP _IOWR('f', 11, struct fiemap)

struct fiemap_request {
    struct fiemap header;
    struct fiemap_extent extents[4];
};

static void fail(const char *operation) {
    fprintf(stderr, "VFS_RUNTIME_FAIL %s errno=%d (%s)\n",
            operation, errno, strerror(errno));
    exit(1);
}

static void require(int condition, const char *operation) {
    if (!condition) {
        errno = EIO;
        fail(operation);
    }
}

static void fill_page(uint8_t *page, uint8_t value) {
    memset(page, value, PAGE_BYTES);
}

static void write_exact(int fd, const void *data, size_t length,
                        off_t offset) {
    const uint8_t *bytes = data;
    size_t complete = 0;

    while (complete < length) {
        ssize_t result = pwrite(fd, bytes + complete, length - complete,
                                offset + (off_t)complete);
        if (result < 0) fail("pwrite");
        if (result == 0) {
            errno = EIO;
            fail("short-pwrite");
        }
        complete += (size_t)result;
    }
}

static void read_exact(int fd, void *data, size_t length, off_t offset) {
    uint8_t *bytes = data;
    size_t complete = 0;

    while (complete < length) {
        ssize_t result = pread(fd, bytes + complete, length - complete,
                               offset + (off_t)complete);
        if (result < 0) fail("pread");
        if (result == 0) {
            errno = EIO;
            fail("short-pread");
        }
        complete += (size_t)result;
    }
}

static void expect_page(int fd, off_t offset, uint8_t value,
                        const char *operation) {
    uint8_t page[PAGE_BYTES];

    read_exact(fd, page, sizeof(page), offset);
    for (size_t index = 0; index < sizeof(page); ++index)
        require(page[index] == value, operation);
}

int main(void) {
    struct fiemap_request map_request;
    struct stat status;
    uint8_t page[PAGE_BYTES];
    uint8_t *mapping;
    off_t sparse_extents[4];
    int fd;

    if (getpid() == 1 && mount(NULL, "/", NULL, MS_REMOUNT, NULL) < 0)
        fail("remount-root-read-write");
    (void)unlink(TEST_PATH);
    fd = open(TEST_PATH, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0) fail("open-sparse");
    if (ftruncate(fd, 16u * PAGE_BYTES) < 0) fail("ftruncate-sparse");
    fill_page(page, 'A');
    write_exact(fd, page, sizeof(page), 0);
    fill_page(page, 'B');
    write_exact(fd, page, sizeof(page), 8u * PAGE_BYTES);
    if (fsync(fd) < 0) fail("fsync-sparse");

    sparse_extents[0] = lseek(fd, 0, SEEK_DATA);
    sparse_extents[1] = lseek(fd, 0, SEEK_HOLE);
    sparse_extents[2] = lseek(fd, PAGE_BYTES, SEEK_DATA);
    sparse_extents[3] = lseek(fd, 8u * PAGE_BYTES, SEEK_HOLE);
    require(sparse_extents[0] == 0 &&
            sparse_extents[1] == PAGE_BYTES &&
            sparse_extents[2] == 8u * PAGE_BYTES &&
            sparse_extents[3] == 9u * PAGE_BYTES,
            "seek-data-hole");

    memset(&map_request, 0, sizeof(map_request));
    map_request.header.fm_length = UINT64_MAX;
    map_request.header.fm_flags = FIEMAP_FLAG_SYNC;
    map_request.header.fm_extent_count = 4;
    if (ioctl(fd, FS_IOC_FIEMAP, &map_request) < 0) fail("fiemap");
    require(map_request.header.fm_mapped_extents == 2, "fiemap-count");
    require(map_request.extents[0].fe_logical == 0 &&
            map_request.extents[0].fe_length == PAGE_BYTES,
            "fiemap-first");
    require(map_request.extents[1].fe_logical == 8u * PAGE_BYTES &&
            map_request.extents[1].fe_length == PAGE_BYTES &&
            (map_request.extents[1].fe_flags & FIEMAP_EXTENT_LAST),
            "fiemap-last");

    mapping = mmap(NULL, 16u * PAGE_BYTES, PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED) fail("mmap-sparse");
    memset(mapping + PAGE_BYTES, 'C', PAGE_BYTES);
    if (msync(mapping + PAGE_BYTES, PAGE_BYTES, MS_SYNC) < 0)
        fail("msync-sparse");
    if (fsync(fd) < 0) fail("fsync-mapped");
    if (munmap(mapping, 16u * PAGE_BYTES) < 0) fail("munmap-sparse");
    close(fd);

    fd = open(TEST_PATH, O_RDONLY);
    if (fd < 0) fail("reopen-sparse");
    expect_page(fd, PAGE_BYTES, 'C', "mapped-persistence");
    close(fd);
    if (unlink(TEST_PATH) < 0) fail("unlink-sparse");

    fd = open(TEST_PATH, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0) fail("open-truncate");
    for (uint8_t value = 'A'; value <= 'C'; ++value) {
        fill_page(page, value);
        write_exact(fd, page, sizeof(page), (value - 'A') * PAGE_BYTES);
    }
    if (fsync(fd) < 0) fail("fsync-truncate-fixture");
    mapping = mmap(NULL, 3u * PAGE_BYTES, PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED) fail("mmap-truncate");
    if (ftruncate(fd, PAGE_BYTES + PAGE_BYTES / 2u) < 0)
        fail("ftruncate-shrink");
    require(mapping[PAGE_BYTES] == 'B', "truncate-retained-mapping");
    if (ftruncate(fd, 3u * PAGE_BYTES) < 0) fail("ftruncate-extend");
    for (size_t index = PAGE_BYTES + PAGE_BYTES / 2u;
         index < 3u * PAGE_BYTES; ++index)
        require(mapping[index] == 0, "truncate-zero-extension");
    if (munmap(mapping, 3u * PAGE_BYTES) < 0) fail("munmap-truncate");
    close(fd);
    if (unlink(TEST_PATH) < 0) fail("unlink-truncate");

    fd = open(TEST_PATH, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0) fail("open-fallocate");
    for (uint8_t value = 'A'; value <= 'E'; ++value) {
        fill_page(page, value);
        write_exact(fd, page, sizeof(page), (value - 'A') * PAGE_BYTES);
    }
    if (fsync(fd) < 0) fail("fsync-fallocate-fixture");
    mapping = mmap(NULL, 5u * PAGE_BYTES, PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED) fail("mmap-fallocate");
    if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                  PAGE_BYTES, PAGE_BYTES) < 0)
        fail("fallocate-punch");
    expect_page(fd, PAGE_BYTES, 0, "punch-read");
    for (size_t index = PAGE_BYTES; index < 2u * PAGE_BYTES; ++index)
        require(mapping[index] == 0, "punch-mapping");
    require(lseek(fd, PAGE_BYTES, SEEK_DATA) == 2u * PAGE_BYTES,
            "punch-seek-data");

    if (fallocate(fd, FALLOC_FL_COLLAPSE_RANGE,
                  PAGE_BYTES, PAGE_BYTES) < 0)
        fail("fallocate-collapse");
    if (fstat(fd, &status) < 0) fail("fstat-collapse");
    require(status.st_size == 4u * PAGE_BYTES, "collapse-size");
    expect_page(fd, 0, 'A', "collapse-page-a");
    expect_page(fd, PAGE_BYTES, 'C', "collapse-page-c");
    expect_page(fd, 2u * PAGE_BYTES, 'D', "collapse-page-d");
    expect_page(fd, 3u * PAGE_BYTES, 'E', "collapse-page-e");
    require(mapping[PAGE_BYTES] == 'C' &&
            mapping[2u * PAGE_BYTES] == 'D' &&
            mapping[3u * PAGE_BYTES] == 'E', "collapse-mapping");

    if (fallocate(fd, FALLOC_FL_INSERT_RANGE,
                  2u * PAGE_BYTES, PAGE_BYTES) < 0)
        fail("fallocate-insert");
    if (fstat(fd, &status) < 0) fail("fstat-insert");
    require(status.st_size == 5u * PAGE_BYTES, "insert-size");
    expect_page(fd, 0, 'A', "insert-page-a");
    expect_page(fd, PAGE_BYTES, 'C', "insert-page-c");
    expect_page(fd, 2u * PAGE_BYTES, 0, "insert-hole");
    expect_page(fd, 3u * PAGE_BYTES, 'D', "insert-page-d");
    expect_page(fd, 4u * PAGE_BYTES, 'E', "insert-page-e");
    require(mapping[2u * PAGE_BYTES] == 0 &&
            mapping[3u * PAGE_BYTES] == 'D' &&
            mapping[4u * PAGE_BYTES] == 'E', "insert-mapping");
    require(lseek(fd, 2u * PAGE_BYTES, SEEK_DATA) == 3u * PAGE_BYTES,
            "insert-seek-data");
    if (fsync(fd) < 0) fail("fsync-fallocate");
    if (munmap(mapping, 5u * PAGE_BYTES) < 0) fail("munmap-fallocate");
    close(fd);
    if (unlink(TEST_PATH) < 0) fail("unlink-fallocate");

    puts("VFS_SPARSE_WRITEBACK_RUNTIME_PASS extents=2 "
         "truncate=shrink,extend fallocate_modes=punch,collapse,insert");
    fflush(stdout);
    if (getpid() == 1) {
        sync();
        if (reboot(RB_POWER_OFF) < 0) fail("poweroff-after-pass");
    }
    return 0;
}
