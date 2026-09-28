/* SPDX-License-Identifier: MPL-2.0 */
/* Exercise the ext4 ACL ABI through real xattr operations and disk read-back. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define EDGEOS_HOST_TEST 1
#define STDIO_H
#define STRING_H
#ifndef EXT4_TEST_SOURCE
#define EXT4_TEST_SOURCE "../../src/fs/ext4/ext4.c"
#endif
#include EXT4_TEST_SOURCE
#include "../../src/fs/permission.c"

static const uint8_t journal_disk[] = {
    1,0,0,0, 1,0,7,0, 4,0,5,0, 8,0,5,0,4,0,0,0, 16,0,5,0, 32,0,5,0
};
static const uint8_t journal_xattr[] = {
    2,0,0,0, 1,0,7,0,255,255,255,255, 4,0,5,0,255,255,255,255,
    8,0,5,0,4,0,0,0, 16,0,5,0,255,255,255,255, 32,0,5,0,255,255,255,255
};
static const uint8_t empty_acl[] = {2,0,0,0};
static uint8_t disk[32 * 4096];
static ext4_fs_t fs;
static block_device_t device;
static vfs_superblock_t super;
static vfs_inode_t inode;
static unsigned pages_live, allocations, writes;
static int fail_allocation;
static unsigned path_invalidations;
void vfs_path_cache_invalidate_all(void) { ++path_invalidations; }
int linux_group_list_contains(const linux_group_list_t *groups, uint32_t gid) {
    (void)groups; (void)gid; assert(!"No supplementary groups in this fixture"); return 0;
}

void *arch_vm_alloc_page(void) {
    if (fail_allocation) return NULL;
    void *page = calloc(1, 4096);
    assert(page);
    ++pages_live;
    ++allocations;
    return page;
}
void arch_vm_free_page(void *page) {
    assert(page && pages_live);
    --pages_live;
    free(page);
}
int kernel_current_pid(void) { return 1; }
const char *kernel_current_comm(void) { return "acl-backend-test"; }
uintptr_t kernel_current_context_token(void) { return 1; }
int kernel_runtime_wait_sequence(volatile uint64_t *sequence, uint64_t observed,
                                 uint64_t timeout) {
    (void)sequence; (void)observed; (void)timeout;
    assert(!"Unexpected contention"); return 0;
}
int kernel_runtime_yield(void) { assert(!"Unexpected contention"); return 0; }
int kernel_runtime_contention_begin(void) { assert(!"Unexpected contention"); return 0; }
void kernel_runtime_contention_end(int released) { (void)released; assert(0); }
void kernel_runtime_contention_notify(void) {}
#ifdef __aarch64__
uint32_t edgeos_arm64_page_lifecycle(uint64_t physical,
        uint64_t *last_free_caller, uint64_t *last_alloc_caller) {
    (void)physical;
    if (last_free_caller) *last_free_caller = 0;
    if (last_alloc_caller) *last_alloc_caller = 0;
    return 1;
}
#endif
void kernel_runtime_notify_sequence(volatile uint64_t *sequence) { (void)sequence; }
uint64_t boottime_realtime_us(void) { return 123000000; }
int block_read_sectors(block_device_t *dev, uint32_t lba, uint32_t count, void *out) {
    assert(dev == &device && (uint64_t)(lba + count) * 512 <= sizeof(disk));
    memcpy(out, disk + lba * 512, count * 512); return 0;
}
int block_write_sectors(block_device_t *dev, uint32_t lba, uint32_t count, const void *in) {
    assert(dev == &device && (uint64_t)(lba + count) * 512 <= sizeof(disk));
    memcpy(disk + lba * 512, in, count * 512); ++writes; return 0;
}

static ext4_xattr_view_t view_for(uint8_t *data, uint32_t size, int external) {
    ext4_xattr_view_t view = {0};
    view.data = data; view.size = size; view.external = external;
    view.entry_offset = external ? sizeof(ext4_xattr_header_t) : 4;
    view.value_base = external ? 0 : 4;
    return view;
}

static void fixture(const char *name, const uint8_t *value, uint32_t length,
                    int external) {
    assert(!pages_live);
    memset(&fs, 0, sizeof(fs)); memset(disk, 0, sizeof(disk));
    device.sector_size = 512;
    fs.bdev = &device; fs.block_size = 4096; fs.desc_size = sizeof(ext4_bgdesc_t);
    fs.sb.magic = 0xef53; fs.sb.inodes_count = fs.sb.inodes_per_group = 16;
    fs.sb.blocks_count_lo = fs.sb.blocks_per_group = 32; fs.sb.inode_size = 256;
    fs.bg.inode_table_lo = 5;
    memcpy(disk + 4096, &fs.bg, sizeof(fs.bg));
    ext4_inode_t *raw = (void *)(disk + 5 * 4096);
    raw->mode = 0042755; raw->links_count = 2;
    uint16_t extra = 32;
    memcpy((uint8_t *)raw + sizeof(*raw), &extra, sizeof(extra));
    super.fs_private = &fs; inode.ino = 1; inode.mode = VFS_INODE_DIR | 02755;
    g_ext4_mounts = &fs;
    ext4_xattr_key_t key;
    assert(ext4_xattr_split_name(name, &key) == 0);
    uint8_t *area = external ? disk + 20 * 4096 : (uint8_t *)raw + 160;
    uint32_t size = external ? 4096 : 96;
    assert(ext4_xattr_build(area, size, external, NULL, &key, value, length, 1, NULL) == 0);
    if (external) {
        /* Keep a second attribute so removal exercises the existing block. */
        uint8_t copy[4096]; memcpy(copy, area, sizeof(copy));
        ext4_xattr_view_t old = view_for(copy, sizeof(copy), 1);
        ext4_xattr_key_t other = { .index = EXT4_XATTR_INDEX_USER, .length = 4, .name = "keep" };
        assert(ext4_xattr_build(area, size, 1, &old, &other, "raw", 3, 1, NULL) == 0);
        raw->file_acl_lo = 20; raw->blocks_lo = 8;
    }
    writes = 0;
}
static void finish(void) {
    assert(!fs.op_lock && !fs.op_lock_depth);
    ext4_dynamic_state_release(&fs); g_ext4_mounts = NULL;
    assert(!pages_live);
}
static void check_raw(const char *name, const void *expected, uint32_t length, int external) {
    /* Flush deferred writes, then inspect device bytes without cache reads. */
    assert(block_cache_flush_all(&fs) == 0);
    ext4_inode_t *raw = (void *)(disk + 5 * 4096);
    uint8_t *area = external ? disk + raw->file_acl_lo * 4096 : (uint8_t *)raw + 160;
    ext4_xattr_view_t view = view_for(area, external ? 4096 : 96, external);
    uint32_t magic; memcpy(&magic, area, 4);
    if (!magic) { assert(!expected); return; }
    assert(ext4_xattr_validate_area(&view) == 0);
    ext4_xattr_key_t key; assert(ext4_xattr_split_name(name, &key) == 0);
    const ext4_xattr_entry_t *entry = ext4_xattr_lookup(&view, &key);
    if (!expected) { assert(!entry); return; }
    assert(entry && entry->value_size == length);
    assert(!memcmp(view.data + view.value_base + entry->value_offs, expected, length));
}
static void get_journal(const char *name) {
    uint8_t out[64]; memset(out, 0xa5, sizeof(out));
    assert(ext4_getxattr_locked(&super, &inode, name, NULL, 0) == 44);
    assert(ext4_getxattr_locked(&super, &inode, name, out, 0) == 44);
    assert(ext4_getxattr_locked(&super, &inode, name, out, 43) == VFS_XATTR_ERR_RANGE);
    for (unsigned i = 0; i < sizeof(out); ++i) assert(out[i] == 0xa5);
    assert(ext4_getxattr_locked(&super, &inode, name, NULL, 44) == VFS_XATTR_ERR_INVALID);
    assert(ext4_getxattr_locked(&super, &inode, name, out, 44) == 44);
    assert(!memcmp(out, journal_xattr, 44));
    for (unsigned i = 44; i < sizeof(out); ++i) assert(out[i] == 0xa5);
}
static void roundtrip(const char *name, int external) {
    fixture(name, journal_disk, sizeof(journal_disk), external);
    get_journal(name); assert(!writes);
    unsigned before = allocations;
    assert(ext4_setxattr_locked(&super, &inode, name, journal_xattr, 44, VFS_XATTR_CREATE) == VFS_XATTR_ERR_EXISTS);
    assert(allocations == before && !writes);
    /* Conversion must survive the builder clearing its scratch destination. */
    memcpy(fs.xattr_new, journal_xattr, 44);
    assert(ext4_setxattr_locked(&super, &inode, name, fs.xattr_new, 44, VFS_XATTR_REPLACE) == 0);
    assert(allocations > before);
    check_raw(name, journal_disk, 28, external); assert(writes); get_journal(name);
    unsigned saved_writes = writes;
    fail_allocation = 1;
    assert(ext4_setxattr_locked(&super, &inode, name, journal_xattr, 44, 0) == VFS_XATTR_ERR_NOSPC);
    fail_allocation = 0;
    assert(writes == saved_writes); check_raw(name, journal_disk, 28, external);
    uint8_t bad[44]; memcpy(bad, journal_xattr, sizeof(bad)); bad[6] = 8;
    assert(ext4_setxattr_locked(&super, &inode, name, bad, 44, 0) == VFS_XATTR_ERR_INVALID);
    assert(ext4_setxattr_locked(&super, &inode, name, NULL, 0, 0) == VFS_XATTR_ERR_INVALID);
    assert(writes == saved_writes);
    assert(ext4_setxattr_locked(&super, &inode, name, empty_acl, 4, VFS_XATTR_REPLACE) == 0);
    check_raw(name, NULL, 0, external);
    assert(ext4_getxattr_locked(&super, &inode, name, NULL, 0) == VFS_XATTR_ERR_NO_DATA);
    assert(ext4_setxattr_locked(&super, &inode, name, empty_acl, 4, VFS_XATTR_REPLACE) == VFS_XATTR_ERR_NO_DATA);
    saved_writes = writes;
    assert(ext4_setxattr_locked(&super, &inode, name, empty_acl, 4, VFS_XATTR_CREATE) == 0);
    assert(writes == saved_writes);
    if (external) check_raw("user.keep", "raw", 3, 1);
    /* A fresh set must persist compact v1, even after removal. */
    assert(ext4_setxattr_locked(&super, &inode, name, journal_xattr, 44, VFS_XATTR_CREATE) == 0);
    check_raw(name, journal_disk, 28, 0); get_journal(name);
    finish();
}
static void malformed_and_legacy(const char *name, int external) {
    uint8_t bad[28]; memcpy(bad, journal_disk, sizeof(bad)); bad[6] = 8;
    fixture(name, bad, sizeof(bad), external);
    uint8_t out[64]; memset(out, 0xa5, sizeof(out));
    assert(ext4_getxattr_locked(&super, &inode, name, NULL, 0) == VFS_XATTR_ERR_IO);
    assert(ext4_getxattr_locked(&super, &inode, name, out, sizeof(out)) == VFS_XATTR_ERR_IO);
    for (unsigned i = 0; i < sizeof(out); ++i) assert(out[i] == 0xa5);
    finish();
    fixture(name, journal_disk, 4, external);
    assert(ext4_getxattr_locked(&super, &inode, name, NULL, 0) == VFS_XATTR_ERR_NO_DATA);
    finish();
    fixture(name, journal_xattr, 44, external); get_journal(name);
    assert(ext4_setxattr_locked(&super, &inode, name, journal_xattr, 44, 0) == 0);
    check_raw(name, journal_disk, 28, external); finish();
}
static uint16_t persisted_mode(void) {
    assert(block_cache_flush_all(&fs) == 0);
    return ((ext4_inode_t *)(disk + 5 * 4096))->mode;
}
static void mode_sync(int external, int legacy) {
    const char *name = "system.posix_acl_access";
    const uint8_t acl_disk[] = {
        1,0,0,0, 1,0,7,0, 2,0,7,0,42,0,0,0,
        4,0,5,0, 8,0,7,0,4,0,0,0, 16,0,7,0, 32,0,1,0
    };
    uint8_t acl_xattr[52], out[52], changed[52], expected_disk[36];
    assert(edge_ext4_acl_from_disk(acl_disk, 36, acl_xattr, 52) == 52);
    fixture(name, legacy ? acl_xattr : acl_disk, legacy ? 52 : 36, external);
    /* Real permission evaluator grants the named user and group initially. */
    assert(permission_posix_acl_check(&inode, 4, 42, 99, NULL, 0, acl_xattr, 52) == 0);
    assert(permission_posix_acl_check(&inode, 4, 99, 4, NULL, 0, acl_xattr, 52) == 0);
    unsigned before = path_invalidations;
    assert(ext4_setxattr_locked(&super, &inode, name, acl_xattr, 52, 0) == 0);
    assert((persisted_mode() & 07777) == 02771);
    assert((inode.mode & 07777) == 02771 && path_invalidations > before);
    /* Restrict the ACL mask; mode group bits must follow the mask, not GROUP_OBJ. */
    memcpy(changed, acl_xattr, 52); changed[38] = 2;
    assert(ext4_setxattr_locked(&super, &inode, name, changed, 52, 0) == 0);
    assert((persisted_mode() & 07777) == 02721 && (inode.mode & 07777) == 02721);
    /* Allocation failure must not change either permission representation. */
    fail_allocation = 1;
    assert(ext4_setattr(&super, &inode, 0, 0, 0, VFS_SETATTR_MODE) < 0);
    fail_allocation = 0;
    assert((persisted_mode() & 07777) == 02721);
    assert(ext4_getxattr_locked(&super, &inode, name, out, 52) == 52);
    assert(!memcmp(out, changed, 52));
    assert(ext4_setattr(&super, &inode, 0, 0, 0, VFS_SETATTR_MODE) == 0);
    assert((persisted_mode() & 07777) == 0);
    assert(ext4_getxattr_locked(&super, &inode, name, out, 52) == 52);
    memcpy(changed, acl_xattr, 52);
    changed[6] = changed[38] = changed[46] = 0;
    assert(!memcmp(out, changed, 52)); /* Named IDs, grants, and GROUP_OBJ retained. */
    assert(edge_ext4_acl_to_disk(changed, 52, expected_disk, 36) == 36);
    check_raw(name, expected_disk, 36, external);
    for (unsigned who = 0; who < 4; ++who) {
        uint32_t uid = who == 0 ? 0 : who == 1 ? 42 : 99;
        uint32_t gid = who == 2 ? 4 : 99;
        for (int bit = 1; bit <= 4; bit <<= 1)
            assert(permission_posix_acl_check(&inode, bit, uid, gid, NULL, 0, out, 52) == -EDGE_LINUX_EACCES);
    }
    /* Restoring group read changes the mask while retaining the named grants. */
    assert(ext4_setattr(&super, &inode, 0640, 0, 0, VFS_SETATTR_MODE) == 0);
    assert((persisted_mode() & 07777) == 0640);
    assert(ext4_getxattr_locked(&super, &inode, name, out, 52) == 52);
    assert(permission_posix_acl_check(&inode, 4, 42, 99, NULL, 0, out, 52) == 0);
    assert(permission_posix_acl_check(&inode, 2, 42, 99, NULL, 0, out, 52) == -EDGE_LINUX_EACCES);
    finish();
    /* chmod on an untouched legacy v2 value also emits compact v1. */
    fixture(name, acl_xattr, 52, external);
    assert(ext4_setattr(&super, &inode, 0, 0, 0, VFS_SETATTR_MODE) == 0);
    check_raw(name, expected_disk, 36, external); finish();
}
static void minimal_and_default_mode(int external) {
    const char *access = "system.posix_acl_access", *defaults = "system.posix_acl_default";
    uint8_t minimal[] = {2,0,0,0, 1,0,6,0,255,255,255,255,
        4,0,4,0,255,255,255,255, 32,0,0,0,255,255,255,255};
    fixture(access, journal_disk, 28, external);
    assert(ext4_setxattr_locked(&super, &inode, access, minimal, 28, 0) == 0);
    assert((persisted_mode() & 07777) == 02640);
    assert(ext4_setattr(&super, &inode, 0751, 123, 456,
        VFS_SETATTR_MODE | VFS_SETATTR_UID | VFS_SETATTR_GID) == 0);
    assert((persisted_mode() & 07777) == 0751);
    ext4_inode_t *raw = (void *)(disk + 5 * 4096);
    assert(ext4_inode_uid(raw) == 123 && ext4_inode_gid(raw) == 456);
    uint8_t out[28];
    assert(ext4_getxattr_locked(&super, &inode, access, out, 28) == 28);
    minimal[6] = 7; minimal[14] = 5; minimal[22] = 1;
    assert(!memcmp(out, minimal, 28)); finish();
    fixture(defaults, journal_disk, 28, external);
    unsigned before = path_invalidations;
    assert(ext4_setxattr_locked(&super, &inode, defaults, minimal, 28, 0) == 0);
    assert((persisted_mode() & 07777) == 02755 && path_invalidations == before);
    assert(ext4_setattr(&super, &inode, 0, 0, 0, VFS_SETATTR_MODE) == 0);
    assert((persisted_mode() & 07777) == 0);
    assert(ext4_getxattr_locked(&super, &inode, defaults, out, 28) == 28);
    assert(!memcmp(out, minimal, 28)); finish();
    uint8_t bad[28]; memcpy(bad, journal_disk, 28); bad[6] = 8;
    fixture(access, bad, 28, external);
    assert(ext4_setattr(&super, &inode, 0, 0, 0, VFS_SETATTR_MODE) < 0);
    assert((persisted_mode() & 07777) == 02755); check_raw(access, bad, 28, external); finish();
}
int main(void) {
    for (int external = 0; external < 2; ++external) {
        mode_sync(external, 0); mode_sync(external, 1);
        minimal_and_default_mode(external);
    }
    const char *names[] = {"system.posix_acl_access", "system.posix_acl_default"};
    for (unsigned n = 0; n < 2; ++n) for (int external = 0; external < 2; ++external) {
        roundtrip(names[n], external); malformed_and_legacy(names[n], external);
    }
    fixture("user.raw", journal_disk, 28, 0);
    uint8_t out[44];
    assert(ext4_getxattr_locked(&super, &inode, "user.raw", out, sizeof(out)) == 28);
    assert(!memcmp(out, journal_disk, 28));
    assert(ext4_setxattr_locked(&super, &inode, "user.raw", journal_xattr, 44, 0) == 0);
    check_raw("user.raw", journal_xattr, 44, 0); finish();
    puts("ext4_acl_backend_unit: PASS (inline/external access/default ACLs, disk read-back, flags, errors, legacy v2, raw xattrs, chmod and ACL mode synchronization)");
    return 0;
}
