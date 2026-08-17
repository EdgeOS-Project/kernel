/* SPDX-License-Identifier: MPL-2.0 */
/* Host unit tests for the architecture-neutral EdgeOS NFSv3 protocol core. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fs/nfsd.h"
#include "vfs/vfs.h"

static vfs_superblock_t g_superblock;
static vfs_inode_t g_root;
static vfs_inode_t g_file;
static vfs_inode_t g_created;
static vfs_inode_t g_directory;
static char g_file_data[128] = "hello-data";
static uint32_t g_file_size = 10u;
static int g_has_created;
static int g_has_directory;

static void fail(const char *message) {
    fprintf(stderr, "nfsd protocol unit failed: %s\n", message);
    exit(1);
}

static void put_u32(uint8_t *buffer, uint32_t *offset, uint32_t value) {
    buffer[(*offset)++] = (uint8_t)(value >> 24);
    buffer[(*offset)++] = (uint8_t)(value >> 16);
    buffer[(*offset)++] = (uint8_t)(value >> 8);
    buffer[(*offset)++] = (uint8_t)value;
}

static uint32_t get_u32(const uint8_t *buffer, uint32_t *offset) {
    uint32_t value = ((uint32_t)buffer[*offset] << 24) |
        ((uint32_t)buffer[*offset + 1u] << 16) |
        ((uint32_t)buffer[*offset + 2u] << 8) |
        buffer[*offset + 3u];
    *offset += 4u;
    return value;
}

static void put_u64(uint8_t *buffer, uint32_t *offset, uint64_t value) {
    put_u32(buffer, offset, (uint32_t)(value >> 32));
    put_u32(buffer, offset, (uint32_t)value);
}

static void put_opaque(uint8_t *buffer, uint32_t *offset,
                       const void *data, uint32_t length) {
    uint32_t padding = (4u - (length & 3u)) & 3u;
    put_u32(buffer, offset, length);
    memcpy(buffer + *offset, data, length);
    *offset += length;
    memset(buffer + *offset, 0, padding);
    *offset += padding;
}

static void put_string(uint8_t *buffer, uint32_t *offset,
                       const char *value) {
    put_opaque(buffer, offset, value, (uint32_t)strlen(value));
}

static uint32_t begin_call(uint8_t *request, uint32_t program,
                           uint32_t version, uint32_t procedure) {
    uint32_t offset = 0;
    put_u32(request, &offset, 0x12345678u);
    put_u32(request, &offset, 0u);
    put_u32(request, &offset, 2u);
    put_u32(request, &offset, program);
    put_u32(request, &offset, version);
    put_u32(request, &offset, procedure);
    put_u32(request, &offset, 0u);
    put_u32(request, &offset, 0u);
    put_u32(request, &offset, 0u);
    put_u32(request, &offset, 0u);
    return offset;
}

static uint32_t dispatch(const uint8_t *request, uint32_t request_bytes,
                         uint8_t *response) {
    uint32_t response_bytes = 0;
    uint32_t offset = 0;
    if (edge_nfsd_rpc_dispatch(request, request_bytes, response, 65536u,
                               &response_bytes) < 0)
        fail("dispatcher rejected a valid request");
    if (response_bytes < 24u || get_u32(response, &offset) != 0x12345678u ||
        get_u32(response, &offset) != 1u || get_u32(response, &offset) != 0u)
        fail("invalid RPC reply header");
    offset += 8u;
    if (get_u32(response, &offset) != 0u)
        fail("RPC call did not succeed");
    return response_bytes;
}

static int test_lookup(vfs_superblock_t *sb, vfs_inode_t *directory,
                       const char *name, vfs_inode_t *out) {
    (void)sb;
    if (directory->ino != g_root.ino) return -1;
    if (strcmp(name, "hello") == 0) {
        *out = g_file;
        out->size = g_file_size;
        return 0;
    }
    if (strcmp(name, "newfile") == 0 && g_has_created) {
        *out = g_created;
        return 0;
    }
    if (strcmp(name, "newdir") == 0 && g_has_directory) {
        *out = g_directory;
        return 0;
    }
    return -1;
}

static int test_read(vfs_superblock_t *sb, vfs_inode_t *inode,
                     uint32_t offset, void *buffer, uint32_t length) {
    uint32_t available;
    (void)sb;
    if (inode->ino != g_file.ino || offset > g_file_size) return -1;
    available = g_file_size - offset;
    if (length > available) length = available;
    memcpy(buffer, g_file_data + offset, length);
    return 0;
}

static int test_write(vfs_superblock_t *sb, vfs_inode_t *inode,
                      uint32_t offset, const void *buffer, uint32_t length) {
    (void)sb;
    if (inode->ino != g_file.ino || offset + length > sizeof(g_file_data))
        return -1;
    memcpy(g_file_data + offset, buffer, length);
    if (offset + length > g_file_size) g_file_size = offset + length;
    inode->size = g_file_size;
    return 0;
}

static int test_create(vfs_superblock_t *sb, vfs_inode_t *directory,
                       const char *name, uint16_t mode, vfs_inode_t *out) {
    (void)sb;
    if (directory->ino != g_root.ino || strcmp(name, "newfile") != 0 ||
        g_has_created)
        return -1;
    g_created.ino = 3u;
    g_created.generation = 1u;
    g_created.mode = VFS_INODE_FILE | (mode & 0777u);
    g_created.nlink = 1u;
    g_created.nlink_valid = 1u;
    g_has_created = 1;
    *out = g_created;
    return 0;
}

static int test_mkdir(vfs_superblock_t *sb, vfs_inode_t *directory,
                      const char *name, uint16_t mode, vfs_inode_t *out) {
    (void)sb;
    if (directory->ino != g_root.ino || strcmp(name, "newdir") != 0 ||
        g_has_directory)
        return -1;
    g_directory.ino = 4u;
    g_directory.generation = 1u;
    g_directory.mode = VFS_INODE_DIR | (mode & 0777u);
    g_directory.nlink = 2u;
    g_directory.nlink_valid = 1u;
    g_has_directory = 1;
    *out = g_directory;
    return 0;
}

static int test_readdir(vfs_superblock_t *sb, vfs_inode_t *directory,
                        uint32_t index, char *name, vfs_inode_t *out) {
    (void)sb;
    if (directory->ino != g_root.ino) return -1;
    if (index == 0u) {
        strcpy(name, "hello");
        *out = g_file;
        out->size = g_file_size;
        return 0;
    }
    if (index == 1u && g_has_created) {
        strcpy(name, "newfile");
        *out = g_created;
        return 0;
    }
    return -1;
}

static int test_statfs(vfs_superblock_t *sb, uint32_t *total,
                       uint32_t *used) {
    (void)sb;
    *total = 1024u;
    *used = 128u;
    return 0;
}

static int test_encode(vfs_superblock_t *sb, const vfs_inode_t *inode,
                       uint32_t *type, void *handle, uint32_t *bytes) {
    (void)sb;
    if (*bytes < 8u) return -3;
    *type = 1u;
    memcpy(handle, &inode->ino, 4u);
    memcpy((uint8_t *)handle + 4u, &inode->generation, 4u);
    *bytes = 8u;
    return 0;
}

static int test_decode(vfs_superblock_t *sb, uint32_t type,
                       const void *handle, uint32_t bytes,
                       vfs_inode_t *out) {
    uint32_t ino;
    (void)sb;
    if (type != 1u || bytes != 8u) return -1;
    memcpy(&ino, handle, 4u);
    if (ino == g_root.ino) *out = g_root;
    else if (ino == g_file.ino) {
        *out = g_file;
        out->size = g_file_size;
    } else if (ino == g_created.ino && g_has_created) *out = g_created;
    else if (ino == g_directory.ino && g_has_directory) *out = g_directory;
    else return -1;
    return 0;
}

uint64_t boottime_realtime_us(void) { return 1000000u; }

int vfs_resolve_canonical(const char *path, char *resolved,
                          uint32_t capacity, vfs_inode_t *inode,
                          vfs_superblock_t **superblock) {
    if (strcmp(path, "/export") != 0 || capacity < 8u) return -1;
    strcpy(resolved, "/export");
    if (inode) *inode = g_root;
    if (superblock) *superblock = &g_superblock;
    return 0;
}

int vfs_mount_id_for_superblock(const vfs_superblock_t *superblock,
                                uint64_t *mount_id) {
    if (superblock != &g_superblock) return -1;
    *mount_id = 7u;
    return 0;
}

vfs_superblock_t *vfs_superblock_for_mount_id(uint64_t mount_id) {
    return mount_id == 7u ? &g_superblock : NULL;
}

vfs_superblock_t *vfs_superblock_acquire(vfs_superblock_t *superblock) {
    return superblock;
}

void vfs_superblock_release(vfs_superblock_t *superblock) {
    (void)superblock;
}

int vfs_encode_file_handle(vfs_superblock_t *sb, const vfs_inode_t *inode,
                           uint32_t *type, void *handle, uint32_t *bytes) {
    return test_encode(sb, inode, type, handle, bytes);
}

int vfs_decode_file_handle(vfs_superblock_t *sb, uint32_t type,
                           const void *handle, uint32_t bytes,
                           vfs_inode_t *out) {
    return test_decode(sb, type, handle, bytes, out);
}

int vfs_inode_refresh(vfs_superblock_t *sb, vfs_inode_t *inode) {
    return test_decode(sb, 1u, &inode->ino, 8u, inode);
}

int vfs_permission_check_as(const vfs_inode_t *inode, int mask,
                            uint32_t uid, uint32_t gid,
                            const struct linux_group_list *groups,
                            uint64_t capabilities) {
    (void)inode; (void)mask; (void)uid; (void)gid;
    (void)groups; (void)capabilities;
    return 0;
}

int vfs_truncate_inode(vfs_superblock_t *sb, vfs_inode_t *inode,
                       uint32_t length) {
    (void)sb;
    if (inode->ino != g_file.ino || length > sizeof(g_file_data)) return -1;
    g_file_size = length;
    inode->size = length;
    return 0;
}

int vfs_inode_setattr(vfs_superblock_t *sb, vfs_inode_t *inode,
                      uint16_t mode, uint32_t uid, uint32_t gid,
                      uint32_t valid) {
    (void)sb;
    if (valid & VFS_SETATTR_MODE)
        inode->mode = (inode->mode & 0xf000u) | (mode & 07777u);
    if (valid & VFS_SETATTR_UID) inode->uid = uid;
    if (valid & VFS_SETATTR_GID) inode->gid = gid;
    if (inode->ino == g_created.ino) g_created = *inode;
    return 0;
}

int vfs_inode_utimens(vfs_superblock_t *sb, vfs_inode_t *inode,
                      uint32_t atime, uint32_t mtime,
                      int set_atime, int set_mtime) {
    (void)sb;
    if (set_atime) inode->atime = atime;
    if (set_mtime) inode->mtime = mtime;
    return 0;
}

int vfs_sync_inode(vfs_superblock_t *sb, const vfs_inode_t *inode,
                   int data_only) {
    (void)sb; (void)inode; (void)data_only;
    return 0;
}

int vfs_sync_mutation_if_required(vfs_superblock_t *sb,
                                  int directory_mutation) {
    (void)sb; (void)directory_mutation;
    return 0;
}

void vfs_path_cache_invalidate_all(void) {}

int main(void) {
    static filesystem_ops_t operations;
    static uint8_t request[65536];
    static uint8_t response[65536];
    uint8_t root_handle[64], file_handle[64];
    uint32_t root_handle_bytes, file_handle_bytes;
    uint32_t offset, response_bytes, cursor, length;

    memset(&operations, 0, sizeof(operations));
    operations.lookup = test_lookup;
    operations.read = test_read;
    operations.write = test_write;
    operations.create = test_create;
    operations.mkdir = test_mkdir;
    operations.readdir = test_readdir;
    operations.statfs = test_statfs;
    operations.encode_handle = test_encode;
    operations.decode_handle = test_decode;
    memset(&g_superblock, 0, sizeof(g_superblock));
    g_superblock.ops = &operations;
    g_superblock.mount_id = 7u;
    g_root.ino = 1u;
    g_root.generation = 1u;
    g_root.mode = VFS_INODE_DIR | 0777u;
    g_root.nlink = 2u;
    g_root.nlink_valid = 1u;
    g_file.ino = 2u;
    g_file.generation = 1u;
    g_file.mode = VFS_INODE_FILE | 0666u;
    g_file.size = g_file_size;
    g_file.nlink = 1u;
    g_file.nlink_valid = 1u;

    if (edge_nfsd_initialize() < 0 ||
        edge_nfsd_export_add("/export", EDGE_NFSD_EXPORT_ROOT_SQUASH) < 0)
        fail("export setup failed");

    offset = begin_call(request, 100000u, 2u, 3u);
    put_u32(request, &offset, 100003u);
    put_u32(request, &offset, 3u);
    put_u32(request, &offset, 6u);
    put_u32(request, &offset, 0u);
    response_bytes = dispatch(request, offset, response);
    cursor = 24u;
    if (response_bytes != 28u || get_u32(response, &cursor) != 2049u)
        fail("rpcbind GETPORT result is wrong");

    offset = begin_call(request, 100005u, 3u, 1u);
    put_string(request, &offset, "/export");
    response_bytes = dispatch(request, offset, response);
    cursor = 24u;
    if (get_u32(response, &cursor) != 0u) fail("mount request failed");
    root_handle_bytes = get_u32(response, &cursor);
    if (!root_handle_bytes || root_handle_bytes > sizeof(root_handle))
        fail("mount returned an invalid handle");
    memcpy(root_handle, response + cursor, root_handle_bytes);

    offset = begin_call(request, 100003u, 3u, 1u);
    put_opaque(request, &offset, root_handle, root_handle_bytes);
    response_bytes = dispatch(request, offset, response);
    cursor = 24u;
    if (response_bytes < 112u || get_u32(response, &cursor) != 0u ||
        get_u32(response, &cursor) != 2u)
        fail("NFS GETATTR did not return the exported directory");

    offset = begin_call(request, 100003u, 3u, 3u);
    put_opaque(request, &offset, root_handle, root_handle_bytes);
    put_string(request, &offset, "hello");
    response_bytes = dispatch(request, offset, response);
    cursor = 24u;
    if (get_u32(response, &cursor) != 0u)
        fail("NFS LOOKUP failed");
    file_handle_bytes = get_u32(response, &cursor);
    if (!file_handle_bytes || file_handle_bytes > sizeof(file_handle))
        fail("LOOKUP returned an invalid handle");
    memcpy(file_handle, response + cursor, file_handle_bytes);

    offset = begin_call(request, 100003u, 3u, 6u);
    put_opaque(request, &offset, file_handle, file_handle_bytes);
    put_u64(request, &offset, 0u);
    put_u32(request, &offset, 32u);
    response_bytes = dispatch(request, offset, response);
    cursor = 24u;
    if (get_u32(response, &cursor) != 0u) fail("NFS READ failed");
    cursor += 88u;
    length = get_u32(response, &cursor);
    cursor += 4u;
    if (length != 10u || get_u32(response, &cursor) != 10u ||
        memcmp(response + cursor, "hello-data", 10u) != 0)
        fail("NFS READ returned incorrect data");
    (void)response_bytes;

    offset = begin_call(request, 100003u, 3u, 7u);
    put_opaque(request, &offset, file_handle, file_handle_bytes);
    put_u64(request, &offset, 0u);
    put_u32(request, &offset, 3u);
    put_u32(request, &offset, 2u);
    put_opaque(request, &offset, "new", 3u);
    dispatch(request, offset, response);
    cursor = 24u;
    if (get_u32(response, &cursor) != 0u ||
        memcmp(g_file_data, "new", 3u) != 0)
        fail("NFS WRITE failed");

    offset = begin_call(request, 100003u, 3u, 8u);
    put_opaque(request, &offset, root_handle, root_handle_bytes);
    put_string(request, &offset, "newfile");
    put_u32(request, &offset, 0u);
    put_u32(request, &offset, 1u); put_u32(request, &offset, 0644u);
    put_u32(request, &offset, 0u); put_u32(request, &offset, 0u);
    put_u32(request, &offset, 0u); put_u32(request, &offset, 0u);
    put_u32(request, &offset, 0u);
    dispatch(request, offset, response);
    cursor = 24u;
    if (get_u32(response, &cursor) != 0u || !g_has_created ||
        g_created.uid != 65534u || g_created.gid != 65534u)
        fail("NFS CREATE failed");

    offset = begin_call(request, 100003u, 3u, 9u);
    put_opaque(request, &offset, root_handle, root_handle_bytes);
    put_string(request, &offset, "newdir");
    put_u32(request, &offset, 1u); put_u32(request, &offset, 0755u);
    put_u32(request, &offset, 0u); put_u32(request, &offset, 0u);
    put_u32(request, &offset, 0u); put_u32(request, &offset, 0u);
    put_u32(request, &offset, 0u);
    dispatch(request, offset, response);
    cursor = 24u;
    if (get_u32(response, &cursor) != 0u || !g_has_directory)
        fail("NFS MKDIR failed");

    dispatch(request, offset, response);
    cursor = 24u;
    if (get_u32(response, &cursor) != 17u)
        fail("NFS MKDIR did not preserve EEXIST");

    puts("nfsd protocol unit: PASS");
    return 0;
}
