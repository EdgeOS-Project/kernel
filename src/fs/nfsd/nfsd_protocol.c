/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS ONC RPC, mount protocol v3, and NFSv3 server core.
 * Copyright (c) EdgeOS Contributors.
 *
 * The protocol engine is architecture-neutral and does not depend on a
 * particular network transport.  Keeping one bounded dispatcher also gives
 * UDP and TCP identical Linux-visible filesystem behavior.
 */

#include "fs/nfsd.h"
#include "kernel/groups.h"
#include "kernel/linux_errno.h"
#include "sys/boottime.h"
#include "vfs/vfs.h"
#include "stdio.h"
#include "string.h"

#define NFSD_MAX_EXPORTS 16u
#define NFSD_MAX_AUTH_GROUPS 32u
#define NFSD_MAX_NAME 255u
#define NFSD_PROTOCOL_PATH_MAX 1024u
#define NFSD_MAX_DATA 32768u
#define NFSD_FH_MAX 64u
#define NFSD_FH_PAYLOAD_MAX 32u

#define RPC_CALL 0u
#define RPC_REPLY 1u
#define RPC_VERSION 2u
#define RPC_MSG_ACCEPTED 0u
#define RPC_MSG_DENIED 1u
#define RPC_SUCCESS 0u
#define RPC_PROG_UNAVAIL 1u
#define RPC_PROG_MISMATCH 2u
#define RPC_PROC_UNAVAIL 3u
#define RPC_GARBAGE_ARGS 4u
#define RPC_SYSTEM_ERR 5u
#define RPC_MISMATCH 0u
#define RPC_AUTH_ERROR 1u
#define RPC_AUTH_NONE 0u
#define RPC_AUTH_SYS 1u

#define RPCB_PROGRAM 100000u
#define RPCB_VERSION 2u
#define MOUNT_PROGRAM 100005u
#define MOUNT_VERSION 3u
#define NFS_PROGRAM 100003u
#define NFS_VERSION 3u

#define IPPROTO_TCP_VALUE 6u
#define IPPROTO_UDP_VALUE 17u
#define RPCB_PORT 111u
#define MOUNT_PORT 20048u
#define NFS_PORT 2049u

#define NFS3_OK 0u
#define NFS3ERR_PERM 1u
#define NFS3ERR_NOENT 2u
#define NFS3ERR_IO 5u
#define NFS3ERR_NXIO 6u
#define NFS3ERR_ACCES 13u
#define NFS3ERR_EXIST 17u
#define NFS3ERR_XDEV 18u
#define NFS3ERR_NODEV 19u
#define NFS3ERR_NOTDIR 20u
#define NFS3ERR_ISDIR 21u
#define NFS3ERR_INVAL 22u
#define NFS3ERR_FBIG 27u
#define NFS3ERR_NOSPC 28u
#define NFS3ERR_ROFS 30u
#define NFS3ERR_MLINK 31u
#define NFS3ERR_NAMETOOLONG 63u
#define NFS3ERR_NOTEMPTY 66u
#define NFS3ERR_DQUOT 69u
#define NFS3ERR_STALE 70u
#define NFS3ERR_REMOTE 71u
#define NFS3ERR_BADHANDLE 10001u
#define NFS3ERR_NOT_SYNC 10002u
#define NFS3ERR_BAD_COOKIE 10003u
#define NFS3ERR_NOTSUPP 10004u
#define NFS3ERR_TOOSMALL 10005u
#define NFS3ERR_SERVERFAULT 10006u
#define NFS3ERR_BADTYPE 10007u

#define MNT3_OK 0u
#define MNT3ERR_PERM 1u
#define MNT3ERR_NOENT 2u
#define MNT3ERR_IO 5u
#define MNT3ERR_ACCES 13u
#define MNT3ERR_NOTDIR 20u
#define MNT3ERR_INVAL 22u
#define MNT3ERR_NAMETOOLONG 63u
#define MNT3ERR_NOTSUPP 10004u
#define MNT3ERR_SERVERFAULT 10006u

#define ACCESS3_READ 0x0001u
#define ACCESS3_LOOKUP 0x0002u
#define ACCESS3_MODIFY 0x0004u
#define ACCESS3_EXTEND 0x0008u
#define ACCESS3_DELETE 0x0010u
#define ACCESS3_EXECUTE 0x0020u

#define NFSD_HANDLE_MAGIC 0x454e4633u
#define NFSD_HANDLE_VERSION 1u
#define NFSD_COOKIE_SALT 0x91d7a6c5u
#define NFSD_HANDLER static __attribute__((noinline)) uint32_t

typedef struct {
    const uint8_t *data;
    uint32_t length;
    uint32_t offset;
    int failed;
} xdr_reader_t;

typedef struct {
    uint8_t *data;
    uint32_t capacity;
    uint32_t offset;
    int failed;
} xdr_writer_t;

typedef struct {
    uint32_t uid;
    uint32_t gid;
    uint32_t group_count;
    uint32_t group_values[NFSD_MAX_AUTH_GROUPS];
} nfsd_credential_t;

typedef struct {
    uint32_t id;
    uint32_t flags;
    uint64_t mount_id;
    vfs_superblock_t *superblock;
    char path[VFS_PATH_MAX];
    vfs_inode_t root;
    uint8_t used;
} nfsd_export_t;

typedef struct {
    nfsd_export_t *export_entry;
    vfs_superblock_t *superblock;
    vfs_inode_t inode;
} nfsd_object_t;

typedef struct {
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
    uint32_t atime;
    uint32_t mtime;
    uint32_t valid;
    uint8_t atime_how;
    uint8_t mtime_how;
} nfsd_sattr_t;

#define NFSD_SATTR_MODE 0x01u
#define NFSD_SATTR_UID 0x02u
#define NFSD_SATTR_GID 0x04u
#define NFSD_SATTR_SIZE 0x08u

static nfsd_export_t g_exports[NFSD_MAX_EXPORTS];
static uint32_t g_next_export_id = 1u;
static uint32_t g_handle_key = 0x6e667333u;
static uint8_t g_initialized;
static char g_export_canonical[VFS_PATH_MAX];

static uint32_t read_be32(const uint8_t *source) {
    return ((uint32_t)source[0] << 24) | ((uint32_t)source[1] << 16) |
           ((uint32_t)source[2] << 8) | source[3];
}

static void write_be32(uint8_t *destination, uint32_t value) {
    destination[0] = (uint8_t)(value >> 24);
    destination[1] = (uint8_t)(value >> 16);
    destination[2] = (uint8_t)(value >> 8);
    destination[3] = (uint8_t)value;
}

static uint32_t xdr_get_u32(xdr_reader_t *reader) {
    uint32_t value;
    if (!reader || reader->failed || reader->offset > reader->length ||
        reader->length - reader->offset < 4u) {
        if (reader) reader->failed = 1;
        return 0;
    }
    value = read_be32(reader->data + reader->offset);
    reader->offset += 4u;
    return value;
}

static uint64_t xdr_get_u64(xdr_reader_t *reader) {
    uint64_t high = xdr_get_u32(reader);
    uint64_t low = xdr_get_u32(reader);
    return (high << 32) | low;
}

static const uint8_t *xdr_get_opaque(xdr_reader_t *reader,
                                     uint32_t maximum,
                                     uint32_t *length_out) {
    uint32_t length = xdr_get_u32(reader);
    uint32_t padded;
    const uint8_t *value;
    if (reader->failed || length > maximum || length > UINT32_MAX - 3u) {
        reader->failed = 1;
        return 0;
    }
    padded = (length + 3u) & ~3u;
    if (reader->offset > reader->length ||
        padded > reader->length - reader->offset) {
        reader->failed = 1;
        return 0;
    }
    value = reader->data + reader->offset;
    reader->offset += padded;
    if (length_out) *length_out = length;
    return value;
}

static int xdr_get_string(xdr_reader_t *reader, char *destination,
                          uint32_t capacity) {
    uint32_t length = 0;
    const uint8_t *value;
    if (!destination || capacity == 0u) {
        if (reader) reader->failed = 1;
        return -1;
    }
    value = xdr_get_opaque(reader, capacity - 1u, &length);
    if (!value) return -1;
    memcpy(destination, value, length);
    destination[length] = 0;
    return 0;
}

static void xdr_put_u32(xdr_writer_t *writer, uint32_t value) {
    if (!writer || writer->failed || writer->offset > writer->capacity ||
        writer->capacity - writer->offset < 4u) {
        if (writer) writer->failed = 1;
        return;
    }
    write_be32(writer->data + writer->offset, value);
    writer->offset += 4u;
}

static void xdr_put_u64(xdr_writer_t *writer, uint64_t value) {
    xdr_put_u32(writer, (uint32_t)(value >> 32));
    xdr_put_u32(writer, (uint32_t)value);
}

static void xdr_put_fixed(xdr_writer_t *writer, const void *data,
                          uint32_t length) {
    if (!writer || writer->failed || writer->offset > writer->capacity ||
        length > writer->capacity - writer->offset) {
        if (writer) writer->failed = 1;
        return;
    }
    if (length) memcpy(writer->data + writer->offset, data, length);
    writer->offset += length;
}

static void xdr_put_opaque(xdr_writer_t *writer, const void *data,
                           uint32_t length) {
    static const uint8_t zeros[3] = {0, 0, 0};
    uint32_t padding = (4u - (length & 3u)) & 3u;
    xdr_put_u32(writer, length);
    xdr_put_fixed(writer, data, length);
    xdr_put_fixed(writer, zeros, padding);
}

static void xdr_put_string(xdr_writer_t *writer, const char *value) {
    uint32_t length = 0;
    if (value) while (value[length]) ++length;
    xdr_put_opaque(writer, value, length);
}

static uint32_t nfsd_checksum(const uint8_t *data, uint32_t length) {
    uint32_t value = 2166136261u ^ g_handle_key;
    uint32_t index;
    for (index = 0; index < length; ++index) {
        value ^= data[index];
        value *= 16777619u;
        value ^= value >> 13;
    }
    return value ^ NFSD_COOKIE_SALT;
}

static nfsd_export_t *nfsd_export_by_id(uint32_t id) {
    uint32_t index;
    for (index = 0; index < NFSD_MAX_EXPORTS; ++index)
        if (g_exports[index].used && g_exports[index].id == id)
            return &g_exports[index];
    return 0;
}

static nfsd_export_t *nfsd_export_by_path(const char *path) {
    uint32_t index;
    for (index = 0; index < NFSD_MAX_EXPORTS; ++index)
        if (g_exports[index].used && strcmp(g_exports[index].path, path) == 0)
            return &g_exports[index];
    return 0;
}

static uint32_t nfsd_error_status(int error) {
    int code = error < 0 ? -error : error;
    switch (code) {
        case 0: return NFS3_OK;
        case EDGE_LINUX_EPERM: return NFS3ERR_PERM;
        case EDGE_LINUX_ENOENT: return NFS3ERR_NOENT;
        case EDGE_LINUX_EIO: return NFS3ERR_IO;
        case EDGE_LINUX_ENXIO: return NFS3ERR_NXIO;
        case EDGE_LINUX_EACCES: return NFS3ERR_ACCES;
        case EDGE_LINUX_EEXIST: return NFS3ERR_EXIST;
        case EDGE_LINUX_EXDEV: return NFS3ERR_XDEV;
        case EDGE_LINUX_ENODEV: return NFS3ERR_NODEV;
        case EDGE_LINUX_ENOTDIR: return NFS3ERR_NOTDIR;
        case EDGE_LINUX_EISDIR: return NFS3ERR_ISDIR;
        case EDGE_LINUX_EINVAL: return NFS3ERR_INVAL;
        case EDGE_LINUX_EFBIG: return NFS3ERR_FBIG;
        case EDGE_LINUX_ENOSPC: return NFS3ERR_NOSPC;
        case EDGE_LINUX_EROFS: return NFS3ERR_ROFS;
        case EDGE_LINUX_EMLINK: return NFS3ERR_MLINK;
        case EDGE_LINUX_ENAMETOOLONG: return NFS3ERR_NAMETOOLONG;
        case EDGE_LINUX_ENOTEMPTY: return NFS3ERR_NOTEMPTY;
        case EDGE_LINUX_EDQUOT: return NFS3ERR_DQUOT;
        case EDGE_LINUX_ESTALE: return NFS3ERR_STALE;
        case EDGE_LINUX_EREMOTE: return NFS3ERR_REMOTE;
        case EDGE_LINUX_EOPNOTSUPP:
        case EDGE_LINUX_ENOSYS: return NFS3ERR_NOTSUPP;
        default: return NFS3ERR_IO;
    }
}

static uint32_t nfsd_inode_type(const vfs_inode_t *inode) {
    switch (inode->mode & 0xf000u) {
        case VFS_INODE_FILE: return 1u;
        case VFS_INODE_DIR: return 2u;
        case VFS_INODE_BLK: return 3u;
        case VFS_INODE_CHR: return 4u;
        case VFS_INODE_LNK: return 5u;
        case VFS_INODE_SOCK: return 6u;
        case VFS_INODE_FIFO: return 7u;
        default: return 0u;
    }
}

static void nfsd_put_time(xdr_writer_t *writer, uint32_t seconds) {
    xdr_put_u32(writer, seconds);
    xdr_put_u32(writer, 0u);
}

static void nfsd_put_attr(xdr_writer_t *writer,
                          const nfsd_object_t *object) {
    const vfs_inode_t *inode = &object->inode;
    uint64_t fsid = object->export_entry->mount_id;
    xdr_put_u32(writer, nfsd_inode_type(inode));
    xdr_put_u32(writer, inode->mode & 07777u);
    xdr_put_u32(writer, vfs_inode_link_count(inode));
    xdr_put_u32(writer, inode->uid);
    xdr_put_u32(writer, inode->gid);
    xdr_put_u64(writer, inode->size);
    xdr_put_u64(writer, inode->size);
    xdr_put_u32(writer, (uint32_t)(inode->rdev >> 32));
    xdr_put_u32(writer, (uint32_t)inode->rdev);
    xdr_put_u64(writer, fsid);
    xdr_put_u64(writer, ((uint64_t)inode->generation << 32) | inode->ino);
    nfsd_put_time(writer, inode->atime);
    nfsd_put_time(writer, inode->mtime);
    nfsd_put_time(writer, inode->ctime);
}

static void nfsd_put_post_attr(xdr_writer_t *writer,
                               nfsd_object_t *object) {
    if (!object || !object->superblock) {
        xdr_put_u32(writer, 0u);
        return;
    }
    if (vfs_inode_refresh(object->superblock, &object->inode) < 0) {
        xdr_put_u32(writer, 0u);
        return;
    }
    xdr_put_u32(writer, 1u);
    nfsd_put_attr(writer, object);
}

static void nfsd_put_pre_attr(xdr_writer_t *writer,
                              const vfs_inode_t *inode) {
    if (!inode) {
        xdr_put_u32(writer, 0u);
        return;
    }
    xdr_put_u32(writer, 1u);
    xdr_put_u64(writer, inode->size);
    nfsd_put_time(writer, inode->mtime);
    nfsd_put_time(writer, inode->ctime);
}

static void nfsd_put_wcc(xdr_writer_t *writer, const vfs_inode_t *before,
                         nfsd_object_t *after) {
    nfsd_put_pre_attr(writer, before);
    nfsd_put_post_attr(writer, after);
}

static int nfsd_encode_handle(const nfsd_object_t *object,
                              uint8_t output[NFSD_FH_MAX],
                              uint32_t *length_out) {
    uint8_t filesystem_handle[NFSD_FH_PAYLOAD_MAX];
    uint32_t filesystem_length = sizeof(filesystem_handle);
    uint32_t handle_type = 0;
    uint32_t offset = 0;
    uint32_t checksum;
    int result;
    if (!object || !object->export_entry || !object->superblock ||
        !length_out) return -1;
    result = vfs_encode_file_handle(object->superblock, &object->inode,
                                    &handle_type, filesystem_handle,
                                    &filesystem_length);
    if (result < 0 || filesystem_length > NFSD_FH_PAYLOAD_MAX) return -1;
    write_be32(output + offset, NFSD_HANDLE_MAGIC); offset += 4u;
    write_be32(output + offset, NFSD_HANDLE_VERSION); offset += 4u;
    write_be32(output + offset, object->export_entry->id); offset += 4u;
    write_be32(output + offset,
               (uint32_t)(object->export_entry->mount_id >> 32)); offset += 4u;
    write_be32(output + offset,
               (uint32_t)object->export_entry->mount_id); offset += 4u;
    write_be32(output + offset, handle_type); offset += 4u;
    write_be32(output + offset, filesystem_length); offset += 4u;
    memcpy(output + offset, filesystem_handle, filesystem_length);
    offset += filesystem_length;
    checksum = nfsd_checksum(output, offset);
    write_be32(output + offset, checksum); offset += 4u;
    *length_out = offset;
    return 0;
}

static int nfsd_decode_handle_bytes(const uint8_t *handle, uint32_t length,
                                    nfsd_object_t *object) {
    uint32_t export_id;
    uint64_t mount_id;
    uint32_t handle_type;
    uint32_t filesystem_length;
    uint32_t checksum;
    nfsd_export_t *entry;
    vfs_superblock_t *superblock;
    if (!handle || !object || length < 32u || length > NFSD_FH_MAX ||
        read_be32(handle) != NFSD_HANDLE_MAGIC ||
        read_be32(handle + 4u) != NFSD_HANDLE_VERSION)
        return -EDGE_LINUX_EINVAL;
    filesystem_length = read_be32(handle + 24u);
    if (filesystem_length > NFSD_FH_PAYLOAD_MAX ||
        length != 32u + filesystem_length)
        return -EDGE_LINUX_EINVAL;
    checksum = read_be32(handle + length - 4u);
    if (checksum != nfsd_checksum(handle, length - 4u))
        return -EDGE_LINUX_EINVAL;
    export_id = read_be32(handle + 8u);
    mount_id = ((uint64_t)read_be32(handle + 12u) << 32) |
               read_be32(handle + 16u);
    handle_type = read_be32(handle + 20u);
    entry = nfsd_export_by_id(export_id);
    if (!entry || entry->mount_id != mount_id) {
        printf("[nfsd] stale handle export=%u mount=%u:%u\n",
               export_id, (uint32_t)(mount_id >> 32), (uint32_t)mount_id);
        return -EDGE_LINUX_ESTALE;
    }
    superblock = entry->superblock;
    if (!superblock) {
        printf("[nfsd] stale handle missing export filesystem=%u:%u\n",
               (uint32_t)(mount_id >> 32), (uint32_t)mount_id);
        return -EDGE_LINUX_ESTALE;
    }
    memset(object, 0, sizeof(*object));
    object->export_entry = entry;
    object->superblock = superblock;
    if (vfs_decode_file_handle(superblock, handle_type, handle + 28u,
                               filesystem_length, &object->inode) < 0) {
        printf("[nfsd] stale filesystem handle type=%u bytes=%u mount=%u:%u\n",
               handle_type, filesystem_length,
               (uint32_t)(mount_id >> 32), (uint32_t)mount_id);
        return -EDGE_LINUX_ESTALE;
    }
    return 0;
}

static int nfsd_get_object(xdr_reader_t *reader, nfsd_object_t *object) {
    uint32_t length = 0;
    if (object) memset(object, 0, sizeof(*object));
    const uint8_t *handle = xdr_get_opaque(reader, NFSD_FH_MAX, &length);
    if (!handle) return -EDGE_LINUX_EINVAL;
    return nfsd_decode_handle_bytes(handle, length, object);
}

static void nfsd_put_handle(xdr_writer_t *writer,
                            const nfsd_object_t *object) {
    uint8_t handle[NFSD_FH_MAX];
    uint32_t length = 0;
    if (nfsd_encode_handle(object, handle, &length) < 0) {
        writer->failed = 1;
        return;
    }
    xdr_put_opaque(writer, handle, length);
}

static int nfsd_parse_auth_sys(const uint8_t *body, uint32_t length,
                               nfsd_credential_t *credential) {
    xdr_reader_t reader = {body, length, 0u, 0};
    uint32_t hostname_length;
    uint32_t group_count;
    uint32_t index;
    (void)xdr_get_u32(&reader);
    (void)xdr_get_opaque(&reader, 255u, &hostname_length);
    credential->uid = xdr_get_u32(&reader);
    credential->gid = xdr_get_u32(&reader);
    group_count = xdr_get_u32(&reader);
    if (reader.failed || group_count > NFSD_MAX_AUTH_GROUPS) return -1;
    credential->group_count = group_count;
    for (index = 0; index < group_count; ++index)
        credential->group_values[index] = xdr_get_u32(&reader);
    return reader.failed ? -1 : 0;
}

static int nfsd_permission(const nfsd_object_t *object,
                           const nfsd_credential_t *credential,
                           int mask) {
    linux_group_list_t groups;
    uint32_t uid = credential->uid;
    uint32_t gid = credential->gid;
    uint64_t capabilities = 0;
    if (object->export_entry->flags & EDGE_NFSD_EXPORT_ROOT_SQUASH &&
        uid == 0u) {
        uid = 65534u;
        gid = 65534u;
    }
    memset(&groups, 0, sizeof(groups));
    groups.count = credential->group_count;
    if (groups.count) {
        groups.page_count = 1u;
        groups.pages[0].values = (uint32_t *)credential->group_values;
    }
    if (uid == 0u)
        capabilities = (1ULL << EDGE_LINUX_CAP_DAC_OVERRIDE) |
                       (1ULL << EDGE_LINUX_CAP_DAC_READ_SEARCH);
    return vfs_permission_check_as(&object->inode, mask, uid, gid,
                                   &groups, capabilities);
}

static void nfsd_mapped_identity(const nfsd_object_t *object,
                                 const nfsd_credential_t *credential,
                                 uint32_t *uid, uint32_t *gid) {
    *uid = credential->uid;
    *gid = credential->gid;
    if ((object->export_entry->flags & EDGE_NFSD_EXPORT_ROOT_SQUASH) &&
        *uid == 0u) {
        *uid = 65534u;
        *gid = 65534u;
    }
}

static int nfsd_credential_has_group(const nfsd_object_t *object,
                                     const nfsd_credential_t *credential,
                                     uint32_t target_gid) {
    uint32_t uid, gid, index;
    nfsd_mapped_identity(object, credential, &uid, &gid);
    (void)uid;
    if (gid == target_gid) return 1;
    for (index = 0; index < credential->group_count; ++index)
        if (credential->group_values[index] == target_gid) return 1;
    return 0;
}

static int nfsd_require_write(const nfsd_object_t *object,
                              const nfsd_credential_t *credential,
                              int mask) {
    if (object->export_entry->flags & EDGE_NFSD_EXPORT_READ_ONLY)
        return -EDGE_LINUX_EROFS;
    return nfsd_permission(object, credential, mask);
}

static int nfsd_lookup(nfsd_object_t *directory, const char *name,
                       nfsd_object_t *result) {
    if (!directory->superblock->ops ||
        !directory->superblock->ops->lookup)
        return -EDGE_LINUX_EOPNOTSUPP;
    memset(result, 0, sizeof(*result));
    result->export_entry = directory->export_entry;
    result->superblock = directory->superblock;
    if (directory->superblock->ops->lookup(directory->superblock,
            &directory->inode, name, &result->inode) < 0)
        return -EDGE_LINUX_ENOENT;
    return 0;
}

static int nfsd_parse_sattr(xdr_reader_t *reader, nfsd_sattr_t *attributes) {
    uint32_t selector;
    memset(attributes, 0, sizeof(*attributes));
    if (xdr_get_u32(reader)) {
        attributes->mode = xdr_get_u32(reader);
        attributes->valid |= NFSD_SATTR_MODE;
    }
    if (xdr_get_u32(reader)) {
        attributes->uid = xdr_get_u32(reader);
        attributes->valid |= NFSD_SATTR_UID;
    }
    if (xdr_get_u32(reader)) {
        attributes->gid = xdr_get_u32(reader);
        attributes->valid |= NFSD_SATTR_GID;
    }
    if (xdr_get_u32(reader)) {
        attributes->size = xdr_get_u64(reader);
        attributes->valid |= NFSD_SATTR_SIZE;
    }
    selector = xdr_get_u32(reader);
    if (selector == 1u) {
        attributes->atime = (uint32_t)(boottime_realtime_us() / 1000000u);
        attributes->atime_how = 1u;
    } else if (selector == 2u) {
        attributes->atime = xdr_get_u32(reader);
        (void)xdr_get_u32(reader);
        attributes->atime_how = 2u;
    } else if (selector != 0u) reader->failed = 1;
    selector = xdr_get_u32(reader);
    if (selector == 1u) {
        attributes->mtime = (uint32_t)(boottime_realtime_us() / 1000000u);
        attributes->mtime_how = 1u;
    } else if (selector == 2u) {
        attributes->mtime = xdr_get_u32(reader);
        (void)xdr_get_u32(reader);
        attributes->mtime_how = 2u;
    } else if (selector != 0u) reader->failed = 1;
    return reader->failed ? -1 : 0;
}

static int nfsd_apply_sattr(nfsd_object_t *object,
                            const nfsd_credential_t *credential,
                            const nfsd_sattr_t *attributes,
                            int newly_created) {
    uint32_t setattr_valid = 0;
    uint32_t uid = attributes->uid;
    uint32_t gid = attributes->gid;
    uint32_t caller_uid, caller_gid;
    int privileged, owner;
    int result;
    if (object->export_entry->flags & EDGE_NFSD_EXPORT_READ_ONLY)
        return -EDGE_LINUX_EROFS;
    nfsd_mapped_identity(object, credential, &caller_uid, &caller_gid);
    (void)caller_gid;
    privileged = caller_uid == 0u;
    owner = caller_uid == object->inode.uid;
    if (!newly_created && !privileged && !owner) {
        int only_current_time = attributes->valid == 0u &&
            (!attributes->atime_how || attributes->atime_how == 1u) &&
            (!attributes->mtime_how || attributes->mtime_how == 1u) &&
            (attributes->atime_how || attributes->mtime_how);
        if (!only_current_time ||
            nfsd_permission(object, credential, 2) < 0)
            return -EDGE_LINUX_EPERM;
    }
    if ((attributes->valid & NFSD_SATTR_UID) &&
        !privileged && attributes->uid != caller_uid)
        return -EDGE_LINUX_EPERM;
    if ((attributes->valid & NFSD_SATTR_GID) && !privileged &&
        !nfsd_credential_has_group(object, credential, attributes->gid))
        return -EDGE_LINUX_EPERM;
    if (attributes->valid & NFSD_SATTR_SIZE) {
        if (attributes->size > UINT32_MAX) return -EDGE_LINUX_EFBIG;
        if (!newly_created &&
            nfsd_permission(object, credential, 2) < 0)
            return -EDGE_LINUX_EACCES;
        result = vfs_truncate_inode(object->superblock, &object->inode,
                                    (uint32_t)attributes->size);
        if (result < 0) return result;
    }
    if (attributes->valid & NFSD_SATTR_MODE)
        setattr_valid |= VFS_SETATTR_MODE;
    if (attributes->valid & NFSD_SATTR_UID)
        setattr_valid |= VFS_SETATTR_UID;
    if (attributes->valid & NFSD_SATTR_GID)
        setattr_valid |= VFS_SETATTR_GID;
    if (setattr_valid) {
        result = vfs_inode_setattr(object->superblock, &object->inode,
            (uint16_t)attributes->mode, uid, gid, setattr_valid);
        if (result < 0) return result;
    }
    if (attributes->atime_how || attributes->mtime_how) {
        result = vfs_inode_utimens(object->superblock, &object->inode,
            attributes->atime, attributes->mtime,
            attributes->atime_how != 0u, attributes->mtime_how != 0u);
        if (result < 0) return result;
    }
    return 0;
}

static int nfsd_initialize_created_object(
        nfsd_object_t *object, const nfsd_credential_t *credential,
        const nfsd_sattr_t *attributes) {
    uint32_t uid, gid;
    int result;
    nfsd_mapped_identity(object, credential, &uid, &gid);
    result = vfs_inode_setattr(object->superblock, &object->inode,
        object->inode.mode, uid, gid, VFS_SETATTR_UID | VFS_SETATTR_GID);
    if (result < 0) {
        printf("[nfsd] created object identity failed ino=%u result=%d\n",
               object->inode.ino, result);
        return result;
    }
    result = nfsd_apply_sattr(object, credential, attributes, 1);
    if (result < 0)
        printf("[nfsd] created object attributes failed ino=%u result=%d\n",
               object->inode.ino, result);
    return result;
}

static uint32_t nfsd_access_mask(nfsd_object_t *object,
                                 const nfsd_credential_t *credential,
                                 uint32_t requested) {
    uint32_t allowed = 0;
    uint16_t kind = object->inode.mode & 0xf000u;
    if ((requested & ACCESS3_READ) &&
        nfsd_permission(object, credential, 4) == 0)
        allowed |= ACCESS3_READ;
    if ((requested & ACCESS3_LOOKUP) && kind == VFS_INODE_DIR &&
        nfsd_permission(object, credential, 1) == 0)
        allowed |= ACCESS3_LOOKUP;
    if ((requested & ACCESS3_EXECUTE) && kind != VFS_INODE_DIR &&
        nfsd_permission(object, credential, 1) == 0)
        allowed |= ACCESS3_EXECUTE;
    if (!(object->export_entry->flags & EDGE_NFSD_EXPORT_READ_ONLY) &&
        nfsd_permission(object, credential, 2) == 0) {
        allowed |= requested & (ACCESS3_MODIFY | ACCESS3_EXTEND);
        if (kind == VFS_INODE_DIR) allowed |= requested & ACCESS3_DELETE;
    }
    return allowed;
}

static void nfsd_reply_status_attr(xdr_writer_t *writer, uint32_t status,
                                   nfsd_object_t *object) {
    xdr_put_u32(writer, status);
    nfsd_put_post_attr(writer, object);
}

NFSD_HANDLER nfsd_proc_getattr(xdr_reader_t *reader,
                                  xdr_writer_t *writer) {
    nfsd_object_t object;
    int result = nfsd_get_object(reader, &object);
    uint32_t status = result < 0 ? NFS3ERR_STALE : NFS3_OK;
    xdr_put_u32(writer, status);
    if (status == NFS3_OK) nfsd_put_attr(writer, &object);
    return status;
}

NFSD_HANDLER nfsd_proc_setattr(xdr_reader_t *reader,
                                  xdr_writer_t *writer,
                                  const nfsd_credential_t *credential) {
    nfsd_object_t object;
    nfsd_sattr_t attributes;
    vfs_inode_t before;
    int result = nfsd_get_object(reader, &object);
    uint32_t guard;
    uint32_t guard_seconds = 0;
    uint32_t status;
    if (result < 0) {
        xdr_put_u32(writer, NFS3ERR_STALE);
        nfsd_put_wcc(writer, 0, 0);
        return NFS3ERR_STALE;
    }
    before = object.inode;
    if (nfsd_parse_sattr(reader, &attributes) < 0) {
        xdr_put_u32(writer, NFS3ERR_INVAL);
        nfsd_put_wcc(writer, &before, &object);
        return NFS3ERR_INVAL;
    }
    guard = xdr_get_u32(reader);
    if (guard) {
        guard_seconds = xdr_get_u32(reader);
        (void)xdr_get_u32(reader);
    }
    if (reader->failed) status = NFS3ERR_INVAL;
    else if (guard && guard_seconds != object.inode.ctime)
        status = NFS3ERR_NOT_SYNC;
    else {
        result = nfsd_apply_sattr(&object, credential, &attributes, 0);
        status = nfsd_error_status(result);
    }
    xdr_put_u32(writer, status);
    nfsd_put_wcc(writer, &before, &object);
    return status;
}

NFSD_HANDLER nfsd_proc_lookup(xdr_reader_t *reader,
                                 xdr_writer_t *writer,
                                 const nfsd_credential_t *credential) {
    nfsd_object_t directory;
    nfsd_object_t object;
    char name[NFSD_MAX_NAME + 1u];
    int result = nfsd_get_object(reader, &directory);
    uint32_t status;
    if (result < 0) {
        xdr_put_u32(writer, NFS3ERR_STALE);
        nfsd_put_post_attr(writer, 0);
        return NFS3ERR_STALE;
    }
    if (xdr_get_string(reader, name, sizeof(name)) < 0 || !name[0])
        result = -EDGE_LINUX_EINVAL;
    else if ((directory.inode.mode & 0xf000u) != VFS_INODE_DIR)
        result = -EDGE_LINUX_ENOTDIR;
    else if (nfsd_permission(&directory, credential, 1) < 0)
        result = -EDGE_LINUX_EACCES;
    else if (strcmp(name, ".") == 0)
        object = directory;
    else result = nfsd_lookup(&directory, name, &object);
    status = nfsd_error_status(result);
    xdr_put_u32(writer, status);
    if (status == NFS3_OK) {
        nfsd_put_handle(writer, &object);
        nfsd_put_post_attr(writer, &object);
    }
    nfsd_put_post_attr(writer, &directory);
    return status;
}

NFSD_HANDLER nfsd_proc_access(xdr_reader_t *reader,
                                 xdr_writer_t *writer,
                                 const nfsd_credential_t *credential) {
    nfsd_object_t object;
    int result = nfsd_get_object(reader, &object);
    uint32_t requested = xdr_get_u32(reader);
    if (result < 0) {
        nfsd_reply_status_attr(writer, NFS3ERR_STALE, 0);
        return NFS3ERR_STALE;
    }
    xdr_put_u32(writer, NFS3_OK);
    nfsd_put_post_attr(writer, &object);
    xdr_put_u32(writer, nfsd_access_mask(&object, credential, requested));
    return NFS3_OK;
}

NFSD_HANDLER nfsd_proc_readlink(xdr_reader_t *reader,
                                   xdr_writer_t *writer,
                                   const nfsd_credential_t *credential) {
    nfsd_object_t object;
    char target[NFSD_PROTOCOL_PATH_MAX + 1u];
    int result = nfsd_get_object(reader, &object);
    uint32_t status;
    if (result == 0 && (object.inode.mode & 0xf000u) != VFS_INODE_LNK)
        result = -EDGE_LINUX_EINVAL;
    if (result == 0 && nfsd_permission(&object, credential, 4) < 0)
        result = -EDGE_LINUX_EACCES;
    if (result == 0 && (!object.superblock->ops ||
        !object.superblock->ops->readlink))
        result = -EDGE_LINUX_EOPNOTSUPP;
    if (result == 0 && object.superblock->ops->readlink(object.superblock,
            &object.inode, target, sizeof(target)) < 0)
        result = -EDGE_LINUX_EIO;
    status = nfsd_error_status(result);
    nfsd_reply_status_attr(writer, status, result == 0 ? &object : 0);
    if (status == NFS3_OK) xdr_put_string(writer, target);
    return status;
}

NFSD_HANDLER nfsd_proc_read(xdr_reader_t *reader, xdr_writer_t *writer,
                               const nfsd_credential_t *credential) {
    static uint8_t data[NFSD_MAX_DATA];
    nfsd_object_t object;
    int result = nfsd_get_object(reader, &object);
    uint64_t offset = xdr_get_u64(reader);
    uint32_t count = xdr_get_u32(reader);
    uint32_t actual = 0;
    uint32_t status;
    if (result == 0 && (object.inode.mode & 0xf000u) == VFS_INODE_DIR)
        result = -EDGE_LINUX_EISDIR;
    if (result == 0 && nfsd_permission(&object, credential, 4) < 0)
        result = -EDGE_LINUX_EACCES;
    if (result == 0 && offset > UINT32_MAX) result = -EDGE_LINUX_EFBIG;
    if (count > NFSD_MAX_DATA) count = NFSD_MAX_DATA;
    if (result == 0 && offset < object.inode.size) {
        uint32_t available = object.inode.size - (uint32_t)offset;
        actual = count < available ? count : available;
        if (!object.superblock->ops || !object.superblock->ops->read)
            result = -EDGE_LINUX_EOPNOTSUPP;
        else if (actual && object.superblock->ops->read(object.superblock,
                 &object.inode, (uint32_t)offset, data, actual) < 0)
            result = -EDGE_LINUX_EIO;
    }
    status = nfsd_error_status(result);
    nfsd_reply_status_attr(writer, status, result == 0 ? &object : 0);
    if (status == NFS3_OK) {
        xdr_put_u32(writer, actual);
        xdr_put_u32(writer, offset + actual >= object.inode.size);
        xdr_put_opaque(writer, data, actual);
    }
    return status;
}

NFSD_HANDLER nfsd_proc_write(xdr_reader_t *reader, xdr_writer_t *writer,
                                const nfsd_credential_t *credential) {
    nfsd_object_t object;
    vfs_inode_t before;
    int result = nfsd_get_object(reader, &object);
    uint64_t offset = xdr_get_u64(reader);
    uint32_t count = xdr_get_u32(reader);
    uint32_t stable = xdr_get_u32(reader);
    uint32_t data_length = 0;
    const uint8_t *data = xdr_get_opaque(reader, NFSD_MAX_DATA, &data_length);
    uint32_t status;
    if (result < 0) {
        xdr_put_u32(writer, NFS3ERR_STALE);
        nfsd_put_wcc(writer, 0, 0);
        return NFS3ERR_STALE;
    }
    before = object.inode;
    if (!data || count != data_length || offset > UINT32_MAX ||
        count > UINT32_MAX - (uint32_t)offset)
        result = -EDGE_LINUX_EINVAL;
    else if ((object.inode.mode & 0xf000u) != VFS_INODE_FILE)
        result = -EDGE_LINUX_EINVAL;
    else result = nfsd_require_write(&object, credential, 2);
    if (result == 0 && (!object.superblock->ops ||
        !object.superblock->ops->write))
        result = -EDGE_LINUX_EOPNOTSUPP;
    if (result == 0 && count && object.superblock->ops->write(
            object.superblock, &object.inode, (uint32_t)offset,
            data, count) < 0)
        result = -EDGE_LINUX_EIO;
    if (result == 0 && stable != 0u &&
        vfs_sync_inode(object.superblock, &object.inode, 0) < 0)
        result = -EDGE_LINUX_EIO;
    status = nfsd_error_status(result);
    xdr_put_u32(writer, status);
    nfsd_put_wcc(writer, &before, &object);
    if (status == NFS3_OK) {
        xdr_put_u32(writer, count);
        xdr_put_u32(writer, stable > 2u ? 2u : stable);
        xdr_put_u32(writer, g_handle_key);
        xdr_put_u32(writer, NFSD_COOKIE_SALT);
    }
    return status;
}

static int nfsd_parse_directory_name(xdr_reader_t *reader,
                                     nfsd_object_t *directory,
                                     char name[NFSD_MAX_NAME + 1u]) {
    int result = nfsd_get_object(reader, directory);
    if (result < 0) return result;
    if (xdr_get_string(reader, name, NFSD_MAX_NAME + 1u) < 0 || !name[0] ||
        strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return -EDGE_LINUX_EINVAL;
    if ((directory->inode.mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    return 0;
}

static int nfsd_create_common(nfsd_object_t *directory, const char *name,
                              uint16_t mode, uint16_t kind,
                              uint64_t rdev, const char *link_target,
                              nfsd_object_t *created) {
    filesystem_ops_t *ops = directory->superblock->ops;
    nfsd_object_t existing;
    int result = -1;
    memset(created, 0, sizeof(*created));
    created->export_entry = directory->export_entry;
    created->superblock = directory->superblock;
    /*
     * Most VFS backends use a compact negative return convention.  Resolve
     * the Linux/NFS-visible collision here so mkdir, symlink, mknod, and a
     * racing CREATE return EEXIST instead of collapsing it into EIO.
     */
    if (nfsd_lookup(directory, name, &existing) == 0)
        return -EDGE_LINUX_EEXIST;
    if (kind == VFS_INODE_FILE && ops && ops->create)
        result = ops->create(directory->superblock, &directory->inode, name,
                             mode, &created->inode);
    else if (kind == VFS_INODE_DIR && ops && ops->mkdir)
        result = ops->mkdir(directory->superblock, &directory->inode, name,
                            mode, &created->inode);
    else if (kind == VFS_INODE_LNK && ops && ops->symlink)
        result = ops->symlink(directory->superblock, &directory->inode, name,
                              link_target, mode, &created->inode);
    else if (ops && ops->mknod)
        result = ops->mknod(directory->superblock, &directory->inode, name,
                            (uint16_t)(kind | (mode & 07777u)), rdev,
                            &created->inode);
    else return -EDGE_LINUX_EOPNOTSUPP;
    if (result < 0) {
        printf("[nfsd] create backend failed name=%s kind=%u result=%d\n",
               name, (uint32_t)kind, result);
        return -EDGE_LINUX_EIO;
    }
    vfs_path_cache_invalidate_all();
    if (vfs_sync_mutation_if_required(directory->superblock, 1) < 0) {
        printf("[nfsd] create sync failed name=%s kind=%u\n",
               name, (uint32_t)kind);
        return -EDGE_LINUX_EIO;
    }
    return 0;
}

NFSD_HANDLER nfsd_proc_create(xdr_reader_t *reader, xdr_writer_t *writer,
                                 const nfsd_credential_t *credential) {
    nfsd_object_t directory;
    nfsd_object_t created;
    vfs_inode_t before;
    nfsd_sattr_t attributes;
    char name[NFSD_MAX_NAME + 1u];
    int result = nfsd_parse_directory_name(reader, &directory, name);
    uint32_t mode_selector;
    uint32_t status;
    memset(&before, 0, sizeof(before));
    if (result == 0) before = directory.inode;
    mode_selector = xdr_get_u32(reader);
    if (mode_selector <= 1u) {
        if (nfsd_parse_sattr(reader, &attributes) < 0)
            result = -EDGE_LINUX_EINVAL;
    } else if (mode_selector == 2u) {
        (void)xdr_get_u64(reader);
        memset(&attributes, 0, sizeof(attributes));
        attributes.mode = 0600u;
        attributes.valid = NFSD_SATTR_MODE;
    } else result = -EDGE_LINUX_EINVAL;
    if (result == 0) result = nfsd_require_write(&directory, credential, 3);
    if (result == 0) {
        nfsd_object_t existing;
        int lookup = nfsd_lookup(&directory, name, &existing);
        if (lookup == 0) {
            if (mode_selector == 0u) {
                created = existing;
                result = nfsd_apply_sattr(&created, credential, &attributes,
                                           0);
            } else result = -EDGE_LINUX_EEXIST;
        } else {
            uint16_t create_mode = (attributes.valid & NFSD_SATTR_MODE) ?
                                   (uint16_t)attributes.mode : 0666u;
            result = nfsd_create_common(&directory, name, create_mode,
                                        VFS_INODE_FILE, 0, 0, &created);
            if (result == 0)
                result = nfsd_initialize_created_object(&created, credential,
                                                        &attributes);
        }
    }
    status = nfsd_error_status(result);
    xdr_put_u32(writer, status);
    if (status == NFS3_OK) {
        xdr_put_u32(writer, 1u);
        nfsd_put_handle(writer, &created);
        nfsd_put_post_attr(writer, &created);
    }
    nfsd_put_wcc(writer, result == 0 ? &before : 0,
                 directory.superblock ? &directory : 0);
    return status;
}

NFSD_HANDLER nfsd_proc_mkdir(xdr_reader_t *reader, xdr_writer_t *writer,
                                const nfsd_credential_t *credential) {
    nfsd_object_t directory;
    nfsd_object_t created;
    vfs_inode_t before;
    nfsd_sattr_t attributes;
    char name[NFSD_MAX_NAME + 1u];
    int result = nfsd_parse_directory_name(reader, &directory, name);
    uint32_t status;
    memset(&before, 0, sizeof(before));
    if (result == 0) before = directory.inode;
    if (nfsd_parse_sattr(reader, &attributes) < 0)
        result = -EDGE_LINUX_EINVAL;
    if (result == 0) result = nfsd_require_write(&directory, credential, 3);
    if (result == 0) result = nfsd_create_common(&directory, name,
        (attributes.valid & NFSD_SATTR_MODE) ?
            (uint16_t)attributes.mode : 0777u,
        VFS_INODE_DIR, 0, 0, &created);
    if (result == 0)
        result = nfsd_initialize_created_object(&created, credential,
                                                &attributes);
    status = nfsd_error_status(result);
    xdr_put_u32(writer, status);
    if (status == NFS3_OK) {
        xdr_put_u32(writer, 1u);
        nfsd_put_handle(writer, &created);
        nfsd_put_post_attr(writer, &created);
    }
    nfsd_put_wcc(writer, directory.superblock ? &before : 0,
                 directory.superblock ? &directory : 0);
    return status;
}

NFSD_HANDLER nfsd_proc_symlink(xdr_reader_t *reader, xdr_writer_t *writer,
                                  const nfsd_credential_t *credential) {
    nfsd_object_t directory;
    nfsd_object_t created;
    vfs_inode_t before;
    nfsd_sattr_t attributes;
    char name[NFSD_MAX_NAME + 1u];
    char target[NFSD_PROTOCOL_PATH_MAX + 1u];
    int result = nfsd_parse_directory_name(reader, &directory, name);
    uint32_t status;
    memset(&before, 0, sizeof(before));
    if (result == 0) before = directory.inode;
    if (nfsd_parse_sattr(reader, &attributes) < 0 ||
        xdr_get_string(reader, target, sizeof(target)) < 0)
        result = -EDGE_LINUX_EINVAL;
    if (result == 0) result = nfsd_require_write(&directory, credential, 3);
    if (result == 0) result = nfsd_create_common(&directory, name, 0777u,
        VFS_INODE_LNK, 0, target, &created);
    if (result == 0)
        result = nfsd_initialize_created_object(&created, credential,
                                                &attributes);
    status = nfsd_error_status(result);
    xdr_put_u32(writer, status);
    if (status == NFS3_OK) {
        xdr_put_u32(writer, 1u);
        nfsd_put_handle(writer, &created);
        nfsd_put_post_attr(writer, &created);
    }
    nfsd_put_wcc(writer, directory.superblock ? &before : 0,
                 directory.superblock ? &directory : 0);
    return status;
}

NFSD_HANDLER nfsd_proc_mknod(xdr_reader_t *reader, xdr_writer_t *writer,
                                const nfsd_credential_t *credential) {
    nfsd_object_t directory;
    nfsd_object_t created;
    vfs_inode_t before;
    nfsd_sattr_t attributes;
    char name[NFSD_MAX_NAME + 1u];
    int result = nfsd_parse_directory_name(reader, &directory, name);
    uint32_t type = xdr_get_u32(reader);
    uint32_t major = 0, minor = 0;
    uint16_t kind = 0;
    uint32_t status;
    memset(&before, 0, sizeof(before));
    if (result == 0) before = directory.inode;
    if (type == 3u || type == 4u) {
        if (nfsd_parse_sattr(reader, &attributes) < 0)
            result = -EDGE_LINUX_EINVAL;
        major = xdr_get_u32(reader);
        minor = xdr_get_u32(reader);
        kind = type == 3u ? VFS_INODE_BLK : VFS_INODE_CHR;
    } else if (type == 6u || type == 7u) {
        if (nfsd_parse_sattr(reader, &attributes) < 0)
            result = -EDGE_LINUX_EINVAL;
        kind = type == 6u ? VFS_INODE_SOCK : VFS_INODE_FIFO;
    } else result = -EDGE_LINUX_EINVAL;
    if (result == 0) result = nfsd_require_write(&directory, credential, 3);
    if (result == 0 && (type == 3u || type == 4u)) {
        uint32_t uid, gid;
        nfsd_mapped_identity(&directory, credential, &uid, &gid);
        (void)gid;
        if (uid != 0u) result = -EDGE_LINUX_EPERM;
    }
    if (result == 0) result = nfsd_create_common(&directory, name,
        (attributes.valid & NFSD_SATTR_MODE) ?
            (uint16_t)attributes.mode : 0666u,
        kind, ((uint64_t)major << 32) | minor, 0, &created);
    if (result == 0)
        result = nfsd_initialize_created_object(&created, credential,
                                                &attributes);
    status = nfsd_error_status(result);
    xdr_put_u32(writer, status);
    if (status == NFS3_OK) {
        xdr_put_u32(writer, 1u);
        nfsd_put_handle(writer, &created);
        nfsd_put_post_attr(writer, &created);
    }
    nfsd_put_wcc(writer, directory.superblock ? &before : 0,
                 directory.superblock ? &directory : 0);
    return status;
}

NFSD_HANDLER nfsd_proc_remove(xdr_reader_t *reader, xdr_writer_t *writer,
                                 const nfsd_credential_t *credential,
                                 int directory_remove) {
    nfsd_object_t directory;
    vfs_inode_t before;
    char name[NFSD_MAX_NAME + 1u];
    int result = nfsd_parse_directory_name(reader, &directory, name);
    uint32_t status;
    memset(&before, 0, sizeof(before));
    if (result == 0) before = directory.inode;
    if (result == 0) result = nfsd_require_write(&directory, credential, 3);
    if (result == 0) {
        filesystem_ops_t *ops = directory.superblock->ops;
        if (directory_remove) {
            if (!ops || !ops->rmdir) result = -EDGE_LINUX_EOPNOTSUPP;
            else if (ops->rmdir(directory.superblock, &directory.inode,
                                name) < 0)
                result = -EDGE_LINUX_EIO;
        } else {
            if (!ops || !ops->unlink) result = -EDGE_LINUX_EOPNOTSUPP;
            else if (ops->unlink(directory.superblock, &directory.inode,
                                 name) < 0)
                result = -EDGE_LINUX_EIO;
        }
        if (result == 0) {
            vfs_path_cache_invalidate_all();
            if (vfs_sync_mutation_if_required(directory.superblock, 1) < 0)
                result = -EDGE_LINUX_EIO;
        }
    }
    status = nfsd_error_status(result);
    xdr_put_u32(writer, status);
    nfsd_put_wcc(writer, directory.superblock ? &before : 0,
                 directory.superblock ? &directory : 0);
    return status;
}

NFSD_HANDLER nfsd_proc_rename(xdr_reader_t *reader, xdr_writer_t *writer,
                                 const nfsd_credential_t *credential) {
    nfsd_object_t old_directory, new_directory;
    vfs_inode_t old_before, new_before;
    char old_name[NFSD_MAX_NAME + 1u], new_name[NFSD_MAX_NAME + 1u];
    int result = nfsd_parse_directory_name(reader, &old_directory, old_name);
    uint32_t status;
    memset(&new_directory, 0, sizeof(new_directory));
    memset(&old_before, 0, sizeof(old_before));
    memset(&new_before, 0, sizeof(new_before));
    if (result == 0) old_before = old_directory.inode;
    if (nfsd_parse_directory_name(reader, &new_directory, new_name) < 0)
        result = -EDGE_LINUX_EINVAL;
    else new_before = new_directory.inode;
    if (result == 0 && old_directory.superblock != new_directory.superblock)
        result = -EDGE_LINUX_EXDEV;
    if (result == 0) result = nfsd_require_write(&old_directory, credential, 3);
    if (result == 0) result = nfsd_require_write(&new_directory, credential, 3);
    if (result == 0 && (!old_directory.superblock->ops ||
        !old_directory.superblock->ops->rename))
        result = -EDGE_LINUX_EOPNOTSUPP;
    if (result == 0 && old_directory.superblock->ops->rename(
            old_directory.superblock, &old_directory.inode, old_name,
            &new_directory.inode, new_name) < 0)
        result = -EDGE_LINUX_EIO;
    if (result == 0) {
        vfs_path_cache_invalidate_all();
        if (vfs_sync_mutation_if_required(old_directory.superblock, 1) < 0)
            result = -EDGE_LINUX_EIO;
    }
    status = nfsd_error_status(result);
    xdr_put_u32(writer, status);
    nfsd_put_wcc(writer, old_directory.superblock ? &old_before : 0,
                 old_directory.superblock ? &old_directory : 0);
    nfsd_put_wcc(writer, new_directory.superblock ? &new_before : 0,
                 new_directory.superblock ? &new_directory : 0);
    return status;
}

NFSD_HANDLER nfsd_proc_link(xdr_reader_t *reader, xdr_writer_t *writer,
                               const nfsd_credential_t *credential) {
    nfsd_object_t source, directory;
    vfs_inode_t directory_before;
    char name[NFSD_MAX_NAME + 1u];
    int result = nfsd_get_object(reader, &source);
    uint32_t status;
    memset(&directory, 0, sizeof(directory));
    memset(&directory_before, 0, sizeof(directory_before));
    if (nfsd_parse_directory_name(reader, &directory, name) < 0)
        result = -EDGE_LINUX_EINVAL;
    else directory_before = directory.inode;
    if (result == 0 && source.superblock != directory.superblock)
        result = -EDGE_LINUX_EXDEV;
    if (result == 0) result = nfsd_require_write(&directory, credential, 3);
    if (result == 0 && (!source.superblock->ops ||
        !source.superblock->ops->link))
        result = -EDGE_LINUX_EOPNOTSUPP;
    if (result == 0 && source.superblock->ops->link(source.superblock,
            &source.inode, &directory.inode, name) < 0)
        result = -EDGE_LINUX_EIO;
    if (result == 0) {
        vfs_path_cache_invalidate_all();
        if (vfs_sync_mutation_if_required(source.superblock, 1) < 0)
            result = -EDGE_LINUX_EIO;
    }
    status = nfsd_error_status(result);
    xdr_put_u32(writer, status);
    nfsd_put_post_attr(writer, source.superblock ? &source : 0);
    nfsd_put_wcc(writer, directory.superblock ? &directory_before : 0,
                 directory.superblock ? &directory : 0);
    return status;
}

static uint64_t nfsd_cookie_verifier(const nfsd_object_t *directory) {
    return ((uint64_t)directory->inode.generation << 32) ^
           directory->inode.mtime ^ directory->export_entry->id;
}

NFSD_HANDLER nfsd_proc_readdir(xdr_reader_t *reader, xdr_writer_t *writer,
                                  const nfsd_credential_t *credential,
                                  int plus) {
    nfsd_object_t directory;
    nfsd_object_t child;
    int result = nfsd_get_object(reader, &directory);
    uint64_t cookie = xdr_get_u64(reader);
    uint64_t verifier = xdr_get_u64(reader);
    uint32_t directory_count = 0;
    uint32_t maximum_count;
    uint32_t index;
    uint32_t emitted = 0;
    uint32_t response_start = writer->offset;
    uint32_t directory_bytes = 0;
    uint32_t status;
    if (plus) directory_count = xdr_get_u32(reader);
    maximum_count = xdr_get_u32(reader);
    if (result == 0 && (directory.inode.mode & 0xf000u) != VFS_INODE_DIR)
        result = -EDGE_LINUX_ENOTDIR;
    if (result == 0 && nfsd_permission(&directory, credential, 5) < 0)
        result = -EDGE_LINUX_EACCES;
    if (result == 0 && cookie != 0u && verifier != nfsd_cookie_verifier(&directory))
        result = -EDGE_LINUX_EINVAL;
    if (result == 0 && (!directory.superblock->ops ||
        !directory.superblock->ops->readdir))
        result = -EDGE_LINUX_EOPNOTSUPP;
    if (maximum_count < (plus ? 256u : 128u)) result = -EDGE_LINUX_ENOBUFS;
    status = result == -EDGE_LINUX_ENOBUFS ? NFS3ERR_TOOSMALL :
             nfsd_error_status(result);
    nfsd_reply_status_attr(writer, status, result == 0 ? &directory : 0);
    if (status != NFS3_OK) return status;
    xdr_put_u64(writer, nfsd_cookie_verifier(&directory));
    index = cookie > UINT32_MAX ? UINT32_MAX : (uint32_t)cookie;
    while (!writer->failed && index < UINT32_MAX) {
        char name[NFSD_MAX_NAME + 1u];
        uint32_t entry_start = writer->offset;
        uint32_t name_bytes;
        uint32_t directory_entry_bytes;
        memset(&child, 0, sizeof(child));
        child.export_entry = directory.export_entry;
        child.superblock = directory.superblock;
        if (directory.superblock->ops->readdir(directory.superblock,
                &directory.inode, index, name, &child.inode) < 0)
            break;
        name_bytes = (uint32_t)strlen(name);
        directory_entry_bytes = 24u + ((name_bytes + 3u) & ~3u);
        if ((plus && directory_count &&
             directory_bytes + directory_entry_bytes + 4u > directory_count) ||
            writer->offset - response_start + directory_entry_bytes + 8u >
                maximum_count)
            break;
        xdr_put_u32(writer, 1u);
        xdr_put_u64(writer,
            ((uint64_t)child.inode.generation << 32) | child.inode.ino);
        xdr_put_string(writer, name);
        xdr_put_u64(writer, (uint64_t)index + 1u);
        if (plus) {
            nfsd_put_post_attr(writer, &child);
            xdr_put_u32(writer, 1u);
            nfsd_put_handle(writer, &child);
        }
        if (writer->failed ||
            writer->offset - response_start + 8u > maximum_count) {
            writer->failed = 0;
            writer->offset = entry_start;
            break;
        }
        directory_bytes += directory_entry_bytes;
        ++index;
        ++emitted;
    }
    xdr_put_u32(writer, 0u);
    {
        char probe[NFSD_MAX_NAME + 1u];
        vfs_inode_t probe_inode;
        int eof = directory.superblock->ops->readdir(directory.superblock,
            &directory.inode, index, probe, &probe_inode) < 0;
        xdr_put_u32(writer, eof ? 1u : 0u);
    }
    (void)emitted;
    return NFS3_OK;
}

NFSD_HANDLER nfsd_proc_fsstat(xdr_reader_t *reader,
                                 xdr_writer_t *writer) {
    nfsd_object_t object;
    uint32_t total_kb = 0, used_kb = 0;
    int result = nfsd_get_object(reader, &object);
    uint32_t status;
    if (result == 0 && object.superblock->ops &&
        object.superblock->ops->statfs) {
        if (object.superblock->ops->statfs(object.superblock,
                &total_kb, &used_kb) < 0)
            result = -EDGE_LINUX_EIO;
    } else if (result == 0) result = -EDGE_LINUX_EOPNOTSUPP;
    status = nfsd_error_status(result);
    nfsd_reply_status_attr(writer, status, result == 0 ? &object : 0);
    if (status == NFS3_OK) {
        uint64_t total = (uint64_t)total_kb * 1024u;
        uint64_t free = total_kb >= used_kb ?
            (uint64_t)(total_kb - used_kb) * 1024u : 0u;
        xdr_put_u64(writer, total);
        xdr_put_u64(writer, free);
        xdr_put_u64(writer, free);
        xdr_put_u64(writer, 0xffffffffu);
        xdr_put_u64(writer, 0xffffffffu);
        xdr_put_u64(writer, 0xffffffffu);
        xdr_put_u32(writer, 0u);
    }
    return status;
}

NFSD_HANDLER nfsd_proc_fsinfo(xdr_reader_t *reader,
                                 xdr_writer_t *writer) {
    nfsd_object_t object;
    int result = nfsd_get_object(reader, &object);
    uint32_t status = result < 0 ? NFS3ERR_STALE : NFS3_OK;
    nfsd_reply_status_attr(writer, status, result == 0 ? &object : 0);
    if (status == NFS3_OK) {
        xdr_put_u32(writer, NFSD_MAX_DATA);
        xdr_put_u32(writer, NFSD_MAX_DATA);
        xdr_put_u32(writer, 4096u);
        xdr_put_u32(writer, NFSD_MAX_DATA);
        xdr_put_u32(writer, NFSD_MAX_DATA);
        xdr_put_u32(writer, 4096u);
        xdr_put_u32(writer, NFSD_MAX_DATA);
        xdr_put_u64(writer, UINT32_MAX);
        xdr_put_u32(writer, 0u);
        xdr_put_u32(writer, 1000000u);
        xdr_put_u32(writer, 0x0001u | 0x0002u | 0x0008u | 0x0010u);
    }
    return status;
}

NFSD_HANDLER nfsd_proc_pathconf(xdr_reader_t *reader,
                                   xdr_writer_t *writer) {
    nfsd_object_t object;
    int result = nfsd_get_object(reader, &object);
    uint32_t status = result < 0 ? NFS3ERR_STALE : NFS3_OK;
    nfsd_reply_status_attr(writer, status, result == 0 ? &object : 0);
    if (status == NFS3_OK) {
        xdr_put_u32(writer, 32000u);
        xdr_put_u32(writer, NFSD_MAX_NAME);
        xdr_put_u32(writer, 1u);
        xdr_put_u32(writer, 1u);
        xdr_put_u32(writer, 0u);
        xdr_put_u32(writer, 1u);
    }
    return status;
}

NFSD_HANDLER nfsd_proc_commit(xdr_reader_t *reader,
                                 xdr_writer_t *writer,
                                 const nfsd_credential_t *credential) {
    nfsd_object_t object;
    vfs_inode_t before;
    int result = nfsd_get_object(reader, &object);
    (void)xdr_get_u64(reader);
    (void)xdr_get_u32(reader);
    memset(&before, 0, sizeof(before));
    if (result == 0) before = object.inode;
    if (result == 0) result = nfsd_require_write(&object, credential, 2);
    if (result == 0 && vfs_sync_inode(object.superblock, &object.inode, 0) < 0)
        result = -EDGE_LINUX_EIO;
    xdr_put_u32(writer, nfsd_error_status(result));
    nfsd_put_wcc(writer, object.superblock ? &before : 0,
                 object.superblock ? &object : 0);
    if (result == 0) {
        xdr_put_u32(writer, g_handle_key);
        xdr_put_u32(writer, NFSD_COOKIE_SALT);
    }
    return nfsd_error_status(result);
}

static int nfsd_dispatch_nfs(uint32_t procedure, xdr_reader_t *reader,
                             xdr_writer_t *writer,
                             const nfsd_credential_t *credential) {
    switch (procedure) {
        case 0u: return 0;
        case 1u: (void)nfsd_proc_getattr(reader, writer); break;
        case 2u: (void)nfsd_proc_setattr(reader, writer, credential); break;
        case 3u: (void)nfsd_proc_lookup(reader, writer, credential); break;
        case 4u: (void)nfsd_proc_access(reader, writer, credential); break;
        case 5u: (void)nfsd_proc_readlink(reader, writer, credential); break;
        case 6u: (void)nfsd_proc_read(reader, writer, credential); break;
        case 7u: (void)nfsd_proc_write(reader, writer, credential); break;
        case 8u: (void)nfsd_proc_create(reader, writer, credential); break;
        case 9u: (void)nfsd_proc_mkdir(reader, writer, credential); break;
        case 10u: (void)nfsd_proc_symlink(reader, writer, credential); break;
        case 11u: (void)nfsd_proc_mknod(reader, writer, credential); break;
        case 12u: (void)nfsd_proc_remove(reader, writer, credential, 0); break;
        case 13u: (void)nfsd_proc_remove(reader, writer, credential, 1); break;
        case 14u: (void)nfsd_proc_rename(reader, writer, credential); break;
        case 15u: (void)nfsd_proc_link(reader, writer, credential); break;
        case 16u: (void)nfsd_proc_readdir(reader, writer, credential, 0); break;
        case 17u: (void)nfsd_proc_readdir(reader, writer, credential, 1); break;
        case 18u: (void)nfsd_proc_fsstat(reader, writer); break;
        case 19u: (void)nfsd_proc_fsinfo(reader, writer); break;
        case 20u: (void)nfsd_proc_pathconf(reader, writer); break;
        case 21u: (void)nfsd_proc_commit(reader, writer, credential); break;
        default: return RPC_PROC_UNAVAIL;
    }
    return reader->failed ? RPC_GARBAGE_ARGS : RPC_SUCCESS;
}

static int nfsd_dispatch_rpcbind(uint32_t procedure, xdr_reader_t *reader,
                                 xdr_writer_t *writer) {
    uint32_t program, version, protocol, port;
    uint32_t index;
    switch (procedure) {
        case 0u: return RPC_SUCCESS;
        case 1u:
        case 2u:
            (void)xdr_get_u32(reader); (void)xdr_get_u32(reader);
            (void)xdr_get_u32(reader); (void)xdr_get_u32(reader);
            xdr_put_u32(writer, 0u);
            return reader->failed ? RPC_GARBAGE_ARGS : RPC_SUCCESS;
        case 3u:
            program = xdr_get_u32(reader);
            version = xdr_get_u32(reader);
            protocol = xdr_get_u32(reader);
            (void)xdr_get_u32(reader);
            port = 0u;
            if (protocol == IPPROTO_UDP_VALUE || protocol == IPPROTO_TCP_VALUE) {
                if (program == RPCB_PROGRAM && version == RPCB_VERSION)
                    port = RPCB_PORT;
                else if (program == MOUNT_PROGRAM && version == MOUNT_VERSION)
                    port = MOUNT_PORT;
                else if (program == NFS_PROGRAM && version == NFS_VERSION)
                    port = NFS_PORT;
            }
            xdr_put_u32(writer, port);
            return reader->failed ? RPC_GARBAGE_ARGS : RPC_SUCCESS;
        case 4u:
            for (index = 0; index < 6u; ++index) {
                static const uint32_t programs[6] = {
                    RPCB_PROGRAM, RPCB_PROGRAM, MOUNT_PROGRAM,
                    MOUNT_PROGRAM, NFS_PROGRAM, NFS_PROGRAM};
                static const uint32_t versions[6] = {
                    RPCB_VERSION, RPCB_VERSION, MOUNT_VERSION,
                    MOUNT_VERSION, NFS_VERSION, NFS_VERSION};
                static const uint32_t protocols[6] = {
                    IPPROTO_TCP_VALUE, IPPROTO_UDP_VALUE, IPPROTO_TCP_VALUE,
                    IPPROTO_UDP_VALUE, IPPROTO_TCP_VALUE, IPPROTO_UDP_VALUE};
                static const uint32_t ports[6] = {
                    RPCB_PORT, RPCB_PORT, MOUNT_PORT, MOUNT_PORT,
                    NFS_PORT, NFS_PORT};
                xdr_put_u32(writer, 1u);
                xdr_put_u32(writer, programs[index]);
                xdr_put_u32(writer, versions[index]);
                xdr_put_u32(writer, protocols[index]);
                xdr_put_u32(writer, ports[index]);
            }
            xdr_put_u32(writer, 0u);
            return RPC_SUCCESS;
        default: return RPC_PROC_UNAVAIL;
    }
}

static int nfsd_dispatch_mount(uint32_t procedure, xdr_reader_t *reader,
                               xdr_writer_t *writer) {
    char path[NFSD_PROTOCOL_PATH_MAX + 1u];
    nfsd_export_t *entry;
    nfsd_object_t root;
    uint32_t index;
    switch (procedure) {
        case 0u: return RPC_SUCCESS;
        case 1u:
            if (xdr_get_string(reader, path, sizeof(path)) < 0)
                return RPC_GARBAGE_ARGS;
            entry = nfsd_export_by_path(path);
            if (!entry) {
                xdr_put_u32(writer, MNT3ERR_NOENT);
                return RPC_SUCCESS;
            }
            memset(&root, 0, sizeof(root));
            root.export_entry = entry;
            root.superblock = entry->superblock;
            root.inode = entry->root;
            if (!root.superblock) {
                xdr_put_u32(writer, MNT3ERR_SERVERFAULT);
                return RPC_SUCCESS;
            }
            xdr_put_u32(writer, MNT3_OK);
            nfsd_put_handle(writer, &root);
            xdr_put_u32(writer, 2u);
            xdr_put_u32(writer, RPC_AUTH_SYS);
            xdr_put_u32(writer, RPC_AUTH_NONE);
            return RPC_SUCCESS;
        case 2u:
            xdr_put_u32(writer, 0u);
            return RPC_SUCCESS;
        case 3u:
            (void)xdr_get_string(reader, path, sizeof(path));
            return reader->failed ? RPC_GARBAGE_ARGS : RPC_SUCCESS;
        case 4u:
            return RPC_SUCCESS;
        case 5u:
            for (index = 0; index < NFSD_MAX_EXPORTS; ++index) {
                if (!g_exports[index].used) continue;
                xdr_put_u32(writer, 1u);
                xdr_put_string(writer, g_exports[index].path);
                xdr_put_u32(writer, 0u);
            }
            xdr_put_u32(writer, 0u);
            return RPC_SUCCESS;
        default: return RPC_PROC_UNAVAIL;
    }
}

static void nfsd_reply_accepted_header(xdr_writer_t *writer, uint32_t xid,
                                       uint32_t accept_status) {
    xdr_put_u32(writer, xid);
    xdr_put_u32(writer, RPC_REPLY);
    xdr_put_u32(writer, RPC_MSG_ACCEPTED);
    xdr_put_u32(writer, RPC_AUTH_NONE);
    xdr_put_u32(writer, 0u);
    xdr_put_u32(writer, accept_status);
}

int edge_nfsd_rpc_dispatch(const void *request, uint32_t request_bytes,
                           void *response, uint32_t response_capacity,
                           uint32_t *response_bytes) {
    xdr_reader_t reader;
    xdr_writer_t writer;
    xdr_writer_t payload;
    nfsd_credential_t credential;
    uint8_t *response_data = (uint8_t *)response;
    uint32_t xid, rpc_version, program, version, procedure;
    uint32_t credential_flavor, credential_length;
    const uint8_t *credential_body;
    uint32_t verifier_length;
    uint32_t accept_status;
    if (!request || request_bytes < 24u || !response ||
        response_capacity < 24u || !response_bytes)
        return -1;
    reader.data = (const uint8_t *)request;
    reader.length = request_bytes;
    reader.offset = 0u;
    reader.failed = 0;
    writer.data = response_data;
    writer.capacity = response_capacity;
    writer.offset = 0u;
    writer.failed = 0;
    memset(&credential, 0, sizeof(credential));
    credential.uid = 65534u;
    credential.gid = 65534u;
    xid = xdr_get_u32(&reader);
    if (xdr_get_u32(&reader) != RPC_CALL) return -1;
    rpc_version = xdr_get_u32(&reader);
    if (rpc_version != RPC_VERSION) {
        xdr_put_u32(&writer, xid);
        xdr_put_u32(&writer, RPC_REPLY);
        xdr_put_u32(&writer, RPC_MSG_DENIED);
        xdr_put_u32(&writer, RPC_MISMATCH);
        xdr_put_u32(&writer, RPC_VERSION);
        xdr_put_u32(&writer, RPC_VERSION);
        *response_bytes = writer.offset;
        return writer.failed ? -1 : 0;
    }
    program = xdr_get_u32(&reader);
    version = xdr_get_u32(&reader);
    procedure = xdr_get_u32(&reader);
    credential_flavor = xdr_get_u32(&reader);
    credential_body = xdr_get_opaque(&reader, 1024u, &credential_length);
    if (!credential_body) return -1;
    (void)xdr_get_u32(&reader);
    if (!xdr_get_opaque(&reader, 1024u, &verifier_length) || reader.failed)
        return -1;
    if (credential_flavor == RPC_AUTH_SYS) {
        if (nfsd_parse_auth_sys(credential_body, credential_length,
                                &credential) < 0)
            return -1;
    } else if (credential_flavor != RPC_AUTH_NONE) {
        xdr_put_u32(&writer, xid);
        xdr_put_u32(&writer, RPC_REPLY);
        xdr_put_u32(&writer, RPC_MSG_DENIED);
        xdr_put_u32(&writer, RPC_AUTH_ERROR);
        xdr_put_u32(&writer, 1u);
        *response_bytes = writer.offset;
        return writer.failed ? -1 : 0;
    }
    payload = writer;
    payload.offset = 24u;
    if (program == RPCB_PROGRAM) {
        if (version != RPCB_VERSION) accept_status = RPC_PROG_MISMATCH;
        else accept_status = nfsd_dispatch_rpcbind(procedure, &reader, &payload);
    } else if (program == MOUNT_PROGRAM) {
        if (version != MOUNT_VERSION) accept_status = RPC_PROG_MISMATCH;
        else accept_status = nfsd_dispatch_mount(procedure, &reader, &payload);
    } else if (program == NFS_PROGRAM) {
        if (version != NFS_VERSION) accept_status = RPC_PROG_MISMATCH;
        else accept_status = nfsd_dispatch_nfs(procedure, &reader, &payload,
                                               &credential);
    } else accept_status = RPC_PROG_UNAVAIL;
    writer.offset = 0u;
    nfsd_reply_accepted_header(&writer, xid, accept_status);
    if (accept_status == RPC_PROG_MISMATCH) {
        uint32_t supported = program == RPCB_PROGRAM ? RPCB_VERSION :
                             program == MOUNT_PROGRAM ? MOUNT_VERSION :
                             program == NFS_PROGRAM ? NFS_VERSION : 0u;
        xdr_put_u32(&writer, supported);
        xdr_put_u32(&writer, supported);
    } else if (accept_status == RPC_SUCCESS) {
        writer.offset = payload.offset;
        writer.failed = payload.failed;
    }
    if (writer.failed) return -1;
    *response_bytes = writer.offset;
    return 0;
}

int edge_nfsd_initialize(void) {
    if (g_initialized) return 0;
    memset(g_exports, 0, sizeof(g_exports));
    g_next_export_id = 1u;
    g_handle_key ^= (uint32_t)boottime_realtime_us();
    if (!g_handle_key) g_handle_key = 0x6e667333u;
    g_initialized = 1u;
    return 0;
}

int edge_nfsd_export_add(const char *path, uint32_t flags) {
    vfs_inode_t inode;
    vfs_superblock_t *superblock = 0;
    uint64_t mount_id;
    uint8_t probe[NFSD_FH_PAYLOAD_MAX];
    uint32_t probe_length = sizeof(probe), probe_type = 0;
    uint32_t index;
    if (!g_initialized) edge_nfsd_initialize();
    if (!path || path[0] != '/' ||
        flags & ~(EDGE_NFSD_EXPORT_READ_ONLY | EDGE_NFSD_EXPORT_ROOT_SQUASH))
        return -EDGE_LINUX_EINVAL;
    if (vfs_resolve_canonical(path, g_export_canonical,
                              sizeof(g_export_canonical),
                              &inode, &superblock) < 0)
        return -EDGE_LINUX_ENOENT;
    if ((inode.mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    if (!superblock || vfs_mount_id_for_superblock(superblock, &mount_id) < 0)
        return -EDGE_LINUX_ESTALE;
    if (vfs_encode_file_handle(superblock, &inode, &probe_type, probe,
                               &probe_length) < 0 ||
        probe_length > NFSD_FH_PAYLOAD_MAX)
        return -EDGE_LINUX_EOPNOTSUPP;
    if (nfsd_export_by_path(g_export_canonical))
        return -EDGE_LINUX_EEXIST;
    superblock = vfs_superblock_acquire(superblock);
    if (!superblock) return -EDGE_LINUX_ENOMEM;
    for (index = 0; index < NFSD_MAX_EXPORTS; ++index) {
        if (!g_exports[index].used) {
            nfsd_export_t *entry = &g_exports[index];
            memset(entry, 0, sizeof(*entry));
            entry->used = 1u;
            entry->id = g_next_export_id++;
            if (!entry->id) entry->id = g_next_export_id++;
            entry->flags = flags;
            entry->mount_id = mount_id;
            entry->superblock = superblock;
            entry->root = inode;
            memcpy(entry->path, g_export_canonical,
                   strlen(g_export_canonical) + 1u);
            return 0;
        }
    }
    vfs_superblock_release(superblock);
    return -EDGE_LINUX_ENOSPC;
}

int edge_nfsd_export_remove(const char *path) {
    nfsd_export_t *entry;
    if (!path || path[0] != '/') return -EDGE_LINUX_EINVAL;
    if (vfs_resolve_canonical(path, g_export_canonical,
                              sizeof(g_export_canonical), 0, 0) < 0)
        return -EDGE_LINUX_ENOENT;
    entry = nfsd_export_by_path(g_export_canonical);
    if (!entry) return -EDGE_LINUX_ENOENT;
    vfs_superblock_release(entry->superblock);
    memset(entry, 0, sizeof(*entry));
    return 0;
}

uint32_t edge_nfsd_export_count(void) {
    uint32_t count = 0, index;
    for (index = 0; index < NFSD_MAX_EXPORTS; ++index)
        if (g_exports[index].used) ++count;
    return count;
}
