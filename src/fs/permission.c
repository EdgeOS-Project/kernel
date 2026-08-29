/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-neutral Linux VFS credential and mode-bit checks. */

#include "vfs/vfs.h"
#include "kernel/linux_errno.h"
#include "kernel/groups.h"
#include "kernel/io_buffer.h"
#include "kernel/process_runtime.h"
#include "stdio.h"

#ifndef EDGE_SECURITY_DEBUG
#define EDGE_SECURITY_DEBUG 0
#endif

#define EDGE_POSIX_ACL_XATTR_VERSION 0x0002u
#define EDGE_POSIX_ACL_USER_OBJ 0x0001u
#define EDGE_POSIX_ACL_USER 0x0002u
#define EDGE_POSIX_ACL_GROUP_OBJ 0x0004u
#define EDGE_POSIX_ACL_GROUP 0x0008u
#define EDGE_POSIX_ACL_MASK 0x0010u
#define EDGE_POSIX_ACL_OTHER 0x0020u
#define EDGE_POSIX_ACL_HEADER_SIZE 4u
#define EDGE_POSIX_ACL_ENTRY_SIZE 8u

static uint16_t permission_read_le16(const uint8_t *source) {
    return (uint16_t)source[0] | (uint16_t)((uint16_t)source[1] << 8);
}

static uint32_t permission_read_le32(const uint8_t *source) {
    return (uint32_t)source[0] | ((uint32_t)source[1] << 8) |
           ((uint32_t)source[2] << 16) | ((uint32_t)source[3] << 24);
}

static int permission_bits_result(const vfs_inode_t *inode,
                                  uint16_t requested, uint16_t bits,
                                  uint64_t capabilities) {
    uint16_t mode = inode->mode & 07777u;
    uint16_t kind = inode->mode & 0xf000u;
    uint16_t missing;

    if ((bits & requested) == requested) return 0;
    missing = (uint16_t)(requested & ~bits);
    if (capabilities & (1ULL << EDGE_LINUX_CAP_DAC_OVERRIDE)) {
        if (!(missing & 1u) || kind == VFS_INODE_DIR || (mode & 0111u))
            return 0;
    }
    if ((capabilities & (1ULL << EDGE_LINUX_CAP_DAC_READ_SEARCH)) &&
        !(missing & 2u) &&
        (!(missing & 1u) || kind == VFS_INODE_DIR))
        return 0;
    return -EDGE_LINUX_EACCES;
}

static int permission_posix_acl_check(
        const vfs_inode_t *inode, int access_mask,
        uint32_t uid, uint32_t gid,
        const struct linux_group_list *groups, uint64_t capabilities,
        const uint8_t *acl, uint32_t length) {
    uint16_t requested = (uint16_t)access_mask & 7u;
    uint16_t owner_bits = 0u;
    uint16_t named_user_bits = 0u;
    uint16_t group_bits = 0u;
    uint16_t other_bits = 0u;
    uint16_t mask_bits = 7u;
    int owner_present = 0;
    int named_user_present = 0;
    int group_object_present = 0;
    int group_matched = 0;
    int mask_present = 0;
    int other_present = 0;
    int extended = 0;

    if (!acl || length < EDGE_POSIX_ACL_HEADER_SIZE ||
        permission_read_le32(acl) != EDGE_POSIX_ACL_XATTR_VERSION ||
        (length - EDGE_POSIX_ACL_HEADER_SIZE) % EDGE_POSIX_ACL_ENTRY_SIZE)
        return -EDGE_LINUX_EACCES;
    for (uint32_t offset = EDGE_POSIX_ACL_HEADER_SIZE;
         offset < length; offset += EDGE_POSIX_ACL_ENTRY_SIZE) {
        uint16_t tag = permission_read_le16(acl + offset);
        uint16_t permissions = permission_read_le16(acl + offset + 2u);
        uint32_t identifier = permission_read_le32(acl + offset + 4u);

        if (permissions & ~7u) return -EDGE_LINUX_EACCES;
        switch (tag) {
        case EDGE_POSIX_ACL_USER_OBJ:
            if (owner_present) return -EDGE_LINUX_EACCES;
            owner_present = 1;
            owner_bits = permissions;
            break;
        case EDGE_POSIX_ACL_USER:
            extended = 1;
            if (identifier == uid) {
                if (named_user_present) return -EDGE_LINUX_EACCES;
                named_user_present = 1;
                named_user_bits = permissions;
            }
            break;
        case EDGE_POSIX_ACL_GROUP_OBJ:
            if (group_object_present) return -EDGE_LINUX_EACCES;
            group_object_present = 1;
            if (gid == inode->gid ||
                (groups && linux_group_list_contains(groups, inode->gid))) {
                group_matched = 1;
                group_bits |= permissions;
            }
            break;
        case EDGE_POSIX_ACL_GROUP:
            extended = 1;
            if (gid == identifier ||
                (groups && linux_group_list_contains(groups, identifier))) {
                group_matched = 1;
                group_bits |= permissions;
            }
            break;
        case EDGE_POSIX_ACL_MASK:
            if (mask_present) return -EDGE_LINUX_EACCES;
            mask_present = 1;
            mask_bits = permissions;
            break;
        case EDGE_POSIX_ACL_OTHER:
            if (other_present) return -EDGE_LINUX_EACCES;
            other_present = 1;
            other_bits = permissions;
            break;
        default:
            return -EDGE_LINUX_EACCES;
        }
    }
    if (!owner_present || !group_object_present || !other_present ||
        (extended && !mask_present))
        return -EDGE_LINUX_EACCES;
    if (uid == inode->uid)
        return permission_bits_result(
            inode, requested, owner_bits, capabilities);
    if (named_user_present)
        return permission_bits_result(
            inode, requested, named_user_bits & mask_bits, capabilities);
    if (group_matched)
        return permission_bits_result(
            inode, requested, group_bits & mask_bits, capabilities);
    return permission_bits_result(
        inode, requested, other_bits, capabilities);
}

int vfs_permission_check_as(const vfs_inode_t *inode, int access_mask,
                            uint32_t uid, uint32_t gid,
                            const struct linux_group_list *groups,
                            uint64_t capabilities) {
    uint16_t mode;
    uint16_t bits;
    uint16_t requested;

    if (!inode) return -EDGE_LINUX_EINVAL;
    requested = (uint16_t)access_mask & 7u;
    if (!requested) return 0;
    mode = inode->mode & 07777u;
    if (uid == inode->uid)
        bits = (uint16_t)((mode >> 6) & 7u);
    else if (gid == inode->gid ||
             (groups && linux_group_list_contains(groups, inode->gid)))
        bits = (uint16_t)((mode >> 3) & 7u);
    else bits = (uint16_t)(mode & 7u);
    if (permission_bits_result(
            inode, requested, bits, capabilities) == 0) return 0;

    if (EDGE_SECURITY_DEBUG)
        printf("[sec] perm denied uid=%u ino=%u request=%o mode=%o\n",
               uid, inode->ino, requested, mode);
    return -EDGE_LINUX_EACCES;
}

int vfs_permission_check_with_acl(vfs_superblock_t *superblock,
                                  const vfs_inode_t *inode,
                                  int access_mask) {
    kernel_linux_identity_t identity;
    linux_group_list_t groups;
    kernel_io_buffer_t buffer;
    int length;
    int result;

    if (!superblock || !inode || !superblock->ops ||
        !superblock->ops->getxattr)
        return vfs_permission_check(inode, access_mask);
    length = vfs_inode_getxattr(
        superblock, inode, "system.posix_acl_access", 0, 0);
    if (length <= 0)
        return vfs_permission_check(inode, access_mask);
    if ((uint32_t)length > KERNEL_IO_BUFFER_SIZE ||
        kernel_io_buffer_acquire(&buffer) < 0)
        return -EDGE_LINUX_EACCES;
    result = vfs_inode_getxattr(
        superblock, inode, "system.posix_acl_access",
        buffer.data, (uint32_t)length);
    if (result != length) {
        kernel_io_buffer_release(&buffer);
        return -EDGE_LINUX_EACCES;
    }
    if (kernel_current_linux_identity(&identity) < 0) {
        kernel_io_buffer_release(&buffer);
        return 0;
    }
    linux_group_list_init(&groups);
    if (kernel_current_groups_snapshot(&groups) < 0) {
        kernel_io_buffer_release(&buffer);
        return -EDGE_LINUX_EACCES;
    }
    result = permission_posix_acl_check(
        inode, access_mask, identity.fsuid, identity.fsgid, &groups,
        identity.effective_capabilities, buffer.data, (uint32_t)length);
    linux_group_list_release(&groups);
    kernel_io_buffer_release(&buffer);
    return result;
}

int vfs_permission_check(const vfs_inode_t *inode, int access_mask) {
    kernel_linux_identity_t identity;
    linux_group_list_t groups;
    int result;
    if (kernel_current_linux_identity(&identity) < 0) return 0;
    linux_group_list_init(&groups);
    if (kernel_current_groups_snapshot(&groups) < 0)
        return -EDGE_LINUX_EACCES;
    result = vfs_permission_check_as(
        inode, access_mask, identity.fsuid, identity.fsgid, &groups,
        identity.effective_capabilities);
    linux_group_list_release(&groups);
    return result;
}

static int vfs_search_directory_as(
    const char *path, uint32_t uid, uint32_t gid,
    const linux_group_list_t *groups, uint64_t capabilities) {
    vfs_inode_t inode;
    if (vfs_resolve(path, &inode, 0, 0, 0) < 0)
        return -EDGE_LINUX_ENOENT;
    if ((inode.mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    return vfs_permission_check_as(
               &inode, 1, uid, gid, groups, capabilities) < 0 ?
           -EDGE_LINUX_EACCES : 0;
}

int vfs_path_search_check_as(const char *path, char *scratch,
                             uint32_t scratch_capacity, int include_final,
                             uint32_t uid, uint32_t gid,
                             const struct linux_group_list *groups,
                             uint64_t capabilities) {
    uint32_t source = 0;
    uint32_t output = 1;
    int status;
    if (!path || path[0] != '/' || !scratch || scratch_capacity < 2u)
        return -EDGE_LINUX_EINVAL;
    scratch[0] = '/';
    scratch[1] = 0;
    while (path[source] == '/') ++source;
    if (!path[source])
        return include_final ? vfs_search_directory_as(
            scratch, uid, gid, groups, capabilities) : 0;

    status = vfs_search_directory_as(
        scratch, uid, gid, groups, capabilities);
    if (status < 0) return status;
    while (path[source]) {
        uint32_t start = source;
        uint32_t length;
        uint32_t next;
        while (path[source] && path[source] != '/') ++source;
        length = source - start;
        next = source;
        while (path[next] == '/') ++next;
        if (!path[next] && !include_final) break;
        if (output > 1u) {
            if (output + 1u >= scratch_capacity)
                return -EDGE_LINUX_ENAMETOOLONG;
            scratch[output++] = '/';
        }
        if (length >= scratch_capacity - output)
            return -EDGE_LINUX_ENAMETOOLONG;
        for (uint32_t index = 0; index < length; ++index)
            scratch[output++] = path[start + index];
        scratch[output] = 0;
        status = vfs_search_directory_as(
            scratch, uid, gid, groups, capabilities);
        if (status < 0) return status;
        source = next;
    }
    return 0;
}

int vfs_path_search_check(const char *path, char *scratch,
                          uint32_t scratch_capacity, int include_final) {
    kernel_linux_identity_t identity;
    linux_group_list_t groups;
    int result;
    if (kernel_current_linux_identity(&identity) < 0) return 0;
    linux_group_list_init(&groups);
    if (kernel_current_groups_snapshot(&groups) < 0)
        return -EDGE_LINUX_EACCES;
    result = vfs_path_search_check_as(
        path, scratch, scratch_capacity, include_final,
        identity.fsuid, identity.fsgid, &groups,
        identity.effective_capabilities);
    linux_group_list_release(&groups);
    return result;
}
