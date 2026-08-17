/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-neutral Linux VFS credential and mode-bit checks. */

#include "vfs/vfs.h"
#include "kernel/linux_errno.h"
#include "kernel/groups.h"
#include "kernel/process_runtime.h"
#include "stdio.h"

#ifndef EDGE_SECURITY_DEBUG
#define EDGE_SECURITY_DEBUG 0
#endif

int vfs_permission_check_as(const vfs_inode_t *inode, int access_mask,
                            uint32_t uid, uint32_t gid,
                            const struct linux_group_list *groups,
                            uint64_t capabilities) {
    uint16_t mode;
    uint16_t bits;
    uint16_t requested;
    uint16_t missing;
    uint16_t kind;

    if (!inode) return -EDGE_LINUX_EINVAL;
    requested = (uint16_t)access_mask & 7u;
    if (!requested) return 0;
    mode = inode->mode & 07777u;
    kind = inode->mode & 0xf000u;
    if (uid == inode->uid)
        bits = (uint16_t)((mode >> 6) & 7u);
    else if (gid == inode->gid ||
             (groups && linux_group_list_contains(groups, inode->gid)))
        bits = (uint16_t)((mode >> 3) & 7u);
    else bits = (uint16_t)(mode & 7u);
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

    if (EDGE_SECURITY_DEBUG)
        printf("[sec] perm denied uid=%u ino=%u request=%o mode=%o\n",
               uid, inode->ino, requested, mode);
    return -EDGE_LINUX_EACCES;
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
