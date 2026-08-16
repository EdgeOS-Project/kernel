/* SPDX-License-Identifier: MPL-2.0 */
/* Filesystem-backed loader for source-built BSD driver modules. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/driver_loader.h"
#include "compat/freebsd/edgeos/linker.h"
#include "compat/freebsd/edgeos/module.h"
#include "compat/freebsd/edgeos/systm.h"
#include "mm/arch_vm.h"
#include "vfs/vfs.h"

#define BSD_DRIVER_LOADER_PAGE_SIZE 4096u
#define BSD_DRIVER_MODULE_MAX_BYTES (128u * 1024u * 1024u)
#define BSD_DRIVER_CONFIG_MAX_BYTES (64u * 1024u)

#define BSD_DRIVER_ENOENT 2
#define BSD_DRIVER_ENOEXEC 8
#define BSD_DRIVER_ENOMEM 12
#define BSD_DRIVER_EEXIST 17
#define BSD_DRIVER_EINVAL 22
#define BSD_DRIVER_EFBIG 27

void printf(const char *format, ...);

static void
driver_loader_free_pages(void *memory, uint32_t page_count)
{
    unsigned char *bytes = memory;

    if (!memory)
        return;
    for (uint32_t page = 0; page < page_count; ++page) {
        arch_vm_free_page(bytes +
            (uint64_t)page * BSD_DRIVER_LOADER_PAGE_SIZE);
    }
}

static int
driver_loader_read_file(const char *path, uint32_t maximum,
    void **buffer_out, uint32_t *size_out, uint32_t *pages_out)
{
    vfs_inode_t inode;
    vfs_superblock_t *superblock = 0;
    uint64_t allocation_bytes;
    uint32_t pages;
    void *buffer;
    int bytes_read;

    if (!path || !buffer_out || !size_out || !pages_out)
        return BSD_DRIVER_EINVAL;
    *buffer_out = 0;
    *size_out = 0;
    *pages_out = 0;
    if (vfs_resolve(path, &inode, &superblock, 0, 0) < 0)
        return BSD_DRIVER_ENOENT;
    if ((inode.mode & VFS_INODE_FILE) == 0)
        return BSD_DRIVER_EINVAL;
    if (!superblock || !superblock->ops || !superblock->ops->read)
        return BSD_DRIVER_ENOEXEC;
    if (!inode.size) {
        printf("[bsd-bridge] empty module file %s\n", path);
        return BSD_DRIVER_ENOEXEC;
    }
    if (inode.size > maximum)
        return BSD_DRIVER_EFBIG;
    pages = (inode.size + BSD_DRIVER_LOADER_PAGE_SIZE - 1u) /
        BSD_DRIVER_LOADER_PAGE_SIZE;
    allocation_bytes = (uint64_t)pages * BSD_DRIVER_LOADER_PAGE_SIZE;
    buffer = arch_vm_alloc_pages(pages);
    if (!buffer)
        return BSD_DRIVER_ENOMEM;
    bsd_memset(buffer, 0, (size_t)allocation_bytes);
    bytes_read = superblock->ops->read(
        superblock, &inode, 0, buffer, inode.size);
    if (bytes_read < 0 || (uint32_t)bytes_read != inode.size) {
        printf("[bsd-bridge] module file %s short read: %d/%u\n",
            path, bytes_read, inode.size);
        driver_loader_free_pages(buffer, pages);
        return BSD_DRIVER_ENOEXEC;
    }
    *buffer_out = buffer;
    *size_out = inode.size;
    *pages_out = pages;
    return 0;
}

int
bsd_driver_module_load_path(const char *path,
    struct linker_file **file_out)
{
    bsd_linker_image_t *image = 0;
    void *object = 0;
    uint32_t object_size = 0;
    uint32_t object_pages = 0;
    int error;

    if (file_out)
        *file_out = 0;
    error = driver_loader_read_file(path, BSD_DRIVER_MODULE_MAX_BYTES,
        &object, &object_size, &object_pages);
    if (error) {
        printf("[bsd-bridge] module read %s failed: %d\n", path, error);
        return error;
    }
    error = bsd_linker_load_object(object, object_size,
        BSD_LINKER_ARCH_NATIVE, bsd_driver_symbol_resolve, 0, &image);
    driver_loader_free_pages(object, object_pages);
    if (error) {
        printf("[bsd-bridge] module object %s failed: %d\n", path, error);
        return BSD_DRIVER_ENOEXEC;
    }
    error = bsd_module_activate_image(image, path, file_out);
    if (error) {
        if (error == BSD_DRIVER_EEXIST)
            return error;
        printf("[bsd-bridge] module activation %s failed: %d\n",
            path, error);
        return error;
    }
    printf("[bsd-bridge] loaded module %s\n", path);
    return 0;
}

int
bsd_driver_modules_load_config(const char *path)
{
    char module_path[BSD_DRIVER_MODULE_PATH_MAX];
    unsigned char *config = 0;
    uint32_t config_size = 0;
    uint32_t config_pages = 0;
    size_t cursor = 0;
    int error;

    error = driver_loader_read_file(path, BSD_DRIVER_CONFIG_MAX_BYTES,
        (void **)&config, &config_size, &config_pages);
    if (error) {
        printf("[bsd-bridge] module config %s failed: %d\n", path, error);
        return error;
    }
    while (cursor < config_size) {
        size_t begin;
        size_t end;

        while (cursor < config_size &&
            (config[cursor] == ' ' || config[cursor] == '\t' ||
             config[cursor] == '\r' || config[cursor] == '\n'))
            cursor++;
        if (cursor >= config_size)
            break;
        if (config[cursor] == '#') {
            while (cursor < config_size && config[cursor] != '\n')
                cursor++;
            continue;
        }
        begin = cursor;
        while (cursor < config_size &&
            config[cursor] != ' ' && config[cursor] != '\t' &&
            config[cursor] != '\r' && config[cursor] != '\n' &&
            config[cursor] != '#')
            cursor++;
        end = cursor;
        while (cursor < config_size && config[cursor] != '\n')
            cursor++;
        error = bsd_driver_module_resolve_path(
            (const char *)config + begin, end - begin, module_path,
            sizeof(module_path));
        if (!error)
            error = bsd_driver_module_load_path(module_path, 0);
        if (error)
            break;
    }
    driver_loader_free_pages(config, config_pages);
    return error;
}

int
bsd_driver_modules_load_default(void)
{
    static const char path[] =
#ifdef CONFIG_BSD_DRIVER_MODULE_CONFIG
        CONFIG_BSD_DRIVER_MODULE_CONFIG;
#else
        "/etc/modules.load";
#endif
    vfs_inode_t inode;

    if (vfs_resolve(path, &inode, 0, 0, 0) < 0)
        return 0;
    return bsd_driver_modules_load_config(path);
}
