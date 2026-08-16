/* SPDX-License-Identifier: MPL-2.0 */
/* Shared firmware metadata adapter for unmodified BSD drivers. */

#include <stddef.h>
#include <stdint.h>

#ifdef BSD_BRIDGE_HOST_TEST
int printf(const char *format, ...);
#else
void printf(const char *format, ...);
#endif

#include "compat/freebsd/edgeos/firmware.h"
#ifdef CONFIG_BSD_DRIVER_ACPICA
#include "compat/freebsd/edgeos/acpica.h"
#endif
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/systm.h"

#ifdef BSD_BRIDGE_HOST_TEST
#include "compat/freebsd/contrib/dev/acpica/include/acpi.h"
#else
#include "compat/freebsd/dev/acpica/acpivar.h"
#endif
#include "compat/freebsd/dev/ofw/ofw_bus.h"
#include <sys/firmware.h>
#ifndef BSD_BRIDGE_HOST_TEST
#include <sys/efi.h>
#include <machine/pc/bios.h>
#include <vm/pmap.h>
#endif

#ifndef BSD_BRIDGE_HOST_TEST
#include "vfs/vfs.h"
#endif

#define BSD_FIRMWARE_MAGIC UINT32_C(0x42534657)
#define BSD_FIRMWARE_IMAGE_MAGIC UINT32_C(0x42534649)
#define BSD_FIRMWARE_EBUSY 16
#define BSD_FIRMWARE_EINVAL 22
#define BSD_FIRMWARE_ENOMEM 12
#define BSD_FIRMWARE_MAX_BYTES (32u * 1024u * 1024u)
#define BSD_FIRMWARE_PATH_MAX 512u

typedef struct bsd_firmware_record {
    uint32_t magic;
    bsd_firmware_kind_t kind;
    int enabled;
    size_t compatible_count;
    phandle_t node;
    void *acpi_handle;
    void *acpi_private;
    uint32_t acpi_flags;
    int acpi_domain;
    const char *hardware_id;
    const char *compatible[];
} bsd_firmware_record_t;

typedef struct bsd_firmware_image {
    struct bsd_firmware_image *next;
    struct bsd_firmware_image *parent;
    struct firmware public;
    uint32_t magic;
    uint32_t references;
    uint32_t child_count;
    uint8_t owns_data;
} bsd_firmware_image_t;

typedef struct bsd_firmware_file_alias {
    struct bsd_firmware_file_alias *next;
    const char *request_name;
    const char *file_name;
} bsd_firmware_file_alias_t;

static volatile uint32_t g_firmware_image_guard;
static bsd_firmware_image_t *g_firmware_images;

#ifndef BSD_BRIDGE_HOST_TEST
static const struct efi_ops g_default_efi_ops;
__attribute__((weak)) const struct efi_ops *active_efi_ops =
    &g_default_efi_ops;
#endif

#ifndef BSD_BRIDGE_HOST_TEST
uint32_t
bios_sigsearch(uint32_t start, unsigned char *signature,
    int signature_length, int paragraph_length, int signature_offset)
{
    const uint32_t bios_start = UINT32_C(0x000e0000);
    const uint32_t bios_size = UINT32_C(0x00020000);
    unsigned char *mapping;
    uint32_t offset;

    if (!signature || signature_length <= 0 || paragraph_length <= 0 ||
        signature_offset < 0)
        return 0;
    if (start == 0)
        start = bios_start;
    if (start < bios_start || start >= bios_start + bios_size)
        return 0;
    mapping = pmap_mapbios(bios_start, bios_size);
    if (!mapping)
        return 0;
    offset = start - bios_start;
    while ((uint64_t)offset + (uint32_t)signature_offset +
        (uint32_t)signature_length < bios_size) {
        if (bsd_memcmp(mapping + offset + (uint32_t)signature_offset,
            signature, (size_t)signature_length) == 0)
            return bios_start + offset;
        offset += (uint32_t)paragraph_length;
    }
    return 0;
}
#endif
static bsd_firmware_file_alias_t *g_firmware_aliases;

static int firmware_string_valid(const char *text);

static void
firmware_image_lock(void)
{
    while (__atomic_test_and_set(
        &g_firmware_image_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__) || defined(_M_ARM64)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
firmware_image_unlock(void)
{
    __atomic_clear(&g_firmware_image_guard, __ATOMIC_RELEASE);
}

static bsd_firmware_image_t *
firmware_image_find_name_locked(const char *name)
{
    for (bsd_firmware_image_t *image = g_firmware_images; image;
        image = image->next) {
        if (bsd_strcasecmp(image->public.name, name) == 0)
            return image;
    }
    return 0;
}

static bsd_firmware_image_t *
firmware_image_find_public_locked(const struct firmware *firmware)
{
    for (bsd_firmware_image_t *image = g_firmware_images; image;
        image = image->next) {
        if (&image->public == firmware)
            return image;
    }
    return 0;
}

static bsd_firmware_image_t *
firmware_image_allocate(const char *name, const void *data, size_t size,
    unsigned int version, int owns_data)
{
    bsd_firmware_image_t *image;
    size_t name_length;

    if (!firmware_string_valid(name) || !data || size == 0)
        return 0;
    name_length = bsd_strlen(name) + 1;
    if (name_length > SIZE_MAX - sizeof(*image))
        return 0;
    image = bsd_malloc(
        sizeof(*image) + name_length, M_DEVBUF, M_WAITOK | M_ZERO);
    if (!image)
        return 0;
    image->public.name = (const char *)(image + 1);
    bsd_memcpy((void *)(uintptr_t)image->public.name, name, name_length);
    image->public.data = data;
    image->public.datasize = size;
    image->public.version = version;
    image->magic = BSD_FIRMWARE_IMAGE_MAGIC;
    image->owns_data = owns_data != 0;
    return image;
}

static void
firmware_image_release(bsd_firmware_image_t *image)
{
    if (!image)
        return;
    if (image->owns_data)
        bsd_free((void *)(uintptr_t)image->public.data, M_DEVBUF);
    image->magic = 0;
    bsd_free(image, M_DEVBUF);
}

static void
firmware_image_insert_locked(bsd_firmware_image_t *image)
{
    image->next = g_firmware_images;
    g_firmware_images = image;
}

static void
firmware_image_remove_locked(bsd_firmware_image_t *image)
{
    bsd_firmware_image_t **position = &g_firmware_images;

    while (*position && *position != image)
        position = &(*position)->next;
    if (*position != image)
        bsd_bridge_panic_stop();
    *position = image->next;
    image->next = 0;
}

static int
firmware_file_name_valid(const char *name)
{
    const char *component = name;

    if (!firmware_string_valid(name))
        return 0;
    for (const char *cursor = name;; ++cursor) {
        if (*cursor != '/' && *cursor != '\0')
            continue;
        if ((cursor - component == 1 && component[0] == '.') ||
            (cursor - component == 2 && component[0] == '.' &&
             component[1] == '.'))
            return 0;
        if (*cursor == '\0')
            break;
        component = cursor + 1;
    }
    return 1;
}

int
bsd_firmware_file_alias_register(const char *request_name,
    const char *file_name)
{
    bsd_firmware_file_alias_t *alias;
    size_t request_length;
    size_t file_length;
    char *strings;

    if (!firmware_file_name_valid(request_name) ||
        !firmware_file_name_valid(file_name))
        return BSD_FIRMWARE_EINVAL;
    request_length = bsd_strlen(request_name) + 1;
    file_length = bsd_strlen(file_name) + 1;
    if (request_length > SIZE_MAX - sizeof(*alias) ||
        file_length > SIZE_MAX - sizeof(*alias) - request_length)
        return BSD_FIRMWARE_EINVAL;
    alias = bsd_malloc(
        sizeof(*alias) + request_length + file_length,
        M_DEVBUF, M_WAITOK | M_ZERO);
    if (!alias)
        return BSD_FIRMWARE_ENOMEM;
    strings = (char *)(alias + 1);
    alias->request_name = strings;
    bsd_memcpy(strings, request_name, request_length);
    strings += request_length;
    alias->file_name = strings;
    bsd_memcpy(strings, file_name, file_length);

    firmware_image_lock();
    for (bsd_firmware_file_alias_t *entry = g_firmware_aliases; entry;
        entry = entry->next) {
        if (bsd_strcasecmp(entry->request_name, request_name) == 0 &&
            bsd_strcasecmp(entry->file_name, file_name) == 0) {
            firmware_image_unlock();
            bsd_free(alias, M_DEVBUF);
            return 0;
        }
    }
    alias->next = g_firmware_aliases;
    g_firmware_aliases = alias;
    firmware_image_unlock();
    return 0;
}

const struct firmware *
firmware_register(const char *name, const void *data, size_t size,
    unsigned int version, const struct firmware *parent_firmware)
{
    bsd_firmware_image_t *parent = 0;
    bsd_firmware_image_t *image;

    image = firmware_image_allocate(name, data, size, version, 0);
    if (!image)
        return 0;
    firmware_image_lock();
    if (firmware_image_find_name_locked(name)) {
        firmware_image_unlock();
        firmware_image_release(image);
        return 0;
    }
    if (parent_firmware) {
        parent = firmware_image_find_public_locked(parent_firmware);
        if (!parent) {
            firmware_image_unlock();
            firmware_image_release(image);
            return 0;
        }
        parent->child_count++;
        image->parent = parent;
    }
    firmware_image_insert_locked(image);
    firmware_image_unlock();
    return &image->public;
}

int
firmware_unregister(const char *name)
{
    bsd_firmware_image_t *image;

    if (!firmware_string_valid(name))
        return BSD_FIRMWARE_EINVAL;
    firmware_image_lock();
    image = firmware_image_find_name_locked(name);
    if (!image) {
        firmware_image_unlock();
        return 0;
    }
    if (image->references != 0 || image->child_count != 0) {
        firmware_image_unlock();
        return BSD_FIRMWARE_EBUSY;
    }
    firmware_image_remove_locked(image);
    if (image->parent && image->parent->child_count != 0)
        image->parent->child_count--;
    firmware_image_unlock();
    firmware_image_release(image);
    return 0;
}

#ifndef BSD_BRIDGE_HOST_TEST
static int
firmware_read_path(const char *path, void **data_out, uint32_t *size_out)
{
    vfs_inode_t inode;
    vfs_superblock_t *superblock = 0;
    void *data;
    int bytes_read;

    if (!path || !data_out || !size_out)
        return 0;
    if (vfs_resolve(path, &inode, &superblock, 0, 0) < 0 ||
        (inode.mode & VFS_INODE_FILE) == 0 || !inode.size ||
        inode.size > BSD_FIRMWARE_MAX_BYTES || !superblock ||
        !superblock->ops || !superblock->ops->read)
        return 0;
    data = bsd_malloc(inode.size, M_DEVBUF, M_WAITOK);
    if (!data)
        return 0;
    bytes_read = superblock->ops->read(
        superblock, &inode, 0, data, inode.size);
    if (bytes_read < 0 || (uint32_t)bytes_read != inode.size) {
        bsd_free(data, M_DEVBUF);
        return 0;
    }
    *data_out = data;
    *size_out = inode.size;
    return 1;
}

static int
firmware_try_file_name(const char *file_name, void **data_out,
    uint32_t *size_out)
{
    static const char *const roots[] = {
        "/lib/firmware",
        "/usr/lib/firmware",
        "/boot/firmware",
    };
    char path[BSD_FIRMWARE_PATH_MAX];

    if (!firmware_file_name_valid(file_name))
        return 0;
    if (file_name[0] == '/')
        return firmware_read_path(file_name, data_out, size_out);
    for (size_t index = 0; index < sizeof(roots) / sizeof(roots[0]);
        ++index) {
        int length = bsd_snprintf(path, sizeof(path), "%s/%s",
            roots[index], file_name);

        if (length > 0 && (size_t)length < sizeof(path) &&
            firmware_read_path(path, data_out, size_out))
            return 1;
    }
    return 0;
}

static int
firmware_load_data(const char *request_name, void **data_out,
    uint32_t *size_out)
{
    if (firmware_try_file_name(request_name, data_out, size_out))
        return 1;
    firmware_image_lock();
    for (bsd_firmware_file_alias_t *alias = g_firmware_aliases; alias;
        alias = alias->next) {
        const char *candidate;

        if (bsd_strcasecmp(alias->request_name, request_name) != 0)
            continue;
        candidate = alias->file_name;
        firmware_image_unlock();
        if (firmware_try_file_name(candidate, data_out, size_out))
            return 1;
        firmware_image_lock();
    }
    firmware_image_unlock();
    return 0;
}
#endif

const struct firmware *
firmware_get_flags(const char *name, uint32_t flags)
{
    bsd_firmware_image_t *image;
#ifndef BSD_BRIDGE_HOST_TEST
    void *data = 0;
    uint32_t size = 0;
#endif

    if (!firmware_file_name_valid(name))
        return 0;
    firmware_image_lock();
    image = firmware_image_find_name_locked(name);
    if (image) {
        if (image->references == 0 && image->parent)
            image->parent->references++;
        image->references++;
        firmware_image_unlock();
        return &image->public;
    }
    firmware_image_unlock();

#ifndef BSD_BRIDGE_HOST_TEST
    if (firmware_load_data(name, &data, &size)) {
        image = firmware_image_allocate(name, data, size, 0, 1);
        if (!image) {
            bsd_free(data, M_DEVBUF);
            return 0;
        }
        firmware_image_lock();
        {
            bsd_firmware_image_t *existing =
                firmware_image_find_name_locked(name);

            if (existing) {
                if (existing->references == 0 && existing->parent)
                    existing->parent->references++;
                existing->references++;
                firmware_image_unlock();
                firmware_image_release(image);
                return &existing->public;
            }
        }
        image->references = 1;
        firmware_image_insert_locked(image);
        firmware_image_unlock();
        return &image->public;
    }
#endif
    if ((flags & FIRMWARE_GET_NOWARN) == 0)
        printf("[bsd-bridge] firmware %s was not found\n", name);
    return 0;
}

const struct firmware *
firmware_get(const char *name)
{
    return firmware_get_flags(name, 0);
}

void
firmware_put(const struct firmware *firmware, int flags)
{
    bsd_firmware_image_t *image;
    int release = 0;

    if (!firmware)
        return;
    firmware_image_lock();
    image = firmware_image_find_public_locked(firmware);
    if (!image || image->magic != BSD_FIRMWARE_IMAGE_MAGIC ||
        image->references == 0) {
        firmware_image_unlock();
        bsd_bridge_panic_stop();
    }
    image->references--;
    if (image->references == 0 && image->parent) {
        if (image->parent->references == 0) {
            firmware_image_unlock();
            bsd_bridge_panic_stop();
        }
        image->parent->references--;
    }
    if (image->references == 0 && image->owns_data &&
        image->child_count == 0 && (flags & FIRMWARE_UNLOAD) != 0) {
        firmware_image_remove_locked(image);
        release = 1;
    }
    firmware_image_unlock();
    if (release)
        firmware_image_release(image);
}

static int
firmware_string_valid(const char *text)
{
    return text && text[0] != '\0';
}

static int
firmware_description_valid(const bsd_firmware_description_t *description)
{
    if (!description ||
        (description->enabled != 0 && description->enabled != 1) ||
        (!description->compatible &&
         description->compatible_count != 0))
        return 0;
    if (description->kind == BSD_FIRMWARE_ACPI)
        return firmware_string_valid(description->hardware_id) ||
            description->acpi_handle != 0;
    if (description->kind != BSD_FIRMWARE_FDT ||
        description->compatible_count == 0)
        return 0;
    for (size_t index = 0; index < description->compatible_count; ++index) {
        if (!firmware_string_valid(description->compatible[index]))
            return 0;
    }
    return 1;
}

static int
firmware_size_add(size_t *total, size_t amount)
{
    if (*total > SIZE_MAX - amount)
        return BSD_FIRMWARE_EINVAL;
    *total += amount;
    return 0;
}

static bsd_firmware_record_t *
firmware_metadata_record(device_t device)
{
    bsd_firmware_record_t *record =
        bsd_device_get_firmware_metadata(device);

    return record && record->magic == BSD_FIRMWARE_MAGIC ? record : 0;
}

int
bsd_firmware_bind(device_t device,
    const bsd_firmware_description_t *description)
{
    bsd_firmware_record_t *record;
    size_t size;
    char *cursor;

    if (!device || !firmware_description_valid(description))
        return BSD_FIRMWARE_EINVAL;
    if (bsd_device_get_firmware_metadata(device))
        return BSD_FIRMWARE_EBUSY;
    if (description->compatible_count >
        (SIZE_MAX - sizeof(*record)) / sizeof(record->compatible[0]))
        return BSD_FIRMWARE_EINVAL;
    size = sizeof(*record) +
        description->compatible_count * sizeof(record->compatible[0]);
    if (description->hardware_id &&
        firmware_size_add(&size,
            bsd_strlen(description->hardware_id) + 1) != 0)
        return BSD_FIRMWARE_EINVAL;
    for (size_t index = 0; index < description->compatible_count; ++index) {
        if (firmware_size_add(&size,
            bsd_strlen(description->compatible[index]) + 1) != 0)
            return BSD_FIRMWARE_EINVAL;
    }

    record = bsd_malloc(size, M_DEVBUF, M_WAITOK | M_ZERO);
    if (!record)
        return 12;
    record->magic = BSD_FIRMWARE_MAGIC;
    record->kind = description->kind;
    record->enabled = description->enabled;
    record->compatible_count = description->compatible_count;
    record->node = description->node;
    record->acpi_handle = description->acpi_handle;
    record->acpi_domain = -1;
    cursor = (char *)&record->compatible[
        description->compatible_count];
    if (description->hardware_id) {
        size_t length = bsd_strlen(description->hardware_id) + 1;

        record->hardware_id = cursor;
        bsd_memcpy(cursor, description->hardware_id, length);
        cursor += length;
    }
    for (size_t index = 0; index < description->compatible_count; ++index) {
        size_t length = bsd_strlen(description->compatible[index]) + 1;

        record->compatible[index] = cursor;
        bsd_memcpy(cursor, description->compatible[index], length);
        cursor += length;
    }
    bsd_device_set_firmware_metadata_owned(device, record);
    return 0;
}

int
bsd_firmware_is_bound(device_t device)
{
    return firmware_metadata_record(device) != 0;
}

int
bsd_firmware_set_acpi_handle(device_t device, void *handle)
{
    bsd_firmware_record_t *record = firmware_metadata_record(device);

    if (!record || record->kind != BSD_FIRMWARE_ACPI || !handle)
        return BSD_FIRMWARE_EINVAL;
    record->acpi_handle = handle;
    return 0;
}

bsd_firmware_kind_t
bsd_firmware_get_kind(device_t device)
{
    bsd_firmware_record_t *record = firmware_metadata_record(device);

    return record ? record->kind : BSD_FIRMWARE_NONE;
}

int
bsd_firmware_status_okay(device_t device)
{
    bsd_firmware_record_t *record = firmware_metadata_record(device);

    return record && record->enabled;
}

int
bsd_firmware_acpi_match(device_t device, const char *hardware_id)
{
    bsd_firmware_record_t *record = firmware_metadata_record(device);

    if (!record || record->kind != BSD_FIRMWARE_ACPI ||
        !firmware_string_valid(hardware_id))
        return 0;
    if (record->hardware_id &&
        bsd_strcasecmp(record->hardware_id, hardware_id) == 0)
        return 1;
    for (size_t index = 0; index < record->compatible_count; ++index) {
        if (bsd_strcasecmp(record->compatible[index], hardware_id) == 0)
            return 1;
    }
    return 0;
}

void *
bsd_firmware_acpi_handle(device_t device)
{
    bsd_firmware_record_t *record = firmware_metadata_record(device);

    return record && record->kind == BSD_FIRMWARE_ACPI ?
        record->acpi_handle : 0;
}

uint32_t
bsd_firmware_acpi_get_flags(device_t device)
{
    bsd_firmware_record_t *record = firmware_metadata_record(device);

    if (!record || record->kind != BSD_FIRMWARE_ACPI)
        return 0;
    return record->acpi_flags;
}

int
bsd_firmware_acpi_set_flags(device_t device, uint32_t flags)
{
    bsd_firmware_record_t *record = firmware_metadata_record(device);

    if (!record || record->kind != BSD_FIRMWARE_ACPI)
        return BSD_FIRMWARE_EINVAL;
    record->acpi_flags = flags;
    return 0;
}

int
bsd_firmware_acpi_get_domain(device_t device)
{
    bsd_firmware_record_t *record = firmware_metadata_record(device);

    if (!record || record->kind != BSD_FIRMWARE_ACPI)
        return -1;
    return record->acpi_domain;
}

int
bsd_firmware_acpi_set_domain(device_t device, int domain)
{
    bsd_firmware_record_t *record = firmware_metadata_record(device);

    if (!record || record->kind != BSD_FIRMWARE_ACPI ||
        (domain != -1 && domain != 0))
        return BSD_FIRMWARE_EINVAL;
    record->acpi_domain = domain;
    return 0;
}

void *
bsd_firmware_acpi_get_private(device_t device)
{
    bsd_firmware_record_t *record = firmware_metadata_record(device);

    if (!record || record->kind != BSD_FIRMWARE_ACPI)
        return 0;
    return record->acpi_private;
}

int
bsd_firmware_acpi_set_private(device_t device, void *private_data)
{
    bsd_firmware_record_t *record = firmware_metadata_record(device);

    if (!record || record->kind != BSD_FIRMWARE_ACPI)
        return BSD_FIRMWARE_EINVAL;
    record->acpi_private = private_data;
    return 0;
}

int
bsd_firmware_fdt_match(device_t device, const char *compatible)
{
    bsd_firmware_record_t *record = firmware_metadata_record(device);

    if (!record || record->kind != BSD_FIRMWARE_FDT ||
        !firmware_string_valid(compatible))
        return 0;
    for (size_t index = 0; index < record->compatible_count; ++index) {
        if (bsd_strcmp(record->compatible[index], compatible) == 0)
            return 1;
    }
    return 0;
}

phandle_t
bsd_firmware_fdt_node(device_t device)
{
    bsd_firmware_record_t *record = firmware_metadata_record(device);

    return record && record->kind == BSD_FIRMWARE_FDT ?
        record->node : (phandle_t)-1;
}

const char *
bsd_firmware_fdt_first_compatible(device_t device)
{
    bsd_firmware_record_t *record = firmware_metadata_record(device);

    return record && record->kind == BSD_FIRMWARE_FDT &&
        record->compatible_count != 0 ? record->compatible[0] : 0;
}

ACPI_HANDLE
acpi_get_handle(device_t device)
{
    ACPI_HANDLE handle;

    if (!device)
        return 0;
    if (bsd_firmware_get_kind(device) != BSD_FIRMWARE_ACPI)
        return 0;
    handle = (ACPI_HANDLE)bsd_firmware_acpi_handle(device);
#ifdef CONFIG_BSD_DRIVER_ACPICA
    return handle;
#else
    return handle ? handle : (ACPI_HANDLE)device;
#endif
}

void
acpi_set_handle(device_t device, ACPI_HANDLE handle)
{
    if (!device || !handle)
        return;
#ifdef CONFIG_BSD_DRIVER_ACPICA
    if (bsd_firmware_set_acpi_handle(device, handle) != 0)
        (void)bsd_acpica_bind_device_handle(device, handle);
#else
    (void)bsd_firmware_set_acpi_handle(device, handle);
#endif
}

device_t
acpi_get_device(ACPI_HANDLE handle)
{
#ifdef CONFIG_BSD_DRIVER_ACPICA
    return (device_t)bsd_acpica_device_for_handle(handle);
#else
    return handle &&
        bsd_firmware_get_kind((device_t)handle) == BSD_FIRMWARE_ACPI ?
        (device_t)handle : 0;
#endif
}

int
acpi_MatchHid(ACPI_HANDLE handle, const char *hardware_id)
{
#ifdef CONFIG_BSD_DRIVER_ACPICA
    int matched = bsd_acpica_handle_match(handle, hardware_id);

    return matched > 0;
#else
    return bsd_firmware_acpi_match((device_t)handle, hardware_id);
#endif
}

int
acpi_disabled(const char *name)
{
#ifdef BSD_BRIDGE_HOST_TEST
    (void)name;
    return 0;
#else
    char key[96];
    char *value;
    int disabled;

    if (!name || !*name)
        return 0;
    bsd_snprintf(key, sizeof(key), "debug.acpi.%s.disabled", name);
    value = kern_getenv(key);
    if (!value)
        return 0;
    disabled = bsd_strcmp(value, "1") == 0 ||
        bsd_strcasecmp(value, "yes") == 0 ||
        bsd_strcasecmp(value, "true") == 0;
    freeenv(value);
    return disabled;
#endif
}

int
bsd_acpi_id_probe(device_t bus, device_t device, char **identifiers,
    char **match)
{
    ACPI_HANDLE handle;

    (void)bus;
    if (match)
        *match = 0;
    if (!device || !identifiers)
        return 6;
    for (size_t index = 0; identifiers[index]; ++index) {
        if (!bsd_firmware_acpi_match(device, identifiers[index]))
            continue;
        if (match)
            *match = identifiers[index];
        return BUS_PROBE_DEFAULT;
    }
    handle = acpi_get_handle(device);
    if (!handle)
        handle = acpi_get_handle(device_get_parent(device));
    if (!handle)
        return 6;
    for (size_t index = 0; identifiers[index]; ++index) {
        if (!acpi_MatchHid(handle, identifiers[index]))
            continue;
        if (match)
            *match = identifiers[index];
        return BUS_PROBE_DEFAULT;
    }
    return 6;
}

int
ofw_bus_status_okay(device_t device)
{
    return bsd_firmware_get_kind(device) == BSD_FIRMWARE_FDT &&
        bsd_firmware_status_okay(device);
}

int
ofw_bus_is_compatible(device_t device, const char *compatible)
{
    return bsd_firmware_fdt_match(device, compatible);
}

phandle_t
ofw_bus_get_node(device_t device)
{
    return bsd_firmware_fdt_node(device);
}
