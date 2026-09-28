/* SPDX-License-Identifier: MPL-2.0 */
/* Shared lifecycle state for source-built BSD driver packages. */

#include <stddef.h>

#include "compat/freebsd/edgeos/package.h"

#define BSD_PACKAGE_ENOENT 2
#define BSD_PACKAGE_EINVAL 22
#define BSD_PACKAGE_EALREADY 37

#if defined(BSD_BRIDGE_HOST_TEST) && \
    !defined(BSD_BRIDGE_PACKAGE_TEST_REGISTRY)
bsd_driver_package_record_t bsd_driver_package_registry[1];
const size_t bsd_driver_package_registry_count = 0;
#endif

static int
package_string_equal(const char *left, const char *right)
{
    if (!left || !right)
        return 0;
    while (*left && *left == *right) {
        left++;
        right++;
    }
    return *left == *right;
}

static int
package_identifier_valid(const char *value)
{
    const char *cursor;

    if (!value || !value[0])
        return 0;
    if (!((value[0] >= 'a' && value[0] <= 'z') ||
          (value[0] >= '0' && value[0] <= '9')))
        return 0;
    for (cursor = value; *cursor; ++cursor) {
        if ((*cursor >= 'a' && *cursor <= 'z') ||
            (*cursor >= '0' && *cursor <= '9') ||
            *cursor == '.' || *cursor == '_' || *cursor == '-')
            continue;
        return 0;
    }
    return 1;
}

static int
package_commit_valid(const char *value)
{
    size_t index;

    if (!value)
        return 0;
    for (index = 0; index < 40; ++index) {
        char character = value[index];

        if (!character ||
            !((character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'f')))
            return 0;
    }
    return value[40] == '\0';
}

static int
package_registry_validate(void)
{
    size_t index;

    for (index = 0; index < bsd_driver_package_registry_count; ++index) {
        const bsd_driver_package_record_t *record =
            &bsd_driver_package_registry[index];
        const bsd_driver_package_descriptor_t *descriptor =
            &record->descriptor;
        size_t enabled_modules = descriptor->builtin_module_count +
            descriptor->loadable_module_count;
        int state = __atomic_load_n(&record->state, __ATOMIC_ACQUIRE);

        if (!package_identifier_valid(descriptor->id) ||
            !package_identifier_valid(descriptor->provider) ||
            !package_commit_valid(descriptor->upstream_commit) ||
            descriptor->source_count == 0 ||
            enabled_modules < descriptor->builtin_module_count ||
            (enabled_modules == 0 &&
             descriptor->disabled_module_count == 0))
            return BSD_PACKAGE_EINVAL;
        if ((enabled_modules == 0 &&
             state != BSD_DRIVER_PACKAGE_DISABLED) ||
            (enabled_modules != 0 &&
             state != BSD_DRIVER_PACKAGE_REGISTERED))
            return BSD_PACKAGE_EINVAL;
        for (size_t previous = 0; previous < index; ++previous) {
            if (package_string_equal(descriptor->id,
                bsd_driver_package_registry[previous].descriptor.id))
                return BSD_PACKAGE_EINVAL;
        }
    }
    return 0;
}

static size_t
package_enabled_module_count(
    const bsd_driver_package_descriptor_t *descriptor)
{
    return descriptor->builtin_module_count +
        descriptor->loadable_module_count;
}

size_t
bsd_driver_package_count(void)
{
    return bsd_driver_package_registry_count;
}

int
bsd_driver_package_get(size_t index, bsd_driver_package_status_t *status)
{
    const bsd_driver_package_record_t *record;

    if (!status)
        return BSD_PACKAGE_EINVAL;
    if (index >= bsd_driver_package_registry_count)
        return BSD_PACKAGE_ENOENT;
    record = &bsd_driver_package_registry[index];
    status->descriptor = record->descriptor;
    status->state = (bsd_driver_package_state_t)__atomic_load_n(
        &record->state, __ATOMIC_ACQUIRE);
    status->error = __atomic_load_n(&record->error, __ATOMIC_ACQUIRE);
    return 0;
}

int
bsd_driver_package_find(const char *id,
    bsd_driver_package_status_t *status)
{
    size_t index;

    if (!id || !status)
        return BSD_PACKAGE_EINVAL;
    for (index = 0; index < bsd_driver_package_registry_count; ++index) {
        if (package_string_equal(id,
            bsd_driver_package_registry[index].descriptor.id))
            return bsd_driver_package_get(index, status);
    }
    return BSD_PACKAGE_ENOENT;
}

int
bsd_driver_packages_prepare(void)
{
    size_t index;
    int error;

    error = package_registry_validate();
    if (error)
        return error;
    for (index = 0; index < bsd_driver_package_registry_count; ++index) {
        bsd_driver_package_record_t *record =
            &bsd_driver_package_registry[index];

        if (package_enabled_module_count(&record->descriptor) == 0)
            continue;
        __atomic_store_n(&record->error, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&record->state, BSD_DRIVER_PACKAGE_STARTING,
            __ATOMIC_RELEASE);
    }
    return 0;
}

int
bsd_driver_packages_activate(void)
{
    size_t index;

    for (index = 0; index < bsd_driver_package_registry_count; ++index) {
        bsd_driver_package_record_t *record =
            &bsd_driver_package_registry[index];

        if (package_enabled_module_count(&record->descriptor) == 0)
            continue;
        if (__atomic_load_n(&record->state, __ATOMIC_ACQUIRE) !=
            BSD_DRIVER_PACKAGE_STARTING)
            return BSD_PACKAGE_EALREADY;
    }
    for (index = 0; index < bsd_driver_package_registry_count; ++index) {
        bsd_driver_package_record_t *record =
            &bsd_driver_package_registry[index];

        if (package_enabled_module_count(&record->descriptor) != 0)
            __atomic_store_n(&record->state, BSD_DRIVER_PACKAGE_ACTIVE,
                __ATOMIC_RELEASE);
    }
    return 0;
}

int
bsd_driver_packages_begin_stop(void)
{
    size_t index;

    for (index = 0; index < bsd_driver_package_registry_count; ++index) {
        const bsd_driver_package_record_t *record =
            &bsd_driver_package_registry[index];

        if (package_enabled_module_count(&record->descriptor) != 0 &&
            __atomic_load_n(&record->state, __ATOMIC_ACQUIRE) !=
            BSD_DRIVER_PACKAGE_ACTIVE)
            return BSD_PACKAGE_EALREADY;
    }
    for (index = 0; index < bsd_driver_package_registry_count; ++index) {
        bsd_driver_package_record_t *record =
            &bsd_driver_package_registry[index];

        if (package_enabled_module_count(&record->descriptor) != 0)
            __atomic_store_n(&record->state, BSD_DRIVER_PACKAGE_STOPPING,
                __ATOMIC_RELEASE);
    }
    return 0;
}

int
bsd_driver_packages_finish_stop(void)
{
    size_t index;

    for (index = 0; index < bsd_driver_package_registry_count; ++index) {
        const bsd_driver_package_record_t *record =
            &bsd_driver_package_registry[index];

        if (package_enabled_module_count(&record->descriptor) != 0 &&
            __atomic_load_n(&record->state, __ATOMIC_ACQUIRE) !=
            BSD_DRIVER_PACKAGE_STOPPING)
            return BSD_PACKAGE_EALREADY;
    }
    for (index = 0; index < bsd_driver_package_registry_count; ++index) {
        bsd_driver_package_record_t *record =
            &bsd_driver_package_registry[index];

        if (package_enabled_module_count(&record->descriptor) != 0)
            __atomic_store_n(&record->state, BSD_DRIVER_PACKAGE_STOPPED,
                __ATOMIC_RELEASE);
    }
    return 0;
}

void
bsd_driver_packages_fail(int error)
{
    size_t index;

    if (error <= 0)
        error = BSD_PACKAGE_EINVAL;
    for (index = 0; index < bsd_driver_package_registry_count; ++index) {
        bsd_driver_package_record_t *record =
            &bsd_driver_package_registry[index];

        if (package_enabled_module_count(&record->descriptor) == 0)
            continue;
        __atomic_store_n(&record->error, error, __ATOMIC_RELEASE);
        __atomic_store_n(&record->state, BSD_DRIVER_PACKAGE_FAILED,
            __ATOMIC_RELEASE);
    }
}
