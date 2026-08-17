/* SPDX-License-Identifier: MPL-2.0 */
/* Shared static module and startup lifecycle for imported BSD drivers. */

#include <stddef.h>
#include <stdint.h>

#ifdef BSD_BRIDGE_HOST_TEST
#include <stdio.h>
#else
void printf(const char *format, ...);
#endif

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/linker.h"
#include "compat/freebsd/edgeos/module.h"
#include "compat/freebsd/edgeos/package.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/kernel.h"
#include "compat/freebsd/sys/module.h"
#include "compat/freebsd/sys/pmckern.h"

#define BSD_MODULE_ENOENT 2
#define BSD_MODULE_ENXIO 6
#define BSD_MODULE_ENOMEM 12
#define BSD_MODULE_EBUSY 16
#define BSD_MODULE_EEXIST 17
#define BSD_MODULE_EINVAL 22
#define BSD_MODULE_EALREADY 37
#define BSD_MODULE_EOPNOTSUPP 45
#define BSD_MODULE_EDEADLK 11

#define BSD_HOST_STATIC_RECORD_LIMIT 4096

struct module {
    struct module *next;
    const moduledata_t *data;
    struct linker_file *container;
    modspecific_t specific;
    uint64_t load_sequence;
    int id;
    unsigned int refs;
    int loaded;
    int loading;
    int unloading;
    int has_specific;
};

struct bsd_builtin_module {
    struct bsd_builtin_module *next;
    char *name;
    int version;
};

struct linker_file {
    struct linker_file *next;
    bsd_linker_image_t *image;
    bsd_linker_record_set_t records;
    char *name;
    uint64_t load_sequence;
};

static volatile unsigned int g_module_guard;
static volatile unsigned int g_linker_guard;
static struct module *g_modules;
static struct bsd_builtin_module *g_builtin_modules;
static struct linker_file *g_linker_files;
static uint64_t g_load_sequence;
static uint64_t g_linker_file_sequence;
static int g_next_module_id = 1;
static int g_module_error;
static volatile int g_sysinit_state;
static enum sysinit_sub_id g_sysinit_resume_subsystem;
static volatile int g_sysuninit_state;

#ifndef BSD_BRIDGE_HOST_TEST
#if defined(_WIN32) || defined(EDGEOS_BSD_COFF_TARGET)
extern unsigned char __ImageBase[];
#define BSD_KERNEL_IMAGE_BASE __ImageBase
#else
extern unsigned char _kernel_start[];
#define BSD_KERNEL_IMAGE_BASE _kernel_start
#endif
#endif

#ifdef BSD_BRIDGE_HOST_TEST
static const void *g_host_sysinit[BSD_HOST_STATIC_RECORD_LIMIT];
static const void *g_host_sysuninit[BSD_HOST_STATIC_RECORD_LIMIT];
static const void *g_host_module_metadata[BSD_HOST_STATIC_RECORD_LIMIT];
static size_t g_host_sysinit_count;
static size_t g_host_sysuninit_count;
static size_t g_host_module_metadata_count;
static int g_host_static_overflow;
#elif defined(_WIN32) || defined(EDGEOS_BSD_COFF_TARGET)
static const void *const g_bsd_sysinit_begin
    __attribute__((used, section(".bsdsi$a"))) BSD_BRIDGE_RETAIN;
static const void *const g_bsd_sysinit_end
    __attribute__((used, section(".bsdsi$z"))) BSD_BRIDGE_RETAIN;
static const void *const g_bsd_sysuninit_begin
    __attribute__((used, section(".bsdsu$a"))) BSD_BRIDGE_RETAIN;
static const void *const g_bsd_sysuninit_end
    __attribute__((used, section(".bsdsu$z"))) BSD_BRIDGE_RETAIN;
static const void *const g_bsd_module_metadata_begin
    __attribute__((used, section(".bsdmm$a"))) BSD_BRIDGE_RETAIN;
static const void *const g_bsd_module_metadata_end
    __attribute__((used, section(".bsdmm$z"))) BSD_BRIDGE_RETAIN;
#else
extern const void *__start_bsd_sysinit[] __attribute__((weak));
extern const void *__stop_bsd_sysinit[] __attribute__((weak));
extern const void *__start_bsd_sysuninit[] __attribute__((weak));
extern const void *__stop_bsd_sysuninit[] __attribute__((weak));
extern const void *__start_bsd_module_metadata[] __attribute__((weak));
extern const void *__stop_bsd_module_metadata[] __attribute__((weak));
#endif

static void
module_guard_lock(void)
{
    while (__atomic_test_and_set(&g_module_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
module_guard_unlock(void)
{
    __atomic_clear(&g_module_guard, __ATOMIC_RELEASE);
}

static void
linker_guard_lock(void)
{
    while (__atomic_test_and_set(&g_linker_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
linker_guard_unlock(void)
{
    __atomic_clear(&g_linker_guard, __ATOMIC_RELEASE);
}

void
bsd_module_lock(void)
{
    module_guard_lock();
}

void
bsd_module_unlock(void)
{
    module_guard_unlock();
}

void
bsd_module_lock_assert(void)
{
    if (__atomic_load_n(&g_module_guard, __ATOMIC_RELAXED) == 0)
        bsd_bridge_panic_stop();
}

void
bsd_static_record_register(enum bsd_static_record_kind kind,
    const void *record)
{
#ifdef BSD_BRIDGE_HOST_TEST
    const void **records;
    size_t *count;

    if (!record)
        return;
    if (kind == BSD_STATIC_SYSINIT) {
        records = g_host_sysinit;
        count = &g_host_sysinit_count;
    } else if (kind == BSD_STATIC_SYSUNINIT) {
        records = g_host_sysuninit;
        count = &g_host_sysuninit_count;
    } else if (kind == BSD_STATIC_MODULE_METADATA) {
        records = g_host_module_metadata;
        count = &g_host_module_metadata_count;
    } else {
        g_host_static_overflow = 1;
        return;
    }
    if (*count >= BSD_HOST_STATIC_RECORD_LIMIT) {
        g_host_static_overflow = 1;
        return;
    }
    records[(*count)++] = record;
#else
    (void)kind;
    (void)record;
#endif
}

static void
static_record_range(enum bsd_static_record_kind kind,
    const void *const **begin, const void *const **end)
{
#ifdef BSD_BRIDGE_HOST_TEST
    if (kind == BSD_STATIC_SYSINIT) {
        *begin = g_host_sysinit;
        *end = g_host_sysinit + g_host_sysinit_count;
    } else if (kind == BSD_STATIC_SYSUNINIT) {
        *begin = g_host_sysuninit;
        *end = g_host_sysuninit + g_host_sysuninit_count;
    } else {
        *begin = g_host_module_metadata;
        *end = g_host_module_metadata + g_host_module_metadata_count;
    }
#elif defined(_WIN32) || defined(EDGEOS_BSD_COFF_TARGET)
    if (kind == BSD_STATIC_SYSINIT) {
        *begin = &g_bsd_sysinit_begin + 1;
        *end = &g_bsd_sysinit_end;
    } else if (kind == BSD_STATIC_SYSUNINIT) {
        *begin = &g_bsd_sysuninit_begin + 1;
        *end = &g_bsd_sysuninit_end;
    } else {
        *begin = &g_bsd_module_metadata_begin + 1;
        *end = &g_bsd_module_metadata_end;
    }
#else
    if (kind == BSD_STATIC_SYSINIT) {
        *begin = __start_bsd_sysinit;
        *end = __stop_bsd_sysinit;
    } else if (kind == BSD_STATIC_SYSUNINIT) {
        *begin = __start_bsd_sysuninit;
        *end = __stop_bsd_sysuninit;
    } else {
        *begin = __start_bsd_module_metadata;
        *end = __stop_bsd_module_metadata;
    }
    if (!*begin || !*end)
        *begin = *end = 0;
#endif
}

struct module_record_iterator {
    const void *const *cursor;
    const void *const *end;
    struct linker_file *file;
    enum bsd_static_record_kind kind;
    int static_complete;
};

static void
module_record_iterator_initialize(struct module_record_iterator *iterator,
    enum bsd_static_record_kind kind)
{
    bsd_memset(iterator, 0, sizeof(*iterator));
    iterator->kind = kind;
    static_record_range(kind, &iterator->cursor, &iterator->end);
}

static const void *
module_record_iterator_next(struct module_record_iterator *iterator)
{
    for (;;) {
        if (iterator->cursor && iterator->cursor < iterator->end) {
            const void *record = *iterator->cursor++;

            if (record)
                return record;
            continue;
        }
        if (!iterator->static_complete) {
            iterator->static_complete = 1;
            iterator->file = g_linker_files;
        } else if (iterator->file) {
            iterator->file = iterator->file->next;
        } else {
            return 0;
        }
        if (!iterator->file)
            continue;
        if (iterator->kind == BSD_STATIC_SYSINIT) {
            iterator->cursor = iterator->file->records.sysinit_begin;
            iterator->end = iterator->file->records.sysinit_end;
        } else if (iterator->kind == BSD_STATIC_SYSUNINIT) {
            iterator->cursor = iterator->file->records.sysuninit_begin;
            iterator->end = iterator->file->records.sysuninit_end;
        } else {
            iterator->cursor = iterator->file->records.metadata_begin;
            iterator->end = iterator->file->records.metadata_end;
        }
    }
}

static struct linker_file *
module_record_container(const void *record)
{
    for (struct linker_file *file = g_linker_files; file;
        file = file->next) {
        for (const void *const *cursor = file->records.metadata_begin;
            cursor && cursor < file->records.metadata_end; ++cursor) {
            if (*cursor == record)
                return file;
        }
    }
    return 0;
}

static int
string_equal(const char *left, const char *right)
{
    return left && right && bsd_strcmp(left, right) == 0;
}

static const char *
module_basename(const char *name)
{
    const char *base = name;

    if (!name)
        return 0;
    for (; *name; ++name) {
        if (*name == '/')
            base = name + 1;
    }
    return base;
}

static const moduledata_t *
record_module_data(const struct bsd_module_static_record *record)
{
    if (!record || record->kind != BSD_MODULE_DECLARATION)
        return 0;
    return (const moduledata_t *)record->data;
}

static int
record_owner_matches_module(const struct bsd_module_static_record *record,
    const struct bsd_module_static_record *declaration,
    const moduledata_t *data)
{
    if (!record || !data)
        return 0;
    if (declaration && string_equal(record->owner, declaration->owner))
        return 1;
    if (string_equal(record->owner, data->name))
        return 1;
    return string_equal(record->owner, module_basename(data->name));
}

static const struct bsd_module_static_record *
find_declaration_by_data(const moduledata_t *data)
{
    struct module_record_iterator iterator;
    const struct bsd_module_static_record *record;

    module_record_iterator_initialize(&iterator,
        BSD_STATIC_MODULE_METADATA);
    while ((record = module_record_iterator_next(&iterator)) != 0) {
        if (record && record->kind == BSD_MODULE_DECLARATION &&
            record->data == data)
            return record;
    }
    return 0;
}

static const struct bsd_module_static_record *
find_declaration_for_provider(const char *name)
{
    struct module_record_iterator iterator;
    const struct bsd_module_static_record *record;
    const struct bsd_module_static_record *suffix_match = 0;

    module_record_iterator_initialize(&iterator,
        BSD_STATIC_MODULE_METADATA);
    while ((record = module_record_iterator_next(&iterator)) != 0) {
        const moduledata_t *data = record_module_data(record);

        if (!data)
            continue;
        if (string_equal(data->name, name) || string_equal(record->owner, name))
            return record;
        if (!suffix_match &&
            string_equal(module_basename(data->name), name))
            suffix_match = record;
    }
    return suffix_match;
}

static struct module *
module_lookup_name_unlocked(const char *name)
{
    struct module *module;

    for (module = g_modules; module; module = module->next) {
        if (string_equal(module->data->name, name))
            return module;
    }
    return 0;
}

static struct module *
module_lookup_id_unlocked(int id)
{
    struct module *module;

    for (module = g_modules; module; module = module->next) {
        if (module->id == id)
            return module;
    }
    return 0;
}

static char *
module_string_duplicate(const char *name)
{
    size_t length;
    char *copy;

    if (!name)
        return 0;
    length = bsd_strlen(name) + 1;
    copy = bsd_malloc(length, M_DEVBUF, M_WAITOK);
    if (copy)
        bsd_memcpy(copy, name, length);
    return copy;
}

int
bsd_module_provide(const char *name, int version)
{
    struct bsd_builtin_module *provider;
    struct bsd_builtin_module *candidate;

    if (!name || !name[0] || version < 0)
        return BSD_MODULE_EINVAL;
    module_guard_lock();
    for (provider = g_builtin_modules; provider; provider = provider->next) {
        if (string_equal(provider->name, name)) {
            int result = provider->version == version ?
                0 : BSD_MODULE_EEXIST;

            module_guard_unlock();
            return result;
        }
    }
    module_guard_unlock();

    candidate = bsd_malloc(sizeof(*candidate), M_DEVBUF,
        M_WAITOK | M_ZERO);
    if (!candidate)
        return BSD_MODULE_ENOMEM;
    candidate->name = module_string_duplicate(name);
    if (!candidate->name) {
        bsd_free(candidate, M_DEVBUF);
        return BSD_MODULE_ENOMEM;
    }
    candidate->version = version;

    module_guard_lock();
    for (provider = g_builtin_modules; provider; provider = provider->next) {
        if (string_equal(provider->name, name))
            break;
    }
    if (!provider) {
        candidate->next = g_builtin_modules;
        g_builtin_modules = candidate;
        candidate = 0;
    }
    module_guard_unlock();
    if (candidate) {
        int result = provider->version == version ?
            0 : BSD_MODULE_EEXIST;

        bsd_free(candidate->name, M_DEVBUF);
        bsd_free(candidate, M_DEVBUF);
        return result;
    }
    return 0;
}

static int
module_provider_version(const char *name, int *version)
{
    struct module_record_iterator iterator;
    const struct bsd_module_static_record *record;
    struct bsd_builtin_module *provider;
    int found = 0;
    int found_version = 0;

    if (string_equal(name, "kernel")) {
        *version = __FreeBSD_version;
        return 0;
    }

    module_guard_lock();
    for (provider = g_builtin_modules; provider; provider = provider->next) {
        if (string_equal(provider->name, name)) {
            *version = provider->version;
            module_guard_unlock();
            return 0;
        }
    }
    module_guard_unlock();

    module_record_iterator_initialize(&iterator,
        BSD_STATIC_MODULE_METADATA);
    while ((record = module_record_iterator_next(&iterator)) != 0) {
        if (!record || record->kind != BSD_MODULE_VERSION ||
            !string_equal(record->name, name))
            continue;
        if (found && found_version != record->preferred)
            return BSD_MODULE_EEXIST;
        found = 1;
        found_version = record->preferred;
    }
    if (found) {
        *version = found_version;
        return 0;
    }
    if (find_declaration_for_provider(name)) {
        *version = 1;
        return 0;
    }
    return BSD_MODULE_ENOENT;
}

int
bsd_module_validate_dependencies(void)
{
    struct module_record_iterator iterator;
    const struct bsd_module_static_record *record;
    int first_error = 0;

#ifdef BSD_BRIDGE_HOST_TEST
    if (g_host_static_overflow)
        return BSD_MODULE_ENOMEM;
#endif
    module_record_iterator_initialize(&iterator,
        BSD_STATIC_MODULE_METADATA);
    while ((record = module_record_iterator_next(&iterator)) != 0) {
        int version;
        int error;

        if (!record || record->kind != BSD_MODULE_DEPENDENCY)
            continue;
        error = module_provider_version(record->name, &version);
        if (error) {
            printf("[bsd-bridge] missing module dependency %s: %d\n",
                record->name ? record->name : "(unnamed)", error);
            if (!first_error)
                first_error = error;
            continue;
        }
        if (version < record->minimum || version > record->maximum) {
            printf("[bsd-bridge] unsupported module dependency %s version "
                "%d (required %d..%d)\n",
                record->name ? record->name : "(unnamed)", version,
                record->minimum, record->maximum);
            if (!first_error)
                first_error = BSD_MODULE_EOPNOTSUPP;
        }
    }
    return first_error;
}

int
module_register(const moduledata_t *data, struct linker_file *container)
{
    struct module *module;

    if (!data || !data->name || !data->name[0])
        return BSD_MODULE_EINVAL;
    module = bsd_malloc(sizeof(*module), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!module)
        return BSD_MODULE_ENOMEM;
    module->data = data;
    module->container = container;
    module->refs = 1;

    module_guard_lock();
    if (module_lookup_name_unlocked(data->name)) {
        module_guard_unlock();
        bsd_free(module, M_DEVBUF);
        return BSD_MODULE_EEXIST;
    }
    module->id = g_next_module_id++;
    module->next = g_modules;
    g_modules = module;
    module_guard_unlock();
    return 0;
}

module_t
module_lookupbyname(const char *name)
{
    module_t module;

    if (!name)
        return 0;
    module_guard_lock();
    module = module_lookup_name_unlocked(name);
    module_guard_unlock();
    return module;
}

module_t
module_lookupbyid(int id)
{
    module_t module;

    module_guard_lock();
    module = module_lookup_id_unlocked(id);
    module_guard_unlock();
    return module;
}

static int module_load_declaration(
    const struct bsd_module_static_record *declaration);
static int module_unload_after(uint64_t minimum_sequence);

static int
module_load_dependencies(module_t module,
    const struct bsd_module_static_record *declaration)
{
    struct module_record_iterator iterator;
    const struct bsd_module_static_record *record;

    module_record_iterator_initialize(&iterator,
        BSD_STATIC_MODULE_METADATA);
    while ((record = module_record_iterator_next(&iterator)) != 0) {
        const struct bsd_module_static_record *dependency_declaration;
        int version;
        int error;

        if (!record || record->kind != BSD_MODULE_DEPENDENCY ||
            !record_owner_matches_module(record, declaration, module->data))
            continue;
        error = module_provider_version(record->name, &version);
        if (error)
            return error;
        if (version < record->minimum || version > record->maximum)
            return BSD_MODULE_EOPNOTSUPP;
        dependency_declaration =
            find_declaration_for_provider(record->name);
        if (dependency_declaration &&
            dependency_declaration != declaration) {
            error = module_load_declaration(dependency_declaration);
            if (error)
                return error;
        }
    }
    return 0;
}

static int
module_load_registered(module_t module,
    const struct bsd_module_static_record *declaration)
{
    uint64_t dependency_sequence;
    int load_invoked = 0;
    int error;

    module_guard_lock();
    if (module->loading) {
        module_guard_unlock();
        return BSD_MODULE_EDEADLK;
    }
    if (module->unloading) {
        module_guard_unlock();
        return BSD_MODULE_EBUSY;
    }
    if (module->loaded) {
        module_guard_unlock();
        return 0;
    }
    module->loading = 1;
    dependency_sequence = g_load_sequence;
    module_guard_unlock();

    error = module_load_dependencies(module, declaration);
    if (!error && module->data->evhand) {
        load_invoked = 1;
        error = module->data->evhand(module, MOD_LOAD, module->data->priv);
    }
    if (error && load_invoked)
        (void)module->data->evhand(module, MOD_UNLOAD, module->data->priv);

    module_guard_lock();
    module->loading = 0;
    if (!error) {
        module->loaded = 1;
        module->load_sequence = ++g_load_sequence;
    }
    module_guard_unlock();
    if (error)
        (void)module_unload_after(dependency_sequence);
    return error;
}

static int
module_load_declaration(const struct bsd_module_static_record *declaration)
{
    const moduledata_t *data = record_module_data(declaration);
    module_t module;
    int error;

    if (!data)
        return BSD_MODULE_EINVAL;
    module = module_lookupbyname(data->name);
    if (!module) {
        error = module_register(data,
            module_record_container(declaration));
        if (error && error != BSD_MODULE_EEXIST)
            return error;
        module = module_lookupbyname(data->name);
    }
    if (!module)
        return BSD_MODULE_ENOMEM;
    return module_load_registered(module, declaration);
}

void
module_register_init(const void *argument)
{
    const moduledata_t *data = argument;
    const struct bsd_module_static_record *declaration;
    int error;

    declaration = find_declaration_by_data(data);
    if (!declaration)
        error = BSD_MODULE_ENOENT;
    else
        error = module_load_declaration(declaration);
    if (error == BSD_MODULE_ENXIO) {
        printf("[bsd-bridge] module %s unavailable on this platform\n",
            data && data->name ? data->name : "(unnamed)");
    } else if (error) {
        g_module_error = error;
        printf("[bsd-bridge] module %s failed to load: %d\n",
            data && data->name ? data->name : "(unnamed)", error);
    }
}

static int
module_has_loaded_dependents(module_t target)
{
    module_t candidate;

    module_guard_lock();
    for (candidate = g_modules; candidate; candidate = candidate->next) {
        const struct bsd_module_static_record *declaration;
        struct module_record_iterator iterator;
        const struct bsd_module_static_record *record;

        if (!candidate->loaded || candidate == target)
            continue;
        declaration = find_declaration_by_data(candidate->data);
        module_record_iterator_initialize(&iterator,
            BSD_STATIC_MODULE_METADATA);
        while ((record = module_record_iterator_next(&iterator)) != 0) {
            if (record && record->kind == BSD_MODULE_DEPENDENCY &&
                record_owner_matches_module(record, declaration,
                    candidate->data) &&
                (string_equal(record->name, target->data->name) ||
                 string_equal(record->name,
                    module_basename(target->data->name)))) {
                module_guard_unlock();
                return 1;
            }
        }
    }
    module_guard_unlock();
    return 0;
}

int
module_quiesce(module_t module)
{
    int error;

    if (!module)
        return BSD_MODULE_EINVAL;
    module_guard_lock();
    if (!module->loaded) {
        module_guard_unlock();
        return 0;
    }
    if (module->loading) {
        module_guard_unlock();
        return BSD_MODULE_EBUSY;
    }
    module_guard_unlock();
    if (!module->data->evhand)
        return 0;
    error = module->data->evhand(module, MOD_QUIESCE,
        module->data->priv);
    if (error == BSD_MODULE_EOPNOTSUPP || error == BSD_MODULE_EINVAL)
        return 0;
    return error;
}

int
module_unload(module_t module)
{
    int error;

    if (!module)
        return BSD_MODULE_EINVAL;
    module_guard_lock();
    if (!module->loaded) {
        module_guard_unlock();
        return 0;
    }
    if (module->refs > 1 || module->loading || module->unloading) {
        module_guard_unlock();
        return BSD_MODULE_EBUSY;
    }
    module->unloading = 1;
    module_guard_unlock();
    if (module_has_loaded_dependents(module)) {
        module_guard_lock();
        module->unloading = 0;
        module_guard_unlock();
        return BSD_MODULE_EBUSY;
    }

    error = module_quiesce(module);
    if (error) {
        module_guard_lock();
        module->unloading = 0;
        module_guard_unlock();
        return error;
    }

    error = module->data->evhand ?
        module->data->evhand(module, MOD_UNLOAD, module->data->priv) : 0;
    module_guard_lock();
    module->unloading = 0;
    if (!error) {
        module->loaded = 0;
        module->load_sequence = 0;
    }
    module_guard_unlock();
    return error;
}

void
module_reference(module_t module)
{
    if (!module)
        return;
    module_guard_lock();
    module->refs++;
    module_guard_unlock();
}

void
module_release(module_t module)
{
    struct module **cursor;
    int release = 0;

    if (!module)
        return;
    module_guard_lock();
    if (module->refs)
        module->refs--;
    if (module->refs == 0 && !module->loaded &&
        !module->loading && !module->unloading) {
        for (cursor = &g_modules; *cursor; cursor = &(*cursor)->next) {
            if (*cursor == module) {
                *cursor = module->next;
                release = 1;
                break;
            }
        }
    }
    module_guard_unlock();
    if (release)
        bsd_free(module, M_DEVBUF);
}

int
module_getid(module_t module)
{
    return module ? module->id : 0;
}

module_t
module_getfnext(module_t module)
{
    return module ? module->next : 0;
}

const char *
module_getname(module_t module)
{
    return module && module->data ? module->data->name : 0;
}

void
module_setspecific(module_t module, modspecific_t *data)
{
    if (!module || !data)
        return;
    module_guard_lock();
    module->specific = *data;
    module->has_specific = 1;
    module_guard_unlock();
}

struct linker_file *
module_file(module_t module)
{
    return module ? module->container : 0;
}

int
modevent_nop(module_t module, int event, void *argument)
{
    (void)module;
    (void)event;
    (void)argument;
    return 0;
}

static int
module_unload_after(uint64_t minimum_sequence)
{
    int first_error = 0;

    for (;;) {
        module_t selected = 0;
        uint64_t selected_sequence = 0;
        int error;

        module_guard_lock();
        for (module_t module = g_modules; module; module = module->next) {
            if (module->loaded &&
                module->load_sequence > minimum_sequence &&
                module->load_sequence > selected_sequence) {
                selected = module;
                selected_sequence = module->load_sequence;
            }
        }
        module_guard_unlock();
        if (!selected)
            break;
        error = module_unload(selected);
        if (error) {
            if (!first_error)
                first_error = error;
            module_guard_lock();
            selected->load_sequence = minimum_sequence;
            module_guard_unlock();
        }
    }
    return first_error;
}

static int
module_unload_all(void)
{
    return module_unload_after(0);
}

static int
sysinit_tuple_before(const struct sysinit *left, size_t left_index,
    const struct sysinit *right, size_t right_index, int reverse)
{
    if (left->subsystem != right->subsystem)
        return reverse ? left->subsystem > right->subsystem :
            left->subsystem < right->subsystem;
    if (left->order != right->order)
        return reverse ? left->order > right->order :
            left->order < right->order;
    return reverse ? left_index > right_index : left_index < right_index;
}

static int
run_sysinit_range_bounded(const void *const *begin, const void *const *end,
    int reverse, enum sysinit_sub_id minimum_subsystem,
    enum sysinit_sub_id maximum_subsystem)
{
    size_t total;
    size_t completed = 0;
    size_t last_index = 0;
    const struct sysinit *last = 0;

    if (!begin || !end || end < begin)
        return 0;
    total = (size_t)(end - begin);
    while (completed < total) {
        const struct sysinit *selected = 0;
        size_t selected_index = 0;

        for (size_t index = 0; index < total; ++index) {
            const struct sysinit *record = begin[index];
            int after_last;

            if (!record || !record->func ||
                record->subsystem == SI_SUB_DUMMY ||
                record->subsystem < minimum_subsystem ||
                record->subsystem > maximum_subsystem)
                continue;
            if (!last) {
                after_last = 1;
            } else if (record->subsystem != last->subsystem) {
                after_last = reverse ?
                    record->subsystem < last->subsystem :
                    record->subsystem > last->subsystem;
            } else if (record->order != last->order) {
                after_last = reverse ?
                    record->order < last->order :
                    record->order > last->order;
            } else {
                after_last = reverse ?
                    index < last_index : index > last_index;
            }
            if (!after_last)
                continue;
            if (!selected || sysinit_tuple_before(record, index, selected,
                selected_index, reverse)) {
                selected = record;
                selected_index = index;
            }
        }
        if (!selected)
            break;
        selected->func(selected->udata);
        if (g_module_error)
            return g_module_error;
        last = selected;
        last_index = selected_index;
        completed++;
    }
    return 0;
}

static int
run_sysinit_range(const void *const *begin, const void *const *end,
    int reverse)
{
    return run_sysinit_range_bounded(begin, end, reverse,
        SI_SUB_DUMMY, SI_SUB_LAST);
}

static int
module_unload_file_modules(struct linker_file *file)
{
    for (;;) {
        module_t selected = 0;
        uint64_t selected_sequence = 0;
        int error;

        module_guard_lock();
        for (module_t module = g_modules; module; module = module->next) {
            if (module->container != file)
                continue;
            if (!selected || module->load_sequence > selected_sequence) {
                selected = module;
                selected_sequence = module->load_sequence;
            }
        }
        if (selected && selected->refs != 1) {
            module_guard_unlock();
            return BSD_MODULE_EBUSY;
        }
        module_guard_unlock();
        if (!selected)
            return 0;
        error = module_unload(selected);
        if (error)
            return error;
        module_release(selected);
    }
}

static int
linker_file_is_registered(struct linker_file *file)
{
    for (struct linker_file *candidate = g_linker_files; candidate;
        candidate = candidate->next) {
        if (candidate == file)
            return 1;
    }
    return 0;
}

static int
linker_file_name_exists(const char *name)
{
    for (struct linker_file *file = g_linker_files; file;
        file = file->next) {
        if (string_equal(file->name, name))
            return 1;
    }
    return 0;
}

static void
linker_file_remove(struct linker_file *file)
{
    struct linker_file **cursor;

    for (cursor = &g_linker_files; *cursor; cursor = &(*cursor)->next) {
        if (*cursor == file) {
            *cursor = file->next;
            file->next = 0;
            return;
        }
    }
}

static int
module_deactivate_file_locked(struct linker_file *file)
{
    int error;

    if (!file || !linker_file_is_registered(file))
        return BSD_MODULE_ENOENT;
    g_module_error = 0;
    error = run_sysinit_range(file->records.sysuninit_begin,
        file->records.sysuninit_end, 1);
    if (!error)
        error = module_unload_file_modules(file);
    if (error)
        return error;
    linker_file_remove(file);
    bsd_linker_release_image(file->image);
    bsd_free(file->name, M_DEVBUF);
    bsd_free(file, M_DEVBUF);
    return 0;
}

int
bsd_module_activate_image(bsd_linker_image_t *image, const char *name,
    struct linker_file **file_out)
{
    struct linker_file *file;
    int error;

    if (file_out)
        *file_out = 0;
    if (!image)
        return BSD_MODULE_EINVAL;
    if (!name || !name[0]) {
        bsd_linker_release_image(image);
        return BSD_MODULE_EINVAL;
    }
    if (!bsd_sysinit_is_complete()) {
        bsd_linker_release_image(image);
        return BSD_MODULE_EBUSY;
    }
    file = bsd_malloc(sizeof(*file), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!file) {
        bsd_linker_release_image(image);
        return BSD_MODULE_ENOMEM;
    }
    file->name = module_string_duplicate(name);
    if (!file->name) {
        bsd_free(file, M_DEVBUF);
        bsd_linker_release_image(image);
        return BSD_MODULE_ENOMEM;
    }
    if (bsd_linker_image_records(image, &file->records) != 0) {
        bsd_free(file->name, M_DEVBUF);
        bsd_free(file, M_DEVBUF);
        bsd_linker_release_image(image);
        return BSD_MODULE_EINVAL;
    }
    file->image = image;

    linker_guard_lock();
    if (linker_file_name_exists(name)) {
        linker_guard_unlock();
        bsd_free(file->name, M_DEVBUF);
        bsd_free(file, M_DEVBUF);
        bsd_linker_release_image(image);
        return BSD_MODULE_EEXIST;
    }
    file->load_sequence = ++g_linker_file_sequence;
    file->next = g_linker_files;
    g_linker_files = file;

    g_module_error = 0;
    error = bsd_module_validate_dependencies();
    if (!error) {
        error = run_sysinit_range(file->records.sysinit_begin,
            file->records.sysinit_end, 0);
    }
    if (error) {
        int unload_error = module_unload_file_modules(file);

        if (unload_error) {
            if (file_out)
                *file_out = file;
            linker_guard_unlock();
            return unload_error;
        }
        linker_file_remove(file);
        bsd_linker_release_image(file->image);
        bsd_free(file->name, M_DEVBUF);
        bsd_free(file, M_DEVBUF);
        linker_guard_unlock();
        return error;
    }
    if (file_out)
        *file_out = file;
    linker_guard_unlock();
    return 0;
}

int
bsd_module_deactivate_file(struct linker_file *file)
{
    int error;

    linker_guard_lock();
    error = module_deactivate_file_locked(file);
    linker_guard_unlock();
    return error;
}

void *
linker_hwpmc_list_objects(void)
{
    struct pmckern_map_in *objects;
    struct linker_file *file;
    size_t count = 1;
    size_t index = 0;

    linker_guard_lock();
    for (file = g_linker_files; file; file = file->next)
        ++count;
    objects = bsd_malloc((count + 1) * sizeof(*objects), M_LINKER,
        M_WAITOK | M_ZERO);
    if (!objects) {
        linker_guard_unlock();
        return 0;
    }
    objects[index].pm_file = (void *)(uintptr_t)"kernel";
#ifndef BSD_BRIDGE_HOST_TEST
    objects[index].pm_address = (uintptr_t)BSD_KERNEL_IMAGE_BASE;
#endif
    ++index;
    for (file = g_linker_files; file; file = file->next) {
        objects[index].pm_file = file->name;
        objects[index].pm_address =
            (uintptr_t)bsd_linker_image_base(file->image);
        ++index;
    }
    linker_guard_unlock();
    return objects;
}

size_t
bsd_module_linked_file_count(void)
{
    size_t count = 0;

    linker_guard_lock();
    for (struct linker_file *file = g_linker_files; file;
        file = file->next)
        count++;
    linker_guard_unlock();
    return count;
}

static int
module_deactivate_all_files(void)
{
    int error = 0;

    linker_guard_lock();
    while (g_linker_files) {
        error = module_deactivate_file_locked(g_linker_files);
        if (error)
            break;
    }
    linker_guard_unlock();
    return error;
}

static int
sysinit_fail(int error)
{
    g_module_error = error;
    (void)module_unload_all();
    bsd_driver_packages_fail(error);
    __atomic_store_n(&g_sysinit_state, 3, __ATOMIC_RELEASE);
    return error;
}

int
bsd_sysinit_run_through(int maximum_subsystem)
{
    const void *const *begin;
    const void *const *end;
    int expected = 0;
    int error;

    if (maximum_subsystem <= (int)SI_SUB_DUMMY ||
        maximum_subsystem >= (int)SI_SUB_LAST)
        return BSD_MODULE_EINVAL;
    if (!__atomic_compare_exchange_n(&g_sysinit_state, &expected, 1, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return BSD_MODULE_EALREADY;
    g_module_error = 0;
    error = bsd_driver_packages_prepare();
    if (!error)
        error = bsd_module_validate_dependencies();
    if (!error) {
        static_record_range(BSD_STATIC_SYSINIT, &begin, &end);
        error = run_sysinit_range_bounded(begin, end, 0,
            SI_SUB_DUMMY,
            (enum sysinit_sub_id)maximum_subsystem);
    }
    if (error)
        return sysinit_fail(error);
    g_sysinit_resume_subsystem =
        (enum sysinit_sub_id)(maximum_subsystem + 1);
    __atomic_store_n(&g_sysinit_state, 4, __ATOMIC_RELEASE);
    return 0;
}

int
bsd_sysinit_run_remaining(void)
{
    const void *const *begin;
    const void *const *end;
    int expected = 4;
    int error;

    if (__atomic_load_n(&g_sysinit_state, __ATOMIC_ACQUIRE) == 2)
        return 0;
    if (!__atomic_compare_exchange_n(&g_sysinit_state, &expected, 1, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return BSD_MODULE_EALREADY;
    g_module_error = 0;
    static_record_range(BSD_STATIC_SYSINIT, &begin, &end);
    error = run_sysinit_range_bounded(begin, end, 0,
        g_sysinit_resume_subsystem, SI_SUB_LAST);
    if (!error)
        error = bsd_driver_packages_activate();
    if (error)
        return sysinit_fail(error);
    __atomic_store_n(&g_sysinit_state, 2, __ATOMIC_RELEASE);
    return 0;
}

int
bsd_sysinit_run_all(void)
{
    const void *const *begin;
    const void *const *end;
    int expected = 0;
    int state;
    int error;

    state = __atomic_load_n(&g_sysinit_state, __ATOMIC_ACQUIRE);
    if (state == 2)
        return 0;
    if (state == 4)
        return bsd_sysinit_run_remaining();
    if (!__atomic_compare_exchange_n(&g_sysinit_state, &expected, 1, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return BSD_MODULE_EALREADY;
    g_module_error = 0;
    error = bsd_driver_packages_prepare();
    if (!error)
        error = bsd_module_validate_dependencies();
    if (!error) {
        static_record_range(BSD_STATIC_SYSINIT, &begin, &end);
        error = run_sysinit_range(begin, end, 0);
    }
    if (!error)
        error = bsd_driver_packages_activate();
    if (error)
        return sysinit_fail(error);
    __atomic_store_n(&g_sysinit_state, 2, __ATOMIC_RELEASE);
    return 0;
}

int
bsd_sysinit_is_complete(void)
{
    return __atomic_load_n(&g_sysinit_state, __ATOMIC_ACQUIRE) == 2;
}

int
bsd_sysuninit_run_all(void)
{
    const void *const *begin;
    const void *const *end;
    int expected = 0;
    int error;
    int unload_error;

    if (__atomic_load_n(&g_sysuninit_state, __ATOMIC_ACQUIRE) == 2)
        return 0;
    if (!__atomic_compare_exchange_n(&g_sysuninit_state, &expected, 1, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return BSD_MODULE_EALREADY;
    g_module_error = 0;
    error = module_deactivate_all_files();
    if (!error)
        error = bsd_driver_packages_begin_stop();
    static_record_range(BSD_STATIC_SYSUNINIT, &begin, &end);
    {
        int sysuninit_error = run_sysinit_range(begin, end, 1);

        if (!error)
            error = sysuninit_error;
    }
    unload_error = module_unload_all();
    if (!error)
        error = unload_error;
    if (!error)
        error = bsd_driver_packages_finish_stop();
    if (error) {
        g_module_error = error;
        bsd_driver_packages_fail(error);
    }
    __atomic_store_n(&g_sysuninit_state, error ? 3 : 2,
        __ATOMIC_RELEASE);
    return error;
}

void
sysinit_add(struct sysinit **set, struct sysinit **set_end)
{
    const void *const *begin = (const void *const *)set;
    const void *const *end = (const void *const *)set_end;
    int error;

    g_module_error = 0;
    error = run_sysinit_range(begin, end, 0);
    if (error)
        g_module_error = error;
}

int
bsd_module_last_error(void)
{
    return g_module_error;
}

size_t
bsd_module_pnp_count(void)
{
    struct module_record_iterator iterator;
    const struct bsd_module_static_record *record;
    size_t count = 0;

    module_record_iterator_initialize(&iterator,
        BSD_STATIC_MODULE_METADATA);
    while ((record = module_record_iterator_next(&iterator)) != 0) {
        if (record && record->kind == BSD_MODULE_PNP)
            count++;
    }
    return count;
}

const struct mod_pnp_match_info *
bsd_module_pnp_get(size_t index)
{
    struct module_record_iterator iterator;
    const struct bsd_module_static_record *record;

    module_record_iterator_initialize(&iterator,
        BSD_STATIC_MODULE_METADATA);
    while ((record = module_record_iterator_next(&iterator)) != 0) {
        if (!record || record->kind != BSD_MODULE_PNP)
            continue;
        if (index == 0)
            return record->data;
        index--;
    }
    return 0;
}
