/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 1997 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * EdgeOS source-compatible static module adapter.
 */

#ifndef _SYS_MODULE_H_
#define _SYS_MODULE_H_

#include "kernel.h"

#ifndef __FreeBSD_version
#define __FreeBSD_version BSD_BRIDGE_FREEBSD_VERSION
#endif

#define MDT_DEPEND 1
#define MDT_MODULE 2
#define MDT_VERSION 3
#define MDT_PNP_INFO 4
#define MDT_STRUCT_VERSION 1
#define MDT_SETNAME "modmetadata_set"

typedef enum modeventtype {
    MOD_LOAD,
    MOD_UNLOAD,
    MOD_SHUTDOWN,
    MOD_QUIESCE,
} modeventtype_t;

struct module;
struct linker_file;
typedef struct module *module_t;
typedef int (*modeventhand_t)(module_t, int, void *);

typedef struct moduledata {
    const char *name;
    modeventhand_t evhand;
    void *priv;
} moduledata_t;

typedef union modspecific {
    int intval;
    unsigned int uintval;
    long longval;
    unsigned long ulongval;
} modspecific_t;

struct mod_depend {
    int md_ver_minimum;
    int md_ver_preferred;
    int md_ver_maximum;
};

struct mod_version {
    int mv_version;
};

struct mod_metadata {
    int md_version;
    int md_type;
    const void *md_data;
    const char *md_cval;
};

struct mod_pnp_match_info {
    const char *descr;
    const char *bus;
    const void *table;
    int entry_len;
    int num_entry;
};

#define BSD_MODULE_RECORD(symbol, kind_value, owner_value, name_value,     \
    data_value, minimum_value, preferred_value, maximum_value, type_value) \
    static const struct bsd_module_static_record symbol = {                \
        (kind_value), (owner_value), (name_value), (data_value),           \
        (minimum_value), (preferred_value), (maximum_value), (type_value), \
    };                                                                     \
    BSD_BRIDGE_LINK_MODULE_RECORD(symbol)

#define MODULE_METADATA_CONCAT(uniquifier) _mod_metadata##uniquifier
#define MODULE_METADATA(uniquifier, type_value, data_value, cval_value)    \
    static const struct mod_metadata MODULE_METADATA_CONCAT(uniquifier) = { \
        MDT_STRUCT_VERSION, (type_value), (data_value), (cval_value),      \
    };                                                                     \
    BSD_MODULE_RECORD(_bsd_generic_metadata##uniquifier,                   \
        BSD_MODULE_GENERIC_METADATA, #uniquifier, (cval_value),            \
        &MODULE_METADATA_CONCAT(uniquifier), 0, 0, 0, (type_value))

#define MODULE_DEPEND_CONCAT(module_name, dependency_name)                \
    _##module_name##_depend_on_##dependency_name
#define MODULE_DEPEND(module_name, dependency_name, minimum_version,      \
    preferred_version, maximum_version)                                   \
    static const struct mod_depend                                        \
    MODULE_DEPEND_CONCAT(module_name, dependency_name) = {                \
        (minimum_version), (preferred_version), (maximum_version),         \
    };                                                                     \
    BSD_MODULE_RECORD(                                                     \
        _bsd_dependency_##module_name##_on_##dependency_name,             \
        BSD_MODULE_DEPENDENCY, #module_name, #dependency_name,            \
        &MODULE_DEPEND_CONCAT(module_name, dependency_name),               \
        (minimum_version), (preferred_version), (maximum_version),         \
        MDT_DEPEND)

#define MODULE_KERNEL_MAXVER                                              \
    (((__FreeBSD_version + 99999) / 100000) * 100000 - 1)

#define DECLARE_MODULE_WITH_MAXVER(name, module_data, subsystem, order, maxver) \
    MODULE_DEPEND(name, kernel, __FreeBSD_version, __FreeBSD_version,      \
        (maxver));                                                         \
    BSD_MODULE_RECORD(_bsd_module_declaration_##name,                      \
        BSD_MODULE_DECLARATION, #name, 0, &(module_data), 0, 0, 0,        \
        MDT_MODULE);                                                       \
    SYSINIT(name##module, subsystem, order, module_register_init,          \
        &(module_data));                                                   \
    struct __bsd_module_declaration_requires_semicolon

#define DECLARE_MODULE(name, module_data, subsystem, order)               \
    DECLARE_MODULE_WITH_MAXVER(name, module_data, subsystem, order,       \
        MODULE_KERNEL_MAXVER)

#define DECLARE_MODULE_TIED(name, module_data, subsystem, order)          \
    DECLARE_MODULE_WITH_MAXVER(name, module_data, subsystem, order,       \
        __FreeBSD_version)

#define MODULE_VERSION_CONCAT(module_name, version_value)                 \
    _##module_name##_version
#define MODULE_VERSION(module_name, version_value)                        \
    static const struct mod_version                                      \
    MODULE_VERSION_CONCAT(module_name, version_value) = {                 \
        (version_value),                                                  \
    };                                                                    \
    BSD_MODULE_RECORD(_bsd_version_##module_name, BSD_MODULE_VERSION,     \
        #module_name, #module_name,                                       \
        &MODULE_VERSION_CONCAT(module_name, version_value),               \
        (version_value), (version_value), (version_value), MDT_VERSION)

#define MODULE_PNP_INFO(description_value, bus_name, unique_name, table_value, \
    entry_count)                                                           \
    static const struct mod_pnp_match_info                                 \
    _module_pnp_##bus_name##_##unique_name = {                             \
        (description_value), #bus_name, (table_value),                     \
        (int)sizeof((table_value)[0]), (entry_count),                      \
    };                                                                     \
    BSD_MODULE_RECORD(_bsd_pnp_##bus_name##_##unique_name, BSD_MODULE_PNP, \
        #unique_name, #bus_name,                                           \
        &_module_pnp_##bus_name##_##unique_name, 0, 0, 0, MDT_PNP_INFO)

void module_register_init(const void *data);
int module_register(const moduledata_t *data, struct linker_file *container);
module_t module_lookupbyname(const char *name);
module_t module_lookupbyid(int id);
int module_quiesce(module_t module);
void module_reference(module_t module);
void module_release(module_t module);
int module_unload(module_t module);
int module_getid(module_t module);
module_t module_getfnext(module_t module);
const char *module_getname(module_t module);
void module_setspecific(module_t module, modspecific_t *data);
struct linker_file *module_file(module_t module);
int modevent_nop(module_t module, int event, void *argument);

#define MOD_XLOCK bsd_module_lock()
#define MOD_SLOCK bsd_module_lock()
#define MOD_XUNLOCK bsd_module_unlock()
#define MOD_SUNLOCK bsd_module_unlock()
#define MOD_LOCK_ASSERT bsd_module_lock_assert()
#define MOD_XLOCK_ASSERT bsd_module_lock_assert()

#endif
