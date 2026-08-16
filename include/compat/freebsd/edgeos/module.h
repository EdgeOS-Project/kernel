/* SPDX-License-Identifier: MPL-2.0 */
/* Static lifecycle records used by the EdgeOS BSD Driver Bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_MODULE_H
#define EDGEOS_COMPAT_FREEBSD_MODULE_H

#include <stddef.h>
#include <stdint.h>

#define BSD_BRIDGE_FREEBSD_VERSION 1600019

struct sysinit;
struct moduledata;
struct mod_pnp_match_info;
struct linker_file;
typedef struct bsd_linker_image bsd_linker_image_t;

enum bsd_static_record_kind {
    BSD_STATIC_SYSINIT = 1,
    BSD_STATIC_SYSUNINIT = 2,
    BSD_STATIC_MODULE_METADATA = 3,
};

enum bsd_module_record_kind {
    BSD_MODULE_DECLARATION = 1,
    BSD_MODULE_DEPENDENCY = 2,
    BSD_MODULE_VERSION = 3,
    BSD_MODULE_PNP = 4,
    BSD_MODULE_GENERIC_METADATA = 5,
};

struct bsd_module_static_record {
    enum bsd_module_record_kind kind;
    const char *owner;
    const char *name;
    const void *data;
    int minimum;
    int preferred;
    int maximum;
    int metadata_type;
};

void bsd_static_record_register(enum bsd_static_record_kind kind,
    const void *record);

#define BSD_BRIDGE_TOKEN_JOIN_INNER(left, right) left##right
#define BSD_BRIDGE_TOKEN_JOIN(left, right) \
    BSD_BRIDGE_TOKEN_JOIN_INNER(left, right)

#if defined(BSD_BRIDGE_HOST_TEST)
#define BSD_BRIDGE_LINK_RECORD(symbol, record_kind, section_name)        \
    static void __attribute__((constructor))                             \
    BSD_BRIDGE_TOKEN_JOIN(symbol, _bsd_register)(void)                   \
    {                                                                    \
        bsd_static_record_register((record_kind), &(symbol));            \
    }
#else
#if defined(_WIN32) || defined(EDGEOS_BSD_COFF_TARGET)
#define BSD_BRIDGE_SYSINIT_SECTION ".bsdsi$m"
#define BSD_BRIDGE_SYSUNINIT_SECTION ".bsdsu$m"
#define BSD_BRIDGE_MODULE_SECTION ".bsdmm$m"
#else
#define BSD_BRIDGE_SYSINIT_SECTION "bsd_sysinit"
#define BSD_BRIDGE_SYSUNINIT_SECTION "bsd_sysuninit"
#define BSD_BRIDGE_MODULE_SECTION "bsd_module_metadata"
#endif

#if (defined(_WIN32) || defined(EDGEOS_BSD_COFF_TARGET)) && \
    defined(__clang__) && defined(__has_attribute)
#if __has_attribute(retain)
#define BSD_BRIDGE_RETAIN __attribute__((retain))
#else
#define BSD_BRIDGE_RETAIN
#endif
#else
#define BSD_BRIDGE_RETAIN
#endif

#define BSD_BRIDGE_LINK_RECORD(symbol, record_kind, section_name)        \
    static const void *const                                             \
    BSD_BRIDGE_TOKEN_JOIN(symbol, _bsd_link)                             \
    __attribute__((used, section(section_name))) BSD_BRIDGE_RETAIN =     \
        &(symbol)
#endif

#define BSD_BRIDGE_LINK_SYSINIT(symbol)                                  \
    BSD_BRIDGE_LINK_RECORD(symbol, BSD_STATIC_SYSINIT,                   \
        BSD_BRIDGE_SYSINIT_SECTION)
#define BSD_BRIDGE_LINK_SYSUNINIT(symbol)                                \
    BSD_BRIDGE_LINK_RECORD(symbol, BSD_STATIC_SYSUNINIT,                 \
        BSD_BRIDGE_SYSUNINIT_SECTION)
#define BSD_BRIDGE_LINK_MODULE_RECORD(symbol)                            \
    BSD_BRIDGE_LINK_RECORD(symbol, BSD_STATIC_MODULE_METADATA,           \
        BSD_BRIDGE_MODULE_SECTION)

int bsd_sysinit_run_all(void);
int bsd_sysinit_run_through(int maximum_subsystem);
int bsd_sysinit_run_remaining(void);
int bsd_sysuninit_run_all(void);
int bsd_sysinit_is_complete(void);

int bsd_module_provide(const char *name, int version);
int bsd_module_validate_dependencies(void);
int bsd_module_last_error(void);
size_t bsd_module_pnp_count(void);
const struct mod_pnp_match_info *bsd_module_pnp_get(size_t index);
/* Activation consumes the image on both success and failure. */
int bsd_module_activate_image(bsd_linker_image_t *image, const char *name,
    struct linker_file **file_out);
int bsd_module_deactivate_file(struct linker_file *file);
size_t bsd_module_linked_file_count(void);

void bsd_module_lock(void);
void bsd_module_unlock(void);
void bsd_module_lock_assert(void);

#endif
