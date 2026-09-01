/* SPDX-License-Identifier: MPL-2.0 */
/* Relocatable object loader used by external BSD driver modules. */

#ifndef EDGEOS_COMPAT_FREEBSD_LINKER_H
#define EDGEOS_COMPAT_FREEBSD_LINKER_H

#include <stddef.h>
#include <stdint.h>

typedef enum bsd_linker_architecture {
    BSD_LINKER_ARCH_NATIVE = 0,
    BSD_LINKER_ARCH_X86_64 = 1,
    BSD_LINKER_ARCH_ARM64 = 2,
} bsd_linker_architecture_t;

typedef struct bsd_linker_image bsd_linker_image_t;

typedef int (*bsd_linker_symbol_resolver_t)(
    const char *name, uint64_t *address, void *context);

typedef struct bsd_linker_record_set {
    const void *const *sysinit_begin;
    const void *const *sysinit_end;
    const void *const *sysuninit_begin;
    const void *const *sysuninit_end;
    const void *const *metadata_begin;
    const void *const *metadata_end;
} bsd_linker_record_set_t;

#define BSD_LINKER_OK 0
#define BSD_LINKER_ERR_INVALID (-1)
#define BSD_LINKER_ERR_ARCHITECTURE (-2)
#define BSD_LINKER_ERR_FORMAT (-3)
#define BSD_LINKER_ERR_MEMORY (-4)
#define BSD_LINKER_ERR_SYMBOL (-5)
#define BSD_LINKER_ERR_RELOCATION (-6)
#define BSD_LINKER_ERR_RANGE (-7)

int bsd_linker_load_object(
    const void *object, size_t object_size,
    bsd_linker_architecture_t expected_architecture,
    bsd_linker_symbol_resolver_t resolver, void *resolver_context,
    bsd_linker_image_t **image_out);
void bsd_linker_release_image(bsd_linker_image_t *image);

bsd_linker_architecture_t bsd_linker_image_architecture(
    const bsd_linker_image_t *image);
const void *bsd_linker_image_base(const bsd_linker_image_t *image);
size_t bsd_linker_image_size(const bsd_linker_image_t *image);
int bsd_linker_image_records(
    const bsd_linker_image_t *image, bsd_linker_record_set_t *records);
int bsd_linker_image_resolve_symbol(
    const bsd_linker_image_t *image, const char *name, uint64_t *address);

#endif
