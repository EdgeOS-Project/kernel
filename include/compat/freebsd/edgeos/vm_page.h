/* SPDX-License-Identifier: MPL-2.0 */
/* Test and platform hooks for the FreeBSD VM-page adapter. */

#ifndef EDGEOS_COMPAT_FREEBSD_VM_PAGE_H
#define EDGEOS_COMPAT_FREEBSD_VM_PAGE_H

#include <stdint.h>

struct vm_page;

int bsd_vm_page_bind(struct vm_page *page, void *allocation,
    uint64_t physical_address);
void bsd_vm_page_unbind(struct vm_page *page, const void *allocation);
int bsd_vm_page_runtime_initialize(void);

#ifdef BSD_BRIDGE_HOST_TEST
void bsd_vm_page_test_backend(void *(*allocate_page)(void),
    void (*release_page)(void *),
    int (*physical_address)(const void *, uint64_t *));
#endif

#endif
