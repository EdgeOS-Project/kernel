/* SPDX-License-Identifier: MPL-2.0 */
/* Test adapter for module lifecycle tests that do not parse object files. */

#ifndef EDGEOS_TESTS_BSD_MODULE_LINKER_TEST_ADAPTER_H
#define EDGEOS_TESTS_BSD_MODULE_LINKER_TEST_ADAPTER_H

#include "compat/freebsd/edgeos/linker.h"

bsd_linker_image_t *bsd_test_linker_image_create(
    const bsd_linker_record_set_t *records);
size_t bsd_test_linker_image_release_count(void);

#endif
