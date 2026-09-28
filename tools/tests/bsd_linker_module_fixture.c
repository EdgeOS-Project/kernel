/* SPDX-License-Identifier: MPL-2.0 */
/* Relocation fixture compiled into native EdgeOS module object formats. */

#include <stdint.h>

extern uint64_t fixture_external_value;
extern uint64_t fixture_external_add(uint64_t value);

typedef struct fixture_module_record {
    const uint64_t *external_value;
    const uint64_t *local_value;
    const char *label;
    uint64_t (*callback)(uint64_t value);
} fixture_module_record_t;

static const uint64_t fixture_local_value = 0x6c6f63616c76616cULL;
static const char fixture_label[] = "edgeos-module-fixture";

static uint64_t
fixture_callback(uint64_t value)
{
    return fixture_external_add(value) + fixture_local_value;
}

static const fixture_module_record_t fixture_record = {
    .external_value = &fixture_external_value,
    .local_value = &fixture_local_value,
    .label = fixture_label,
    .callback = fixture_callback,
};

#if defined(_WIN32)
#define FIXTURE_METADATA_SECTION ".bsdmm$m"
#else
#define FIXTURE_METADATA_SECTION "bsd_module_metadata"
#endif

static const void *const fixture_record_link
    __attribute__((used, section(FIXTURE_METADATA_SECTION))) =
        &fixture_record;
