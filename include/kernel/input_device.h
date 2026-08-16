/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux-compatible input device registry. */

#ifndef EDGEOS_KERNEL_INPUT_DEVICE_H
#define EDGEOS_KERNEL_INPUT_DEVICE_H

#include <stdint.h>

#define EDGE_INPUT_KEYBOARD 0u
#define EDGE_INPUT_POINTER 1u
#define EDGE_INPUT_DEVICE_MAX 16u
#define EDGE_INPUT_BITMAP_BYTES 128u
#define EDGE_INPUT_ABS_AXES 64u

#define EDGE_INPUT_ROLE_UNKNOWN 0u
#define EDGE_INPUT_ROLE_KEYBOARD 1u
#define EDGE_INPUT_ROLE_POINTER 2u

typedef struct {
    int32_t value;
    int32_t minimum;
    int32_t maximum;
    int32_t fuzz;
    int32_t flat;
    int32_t resolution;
} input_absinfo_t;

typedef struct {
    const char *name;
    const char *physical_path;
    const char *driver;
    uint8_t role;
    uint16_t bustype;
    uint16_t vendor;
    uint16_t product;
    uint16_t version;
    uint8_t properties[EDGE_INPUT_BITMAP_BYTES];
    uint8_t event_bits[EDGE_INPUT_BITMAP_BYTES];
    uint8_t key_bits[EDGE_INPUT_BITMAP_BYTES];
    uint8_t relative_bits[EDGE_INPUT_BITMAP_BYTES];
    uint8_t absolute_bits[EDGE_INPUT_BITMAP_BYTES];
    input_absinfo_t absolute[EDGE_INPUT_ABS_AXES];
    uint32_t repeat_delay_ms;
    uint32_t repeat_period_ms;
} input_device_description_t;

void input_device_describe_keyboard(input_device_description_t *description,
                                    const char *name,
                                    const char *physical_path,
                                    const char *driver,
                                    uint16_t bustype, uint16_t vendor,
                                    uint16_t product, uint16_t version);
void input_device_describe_pointer(input_device_description_t *description,
                                   const char *name,
                                   const char *physical_path,
                                   const char *driver,
                                   uint16_t bustype, uint16_t vendor,
                                   uint16_t product, uint16_t version,
                                   int absolute_pointer);

int input_device_register(uint32_t event_index,
                          const input_device_description_t *description,
                          const void *owner);
int input_device_register_available(
    uint32_t preferred_event_index,
    const input_device_description_t *description,
    const void *owner,
    uint32_t *event_index_out);
int input_device_unregister(uint32_t event_index, const void *owner);
int input_device_present(uint32_t device);
uint32_t input_device_role(uint32_t device);
uint32_t input_device_count(void);
const char *input_name(uint32_t device);
const char *input_physical_path(uint32_t device);
const char *input_driver(uint32_t device);
void input_id(uint32_t device, uint16_t out[4]);
uint32_t input_bits(uint32_t device, uint32_t type,
                    uint8_t *out, uint32_t length);
uint32_t input_properties(uint32_t device, uint8_t *out,
                          uint32_t length);
int input_absinfo(uint32_t device, uint32_t axis,
                  input_absinfo_t *out);
int input_repeat_get(uint32_t device, uint32_t values[2]);
int input_repeat_set(uint32_t device, const uint32_t values[2]);

#endif
