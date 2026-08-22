/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/input_device.h"
#include "kernel/linux_input.h"

#define EV_KEY 1u
#define EV_ABS 3u
#define ABS_MT_SLOT 0x2fu
#define ABS_MT_POSITION_X 0x35u

int devtmpfs_refresh_input_nodes(void) {
    return 0;
}

int kernel_device_uevent_emit(
    const char *action, const char *path, const char *subsystem,
    uint32_t major, uint32_t minor, const char *device_name,
    const char *driver, const char *modalias) {
    (void)action;
    (void)path;
    (void)subsystem;
    (void)major;
    (void)minor;
    (void)device_name;
    (void)driver;
    (void)modalias;
    return 0;
}

int linux_evdev_clock_supported(int clock_id) {
    return clock_id == 0 || clock_id == 1 || clock_id == 7;
}

static void set_bit(uint8_t *bitmap, uint32_t bit) {
    bitmap[bit >> 3] |= (uint8_t)(1u << (bit & 7u));
}

static edge_linux_input_ioctl_result_t run_ioctl(
    uint32_t device, uint32_t command, const void *input,
    uint32_t input_length, uint8_t output[EDGE_LINUX_INPUT_IOCTL_BUFFER_SIZE]) {
    edge_linux_input_ioctl_result_t result;
    int status = edge_linux_input_ioctl_execute(
        device, input_device_role(device), command, input, input_length,
        output, EDGE_LINUX_INPUT_IOCTL_BUFFER_SIZE, &result);
    assert(status == 0);
    return result;
}

int main(void) {
    static const int owner_keyboard;
    static const int owner_touch;
    input_device_description_t description;
    edge_linux_input_ioctl_result_t result;
    uint8_t output[EDGE_LINUX_INPUT_IOCTL_BUFFER_SIZE];
    uint32_t map[2];
    uint32_t axis;
    int32_t clock_id;

    input_device_describe_keyboard(
        &description, "Unit keyboard", "unit/input0", "unit", 3u,
        0x1234u, 0x5678u, 1u);
    assert(input_device_register(0u, &description, &owner_keyboard) == 0);

    memset(output, 0, sizeof(output));
    result = run_ioctl(0u, 0x80404506u, 0, 0u, output);
    assert(result.return_value == 14);
    assert(strcmp((const char *)output, "Unit keyboard") == 0);

    input_device_event_state_update(0u, EV_KEY, 30u, 1);
    memset(output, 0, sizeof(output));
    result = run_ioctl(0u, 0x80404518u, 0, 0u, output);
    assert(result.return_value == 64);
    assert((output[30u >> 3] & (1u << (30u & 7u))) != 0);

    map[0] = 30u;
    map[1] = 0u;
    memset(output, 0, sizeof(output));
    result = run_ioctl(0u, 0x80084504u, map, sizeof(map), output);
    (void)result;
    memcpy(map, output, sizeof(map));
    assert(map[1] == 30u);
    map[1] = 31u;
    (void)run_ioctl(0u, 0x40084504u, map, sizeof(map), output);
    map[1] = 0u;
    (void)run_ioctl(0u, 0x80084504u, map, sizeof(map), output);
    memcpy(map, output, sizeof(map));
    assert(map[1] == 31u);

    memset(&description, 0, sizeof(description));
    description.name = "Unit touchscreen";
    description.physical_path = "unit/input1";
    description.driver = "unit";
    description.role = EDGE_INPUT_ROLE_POINTER;
    set_bit(description.event_bits, EV_ABS);
    set_bit(description.absolute_bits, ABS_MT_SLOT);
    set_bit(description.absolute_bits, ABS_MT_POSITION_X);
    description.absolute[ABS_MT_SLOT].minimum = 0;
    description.absolute[ABS_MT_SLOT].maximum = 2;
    assert(input_device_register(1u, &description, &owner_touch) == 0);
    input_device_event_state_update(1u, EV_ABS, ABS_MT_SLOT, 1);
    input_device_event_state_update(1u, EV_ABS, ABS_MT_POSITION_X, 733);
    axis = ABS_MT_POSITION_X;
    memset(output, 0, sizeof(output));
    result = run_ioctl(1u, 0xc010450au, &axis, sizeof(axis), output);
    assert(result.output_length == 16u);
    assert(((int32_t *)output)[0] == (int32_t)ABS_MT_POSITION_X);
    assert(((int32_t *)output)[2] == 733);

    clock_id = 7;
    result = run_ioctl(0u, 0x400445a0u, &clock_id, sizeof(clock_id), output);
    assert(result.action == EDGE_LINUX_INPUT_ACTION_SET_CLOCK);
    assert(result.action_value == 7);

    assert(input_device_unregister(1u, &owner_touch) == 0);
    assert(input_device_unregister(0u, &owner_keyboard) == 0);
    puts("linux_input_unit: PASS");
    return 0;
}
