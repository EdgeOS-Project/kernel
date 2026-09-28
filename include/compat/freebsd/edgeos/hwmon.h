/* SPDX-License-Identifier: MPL-2.0 */
/* Hardware-monitoring frontend for FreeBSD driver sysctl sensors. */

#ifndef EDGEOS_COMPAT_FREEBSD_HWMON_H
#define EDGEOS_COMPAT_FREEBSD_HWMON_H

#include <stddef.h>
#include <stdint.h>

enum bsd_hwmon_sensor_kind {
    BSD_HWMON_SENSOR_TEMPERATURE = 1,
    BSD_HWMON_SENSOR_FAN = 2,
};

#define BSD_HWMON_DEVICE_NAME_MAX 64
#define BSD_HWMON_ATTRIBUTE_NAME_MAX 128
#define BSD_HWMON_LABEL_MAX 128

struct bsd_hwmon_sensor_info {
    enum bsd_hwmon_sensor_kind kind;
    char device[BSD_HWMON_DEVICE_NAME_MAX];
    char attribute[BSD_HWMON_ATTRIBUTE_NAME_MAX];
    char label[BSD_HWMON_LABEL_MAX];
};

size_t bsd_hwmon_sensor_count(void);
int bsd_hwmon_sensor_get(size_t index, struct bsd_hwmon_sensor_info *info);
int bsd_hwmon_sensor_read(const struct bsd_hwmon_sensor_info *info,
    int64_t *value);

#endif
