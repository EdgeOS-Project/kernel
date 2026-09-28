/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS LinuxKPI Open Firmware extensions. */

#ifndef _EDGEOS_LINUXKPI_PREINCLUDE_LINUX_OF_H_
#define _EDGEOS_LINUXKPI_PREINCLUDE_LINUX_OF_H_

#include_next <linux/of.h>
#include <dev/ofw/ofw_bus_subr.h>

struct device_node;
struct device;
struct fwnode_handle;

struct of_device_id {
    char name[32];
    char type[32];
    char compatible[128];
    const void *data;
};

#ifndef of_match_ptr
#define of_match_ptr(_pointer) (_pointer)
#endif

static inline struct device_node *
to_of_node(const struct fwnode_handle *fwnode)
{
    (void)fwnode;
    return NULL;
}

static inline struct device_node *
of_parse_phandle(const struct device_node *node, const char *property,
    int index)
{
    (void)node;
    (void)property;
    (void)index;
    return NULL;
}

static inline void
of_node_put(const struct device_node *node)
{
    (void)node;
}

static inline bool
of_property_read_bool(const struct device_node *node, const char *property)
{
    (void)node;
    (void)property;
    return false;
}

static inline int
of_property_read_string(const struct device_node *node, const char *property,
    const char **value)
{
    (void)node;
    (void)property;
    if (value != NULL)
        *value = NULL;
    return -ENODATA;
}

static inline int
of_property_match_string(const struct device_node *node,
    const char *property, const char *value)
{
    (void)node;
    (void)property;
    (void)value;
    return -ENODATA;
}

static inline int
of_property_count_u32_elems(const struct device_node *node,
    const char *property)
{
    (void)node;
    (void)property;
    return -EINVAL;
}

static inline int
of_property_read_u32_array(const struct device_node *node,
    const char *property, u32 *values, size_t count)
{
    (void)node;
    (void)property;
    (void)values;
    (void)count;
    return -EINVAL;
}

static inline int
of_property_read_u32_index(const struct device_node *node,
    const char *property, int index, u32 *value)
{
    (void)node;
    (void)property;
    (void)index;
    (void)value;
    return -EINVAL;
}

#define of_device_get_match_data(_dev) \
    ((_dev) != NULL && (_dev)->driver != NULL && \
    (_dev)->driver->of_match_table != NULL ? \
    (_dev)->driver->of_match_table[0].data : NULL)

static inline bool
of_machine_is_compatible(const char *compatible)
{
    return ofw_bus_is_machine_compatible(compatible);
}

static inline bool
device_is_compatible(const struct device *dev, const char *compatible)
{
    (void)dev;
    (void)compatible;
    return false;
}

#endif
